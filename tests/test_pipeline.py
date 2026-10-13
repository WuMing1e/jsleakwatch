"""端到端扫描测试: 起本地样例站点, 跑一轮完整扫描。

需要本机允许监听回环端口; 若沙箱禁止 bind, 该用例自动跳过。
"""
from __future__ import annotations

import functools
import http.server
import os
import socketserver
import sys
import tempfile
import threading
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

FIXTURE = ROOT / "fixtures" / "demo_site"


class _Server(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True


class _Handler(http.server.SimpleHTTPRequestHandler):
    extensions_map = {**http.server.SimpleHTTPRequestHandler.extensions_map,
                      ".js": "application/javascript", ".map": "application/json"}

    def log_message(self, *args) -> None:
        pass


@pytest.fixture(scope="module")
def demo_site():
    handler = functools.partial(_Handler, directory=str(FIXTURE))
    try:
        server = _Server(("127.0.0.1", 0), handler)
    except (PermissionError, OSError) as exc:  # 沙箱禁止监听时跳过
        pytest.skip(f"无法监听本地端口: {exc}")
    port = server.server_address[1]
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    yield f"http://127.0.0.1:{port}/"
    server.shutdown()
    server.server_close()


@pytest.fixture(scope="module")
def prepared(demo_site):
    tmp = tempfile.mkdtemp(prefix="jslw-e2e-")
    os.environ["JSLW_DATA_DIR"] = tmp
    import importlib

    from app import config
    importlib.reload(config)
    config.SETTINGS.scan.per_host_delay_ms = 0

    from app import db
    importlib.reload(db)
    db.init_db()
    tid = db.execute(
        "INSERT INTO targets(name, base_url, enabled, interval_minutes, scope, max_depth, "
        "max_assets, include_sourcemaps, probe_common_config, created_at, next_scan_at) "
        "VALUES(?,?,1,60,'same-origin',2,100,1,1,?,?)",
        ("Demo", demo_site, db.utcnow(), db.utcnow()),
    ).lastrowid
    row = db.query_one("SELECT * FROM targets WHERE id=?", (tid,))
    return {k: row[k] for k in row.keys()}, db


def _run(target):
    import asyncio

    from app import scanner
    import importlib
    importlib.reload(scanner)
    return asyncio.run(scanner.scan_target(target))


def test_full_scan_finds_chunks_and_secrets(prepared) -> None:
    target, db = prepared
    result = _run(target)
    assert result.status == "ok", result.error
    assert result.assets_fetched >= 8, "应递归采集到入口、chunk 与 sourcemap"
    urls = {row["url"] for row in db.query("SELECT url FROM assets")}
    assert any(url.endswith("4f2a1b.js") for url in urls), "webpack chunk 应被发现"
    assert any(url.endswith("app.js.map") for url in urls), "sourcemap 应被采集"

    rules = {row["rule_id"] for row in db.query("SELECT DISTINCT rule_id FROM findings")}
    for expected in ("aliyun-access-key-id", "tencent-cloud-secret-id", "stripe-secret-key",
                     "feishu-webhook", "dingtalk-webhook", "aws-access-key-id", "jwt-token"):
        assert expected in rules, f"缺少 {expected} 命中"
    assert len(result.new_findings) >= 15


def test_incremental_scan_is_quiet(prepared) -> None:
    target, db = prepared
    before = db.query_one("SELECT COUNT(*) c FROM findings")["c"]
    result = _run(target)
    assert result.status == "ok"
    assert result.new_findings == [], "内容未变化时不应重复告警"
    assert result.assets_skipped > 0, "未变化的资产应跳过重复检测"
    assert db.query_one("SELECT COUNT(*) c FROM findings")["c"] == before


def test_raw_secret_not_persisted_by_default(prepared) -> None:
    _, db = prepared
    row = db.query_one("SELECT raw_value, match_masked FROM findings LIMIT 1")
    assert row["raw_value"] in (None, "")
    assert "..." in row["match_masked"]


def test_status_transitions(prepared) -> None:
    import asyncio

    from app.scanner import scan_target
    target, db = prepared
    db.execute("UPDATE findings SET status='resolved' WHERE id=(SELECT MIN(id) FROM findings)")
    target["base_url"] = target["base_url"]  # 保持入口不变
    asyncio.run(scan_target(target, full=True))
    resolved = db.query_one("SELECT COUNT(*) c FROM findings WHERE status='resolved'")["c"]
    assert resolved == 0, "命中的凭证重新出现时应从已失效恢复为待处理"


def test_deleted_finding_is_redetected_on_next_scan(prepared) -> None:
    """删掉的发现, 下一轮要能重新命中 —— 增量扫描默认跳过未变资产, 所以删除时必须重新武装。"""
    import asyncio

    from app.scanner import mark_assets_for_recheck, scan_target

    target, db = prepared
    row = db.query_one(
        "SELECT id, target_id, asset_url FROM findings WHERE rule_id='database-url' LIMIT 1"
    )
    assert row is not None, "样例站点里应有 database-url（redis 连接串）命中"

    # 模拟界面上删除这条发现
    db.execute("DELETE FROM findings WHERE id=?", (row["id"],))
    assert mark_assets_for_recheck([row]) == 1, "删除后应把对应资产标记为需要重新检测"

    result = asyncio.run(scan_target(target))
    again = db.query_one("SELECT COUNT(*) c FROM findings WHERE rule_id='database-url'")["c"]
    assert again == 1, "删掉的 redis 连接串应在下一轮扫描里重新命中"
    assert result.assets_skipped < result.assets_fetched, "被标记的资产不应再走跳过分支"
