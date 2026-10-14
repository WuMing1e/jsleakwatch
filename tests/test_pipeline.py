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


def test_scan_records_asset_versions_without_storing_source(prepared) -> None:
    """扫描要给每个变化的资产留一版字符串签名, 且签名里不能出现明文密钥。"""
    import asyncio
    import json

    from app.scanner import scan_target

    target, db = prepared
    db.execute("DELETE FROM asset_versions")
    db.execute("UPDATE assets SET recheck=1 WHERE target_id=?", (target["id"],))
    result = asyncio.run(scan_target(target))

    assert result.assets_changed > 0, "内容变化的资产应被记一版"
    rows = db.query("SELECT url, strings, added FROM asset_versions")
    assert len(rows) >= 8, "样例站点 9 个资产都应留档"
    app_js = next(row for row in rows if row["url"].endswith("/js/app.js"))
    signature = json.loads(app_js["strings"])
    assert any("js" in item for item in signature), "普通字符串要留在签名里, 否则看不出改了什么"
    # 以密钥前缀开头的条目必须是掩码形态（首尾各留几字符 + (len=...)）
    leaked = [item for item in signature
              if item.startswith(("AKIA", "LTAI", "ghp_", "sk_l", "AKID")) and "..." not in item]
    assert leaked == [], f"明文密钥不能进签名: {leaked}"
    assert any("(len=" in item for item in signature), "命中的密钥应以掩码形态留档"

    # 增量扫描（内容未变）不应再产生新版本
    before = db.query_one("SELECT COUNT(*) c FROM asset_versions")["c"]
    asyncio.run(scan_target(target))
    assert db.query_one("SELECT COUNT(*) c FROM asset_versions")["c"] == before


def test_api_endpoint_responses_are_scanned(prepared) -> None:
    """打开接口采集后: JS 里的 GET 接口会被抓回来, 响应体里的密钥同样能命中。"""
    import asyncio

    from app.scanner import scan_config_from_settings, scan_target

    target, db = prepared
    db.set_setting("scan", {**(db.get_setting("scan") or {}),
                            "scan_api_endpoints": True, "max_api_endpoints": 10})
    assert scan_config_from_settings().scan_api_endpoints is True
    try:
        result = asyncio.run(scan_target(target))
        assert result.status == "ok"
        urls = {row["url"] for row in db.query("SELECT url FROM assets WHERE kind='api'")}
        assert any(url.endswith("/api/runtime-config.json") for url in urls), \
            f"接口地址应被发现并抓取, 实际: {urls}"
        hits = db.query(
            "SELECT rule_id, match_masked FROM findings WHERE asset_url LIKE '%api/runtime-config.json'"
        )
        assert any(row["rule_id"] == "aws-access-key-id" for row in hits), \
            f"接口响应里的密钥应被命中, 实际: {[r['rule_id'] for r in hits]}"
        # 接口资产不进变更流（响应常带时间戳, 记版本会刷屏）
        assert db.query_one(
            "SELECT COUNT(*) c FROM asset_versions WHERE url LIKE '%api/runtime-config.json'"
        )["c"] == 0
    finally:
        db.set_setting("scan", {**(db.get_setting("scan") or {}),
                                "scan_api_endpoints": False})


def test_headless_render_finds_runtime_only_addresses(prepared) -> None:
    """无头渲染能拿到静态抓取看不到的运行时接口地址（这里关掉静态接口采集来对照）。"""
    import asyncio

    from app.runtime import find_chrome
    from app.scanner import scan_target

    if not find_chrome():
        pytest.skip("本机没有 Chrome/Chromium，跳过无头渲染用例")
    target, db = prepared
    previous = db.get_setting("scan") or {}
    db.set_setting("scan", {**previous, "headless_render": True, "max_render_pages": 1,
                            "scan_api_endpoints": False})
    try:
        result = asyncio.run(scan_target(target))
        assert result.status == "ok"
        assert result.runtime_seeds >= 1, "无头渲染应补出至少一个地址"
        urls = {row["url"] for row in db.query("SELECT url FROM assets WHERE kind='api'")}
        assert any(url.endswith("/api/runtime-config.json") for url in urls), \
            "运行时才发起的接口地址应由渲染补出来"
    finally:
        db.set_setting("scan", previous)
