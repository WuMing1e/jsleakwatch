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


def test_marked_false_positive_is_not_alerted_again(prepared) -> None:
    """标成误报/忽略后, 后续扫到同一条不应再进告警队列。"""
    import asyncio

    from app.scanner import scan_target

    target, db = prepared
    asyncio.run(scan_target(target, full=True))     # 先用一轮扫描把样例站点的发现跑出来
    row = db.query_one(
        "SELECT id, fingerprint FROM findings WHERE rule_id='database-url' ORDER BY id LIMIT 1")
    assert row is not None
    db.execute("UPDATE findings SET status='false_positive' WHERE id=?", (row["id"],))

    # 强制重扫: 走的是"资产内容未变也会重新检测"的路径, 最容易被误当成新发现
    result = asyncio.run(scan_target(target, full=True))
    after = db.query_one("SELECT status FROM findings WHERE id=?", (row["id"],))
    assert after["status"] == "false_positive", "已标记的状态不该被重扫改回 new"
    assert all(f.get("fingerprint") != row["fingerprint"] for f in result.new_findings), \
        "标记过的命中不该再次进入推送队列"


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


def test_interactive_render_stores_runtime_api_assets(prepared) -> None:
    """Playwright 路由采集拿到的运行时请求也要进入统一接口资产。"""
    import asyncio

    from app.scanner import scan_target

    target, db = prepared
    previous = db.get_setting("scan") or {}
    db.set_setting("scan", {
        **previous,
        "headless_render": True,
        "interactive_render": True,
        "max_render_pages": 2,
        "render_wait_ms": 700,
        "scan_api_endpoints": True,
        "max_api_endpoints": 10,
    })
    try:
        result = asyncio.run(scan_target(target))
        api_assets = db.query(
            "SELECT url FROM assets WHERE target_id=? AND kind='api'", (target["id"],))
        assert result.status == "ok", result.error
        assert any(row["url"].endswith("/api/runtime-config.json") for row in api_assets), \
            f"运行时接口应落库, 实际: {[row['url'] for row in api_assets]}"
    finally:
        db.set_setting("scan", previous)


# ------------------------------------------------------------ 抓取重试

class _FakeStreamResponse:
    """够用的流式响应替身: 只实现 Fetcher._request 用到的几个属性。"""

    def __init__(self, url: str, body: bytes, declared: int | None = None) -> None:
        self.status_code = 200
        self.url = url
        self.encoding = "utf-8"
        self.body = body
        self.headers = {"content-type": "application/javascript"}
        if declared is not None:
            self.headers["content-length"] = str(declared)

    async def aiter_bytes(self):
        step = 256 * 1024                      # 分块给, 贴近真实流式读取
        for i in range(0, len(self.body), step):
            yield self.body[i:i + step]


class _FakeClient:
    """前 N 次抛异常, 之后返回响应: 用来验证"抖动→重试→成功"这条路。"""

    def __init__(self, failures: int = 0, exc: Exception | None = None,
                 body: bytes = b"var a = 1;", declared: int | None = None) -> None:
        self.failures = failures
        self.exc = exc
        self.body = body
        self.declared = declared
        self.calls = 0

    def stream(self, method: str, url: str, **kwargs):
        self.calls += 1
        self.last_timeout = kwargs.get("timeout")
        fail = self.exc is not None and self.calls <= self.failures
        exc = self.exc
        resp = _FakeStreamResponse(url, self.body, self.declared)

        class _Ctx:
            async def __aenter__(inner):
                if fail:
                    raise exc
                return resp

            async def __aexit__(inner, *args):
                return False

        return _Ctx()


def _fetch_with(client, retries: int = 1, max_asset_bytes: int = 0):
    import asyncio

    from app.config import ScanConfig
    from app.fetcher import Fetcher

    fetcher = Fetcher(ScanConfig(max_retries=retries, per_host_delay_ms=0,
                                 max_asset_bytes=max_asset_bytes))
    fetcher._client = client
    return asyncio.run(fetcher.get("http://example.test/a.js")), fetcher


def test_transient_connect_timeout_is_retried_once() -> None:
    """一次连接超时不该让站点变成"部分成功": 重试一次应当拿到内容。"""
    import httpx

    result, fetcher = _fetch_with(_FakeClient(1, httpx.ConnectTimeout("连接超时")), retries=1)
    assert result.ok and result.text == "var a = 1;"
    assert fetcher.requests_made == 1


def test_tls_certificate_error_is_not_retried() -> None:
    """自签证书是永久错误, 重试只会拖慢扫描并放大连接池超时。"""
    import httpx

    client = _FakeClient(99, httpx.ConnectError(
        "[SSL: CERTIFICATE_VERIFY_FAILED] certificate verify failed: self-signed certificate"))
    result, _ = _fetch_with(client, retries=1)
    assert not result.ok and "CERTIFICATE_VERIFY_FAILED" in result.error
    assert client.calls == 1


def test_read_timeout_gets_one_longer_retry() -> None:
    """读取超时后用更长超时补一次, 避免慢 JS 被误判为缺失。"""
    import httpx

    client = _FakeClient(99, httpx.ReadTimeout("响应超时"))
    result, _ = _fetch_with(client, retries=1)
    assert not result.ok and result.error.startswith("ReadTimeout")
    assert client.calls == 2
    assert client.last_timeout == 30.0


def test_read_timeout_retry_recovers_slow_asset() -> None:
    import httpx

    client = _FakeClient(1, httpx.ReadTimeout("响应超时"))
    result, _ = _fetch_with(client, retries=1)
    assert result.ok and result.text == "var a = 1;"
    assert client.calls == 2
    assert client.last_timeout == 30.0


def test_retry_gives_up_and_reports_last_error() -> None:
    import httpx

    client = _FakeClient(99, httpx.ConnectTimeout("连接超时"))
    result, _ = _fetch_with(client, retries=1)
    assert not result.ok and result.error.startswith("ConnectTimeout")
    assert client.calls == 2, "重试一次即放弃"


def test_retries_can_be_turned_off() -> None:
    import httpx

    client = _FakeClient(99, httpx.ConnectTimeout("连接超时"))
    result, _ = _fetch_with(client, retries=0)
    assert not result.ok
    assert client.calls == 1


def test_read_timeout_retry_can_be_turned_off() -> None:
    import httpx

    client = _FakeClient(99, httpx.ReadTimeout("响应超时"))
    result, _ = _fetch_with(client, retries=0)
    assert not result.ok
    assert client.calls == 1


def test_same_host_requests_respect_concurrency_limit() -> None:
    import asyncio

    from app.config import ScanConfig
    from app.fetcher import Fetcher

    class SlowClient(_FakeClient):
        def __init__(self) -> None:
            super().__init__()
            self.active = 0
            self.max_active = 0

        def stream(self, method: str, url: str, **kwargs):
            outer = self

            class _Ctx:
                async def __aenter__(inner):
                    outer.calls += 1
                    outer.active += 1
                    outer.max_active = max(outer.max_active, outer.active)
                    await asyncio.sleep(0.04)
                    return _FakeStreamResponse(url, outer.body)

                async def __aexit__(inner, *args):
                    outer.active -= 1
                    return False

            return _Ctx()

    client = SlowClient()

    async def run():
        fetcher = Fetcher(ScanConfig(
            max_concurrency=6, per_host_concurrency=2, per_host_delay_ms=0,
            max_retries=0,
        ))
        fetcher._client = client
        await asyncio.gather(*(fetcher.get(f"http://same.test/{i}.js") for i in range(8)))

    asyncio.run(run())
    assert client.calls == 8
    assert client.max_active == 2


# ------------------------------------------------------------ 单资产大小上限

def test_asset_larger_than_limit_is_truncated_when_limit_set() -> None:
    body = b"x" * (3 * 1024 * 1024)
    result, _ = _fetch_with(_FakeClient(body=body, declared=len(body)), max_asset_bytes=1_000_000)
    assert result.truncated and len(result.text) == 1_000_000
    assert result.size == len(body), "截断时也要报文件真实大小"


def test_zero_limit_means_no_truncation() -> None:
    """解除大小限制后, 整份文件都要下载并交给检测, 不能再截断。"""
    body = b"var secret = 'x';\n" * 200_000          # 约 3.8 MB
    result, fetcher = _fetch_with(_FakeClient(body=body, declared=len(body)), max_asset_bytes=0)
    assert not result.truncated
    assert len(result.text) == len(body), "0 = 不限, 不应截断"
    assert fetcher.bytes_fetched == len(body)


def test_detector_scans_whole_text_when_unlimited() -> None:
    """检测引擎也不该自己再截一刀: 藏在文件尾部(10MB 之后)的密钥也要被抓到。"""
    from app.rules import Detector

    padding = "var a = 1;\n" * 900_000               # 约 9 MB 噪声
    tail = 'const aws = "AKIA3XQ7ZP2LMN4KQ7DA";'
    findings = Detector().scan_text(padding + tail, target_id=0, asset_url="http://x/big.js")
    # 命中值默认只存掩码, 所以按规则 ID 断言
    assert any(f.rule_id == "aws-access-key-id" for f in findings), "文件尾部的命中不应被截掉"


def test_jshawk_scanner_runs_against_demo_site(demo_site) -> None:
    """真调一次 JSHawk(本机留有工具副本时才跑), 验证"调起脚本 → 读报告"这条链路。"""
    import asyncio

    from app.target_scanners import JSHawkScanner

    scanner = JSHawkScanner(module_dir=str(ROOT / "tools" / "external" / "JSHawk"),
                            threads=4, timeout=120)
    if not scanner.available():
        pytest.skip("本机没有 JSHawk 副本(tools/external/JSHawk), 跳过")
    run = asyncio.run(scanner.scan({"base_url": demo_site, "id": 0, "name": "Demo"}))
    assert not run.error, run.error
    # 样例站的 app.js 里埋了 Google/GitHub/Stripe/JWT/连接串等命中
    assert len(run.hits) >= 4, run.note
    kinds = {h.rule_id for h in run.hits}
    assert any("GITHUB_TOKEN" in k for k in kinds), kinds
    assert any(h.raw for h in run.hits), "命中值要带回明文给上层做掩码入库"


# ------------------------------------------------------------ WAF 挑战页 / 重复内容

WAF_PAGE = """<!doctype html><html><head><meta charset="utf-8">
<meta name="aliyun_waf_aa" content="1adbee4a1f3c0d9e2b7a5c8d0e1f2a3b"></head>
<body><textarea>c2VjcmV0bG9va2luZ2NpcGhlcnRleHQ=</textarea>
<script>var arg1='5de24083e29177ff21e803d163d59e56776a29ea63730eb2fc';
function getRenderData(){return document.getElementById("renderData").innerHTML}</script>
<meta name="aliyun_waf_bb" content="f6d4a4f6661cb5f9eb7338a7c7ddd4c5"></body></html>"""

PLAIN_PAGE = """<!doctype html><html><head><title>站点首页</title></head>
<body><script src="/app.js"></script></body></html>"""


def _serve(handler_cls) -> tuple:
    """起一个临时站点, 返回 (server, base_url)。"""
    try:
        server = _Server(("127.0.0.1", 0), handler_cls)
    except (PermissionError, OSError) as exc:
        pytest.skip(f"无法监听本地端口: {exc}")
    port = server.server_address[1]
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server, f"http://127.0.0.1:{port}/"


def _site_handler(page_body: str):
    """所有路径都返回同一个页面 —— 典型的 SPA 回退 / WAF 拦截。"""

    class Handler(http.server.BaseHTTPRequestHandler):
        def do_GET(self) -> None:
            body = page_body.encode()
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *args) -> None:
            pass

    return Handler


def _new_target(db, base_url: str) -> dict:
    tid = db.execute(
        "INSERT INTO targets(name, base_url, enabled, interval_minutes, scope, max_depth, "
        "max_assets, include_sourcemaps, probe_common_config, created_at, next_scan_at) "
        "VALUES(?,?,1,60,'same-origin',2,50,1,1,?,?)",
        (base_url, base_url, db.utcnow(), db.utcnow()),
    ).lastrowid
    row = db.query_one("SELECT * FROM targets WHERE id=?", (tid,))
    return {k: row[k] for k in row.keys()}


def test_json_manifest_js_urls_are_extracted() -> None:
    """接口清单里的同源 .js 要能挖出来; 跨域、非 js、坏 JSON 都不要。"""
    import json

    from app.scanner import _js_urls_from_json

    site = "https://h5.example.com/"
    base = "https://h5.example.com/api/default/abc"
    manifest = json.dumps({
        "widgets": [
            {"url": "/api/default/abc/assets/bundle/widget/1.2.6/ssoLogin.js"},
            {"url": "https://cdn.other.com/x.js"},
            {"url": "/api/data.json"},
            {"nested": ["./static/js/a.js?v=1", "/static/js/b.js#x"]},
        ],
        "note": "不是脚本",
    })
    urls = _js_urls_from_json(manifest, base, site)
    assert "https://h5.example.com/api/default/abc/assets/bundle/widget/1.2.6/ssoLogin.js" in urls
    assert "https://h5.example.com/api/default/static/js/a.js?v=1" in urls
    assert "https://h5.example.com/static/js/b.js#x" in urls
    assert not any("other.com" in u or u.endswith(".json") for u in urls)
    assert _js_urls_from_json("<html></html>", base, site) == []
    assert _js_urls_from_json("{bad json", base, site) == []


def test_api_manifest_scripts_are_crawled(prepared) -> None:
    """接口返回的 JSON 清单里引用同源脚本时, 扫描要真的把它抓回来并检测。"""
    import json

    _target, db = prepared

    class Handler(http.server.BaseHTTPRequestHandler):
        def do_GET(self) -> None:
            if self.path.startswith("/app.js"):
                body, ctype = b'axios.get("/api/manifest");', "application/javascript"
            elif self.path.startswith("/api/manifest"):
                body = json.dumps({"widgets": [{"url": "/widget/sso.js"}]}).encode()
                ctype = "application/json"
            elif self.path.startswith("/widget/sso.js"):
                body = b'const aws = "AKIA3XQ7ZP2LMN4KQ7DA";'
                ctype = "application/javascript"
            else:
                body = b'<html><script src="/app.js"></script></html>'
                ctype = "text/html"
            self.send_response(200)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *args) -> None:
            pass

    server, url = _serve(Handler)
    previous = db.get_setting("scan") or {}
    db.set_setting("scan", {**previous, "scan_api_endpoints": True,
                            "max_api_endpoints": 20, "headless_render": False})
    try:
        target = _new_target(db, url)
        result = _run(target)
    finally:
        server.shutdown()
        server.server_close()
        db.set_setting("scan", previous)

    assert result.status == "ok", result.error
    urls = [r["url"] for r in db.query(
        "SELECT url FROM assets WHERE target_id=?", (target["id"],))]
    assert any(u.endswith("/widget/sso.js") for u in urls), f"清单里的脚本应被抓取: {urls}"
    hits = [r["rule_id"] for r in db.query(
        "SELECT rule_id FROM findings WHERE target_id=?", (target["id"],))]
    assert "aws-access-key-id" in hits, hits


def test_same_secret_is_upgraded_to_a_more_specific_rule(prepared) -> None:
    """同一把密钥先被通用规则(低等级)命中, 后来被专用规则(高等级)识别时, 要升级而不是并存。"""
    import hashlib

    from app.rules import Detection
    from app.scanner import _upsert_finding

    _target, db = prepared
    tid = int(db.execute(
        "INSERT INTO targets(name, base_url, created_at) VALUES(?,?,?)",
        ("升级测试", "http://up.test/", db.utcnow()),
    ).lastrowid or 0)
    value = "dhV2Rlgmkz8QyjiLW4ZlfsAWKrFrbedb5mOHLz2eBYk"
    digest = hashlib.sha256(value.encode()).hexdigest()
    fid = int(db.execute(
        "INSERT INTO findings(target_id, rule_id, rule_name, severity, category, fingerprint, "
        "match_masked, match_sha256, context, line_no, entropy, asset_url, first_seen_at, last_seen_at, "
        "times_seen, status, verified) VALUES(?,?,?,?,?,?,?,?,?,1,4.9,?,?,?,1,'open','unverified')",
        (tid, "high-entropy-string", "高熵字符串", "low", "secret", "fp-up", "dhV2...eBYk(len=43)",
         digest, "ctx", "http://up.test/a.js", db.utcnow(), db.utcnow()),
    ).lastrowid or 0)

    specific = Detection(
        rule_id="wecom-corpsecret", rule_name="企业微信 CorpSecret", severity="critical",
        category="im", raw=value, masked="dhV2...eBYk(len=43)", sha256=digest, entropy=4.9,
        line_no=1, context="WECHAT_SECRET:\"...\"", fingerprint="fp-new",
    )
    created, _reopened, returned, upgraded = _upsert_finding(
        tid, None, "http://up.test/a.js", specific)
    assert created is False and returned == fid, "同一把值不该新建记录"
    assert upgraded is True, "被更具体的规则识别时应标记为升级(这样才会重新进告警队列)"
    row = db.query_one("SELECT rule_id, severity, match_sha256 FROM findings WHERE id=?", (fid,))
    assert row["rule_id"] == "wecom-corpsecret" and row["severity"] == "critical"
    assert row["match_sha256"] == digest, "升级不该改变值指纹"


def test_render_failure_is_a_warning_not_a_scan_failure(prepared, monkeypatch) -> None:
    """无头渲染是"可选增强": 它失败不该把整站标成"部分成功"。"""
    import asyncio

    from app import scanner

    target_row, db = prepared
    target = _new_target(db, target_row["base_url"])
    previous = db.get_setting("scan") or {}
    db.set_setting("scan", {**previous, "headless_render": True})

    async def fake_seeds(_target, _cfg, _extractor):
        return [], ["无头渲染失败: 渲染超时 (30s)"]

    monkeypatch.setattr(scanner, "collect_runtime_seeds", fake_seeds)
    try:
        result = asyncio.run(scanner.scan_target(target))
    finally:
        db.set_setting("scan", previous)

    assert result.status == "ok", result.error
    assert "渲染超时" in result.render_note


def test_external_hit_inside_base64_is_not_imported(prepared) -> None:
    """JSHawk 报的 Okta token 其实是 Base64 密文里切出来的一段 —— 这种不进发现列表。"""
    import asyncio

    from app.analyzers import RawHit
    from app.scanner import ScanResult, _target_scanner_phase
    from app.target_scanners import ScanRunResult

    _target, db = prepared
    target = _new_target(db, "http://frag.test/")
    url = "http://frag.test/js/chunk.js"
    secret = "00ivkbaFBztxUmeHZluXhgQ25PGNZwlzmrBryzsAfB"

    class FakeScanner:
        name = "faketool"

        async def scan(self, _target):
            return ScanRunResult(hits=[RawHit(rule_id="OKTA_TOKEN", severity="critical",
                                              raw=secret, url=url)])

    blob = "xjqV7" + secret + "DhrNt1r3zdooAjuQbSfCnE7sZ6Yt"
    result = ScanResult(target["id"])
    asyncio.run(_target_scanner_phase(target, [FakeScanner()], set(), result, {url: blob}))
    assert db.query_one("SELECT id FROM findings WHERE target_id=?", (target["id"],)) is None
    assert result.target_scanner_summary["faketool"]["fragments"] == 1


def test_context_snippet_is_taken_around_the_match() -> None:
    from app.scanner import _context_around

    text = "x" * 300 + 'var okta="abcdef123456";' + "y" * 300
    snippet = _context_around(text, "abcdef123456", width=20)
    assert 'okta="abcdef123456"' in snippet
    assert snippet.startswith("…") and snippet.endswith("…")
    assert _context_around(text, "NOT_THERE") == ""


def test_external_hit_context_is_rebuilt_from_the_asset(prepared) -> None:
    """外部工具给的"上下文"如果跟命中位置无关(实测 JSHawk 给的是文件开头), 要换成真实前后文。"""
    import asyncio

    from app.analyzers import RawHit
    from app.scanner import ScanResult, _target_scanner_phase
    from app.target_scanners import ScanRunResult

    _target, db = prepared
    target = _new_target(db, "http://ctx.test/")
    url = "http://ctx.test/js/chunk.js"
    secret = "00ivkbaFBztxUmeHZluXhgQ25PGNZwlzmrBryzsAfB"

    class FakeScanner:
        name = "faketool"

        async def scan(self, _target):
            return ScanRunResult(hits=[RawHit(
                rule_id="OKTA_TOKEN", severity="critical", raw=secret,
                context='(window["webpackJsonp"]=window["webpackJsonp"] []).push([...',
                url=url,
            )])

    text = "x" * 500 + f'var okta="{secret}";' + "y" * 500
    asyncio.run(_target_scanner_phase(target, [FakeScanner()], set(),
                                      ScanResult(target["id"]),
                                      {url: text}))
    row = db.query_one("SELECT context FROM findings WHERE target_id=? AND rule_id=?",
                       (target["id"], "faketool:OKTA_TOKEN"))
    assert row is not None
    assert "var okta=" in row["context"] and secret in row["context"]
    assert "webpackJsonp" not in row["context"], "工具给的误导性片段不该留下"


def test_waf_challenge_page_is_skipped_entirely(prepared) -> None:
    """入口就是人机校验页时: 不落资产、不扫内容, 并且把原因说清楚。

    实测踩过: 阿里云 WAF 校验页里的 <meta name="aliyun_waf_bb"> 被当成
    AccessKey Secret 报了 critical, 还推到了飞书。
    """
    _target, db = prepared
    server, url = _serve(_site_handler(WAF_PAGE))
    try:
        target = _new_target(db, url)
        result = _run(target)
    finally:
        server.shutdown()
        server.server_close()

    assert result.status == "failed"
    assert "人机校验页" in result.error and "aliyun_waf" in result.error
    assert result.assets_fetched == 0, "校验页不该被当成资产"
    kept = db.query("SELECT url FROM assets WHERE target_id=?", (target["id"],))
    assert kept == [], "整站都在校验页后面, 一个资产都不该存"
    assert db.query("SELECT id FROM findings WHERE target_id=?", (target["id"],)) == []


def test_http_error_on_entry_marks_scan_failed(prepared) -> None:
    """入口返回 5xx 时不能因为"没有异常字符串"就误显示成正常。"""
    _target, db = prepared

    class Handler(http.server.BaseHTTPRequestHandler):
        requests: list[str] = []

        def do_GET(self) -> None:
            self.requests.append(self.path)
            body = b"gateway unavailable"
            self.send_response(503)
            self.send_header("Content-Type", "text/plain")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *args) -> None:
            pass

    server, url = _serve(Handler)
    try:
        target = _new_target(db, url)
        result = _run(target)
    finally:
        server.shutdown()
        server.server_close()

    assert result.status == "failed"
    assert "HTTP 503" in result.error
    assert Handler.requests == ["/"], "入口失败后不应继续并发配置探针"


def test_external_scanner_discovered_js_is_ingested(
        prepared, monkeypatch) -> None:
    """JSHawk/JScanner2 发现的 JS 要回写资产库并走统一检测。"""
    import asyncio

    from app import scanner
    from app.target_scanners import ScanRunResult

    _target, db = prepared

    class Handler(http.server.BaseHTTPRequestHandler):
        def do_GET(self) -> None:
            if self.path.startswith("/app.js"):
                body, ctype = b"var a = 1;", "application/javascript"
            elif self.path.startswith("/external.js"):
                body = b'var aws = "AKIA3XQ7ZP2LMN4KQ7DA";'
                ctype = "application/javascript"
            else:
                body = b'<html><script src="/app.js"></script></html>'
                ctype = "text/html"
            self.send_response(200)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *args) -> None:
            pass

    server, url = _serve(Handler)
    external_url = url + "external.js"

    class FakeScanner:
        name = "fake-discovery"

        async def scan(self, _target):
            return ScanRunResult(discovered_urls=[external_url])

    monkeypatch.setattr(scanner, "enabled_target_scanners", lambda: [FakeScanner()])
    try:
        target = _new_target(db, url)
        result = asyncio.run(scanner.scan_target(target))
    finally:
        server.shutdown()
        server.server_close()

    assert external_url in result.discovered_js_urls
    assert db.query_one("SELECT id FROM assets WHERE target_id=? AND url=?",
                        (target["id"], external_url)) is not None
    assert db.query_one("SELECT id FROM findings WHERE target_id=? AND rule_id=?",
                        (target["id"], "aws-access-key-id")) is not None


def test_identical_content_is_stored_only_once(prepared) -> None:
    """SPA 对任意路径都返回同一个页面时, 只存一份, 别把它拆成几十个资产。"""
    _target, db = prepared
    server, url = _serve(_site_handler(PLAIN_PAGE))
    try:
        target = _new_target(db, url)
        result = _run(target)
    finally:
        server.shutdown()
        server.server_close()

    assert result.status == "ok", result.error
    assert result.assets_duplicate >= 1, "配置入口都返回首页, 应当被判定为重复内容"
    urls = [row["url"] for row in db.query("SELECT url FROM assets WHERE target_id=?", (target["id"],))]
    assert len(urls) == 1, f"只该留下入口页, 实际存了 {urls}"
    assert urls[0] == url
    """检测引擎也不该自己再截一刀: 藏在文件尾部(10MB 之后)的密钥也要被抓到。"""
    from app.rules import Detector

    padding = "var a = 1;\n" * 900_000               # 约 9 MB 噪声
    tail = 'const aws = "AKIA3XQ7ZP2LMN4KQ7DA";'
    findings = Detector().scan_text(padding + tail, target_id=0, asset_url="http://x/big.js")
    # 命中值默认只存掩码, 所以按规则 ID 断言
    assert any(f.rule_id == "aws-access-key-id" for f in findings), "文件尾部的命中不应被截掉"
