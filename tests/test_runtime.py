"""无头渲染运行时采集的测试（不真的启动浏览器）。"""
from __future__ import annotations

import asyncio
import json
import os
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

os.environ["JSLW_DATA_DIR"] = tempfile.mkdtemp(prefix="jslw-runtime-")

from app import db, runtime  # noqa: E402
from app.config import ScanConfig  # noqa: E402
from app.discover import Extractor  # noqa: E402
from app.scanner import collect_runtime_seeds  # noqa: E402

db.init_db()


def netlog(events: list[dict]) -> str:
    """构造一份最小 netlog: 常量表 + 数字索引的事件。"""
    types = {"URL_REQUEST_START_JOB": 0, "HTTP_TRANSACTION_READ_HEADERS": 1}
    data = {"constants": {"logEventTypes": types}, "events": events}
    path = Path(tempfile.mkdtemp(prefix="jslw-netlog-")) / "netlog.json"
    path.write_text(json.dumps(data), encoding="utf-8")
    return str(path)


def test_parse_netlog_keeps_only_request_jobs() -> None:
    path = netlog([
        {"type": 0, "params": {"method": "GET", "url": "http://t/"}},
        {"type": 0, "params": {"method": "POST", "url": "http://t/api/save"}},
        {"type": 0, "params": {"url": "http://t/no-method"}},          # 缺 method, 跳过
        {"type": 0, "params": {"method": "GET", "url": "data:text/plain,x"}},  # 非 http, 跳过
        {"type": 1, "params": {"method": "GET", "url": "http://t/other"}},     # 非请求事件, 跳过
        {"type": 0, "params": {"method": "GET", "url": "http://t/"}},          # 重复, 去重
    ])
    assert runtime.parse_netlog(path) == [
        ("GET", "http://t/"),
        ("POST", "http://t/api/save"),
    ]
    assert runtime.parse_netlog("/nonexistent/netlog.json") == []


def test_render_without_chrome_degrades(monkeypatch) -> None:
    monkeypatch.delenv(runtime.CHROME_ENV, raising=False)
    monkeypatch.setattr(runtime, "find_chrome", lambda: None)
    result = runtime.render("http://t/")
    assert result.ok is False and "Chrome" in result.error


def _stub_render(dom: str, requests: list[tuple[str, str]]):
    async def fake_render(url, timeout=0, wait_ms=0, chrome=None):
        return runtime.RenderResult(url=url, ok=True, dom=dom, requests=requests, duration_ms=1)
    return fake_render


def test_collect_runtime_seeds_picks_dom_and_get_requests(monkeypatch) -> None:
    monkeypatch.setattr(runtime, "find_chrome", lambda: "/fake/chrome")
    rendered = """<html><body>
      <script src="/js/app.js"></script>
      <script src="/js/lazy-9f2c1d.js"></script>
    </body></html>"""
    monkeypatch.setattr(runtime, "render_page", _stub_render(rendered, [
        ("GET", "http://t/"),                                  # 入口页本身, 跳过
        ("GET", "http://t/api/runtime-config.json"),           # 运行时接口, 收
        ("POST", "http://t/api/save"),                         # 写请求, 不收
        ("GET", "https://cdn.other.com/x.json"),               # 跨域, 不收
        ("GET", "http://t/js/app.js"),                         # 与 DOM 重复, 只留一条
    ]))
    target = {"id": 1, "base_url": "http://t/"}
    extractor = Extractor(base_url="http://t/", scope="same-origin")
    cfg = ScanConfig(headless_render=True, max_api_endpoints=5, max_render_pages=1)
    seeds, notes = asyncio.run(collect_runtime_seeds(target, cfg, extractor))
    urls = {c.url: c.kind for c in seeds}
    assert notes == []
    assert urls.get("http://t/api/runtime-config.json") == "api"
    assert urls.get("http://t/js/lazy-9f2c1d.js") == "script"
    assert "http://t/api/save" not in urls and "https://cdn.other.com/x.json" not in urls
    assert sum(1 for c in seeds if c.url == "http://t/js/app.js") == 1


def test_collect_runtime_seeds_reports_missing_chrome(monkeypatch) -> None:
    monkeypatch.setattr(runtime, "find_chrome", lambda: None)
    cfg = ScanConfig(headless_render=True)
    seeds, notes = asyncio.run(collect_runtime_seeds({"id": 1, "base_url": "http://t/"},
                                                    cfg, Extractor(base_url="http://t/")))
    assert seeds == [] and notes and "Chrome" in notes[0]
