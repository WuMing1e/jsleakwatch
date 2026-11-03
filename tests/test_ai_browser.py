"""AI 第二阶段浏览器探索的约束与合并测试。"""
from __future__ import annotations

import asyncio
import os
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
os.environ["JSLW_DATA_DIR"] = tempfile.mkdtemp(prefix="jslw-ai-browser-")

from app import ai_browser, db, runtime  # noqa: E402
from app.config import ScanConfig  # noqa: E402
from app.discover import Extractor  # noqa: E402
from app.scanner import collect_runtime_seeds  # noqa: E402

db.init_db()


def test_ai_browser_control_policy() -> None:
    base = "https://site.test/"
    assert ai_browser._safe_control({"text": "统一认证登录", "href": ""}, base)
    assert ai_browser._safe_control({
        "text": "帮助中心", "href": "https://site.test/help",
    }, base)
    assert not ai_browser._safe_control({"text": "登录", "href": ""}, base)
    assert not ai_browser._safe_control({"text": "删除账号", "href": ""}, base)
    assert not ai_browser._safe_control({
        "text": "外部页面", "href": "https://evil.test/page",
    }, base)


def test_ai_controls_mark_used_actions() -> None:
    controls = [
        {"key": "a", "text": "菜单甲", "path": "/a", "tag": "A", "role": ""},
        {"key": "b", "text": "菜单乙", "path": "/b", "tag": "A", "role": ""},
    ]
    public = ai_browser._public_controls(controls, {"a"})
    assert len(public) == 1 and public[0]["text"] == "菜单乙"


def test_ai_discovery_runs_after_deterministic_browser(monkeypatch) -> None:
    monkeypatch.setattr(runtime, "find_chrome", lambda: "/fake/chrome")

    async def fake_deterministic(_base, _cfg):
        from app.browser_crawl import InteractiveCrawlResult
        return InteractiveCrawlResult(
            ok=True,
            pages=[("https://t/", '<script src="/js/base.js"></script>')],
            requests=[],
        )

    async def fake_ai(_base, _cfg):
        return ai_browser.AIBrowserResult(
            ok=True,
            pages=[("https://t/auth", '<script src="/js/auth.js"></script>')],
            requests=[("GET", "https://auth.test/sso.js")],
            actions=2,
            ai_calls=1,
        )

    monkeypatch.setattr("app.browser_crawl.interactive_crawl", fake_deterministic)
    monkeypatch.setattr(ai_browser, "ai_interactive_crawl", fake_ai)
    cfg = ScanConfig(
        headless_render=True, interactive_render=True, ai_discovery=True,
        max_render_pages=2, max_api_endpoints=5, allow_cross_origin_js=True,
    )
    seeds, notes = asyncio.run(collect_runtime_seeds(
        {"id": 1, "base_url": "https://t/"}, cfg,
        Extractor(base_url="https://t/", scope="same-origin",
                  allow_cross_origin_scripts=True),
    ))
    urls = {item.url for item in seeds}
    assert "https://t/js/base.js" in urls
    assert "https://t/js/auth.js" in urls
    assert "https://auth.test/sso.js" in urls
    assert any("AI 探索完成" in note for note in notes)
