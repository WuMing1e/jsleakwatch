"""Playwright 交互式路由采集。

只做安全的匿名/授权浏览：打开同源页面、滚动首屏、切换 tab，并收集网络请求。
不点击提交、删除、退出、支付等可能改变状态的按钮。
"""
from __future__ import annotations

import re
import time
from dataclasses import dataclass, field
from http.cookies import SimpleCookie
from urllib.parse import urldefrag, urljoin, urlparse

from .config import ScanConfig
from .discover import NON_PAGE_EXT, same_origin
from .runtime import _render_lock, find_chrome


UNSAFE_PATH_RE = re.compile(
    r"(?:^|/)(?:logout|signout|exit|delete|remove|destroy|reset|unsubscribe|pay|purchase)(?:/|$)",
    re.I,
)


@dataclass
class InteractiveCrawlResult:
    ok: bool = False
    pages: list[tuple[str, str]] = field(default_factory=list)
    requests: list[tuple[str, str]] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    duration_ms: int = 0


def cookie_records(cookie_header: str, base_url: str) -> list[dict]:
    """把 Cookie 请求头转换为 Playwright 的同源 Cookie，不向第三方扩散。"""
    jar = SimpleCookie()
    try:
        jar.load(cookie_header or "")
    except Exception:
        return []
    return [
        {"name": name, "value": morsel.value, "url": f"{urlparse(base_url).scheme}://{urlparse(base_url).netloc}",
         "path": "/"}
        for name, morsel in jar.items()
        if name and morsel.value
    ]


def acceptable_route(url: str, base_url: str) -> bool:
    """交互路由只进同源页面，跳过静态文件和高风险操作路径。"""
    clean = urldefrag(url)[0]
    parsed = urlparse(clean)
    if parsed.scheme not in ("http", "https") or not same_origin(clean, base_url):
        return False
    if NON_PAGE_EXT.search(parsed.path) or UNSAFE_PATH_RE.search(parsed.path):
        return False
    return True


async def interactive_crawl(base_url: str, cfg: ScanConfig) -> InteractiveCrawlResult:
    """执行有限深度的同源路由浏览并返回 DOM 与网络请求。"""
    started = time.monotonic()
    result = InteractiveCrawlResult()
    binary = find_chrome()
    if not binary:
        result.errors.append("未找到 Chrome/Chromium")
        return result
    try:
        from playwright.async_api import async_playwright
    except ImportError:
        result.errors.append("未安装 playwright")
        return result

    queue = [urldefrag(base_url)[0]]
    queued = set(queue)
    seen_requests: set[tuple[str, str]] = set()
    max_pages = max(1, int(cfg.max_render_pages or 1))
    wait_ms = max(500, int(cfg.render_wait_ms or 4000))

    async with _render_lock():
        try:
            async with async_playwright() as pw:
                launch_args = {"headless": True, "executable_path": binary}
                if cfg.proxy:
                    launch_args["proxy"] = {"server": cfg.proxy}
                browser = await pw.chromium.launch(**launch_args)
                context = await browser.new_context(
                    user_agent=cfg.user_agent,
                    ignore_https_errors=not cfg.verify_tls,
                )
                cookies = cookie_records(cfg.cookies, base_url)
                if cookies:
                    await context.add_cookies(cookies)

                headers = {str(k).lower(): str(v) for k, v in (cfg.extra_headers or {}).items()
                           if k and v}
                if headers:
                    async def _auth_route(route):
                        request = route.request
                        if same_origin(request.url, base_url):
                            await route.continue_(headers={**request.headers, **headers})
                        else:
                            await route.continue_()
                    await context.route("**/*", _auth_route)

                while queue and len(result.pages) < max_pages:
                    page_url = queue.pop(0)
                    page = await context.new_page()

                    def _record_request(request):
                        if request.method != "GET" or not request.url.startswith(("http://", "https://")):
                            return
                        key = (request.method, request.url)
                        if key not in seen_requests:
                            seen_requests.add(key)
                            result.requests.append(key)

                    page.on("request", _record_request)
                    try:
                        response = await page.goto(
                            page_url, wait_until="domcontentloaded",
                            timeout=max(3000, int(cfg.timeout_seconds * 1000)),
                        )
                        if response is None or response.status >= 400:
                            result.errors.append(f"{page_url}: HTTP {response.status if response else '?'}")
                            continue
                        await page.wait_for_timeout(wait_ms)
                        await page.evaluate("window.scrollTo(0, Math.min(document.body.scrollHeight, 4000))")
                        await page.wait_for_timeout(500)

                        # 只切换 tab；不点击提交、删除、退出等操作按钮。
                        tabs = page.locator('[role="tab"]')
                        tab_count = min(await tabs.count(), max(0, int(cfg.interactive_max_clicks or 0)))
                        for index in range(tab_count):
                            tab = tabs.nth(index)
                            try:
                                if await tab.is_visible():
                                    await tab.click(timeout=1200)
                                    await page.wait_for_timeout(250)
                            except Exception:
                                continue

                        result.pages.append((page.url, await page.content()))
                        hrefs = await page.eval_on_selector_all(
                            "a[href]", "els => els.map(e => e.href)"
                        )
                        for href in hrefs:
                            candidate = urldefrag(urljoin(page.url, href))[0]
                            if candidate not in queued and acceptable_route(candidate, base_url):
                                queued.add(candidate)
                                queue.append(candidate)
                    except Exception as exc:  # noqa: BLE001
                        result.errors.append(f"{page_url}: {type(exc).__name__}: {exc}"[:200])
                    finally:
                        await page.close()
                await browser.close()
        except Exception as exc:  # noqa: BLE001
            result.errors.append(f"{type(exc).__name__}: {exc}"[:200])

    result.ok = bool(result.pages)
    result.duration_ms = int((time.monotonic() - started) * 1000)
    return result
