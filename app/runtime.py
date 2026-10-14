"""无头浏览器运行时采集（可选）。

静态抓取拿不到两样东西: JS 执行后才插进来的脚本，以及运行时才拼出来的接口地址。
这里用本机 Chrome/Chromium 的 headless 模式把页面真跑一遍:

- `--dump-dom` 拿执行后的 DOM（能看到动态插入的 script/link）
- `--log-net-log` 拿这次加载发出的全部请求（含 XHR/fetch 的真实方法）

不引入 Python 依赖，只用子进程 + 两个官方开关；没有 Chrome 时整段跳过，
扫描照常进行。渲染走的是匿名请求，不会带上采集用的凭据。
"""
from __future__ import annotations

import glob
import json
import os
import shutil
import subprocess
import tempfile
import time
from dataclasses import dataclass, field
from pathlib import Path
from urllib.parse import urlparse

CHROME_ENV = "JSLW_CHROME_PATH"

_GLOBS = (
    "~/Library/Caches/ms-playwright/chromium_headless_shell-*/chrome-headless-shell-mac*/chrome-headless-shell",
    "~/Library/Caches/ms-playwright/chromium-*/chrome-mac*/Chromium.app/Contents/MacOS/Chromium",
    "~/.cache/ms-playwright/chromium_headless_shell-*/chrome-headless-shell-linux*/chrome-headless-shell",
    "~/.cache/ms-playwright/chromium-*/chrome-linux*/chrome",
)

_FIXED = (
    "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
    "/Applications/Chromium.app/Contents/MacOS/Chromium",
    "/usr/bin/google-chrome",
    "/usr/bin/google-chrome-stable",
    "/usr/bin/chromium",
    "/usr/bin/chromium-browser",
)


def find_chrome() -> str | None:
    """按 环境变量 → Playwright 缓存 → 常见安装路径 → PATH 的顺序找浏览器。"""
    explicit = os.getenv(CHROME_ENV)
    if explicit and Path(explicit).exists():
        return explicit
    for pattern in _GLOBS:
        # 同一条 glob 可能匹配到多个版本, 取版本号最大的那个
        for candidate in sorted(glob.glob(os.path.expanduser(pattern)), reverse=True):
            if Path(candidate).exists():
                return candidate
    for path in _FIXED:
        if Path(path).exists():
            return path
    for name in ("google-chrome", "chrome", "chromium", "chromium-browser", "chrome-headless-shell"):
        found = shutil.which(name)
        if found:
            return found
    return None


@dataclass
class RenderResult:
    url: str
    ok: bool = False
    dom: str = ""
    requests: list[tuple[str, str]] = field(default_factory=list)
    error: str = ""
    duration_ms: int = 0


def parse_netlog(path: str | Path) -> list[tuple[str, str]]:
    """从 Chrome 的 netlog 里取出"方法 + 地址"。

    只有带 url 与 method 的 URL_REQUEST_START_JOB 有意义, 其余（连接、DNS、内部
    请求）都跳过。netlog 是常量表 + 数字索引的结构, 需要先反查事件类型名。
    """
    try:
        data = json.loads(Path(path).read_text(encoding="utf-8", errors="replace"))
    except (OSError, ValueError):
        return []
    types = (data.get("constants") or {}).get("logEventTypes") or {}
    index = {value: name for name, value in types.items()} if isinstance(types, dict) else {}
    out: list[tuple[str, str]] = []
    seen: set[tuple[str, str]] = set()
    for event in data.get("events") or []:
        if index.get(event.get("type")) != "URL_REQUEST_START_JOB":
            continue
        params = event.get("params") or {}
        method, url = params.get("method"), params.get("url")
        if not method or not url or not str(url).startswith(("http://", "https://")):
            continue
        key = (str(method).upper(), str(url))
        if key in seen:
            continue
        seen.add(key)
        out.append(key)
    return out


def render(url: str, timeout: float = 30.0, wait_ms: int = 4000,
           chrome: str | None = None) -> RenderResult:
    """渲染一个页面: 返回执行后的 DOM 与它发出的请求。"""
    binary = chrome or find_chrome()
    result = RenderResult(url=url)
    if not binary:
        result.error = "未找到 Chrome/Chromium, 可用 JSLW_CHROME_PATH 指定"
        return result
    profile = tempfile.mkdtemp(prefix="jslw-chrome-")
    netlog = Path(profile) / "netlog.json"
    started = time.monotonic()
    try:
        proc = subprocess.run(
            [
                binary, "--headless=new", "--no-sandbox", "--disable-gpu",
                "--disable-dev-shm-usage", "--disable-extensions", "--no-first-run",
                "--hide-scrollbars", "--mute-audio",
                f"--user-data-dir={profile}",
                f"--log-net-log={netlog}", "--net-log-capture-mode=IncludeSensitive",
                f"--virtual-time-budget={max(500, int(wait_ms))}",
                "--dump-dom", url,
            ],
            capture_output=True, text=True, timeout=timeout,
            env={**os.environ, "HOME": profile},   # 别碰用户自己的浏览器配置
        )
        result.dom = proc.stdout or ""
        result.requests = parse_netlog(netlog)
        result.ok = bool(result.dom.strip())
        if not result.ok:
            detail = (proc.stderr or "").strip().splitlines()
            result.error = detail[-1][:200] if detail else "渲染没有输出"
    except subprocess.TimeoutExpired:
        result.error = f"渲染超时 ({int(timeout)}s)"
    except Exception as exc:  # noqa: BLE001 - 渲染失败不该影响整轮扫描
        result.error = f"{type(exc).__name__}: {exc}"[:200]
    finally:
        shutil.rmtree(profile, ignore_errors=True)
        result.duration_ms = int((time.monotonic() - started) * 1000)
    return result


def same_origin(a: str, b: str) -> bool:
    pa, pb = urlparse(a), urlparse(b)
    return (pa.scheme, pa.netloc.lower()) == (pb.scheme, pb.netloc.lower())
