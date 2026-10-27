"""HTTP 抓取层: 连接复用、超时、同域礼貌限速、大小截断。"""
from __future__ import annotations

import asyncio
import time
from dataclasses import dataclass
from typing import NamedTuple
from urllib.parse import urlparse

import httpx

from .config import ScanConfig


# 连接类错误按配置次数重试; 读超时通常是单个文件较大或站点瞬时变慢,
# 只额外重试一次, 并放宽超时, 避免把可达的大 JS 直接漏掉。
RETRYABLE_ERRORS = frozenset({"ConnectTimeout", "ConnectError", "PoolTimeout", "RemoteProtocolError"})
RETRY_BACKOFF_S = 0.6
READ_TIMEOUT_RETRY_EXTRA_S = 15.0


@dataclass
class FetchResult:
    url: str
    final_url: str
    status: int
    content_type: str
    text: str
    size: int
    truncated: bool = False
    error: str = ""
    challenge: str = ""        # 命中的是哪家 WAF 人机校验页, 空 = 正常内容

    @property
    def ok(self) -> bool:
        return self.status == 200 and not self.error


# 人机校验页的强特征。这类页面是 200 + text/html, 但内容不是站点自己的:
# 里面塞着 WAF 的随机令牌, 长度常和 API Key 撞上, 直接扫必然制造误报
# (实测: 阿里云 WAF 的 <meta name="aliyun_waf_bb"> 被当成 AccessKey Secret 报了 critical)。
CHALLENGE_MARKERS = (
    ("aliyun_waf", ("aliyun_waf_aa", "aliyun_waf_bb")),
    ("cloudflare", ("__cf_chl", "cf-chl", "just a moment...")),
    ("tencent_waf", ("tencent_waf", "waf.tencent.com")),
)


def detect_challenge(text: str, content_type: str, headers: dict | None = None) -> str:
    """认出 WAF 人机校验页。只认强特征, 宁可漏判也不误杀正常页面。"""
    if headers and "challenge" in str(headers.get("cf-mitigated", "")).lower():
        return "cloudflare"
    if "html" not in (content_type or ""):
        return ""
    sample = text[:60000].lower()
    for name, markers in CHALLENGE_MARKERS:
        if any(marker in sample for marker in markers):
            return name
    return ""


class _RawBody(NamedTuple):
    """一次请求拿到的东西(还没解码成文本)。"""

    status: int
    final_url: str
    encoding: str
    content_type: str
    body: bytes
    size: int          # 文件真实大小(能拿到 Content-Length 时用它, 否则是用实际收到的字节数)
    truncated: bool
    cf_mitigated: str  # Cloudflare 挑战页会带 cf-mitigated: challenge


def looks_binary(data: bytes) -> bool:
    sample = data[:2048]
    if b"\x00" in sample:
        return True
    if not sample:
        return False
    printable = sum(1 for b in sample if 9 <= b <= 13 or 32 <= b <= 126 or b > 127)
    return printable / len(sample) < 0.80


class Fetcher:
    """带全局并发限制与按域限速的异步抓取器。"""

    def __init__(self, cfg: ScanConfig, max_concurrency: int | None = None) -> None:
        self.cfg = cfg
        limit = max_concurrency or cfg.max_concurrency
        self._sem = asyncio.Semaphore(max(1, limit))
        self._host_sems: dict[str, asyncio.Semaphore] = {}
        self._host_locks: dict[str, asyncio.Lock] = {}
        self._host_last: dict[str, float] = {}
        self._client: httpx.AsyncClient | None = None
        self.bytes_fetched = 0
        self.requests_made = 0

    async def __aenter__(self) -> "Fetcher":
        headers = self.headers()
        kwargs: dict = {
            "headers": headers,
            "timeout": httpx.Timeout(self.cfg.timeout_seconds),
            "follow_redirects": True,
            "verify": self.cfg.verify_tls,
            "limits": httpx.Limits(max_connections=max(4, self.cfg.max_concurrency * 2)),
        }
        if self.cfg.proxy:
            kwargs["proxy"] = self.cfg.proxy
        self._client = httpx.AsyncClient(**kwargs)
        return self

    def headers(self) -> dict[str, str]:
        """默认头 + 用户自定义头（后者覆盖前者），用于带凭据采集。"""
        merged: dict[str, str] = {
            "User-Agent": self.cfg.user_agent,
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Language": "zh-CN,zh;q=0.9,en;q=0.8",
        }
        for key, value in (self.cfg.extra_headers or {}).items():
            if key and value:
                merged[str(key)] = str(value)
        if self.cfg.cookies:
            merged["Cookie"] = self.cfg.cookies
        return merged

    async def __aexit__(self, *exc: object) -> None:
        if self._client is not None:
            await self._client.aclose()
            self._client = None

    def _host_lock(self, host: str) -> asyncio.Lock:
        lock = self._host_locks.get(host)
        if lock is None:
            lock = asyncio.Lock()
            self._host_locks[host] = lock
        return lock

    def _host_sem(self, host: str) -> asyncio.Semaphore:
        sem = self._host_sems.get(host)
        if sem is None:
            sem = asyncio.Semaphore(max(1, int(self.cfg.per_host_concurrency or 1)))
            self._host_sems[host] = sem
        return sem

    async def _throttle(self, host: str) -> None:
        delay = max(0, self.cfg.per_host_delay_ms) / 1000.0
        if delay <= 0:
            return
        async with self._host_lock(host):
            last = self._host_last.get(host, 0.0)
            wait = delay - (time.monotonic() - last)
            if wait > 0:
                await asyncio.sleep(wait)
            self._host_last[host] = time.monotonic()

    async def get(self, url: str, allow_any_type: bool = False) -> FetchResult:
        assert self._client is not None, "Fetcher 需在 async with 中使用"
        host = urlparse(url).netloc.lower()
        attempts = max(1, int(self.cfg.max_retries) + 1)
        resp, error = None, ""
        request_timeout: float | None = None
        read_timeout_retried = False
        attempt = 0
        while True:
            async with self._sem:
                async with self._host_sem(host):
                    await self._throttle(host)
                    try:
                        resp = await self._request(url, timeout_seconds=request_timeout)
                    except Exception as exc:  # noqa: BLE001 - 单资产失败不应中断整轮扫描
                        resp, error = None, f"{type(exc).__name__}: {exc}"[:200]
            if resp is not None:
                break

            error_kind = error.split(":", 1)[0].strip()
            permanent_tls_error = (
                error_kind == "ConnectError"
                and "CERTIFICATE_VERIFY_FAILED" in error.upper()
            )
            if (error_kind in RETRYABLE_ERRORS and not permanent_tls_error
                    and attempt + 1 < attempts):
                attempt += 1
                await asyncio.sleep(RETRY_BACKOFF_S * (attempt + 1))
                continue
            # 大 JS / 配置文件的读取超时往往是一次性的。这里不再用同一个 15 秒超时
            # 硬重试, 而是放宽至少 15 秒后再试一次, 同时仍受 max_retries 总开关约束。
            if (error_kind == "ReadTimeout" and attempts > 1
                    and not read_timeout_retried):
                read_timeout_retried = True
                request_timeout = max(
                    float(self.cfg.timeout_seconds) * 2,
                    float(self.cfg.timeout_seconds) + READ_TIMEOUT_RETRY_EXTRA_S,
                )
                await asyncio.sleep(RETRY_BACKOFF_S)
                continue
            break
        if resp is None:
            return FetchResult(url, url, 0, "", "", 0, error=error)
        self.requests_made += 1
        if not allow_any_type and looks_binary(resp.body):
            return FetchResult(url, resp.final_url, resp.status, resp.content_type, "",
                               resp.size, truncated=resp.truncated, error="binary")
        try:
            text = resp.body.decode(resp.encoding, errors="replace")
        except (LookupError, UnicodeDecodeError):
            text = resp.body.decode("utf-8", errors="replace")
        self.bytes_fetched += len(resp.body)

        # 入口页拿到的是人机校验页时, 这轮其实什么都没看到, 交给上层决定要不要继续
        challenge = detect_challenge(text, resp.content_type, {"cf-mitigated": resp.cf_mitigated})
        return FetchResult(
            url=url,
            final_url=resp.final_url,
            status=resp.status,
            content_type=resp.content_type,
            text=text,
            size=resp.size,
            truncated=resp.truncated,
            challenge=challenge,
        )

    async def _request(self, url: str, timeout_seconds: float | None = None) -> _RawBody:
        """流式读取响应。

        `max_asset_bytes` 为 0 时整份读完(不截断); 设了上限就读到上限为止再断开,
        不去把几十兆先拉下来再扔掉。
        """
        limit = max(0, int(self.cfg.max_asset_bytes or 0))
        kwargs = {"timeout": timeout_seconds} if timeout_seconds is not None else {}
        async with self._client.stream("GET", url, **kwargs) as resp:
            encoding = resp.encoding or "utf-8"
            ctype = resp.headers.get("content-type", "").split(";")[0].strip().lower()
            chunks: list[bytes] = []
            size = 0
            async for chunk in resp.aiter_bytes():
                chunks.append(chunk)
                size += len(chunk)
                if limit and size >= limit:
                    break
            body = chunks[0] if len(chunks) == 1 else b"".join(chunks)
            truncated = bool(limit) and len(body) > limit
            if truncated:
                body = body[:limit]
            declared = resp.headers.get("content-length", "")
            # 截断时用 Content-Length 报真实大小, 免得界面上把"截到 5MB"当成文件就这么大
            real_size = int(declared) if (truncated and declared.isdigit()) else max(size, len(body))
            return _RawBody(resp.status_code, str(resp.url), encoding, ctype,
                            body, real_size, truncated,
                            resp.headers.get("cf-mitigated", ""))
