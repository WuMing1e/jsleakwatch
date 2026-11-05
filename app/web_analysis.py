"""Web 前端的确定性预分析。

这里不执行 JavaScript，也不做主动请求。目标是在规则引擎和模型之前完成三件事:

1. 识别常见的字符串编码与字符数组，还原成可继续扫描的文本；
2. 从已采集资产中挑出当前脚本真正引用到的配置、请求、鉴权和加密模块；
3. 把大文件压缩成围绕敏感逻辑的片段，避免只截头尾时漏掉中间内容。

所有输出都有大小上限。页面内容始终是不可信数据，本模块只做字符串解析。
"""
from __future__ import annotations

import base64
import re
import urllib.parse
from dataclasses import dataclass
from pathlib import Path
from typing import Mapping
from urllib.parse import urlparse


MAX_DECODE_VIEWS = 12
MAX_DECODED_CHARS = 24_000
MAX_RELATED_FILES = 3
MAX_RELATED_CHARS = 10_000

_PRINTABLE_MIN_RATIO = 0.88
_MIN_DECODED_LEN = 4

_FROM_CHAR_CODE_RE = re.compile(
    r"\bString\s*\.\s*fromCharCode\s*\(\s*([^()]{1,32000})\s*\)", re.I
)
_FROM_CHAR_CODE_APPLY_RE = re.compile(
    r"\bString\s*\.\s*fromCharCode\s*\.\s*apply\s*\(\s*[^,\n]{0,120},\s*"
    r"\[\s*([^\[\]]{1,32000})\s*\]\s*\)",
    re.I,
)
_NUMBER_ARRAY_RE = re.compile(
    r"\[\s*((?:(?:0x[0-9a-f]+|\d+)\s*,\s*){5,}(?:0x[0-9a-f]+|\d+)\s*)\]",
    re.I,
)
_HEX_ESCAPE_RE = re.compile(r"(?:\\x[0-9a-fA-F]{2}){4,}")
_UNICODE_ESCAPE_RE = re.compile(r"(?:\\u[0-9a-fA-F]{4}){4,}")
_LITERAL_RE = re.compile(r"""(["'`])([^"'`\r\n]{16,8000})\1""")
_IMPORT_RE = re.compile(
    r"""(?:\bfrom\s*|\brequire\s*\(\s*|\bimport\s*\(\s*)["']([^"']+)["']""",
    re.I,
)
_JS_REFERENCE_RE = re.compile(
    r"""(?<![\w])([A-Za-z0-9_@~./:-]+\.(?:js|mjs|cjs)(?:\?[A-Za-z0-9_=&%.-]*)?(?:#[A-Za-z0-9_.-]*)?)(?![\w])""",
    re.I,
)
_PERCENT_ESCAPE_RE = re.compile(r"(?:%[0-9a-fA-F]{2}){3,}")
_SENSITIVE_HINT_RE = re.compile(
    r"(?:fromCharCode|atob\s*\(|btoa\s*\(|Authorization|Bearer|AKID|LTAI|"
    r"access[_-]?key|secret[_-]?key|private[_-]?key|client[_-]?secret|corp[_-]?secret|"
    r"password|passwd|api[_-]?key|token|encrypt|decrypt|signature|\bsign\s*\(|"
    r"jdbc:|redis(?:\+srv)?://|mongodb(?:\+srv)?://|mysql://|postgres(?:ql)?://)",
    re.I,
)


@dataclass(frozen=True)
class DecodedView:
    kind: str
    value: str
    start: int
    end: int
    context: str = ""


@dataclass(frozen=True)
class RelatedAsset:
    url: str
    text: str
    score: int
    reason: str


def _printable_text(value: str, min_len: int = _MIN_DECODED_LEN) -> str:
    text = (value or "").strip()
    if len(text) < min_len:
        return ""
    good = sum(1 for ch in text if ch.isprintable() or ch in "\r\n\t")
    if good / len(text) < _PRINTABLE_MIN_RATIO:
        return ""
    return text


def _decode_bytes(data: bytes) -> str:
    try:
        return _printable_text(data.decode("utf-8"))
    except UnicodeDecodeError:
        return ""


def _parse_char_codes(raw: str, max_codes: int = 4096) -> str:
    parts = [part.strip() for part in raw.split(",") if part.strip()]
    if not 6 <= len(parts) <= max_codes:
        return ""
    values: list[int] = []
    for part in parts:
        if not re.fullmatch(r"(?:0x[0-9a-f]+|\d+)", part, re.I):
            return ""
        try:
            value = int(part, 0 if part.lower().startswith("0x") else 10)
        except ValueError:
            return ""
        if value < 0 or value > 0x10FFFF or 0xD800 <= value <= 0xDFFF:
            return ""
        values.append(value)
    try:
        return _printable_text("".join(chr(value) for value in values))
    except (ValueError, OverflowError):
        return ""


def _context(text: str, start: int, end: int, span: int = 140) -> str:
    snippet = text[max(0, start - span): min(len(text), end + span)]
    return re.sub(r"\s+", " ", snippet).strip()[:420]


def _add_view(
    views: list[DecodedView],
    seen: set[str],
    *,
    kind: str,
    value: str,
    start: int,
    end: int,
    source: str,
) -> None:
    cleaned = _printable_text(value)
    if not cleaned or cleaned in seen:
        return
    seen.add(cleaned)
    views.append(DecodedView(
        kind=kind,
        value=cleaned[:8000],
        start=start,
        end=end,
        context=_context(source, start, end),
    ))


def decode_views(text: str, max_views: int = MAX_DECODE_VIEWS) -> list[DecodedView]:
    """不执行 JS，只还原常见编码和字符数组。"""
    if not text or max_views <= 0:
        return []
    views: list[DecodedView] = []
    seen: set[str] = set()
    lowered = text.lower()

    if "fromcharcode" in lowered:
        for match in _FROM_CHAR_CODE_APPLY_RE.finditer(text):
            value = _parse_char_codes(match.group(1))
            _add_view(views, seen, kind="String.fromCharCode.apply 数组",
                      value=value, start=match.start(), end=match.end(), source=text)
            if len(views) >= max_views:
                return views

        for match in _FROM_CHAR_CODE_RE.finditer(text):
            value = _parse_char_codes(match.group(1))
            _add_view(views, seen, kind="String.fromCharCode",
                      value=value, start=match.start(), end=match.end(), source=text)
            if len(views) >= max_views:
                return views

        # 有些包把 ASCII 数组和目标函数隔开几行；只有附近确实出现 fromCharCode 才还原，
        # 避免把普通数字表误当成文本。
        for match in _NUMBER_ARRAY_RE.finditer(text):
            nearby = lowered[max(0, match.start() - 240): min(len(text), match.end() + 240)]
            if "fromcharcode" not in nearby:
                continue
            value = _parse_char_codes(match.group(1))
            _add_view(views, seen, kind="ASCII 字符数组",
                      value=value, start=match.start(), end=match.end(), source=text)
            if len(views) >= max_views:
                return views

    if "\\x" in text:
        for match in _HEX_ESCAPE_RE.finditer(text):
            body = re.sub(r"\\x", "", match.group(0))
            try:
                value = _decode_bytes(bytes.fromhex(body))
            except ValueError:
                value = ""
            _add_view(views, seen, kind="JavaScript Hex 转义",
                      value=value, start=match.start(), end=match.end(), source=text)
            if len(views) >= max_views:
                return views

    if "\\u" in text:
        for match in _UNICODE_ESCAPE_RE.finditer(text):
            units = [int(item, 16) for item in
                     re.findall(r"\\u([0-9a-fA-F]{4})", match.group(0))]
            chars: list[str] = []
            valid = True
            index = 0
            while index < len(units):
                unit = units[index]
                if 0xD800 <= unit <= 0xDBFF and index + 1 < len(units):
                    low = units[index + 1]
                    if 0xDC00 <= low <= 0xDFFF:
                        chars.append(chr(0x10000 + ((unit - 0xD800) << 10) + (low - 0xDC00)))
                        index += 2
                        continue
                if 0xD800 <= unit <= 0xDFFF:
                    valid = False
                    break
                chars.append(chr(unit))
                index += 1
            _add_view(views, seen, kind="JavaScript Unicode 转义",
                      value="".join(chars) if valid else "",
                      start=match.start(), end=match.end(), source=text)
            if len(views) >= max_views:
                return views

    should_scan_literals = (
        "%" in text
        or "atob" in lowered
        or "base64" in lowered
        or bool(_SENSITIVE_HINT_RE.search(text))
    )
    for match in (_LITERAL_RE.finditer(text) if should_scan_literals else ()):
        raw = match.group(2).strip()
        if not raw:
            continue
        context = text[max(0, match.start() - 180): min(len(text), match.end() + 180)].lower()

        if _PERCENT_ESCAPE_RE.search(raw):
            unquoted = urllib.parse.unquote(raw)
            if unquoted != raw:
                _add_view(views, seen, kind="URL 编码",
                          value=unquoted, start=match.start(), end=match.end(), source=text)
                if len(views) >= max_views:
                    return views

        compact = re.sub(r"\s+", "", raw)
        if re.fullmatch(r"[A-Za-z0-9+/_=-]{24,8000}", compact):
            candidate = compact.replace("-", "+").replace("_", "/")
            try:
                decoded = _decode_bytes(
                    base64.b64decode(candidate + "=" * (-len(candidate) % 4), validate=False)
                )
            except (ValueError, TypeError):
                decoded = ""
            # 普通单词/哈希很难解成足够长的可打印文本；能到这里的通常确实是编码载荷。
            if decoded and (
                _SENSITIVE_HINT_RE.search(decoded)
                or re.search(r"(?:AKIA|AKID|LTAI|sk_live_|gh[pousr]_|https?://|jdbc:|redis://)",
                             decoded, re.I)
                or "atob" in context
            ):
                _add_view(views, seen, kind="Base64 / Base64URL",
                          value=decoded, start=match.start(), end=match.end(), source=text)
                if len(views) >= max_views:
                    return views

        if len(compact) >= 32 and len(compact) % 2 == 0 and re.fullmatch(r"[0-9a-fA-F]+", compact):
            try:
                decoded = _decode_bytes(bytes.fromhex(compact))
            except ValueError:
                decoded = ""
            if decoded:
                _add_view(views, seen, kind="Hex 字符串",
                          value=decoded, start=match.start(), end=match.end(), source=text)
                if len(views) >= max_views:
                    return views

    return views


def decoded_corpus(
    text: str,
    *,
    max_views: int = MAX_DECODE_VIEWS,
    max_chars: int = MAX_DECODED_CHARS,
) -> str:
    """给规则引擎的还原文本。保留少量源码上下文，帮助字段名规则命中。"""
    parts: list[str] = []
    used = 0
    for view in decode_views(text, max_views=max_views):
        block = (
            f"\n/* JSLW_AUTO_DECODED: {view.kind} */\n"
            f"/* context: {view.context} */\n"
            f"{view.value}\n"
            "/* END_JSLW_AUTO_DECODED */\n"
        )
        remaining = max_chars - used
        if remaining <= 0:
            break
        parts.append(block[:remaining])
        used += min(len(block), remaining)
    return "".join(parts)


def decoded_preview(text: str, limit: int = 8000) -> str:
    """给语义模型的自动预还原说明，明确标注这些值由确定性代码产生。"""
    lines: list[str] = []
    used = 0
    for index, view in enumerate(decode_views(text), 1):
        block = (
            f"{index}. [{view.kind}] 值: {view.value[:2000]}\n"
            f"   源码上下文: {view.context[:300]}\n"
        )
        if used + len(block) > limit:
            break
        lines.append(block)
        used += len(block)
    if not lines:
        return ""
    return "系统自动预还原（确定性字符串解码，不是模型猜测）:\n" + "".join(lines)


def semantic_excerpt(text: str, max_chars: int = 12000, window: int = 1400) -> str:
    """大文件优先保留敏感逻辑附近，再补少量头尾作为模块结构上下文。"""
    if not text or len(text) <= max_chars:
        return text

    max_chars = max(1000, int(max_chars))
    ranges: list[tuple[int, int]] = []
    for match in _SENSITIVE_HINT_RE.finditer(text):
        ranges.append((max(0, match.start() - window // 3),
                       min(len(text), match.end() + window)))
        if len(ranges) >= 6:
            break

    merged: list[tuple[int, int]] = []
    for start, end in sorted(ranges):
        if merged and start <= merged[-1][1] + 200:
            merged[-1] = (merged[-1][0], max(merged[-1][1], end))
        else:
            merged.append((start, end))

    snippets: list[str] = []
    used = 0
    for start, end in merged:
        available = max_chars - used
        if available < 400:
            break
        header = f"/* ...片段 @ {start}... */\n"
        snippet = text[start:min(end, start + max(0, available - len(header)))]
        block = header + snippet
        snippets.append(block)
        used += len(block)

    if not snippets:
        head = max_chars // 2
        return text[:head] + "\n/* ...中间省略... */\n" + text[-max_chars // 2:]

    reserve = max(0, max_chars - used - 96)
    if reserve >= 600:
        head_size = reserve // 3
        tail_size = reserve // 3
        snippets.insert(0, "/* ...文件头部... */\n" + text[:head_size])
        snippets.append("/* ...文件尾部... */\n" + text[-tail_size:])
    return "\n/* ...敏感片段之间省略... */\n".join(snippets)[:max_chars]


def _same_origin(first: str, second: str) -> bool:
    left, right = urlparse(first), urlparse(second)
    return bool(
        left.scheme and right.scheme
        and left.scheme.lower() == right.scheme.lower()
        and left.netloc.lower() == right.netloc.lower()
    )


def _asset_tokens(url: str) -> tuple[str, str, str]:
    path = urlparse(url).path
    basename = Path(path).name.lower()
    suffix = Path(path).suffix.lower()
    stem = basename[:-len(suffix)] if suffix else basename
    return basename, stem, path.lower()


def select_related_assets(
    url: str,
    text: str,
    available: Mapping[str, str],
    *,
    max_files: int = 2,
    max_chars_per_file: int = 4000,
) -> list[RelatedAsset]:
    """只从已采集且同源的资产中选取可验证引用，不额外发起请求。"""
    if not url or not text or max_files <= 0:
        return []
    lowered = text.lower()
    imports = [item.lower() for item in _IMPORT_RE.findall(text)]
    explicit_refs = [item.lower() for item in _JS_REFERENCE_RE.findall(text)]
    ranked: list[tuple[int, str, str]] = []

    for candidate_url, candidate_text in available.items():
        if not candidate_text or candidate_url == url or not _same_origin(url, candidate_url):
            continue
        basename, stem, path = _asset_tokens(candidate_url)
        if not basename:
            continue
        score = 0
        reason = ""
        if basename in lowered:
            score += 10
            reason = f"源码直接引用 {basename}"
        elif len(stem) >= 5 and stem in lowered:
            score += 7
            reason = f"源码引用模块名 {stem}"
        elif any(
            spec.rstrip("/").split("/")[-1].split(".")[0] == stem
            for spec in imports
            if spec and not spec.startswith(("http://", "https://"))
        ):
            score += 7
            reason = f"import/require 引用 {stem}"
        elif any(ref and (ref == basename or ref.endswith("/" + basename))
                 for ref in explicit_refs):
            score += 9
            reason = f"脚本路径引用 {basename}"

        if not score:
            continue
        if any(hint in path for hint in (
            "config", "env", "runtime", "request", "api", "auth", "crypto", "sign",
            "util", "common", "global", "setting",
        )):
            score += 2
        if _SENSITIVE_HINT_RE.search(candidate_text):
            score += 3
        if len(candidate_text) < 80_000:
            score += 1
        ranked.append((score, candidate_url, reason))

    related: list[RelatedAsset] = []
    for score, candidate_url, reason in sorted(ranked, reverse=True)[:max_files]:
        candidate_text = available[candidate_url]
        related.append(RelatedAsset(
            url=candidate_url,
            text=semantic_excerpt(candidate_text, max_chars=max_chars_per_file),
            score=score,
            reason=reason,
        ))
    return related


def related_context(
    url: str,
    text: str,
    available: Mapping[str, str],
    *,
    max_files: int = 2,
    max_total_chars: int = MAX_RELATED_CHARS,
) -> str:
    related = select_related_assets(
        url,
        text,
        available,
        max_files=max_files,
        max_chars_per_file=max(1200, max_total_chars // max(1, max_files)),
    )
    parts: list[str] = []
    used = 0
    for item in related:
        block = (
            f"\n<related_file url=\"{item.url}\" reason=\"{item.reason}\">\n"
            f"{item.text}\n</related_file>\n"
        )
        if used + len(block) > max_total_chars:
            break
        parts.append(block)
        used += len(block)
    return "".join(parts)
