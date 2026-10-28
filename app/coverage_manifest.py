"""外部 JS 清单 / 访问日志与本地资产库的差集核对。"""
from __future__ import annotations

import json
import re
from pathlib import Path
from urllib.parse import urldefrag, urljoin, urlparse

from . import db


URL_RE = re.compile(r"https?://[^\s,'\"<>]+", re.I)
REL_PATH_RE = re.compile(r"(?<![\w/])(?:\.{1,2}/|/)?[^\s,'\"<>]+?\.(?:js|mjs|cjs)(?:\?[^\s,'\"<>]*)?", re.I)


def _walk_json(value) -> list[str]:
    if isinstance(value, str):
        return [value]
    if isinstance(value, list):
        return [item for child in value for item in _walk_json(child)]
    if isinstance(value, dict):
        return [item for child in value.values() for item in _walk_json(child)]
    return []


def normalize_js_url(value: str, base_url: str) -> str:
    raw = str(value or "").strip().strip("'\"")
    if not raw or raw.startswith(("data:", "blob:", "javascript:")):
        return ""
    full = urldefrag(urljoin(base_url, raw))[0]
    parsed = urlparse(full)
    if parsed.scheme not in ("http", "https"):
        return ""
    if not parsed.path.lower().endswith((".js", ".mjs", ".cjs")):
        return ""
    return full


def parse_manifest(text: str, base_url: str) -> list[str]:
    """支持 JSON、每行一个 URL、CDN 日志片段和构建产物路径。"""
    values: list[str] = []
    stripped = (text or "").strip()
    if stripped.startswith(("{", "[")):
        try:
            values = _walk_json(json.loads(stripped))
        except json.JSONDecodeError:
            values = []
    if not values:
        values = URL_RE.findall(text or "")
        values.extend(REL_PATH_RE.findall(text or ""))
    urls = {normalize_js_url(value, base_url) for value in values}
    return sorted(url for url in urls if url)


def parse_manifest_file(path: str | Path, base_url: str) -> list[str]:
    return parse_manifest(Path(path).read_text(encoding="utf-8", errors="replace"), base_url)


def coverage_diff(target: dict, text: str) -> dict:
    base_url = target["base_url"]
    expected = parse_manifest(text, base_url)
    stored_rows = db.query(
        "SELECT url FROM assets WHERE target_id=? AND kind IN ('script','map')",
        (int(target["id"]),),
    )
    stored = {urldefrag(str(row["url"]))[0] for row in stored_rows}
    covered = sorted(set(expected) & stored)
    missing = sorted(set(expected) - stored)
    pct = len(covered) / len(expected) * 100 if expected else 100.0
    return {
        "expected": len(expected),
        "covered": len(covered),
        "missing": len(missing),
        "coverage_pct": round(pct, 1),
        "missing_urls": missing[:500],
        "covered_urls": covered[:500],
    }
