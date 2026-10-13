"""资产内容版本与变更。

不保存 JS 原文（明文不外泄是这套系统的底线），只保存每次变化后的字符串签名：
文件里的字符串字面量，其中命中规则的、以及看上去像密钥的都被掩码。
这样既能回答"这次改动新增了什么"，又不会把密钥再复制一份进库里。
"""
from __future__ import annotations

import hashlib
import json
import re
from typing import Any, Iterable

from . import db
from .rules import mask_value, shannon_entropy

MAX_STRINGS = 400        # 每版最多记多少条字符串
MAX_KEEP = 12            # 每个资产保留最近多少版
DIFF_LIMIT = 60          # 差异每侧最多记多少条
STRING_MIN = 3
STRING_MAX = 160

STRING_RE = re.compile(rf"""["'`]([^"'`\n]{{{STRING_MIN},{STRING_MAX}}})["'`]""")

# 高熵且足够长的串按"疑似密钥"处理, 不进签名原文
SECRET_ENTROPY = 3.6
SECRET_MIN_LEN = 20
URL_HINTS = ("http://", "https://", "/", "./", "../", "data:")


def looks_secret(value: str) -> bool:
    if len(value) < SECRET_MIN_LEN or " " in value:
        return False
    if value.startswith(URL_HINTS):
        return False
    return shannon_entropy(value) >= SECRET_ENTROPY


def signature(text: str, secret_hashes: Iterable[str] = ()) -> list[str]:
    """字符串签名: 命中规则(按 sha256 比对)或看着像密钥的一律掩码。

    只拿命中值的 sha256 比对, 因此不需要在别处保留明文命中值。
    """
    known = {h for h in secret_hashes if h}
    out: list[str] = []
    seen: set[str] = set()
    for match in STRING_RE.finditer(text or ""):
        value = match.group(1).strip()
        if not value or value in seen:
            continue
        digest = hashlib.sha256(value.encode("utf-8", "ignore")).hexdigest()
        if digest in known or looks_secret(value):
            value = mask_value(value)
        if value in seen:
            continue
        seen.add(value)
        out.append(value)
        if len(out) >= MAX_STRINGS:
            break
    return out


def _load(raw: str) -> list[str]:
    try:
        data = json.loads(raw or "[]")
    except ValueError:
        return []
    return [str(x) for x in data] if isinstance(data, list) else []


def record_version(
    target_id: int,
    asset_id: int,
    url: str,
    text: str,
    sha256: str,
    secret_hashes: Iterable[str] = (),
    findings: int = 0,
) -> dict[str, Any]:
    """内容变了就存一版, 返回这一版相对上一版的新增/消失字符串。"""
    if not asset_id:
        return {"changed": False, "added": [], "removed": [], "first": False}
    prev = db.query_one(
        "SELECT sha256, strings FROM asset_versions WHERE asset_id=? ORDER BY id DESC LIMIT 1",
        (asset_id,),
    )
    if prev is not None and prev["sha256"] == sha256:
        return {"changed": False, "added": [], "removed": [], "first": False}

    current = signature(text, secret_hashes)
    before = _load(prev["strings"]) if prev is not None else []
    before_set = set(before)
    after_set = set(current)
    # 第一次采集只是基线, 不算"变更": 否则变更流里会被首次采集刷屏
    added = [item for item in current if item not in before_set][:DIFF_LIMIT] if prev else []
    removed = [item for item in before if item not in after_set][:DIFF_LIMIT] if prev else []

    db.execute(
        "INSERT OR IGNORE INTO asset_versions(asset_id, target_id, url, sha256, size, lines, "
        "strings, added, removed, findings, created_at) VALUES(?,?,?,?,?,?,?,?,?,?,?)",
        (asset_id, target_id, url, sha256, len((text or "").encode("utf-8", "ignore")),
         (text or "").count("\n") + 1,
         json.dumps(current, ensure_ascii=False), json.dumps(added, ensure_ascii=False),
         json.dumps(removed, ensure_ascii=False), findings, db.utcnow()),
    )
    _trim(asset_id)
    return {"changed": True, "added": added, "removed": removed, "first": prev is None}


def _trim(asset_id: int, keep: int = MAX_KEEP) -> None:
    db.execute(
        "DELETE FROM asset_versions WHERE asset_id=? AND id NOT IN "
        "(SELECT id FROM asset_versions WHERE asset_id=? ORDER BY id DESC LIMIT ?)",
        (asset_id, asset_id, keep),
    )


def _version_dict(row: Any) -> dict[str, Any]:
    data = {k: row[k] for k in row.keys()}
    for key in ("strings", "added", "removed"):
        data[key] = _load(data.get(key))
    data["added_count"] = len(data["added"])
    data["removed_count"] = len(data["removed"])
    return data


def history(asset_id: int, limit: int = MAX_KEEP) -> list[dict[str, Any]]:
    rows = db.query(
        "SELECT * FROM asset_versions WHERE asset_id=? ORDER BY id DESC LIMIT ?",
        (asset_id, max(1, min(limit, 50))),
    )
    return [_version_dict(row) for row in rows]


def recent_changes(
    target_id: int | None = None, limit: int = 60, only_diff: bool = True, hours: int = 0
) -> list[dict[str, Any]]:
    """跨站变更流: 最近哪些资产变了、变了什么。"""
    where: list[str] = []
    params: list[Any] = []
    if target_id:
        where.append("v.target_id = ?")
        params.append(target_id)
    if only_diff:
        where.append("(v.added <> '[]' OR v.removed <> '[]')")
    if hours > 0:
        from datetime import datetime, timedelta, timezone

        moment = datetime.now(timezone.utc) - timedelta(hours=hours)
        where.append("v.created_at >= ?")
        params.append(moment.isoformat(timespec="seconds"))
    clause = ("WHERE " + " AND ".join(where)) if where else ""
    rows = db.query(
        f"SELECT v.*, t.name AS target_name, t.base_url AS target_url FROM asset_versions v "
        f"LEFT JOIN targets t ON t.id = v.target_id {clause} ORDER BY v.id DESC LIMIT ?",
        (*params, max(1, min(limit, 300))),
    )
    return [{**_version_dict(row), "target_name": row["target_name"],
             "target_url": row["target_url"]} for row in rows]
