"""高误报来源的 AI 预筛门控。

某个来源（rule_id；外部分析器的规则带分析器前缀，如 `jscanner2:secret:other`）
在历史 AI 判定里的误报占比超过阈值时，它的新发现**先不出现在列表里** ——
等 AI 判定通过再展示。

两条防误伤的设计：

1. 只统计"已被 AI 判定过"的样本。未判定的发现不计入分母，否则新来源会被
   永远当作 0% 或 100%，取决于口径;
2. `min_samples` 之下不启用。实测里 `aliyun-access-key-secret` 只有 1 个样本
   且恰好被判误报(100%)，但它显然不该被当成噪声来源闸掉。
"""
from __future__ import annotations

import time
from typing import Any

from . import db

DEFAULT: dict[str, Any] = {
    "enabled": True,
    "fp_threshold": 0.6,   # 误报率超过该值即纳入预筛
    "min_samples": 3,      # 判定样本下限, 低于此值不启用
    # AI 已判定为误报的, 默认也不再展示（不分来源）。
    # 这是"确认后再展示"的直接实现: 关掉即可看到全部。
    "hide_ai_fake": True,
}

# 高误报来源的发现, 只有这两种判定算"AI 确认通过"
PASS_VERDICTS = ("real", "public")

_cache: tuple[float, dict[str, dict]] | None = None


def gate_config() -> dict[str, Any]:
    cfg = dict(DEFAULT)
    for key, value in (db.get_setting("ai_gate") or {}).items():
        if key in cfg and value is not None:
            cfg[key] = value
    return cfg


def save_gate_config(patch: dict[str, Any] | None) -> dict[str, Any]:
    cfg = gate_config()
    for key, value in (patch or {}).items():
        if key in cfg and value is not None:
            cfg[key] = value
    db.set_setting("ai_gate", cfg)
    invalidate()
    return cfg


def invalidate() -> None:
    global _cache
    _cache = None


def source_stats() -> list[dict[str, Any]]:
    """每个来源的判定样本与误报率。"""
    out: list[dict[str, Any]] = []
    for row in db.query(
        "SELECT rule_id, "
        "SUM(CASE WHEN ai_verdict <> '' THEN 1 ELSE 0 END) AS judged, "
        "SUM(CASE WHEN ai_verdict = 'fake' THEN 1 ELSE 0 END) AS fake, "
        "COUNT(*) AS total FROM findings GROUP BY rule_id ORDER BY total DESC"
    ):
        judged = row["judged"] or 0
        fake = row["fake"] or 0
        out.append({
            "rule_id": row["rule_id"],
            "judged": judged,
            "fake": fake,
            "total": row["total"] or 0,
            "fp_rate": round(fake / judged, 3) if judged else None,
        })
    return out


def gated_sources(ttl: float = 3.0) -> dict[str, dict[str, Any]]:
    """当前被纳入预筛的来源（rule_id -> 统计）。"""
    global _cache
    now = time.monotonic()
    if _cache is not None and now - _cache[0] < ttl:
        return _cache[1]
    cfg = gate_config()
    result: dict[str, dict[str, Any]] = {}
    if cfg["enabled"]:
        for item in source_stats():
            rate = item["fp_rate"]
            if rate is None:
                continue
            if item["judged"] >= int(cfg["min_samples"]) and rate > float(cfg["fp_threshold"]):
                result[item["rule_id"]] = item
    _cache = (now, result)
    return result


def is_gated(rule_id: str) -> bool:
    return rule_id in gated_sources()


def exclusion(alias: str = "f") -> tuple[str, list[Any]]:
    """生成用于排除"高误报来源且未被 AI 确认"的 SQL 片段。

    被闸住的发现只要 AI 判定为 real/public, 就照常展示。
    """
    cfg = gate_config()
    parts: list[str] = []
    params: list[Any] = []
    gated = gated_sources()
    if gated:
        keys = list(gated)
        placeholders = ",".join("?" * len(keys))
        passed = ",".join(f"'{v}'" for v in PASS_VERDICTS)
        parts.append(f"({alias}.rule_id NOT IN ({placeholders}) OR {alias}.ai_verdict IN ({passed}))")
        params.extend(keys)
    if cfg.get("hide_ai_fake", True):
        parts.append(f"COALESCE({alias}.ai_verdict, '') <> 'fake'")
    if not parts:
        return "", []
    return (" AND ".join(parts), params)


def hidden_count() -> dict[str, int]:
    """被预筛隐藏的条数（供界面提示）。"""
    sql, params = exclusion("f")
    if not sql:
        return {"hidden": 0, "sources": 0}
    row = db.query_one(
        # 注意必须整体取反: 不加括号时 SQL 会解析成 (NOT A) AND B, 计数会偏小
        f"SELECT COUNT(*) c FROM findings f WHERE NOT ({sql}) "
        f"AND f.status IN ('new','open')", params)
    fake = db.query_one(
        "SELECT COUNT(*) c FROM findings WHERE ai_verdict='fake' AND status IN ('new','open')"
    )["c"] if gate_config().get("hide_ai_fake", True) else 0
    return {"hidden": row["c"] or 0, "sources": len(gated_sources()), "ai_fake": fake or 0}


def summary() -> dict[str, Any]:
    cfg = gate_config()
    gated = gated_sources()
    return {
        "config": cfg,
        "gated_sources": [
            {"rule_id": key, **{k: value[k] for k in ("judged", "fake", "total", "fp_rate")}}
            for key, value in gated.items()
        ],
        "hidden": hidden_count(),
        "sources": source_stats(),
    }
