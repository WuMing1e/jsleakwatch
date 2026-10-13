"""把 gitleaks 规则文件 (TOML) 转换成内置规则。

gitleaks 是 MIT 协议的开源密钥扫描器, 其规则库覆盖面很广。本模块只做格式转换,
不复制其规则内容, 需要时用官方仓库的 TOML 直接导入即可。
"""
from __future__ import annotations

import re
from typing import Any

try:  # Python 3.11+
    import tomllib as _toml
except ModuleNotFoundError:  # pragma: no cover
    import tomli as _toml  # type: ignore[no-redef]

from ..rules import Rule

SEVERITY_OK = {"critical", "high", "medium", "low", "info"}


def _severity(raw: Any) -> str:
    value = str(raw or "").strip().lower()
    return value if value in SEVERITY_OK else "high"


def _slug(value: str) -> str:
    slug = re.sub(r"[^a-z0-9]+", "-", value.strip().lower()).strip("-")
    return slug or "imported-rule"


def parse_toml(text: str, prefix: str = "gl") -> list[Rule]:
    """解析 gitleaks 配置文本, 返回 Rule 列表。"""
    data = _toml.loads(text)
    return rules_from_config(data, prefix=prefix)


def rules_from_config(data: dict[str, Any], prefix: str = "gl") -> list[Rule]:
    out: list[Rule] = []
    for raw in data.get("rules", []) or []:
        pattern = raw.get("regex") or raw.get("secretRegex")
        if not pattern:
            continue
        rule_id = f"{prefix}:{_slug(str(raw.get('id') or raw.get('description') or 'rule'))}"
        allowlist: list[str] = []
        block = raw.get("allowlist") or {}
        if isinstance(block, dict):
            allowlist.extend(str(x) for x in (block.get("regexes") or []))
            allowlist.extend(str(x) for x in (block.get("paths") or []))
        keywords = raw.get("keywords") or []
        if isinstance(keywords, str):
            keywords = [keywords]
        try:
            entropy = float(raw.get("entropy") or 0)
        except (TypeError, ValueError):
            entropy = 0.0
        try:
            secret_group = int(raw.get("secretGroup") or 0)
        except (TypeError, ValueError):
            secret_group = 0
        tags = raw.get("tags") or []
        if isinstance(tags, str):
            tags = [tags]
        out.append(
            Rule(
                id=rule_id,
                name=str(raw.get("description") or raw.get("id") or rule_id)[:80],
                severity=_severity(raw.get("severity")),
                category=str(raw.get("category") or "imported"),
                pattern=str(pattern),
                description=str(raw.get("description") or ""),
                secret_group=secret_group,
                keywords=tuple(str(k) for k in keywords),
                entropy_min=entropy,
                allowlist=tuple(allowlist),
                reference=str(raw.get("reference") or ""),
                tags=tuple(str(t) for t in tags) + ("gitleaks",),
            )
        )
    return out


def rule_to_dict(rule: Rule) -> dict[str, Any]:
    return {
        "id": rule.id,
        "name": rule.name,
        "severity": rule.severity,
        "category": rule.category,
        "pattern": rule.pattern,
        "description": rule.description,
        "secret_group": rule.secret_group,
        "keywords": list(rule.keywords),
        "entropy_min": rule.entropy_min,
        "allowlist": list(rule.allowlist),
        "reference": rule.reference,
        "tags": list(rule.tags),
    }


def rule_from_dict(data: dict[str, Any]) -> Rule:
    return Rule(
        id=str(data["id"]),
        name=str(data.get("name") or data["id"]),
        severity=_severity(data.get("severity")),
        category=str(data.get("category") or "imported"),
        pattern=str(data["pattern"]),
        description=str(data.get("description") or ""),
        secret_group=int(data.get("secret_group") or 0),
        keywords=tuple(str(k) for k in (data.get("keywords") or [])),
        entropy_min=float(data.get("entropy_min") or 0),
        allowlist=tuple(str(x) for x in (data.get("allowlist") or [])),
        reference=str(data.get("reference") or ""),
        tags=tuple(str(t) for t in (data.get("tags") or [])),
    )
