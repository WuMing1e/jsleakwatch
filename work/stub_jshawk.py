"""桩工具: 模拟 JSHawk / JScanner2 这类外部分析器的 CLI 与输出格式。

用途: 在没有真实工具的情况下, 验证适配器、标注流程与打分逻辑端到端可用。
它用另一套规则给出命中, 故意与内置引擎部分重叠、部分不同, 便于观察差异。
"""
from __future__ import annotations

import argparse
import json
import re
import sys

PATTERNS = [
    ("jshawk/cloud-access-key", "critical", r"\b(?:AKIA|LTAI|AKID)[A-Za-z0-9]{12,24}\b"),
    ("jshawk/private-token", "high", r"\b(?:ghp_|sk_live_|xox[baprs]-)[A-Za-z0-9_\-]{16,}"),
    ("jshawk/webhook-url", "high", r"https://[^\s\"'<>]*(?:hook|webhook)[^\s\"'<>]*"),
    ("jshawk/assignment-secret", "medium", r"(?i)(?:secret|token|password|apikey|api_key)\W{0,3}[:=]\W{0,3}([^\"';\s]{12,200})"),
]


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("paths", nargs="*")
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args()

    out: list[dict] = []
    for path in args.paths:
        try:
            with open(path, encoding="utf-8", errors="replace") as handle:
                text = handle.read()
        except OSError:
            continue
        for rule_id, severity, pattern in PATTERNS:
            for match in re.finditer(pattern, text):
                value = match.group(match.lastindex or 0)
                out.append({
                    "rule": rule_id,
                    "severity": severity,
                    "secret": value,
                    "line": text.count("\n", 0, match.start()) + 1,
                    "snippet": text[max(0, match.start() - 60): match.end() + 60].replace("\n", " "),
                })
    json.dump(out, sys.stdout, ensure_ascii=False)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
