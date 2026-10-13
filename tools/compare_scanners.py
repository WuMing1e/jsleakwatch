#!/usr/bin/env python3
"""整站扫描器横向对比。

`tools/benchmark.py` 是按资产逐文件评测（适合"文件 → 命中"型的分析器）；
JSHawk / JScanner2 这类工具自带抓取，输入是整个站点，所以需要单独比对：
在同一批标注（work/labels.jsonl）上，按"命中的凭证值"对账，而不是按文件。

用法:
    python3.10 tools/compare_scanners.py --labels work/labels.jsonl \
        --hit "JSLeakWatch=findings:data/jslw.db:1" \
        --hit "JSHawk=jshawk:tools/external/JSHawk/jshawk_results/xxx/reports/jshawk.json" \
        --hit "JScanner2=jscanner2:tools/external/JScanner2/Result/JScanner_Result.db"

匹配规则: 先把标注里的凭证值从冻结语料里还原出 sha256 索引，再按
① sha256 精确匹配 → ② 前缀/包含兜底（应对工具截断输出）的顺序对账。
"""
from __future__ import annotations

import argparse
import hashlib
import json
import sqlite3
import sys
from dataclasses import dataclass, field
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from app import benchmark, db  # noqa: E402
from app.analyzers import BuiltinAnalyzer  # noqa: E402


@dataclass
class Hit:
    value: str
    rule: str = ""
    severity: str = ""
    url: str = ""


@dataclass
class ToolResult:
    name: str
    hits: list[Hit] = field(default_factory=list)
    runtime_ms: int = 0
    error: str = ""


# ------------------------------------------------------------------ 解析各家输出

def parse_jshawk(path: Path) -> list[Hit]:
    data = json.loads(path.read_text(encoding="utf-8"))
    out: list[Hit] = []
    for item in data.get("findings") or []:
        out.append(Hit(
            value=str(item.get("secret") or item.get("match") or "").strip(),
            rule=str(item.get("type") or item.get("rule") or ""),
            severity=str(item.get("risk") or item.get("severity") or ""),
            url=str(item.get("url") or item.get("source") or ""),
        ))
    return out


def parse_jscanner2(path: Path) -> list[Hit]:
    """读取 JScanner2 的结果库: 自动找含有密钥文本的表与字段。"""
    conn = sqlite3.connect(str(path))
    conn.row_factory = sqlite3.Row
    tables = [row[0] for row in conn.execute(
        "SELECT name FROM sqlite_master WHERE type='table'").fetchall()]
    out: list[Hit] = []
    for table in tables:
        columns = [row[1] for row in conn.execute(f"PRAGMA table_info({table})").fetchall()]
        lowered = {col.lower(): col for col in columns}
        value_col = next((lowered[key] for key in
                          ("sensitive_value", "secret", "match", "sensitive_info", "content",
                           "value", "result", "info", "sensitive", "data") if key in lowered), None)
        if value_col is None:
            continue
        rule_col = next((lowered[key] for key in ("secret_type", "rule", "type", "category", "name", "flag")
                         if key in lowered), None)
        sev_col = next((lowered[key] for key in ("risk_level", "severity", "risk", "level") if key in lowered), None)
        url_col = next((lowered[key] for key in ("js_url", "url", "source", "source_url", "page", "target")
                        if key in lowered), None)
        for row in conn.execute(f"SELECT * FROM {table}").fetchall():
            raw = str(row[value_col] or "")
            if len(raw) < 8:
                continue
            out.append(Hit(value=raw.strip(),
                           rule=str(row[rule_col] or "") if rule_col else f"jscanner2/{table}",
                           severity=str(row[sev_col] or "") if sev_col else "",
                           url=str(row[url_col] or "") if url_col else ""))
    conn.close()
    return out


def parse_findings(path: Path, target_id: str = "") -> list[Hit]:
    """读取本系统的发现库: 用 match_sha256 直接当凭证指纹。"""
    conn = sqlite3.connect(str(path))
    conn.row_factory = sqlite3.Row
    sql = "SELECT rule_id, rule_name, severity, asset_url, match_sha256 FROM findings WHERE status IN ('new','open')"
    params: tuple = ()
    if target_id:
        sql += " AND target_id=?"
        params = (int(target_id),)
    out: list[Hit] = []
    for row in conn.execute(sql, params).fetchall():
        out.append(Hit(value=f"sha256:{row['match_sha256']}", rule=row["rule_id"],
                       severity=row["severity"], url=row["asset_url"] or ""))
    conn.close()
    return out


def parse_generic_json(path: Path) -> list[Hit]:
    data = json.loads(path.read_text(encoding="utf-8"))
    items = data if isinstance(data, list) else next(
        (data[key] for key in ("findings", "results", "items", "matches", "data")
         if isinstance(data.get(key), list)), [])
    out: list[Hit] = []
    for item in items:
        if not isinstance(item, dict):
            continue
        pick = lambda *keys: next((str(item[k]) for k in keys if item.get(k)), "")  # noqa: E731
        value = pick("secret", "match", "value", "evidence", "raw", "sensitive")
        if len(value) < 8:
            continue
        out.append(Hit(value=value.strip(), rule=pick("rule", "type", "id", "name"),
                       severity=pick("severity", "risk", "level"), url=pick("url", "source", "file")))
    return out


PARSERS = {
    "jshawk": parse_jshawk,
    "jscanner2": parse_jscanner2,
    "findings": parse_findings,
    "json": parse_generic_json,
}


def load_tool(spec: str) -> ToolResult:
    """spec: name=kind:path[:extra]"""
    if "=" not in spec or ":" not in spec:
        return ToolResult(name=spec, error="格式应为 name=kind:path")
    name, rest = spec.split("=", 1)
    kind, _, tail = rest.partition(":")
    parts = tail.split(":")
    path, extra = parts[0], (parts[1] if len(parts) > 1 else "")
    parser = PARSERS.get(kind)
    if parser is None:
        return ToolResult(name=name, error=f"未知类型 {kind}")
    try:
        hits = parser(Path(path), extra) if kind == "findings" else parser(Path(path))
    except FileNotFoundError:
        return ToolResult(name=name, error=f"结果文件不存在: {path}")
    except Exception as exc:  # noqa: BLE001
        return ToolResult(name=name, error=f"{type(exc).__name__}: {exc}"[:160])
    return ToolResult(name=name, hits=hits)


# ------------------------------------------------------------------ 对账

def build_value_index(corpus: benchmark.Corpus) -> tuple[dict[str, str], list[str]]:
    """从冻结语料里还原"凭证值 → sha256"，并给出全部值用于兜底匹配。"""
    analyzer = BuiltinAnalyzer()
    sha_to_rule: dict[str, str] = {}
    values: set[str] = set()
    for asset in corpus.assets:
        for hit in analyzer.analyze_text(benchmark.read_asset(corpus, asset), asset.url):
            if not hit.raw:
                continue
            digest = hashlib.sha256(hit.raw.encode("utf-8", "ignore")).hexdigest()
            sha_to_rule[digest] = hit.rule_id
            values.add(hit.raw)
    return sha_to_rule, sorted(values, key=len, reverse=True)


def match_hit(hit: Hit, label_shas: set[str], known_values: list[str]) -> str | None:
    """返回命中的 sha256, 匹配不到返回 None。"""
    if hit.value.startswith("sha256:"):
        digest = hit.value.split(":", 1)[1]
        return digest if digest in label_shas else None
    digest = hashlib.sha256(hit.value.encode("utf-8", "ignore")).hexdigest()
    if digest in label_shas:
        return digest
    # 兜底: 工具把长值截断了
    if len(hit.value) >= 12:
        for value in known_values:
            if len(value) < 12:
                continue
            if value.startswith(hit.value) or hit.value.startswith(value):
                candidate = hashlib.sha256(value.encode("utf-8", "ignore")).hexdigest()
                if candidate in label_shas:
                    return candidate
    return None


def main() -> int:
    parser = argparse.ArgumentParser(description="整站扫描器横向对比")
    parser.add_argument("--labels", required=True)
    parser.add_argument("--corpus", default="demo", help="用于还原凭证值的冻结语料名")
    parser.add_argument("--hit", action="append", default=[], help="name=kind:path")
    parser.add_argument("--markdown", default="")
    args = parser.parse_args()

    db.init_db()
    labels = benchmark.load_labels(args.labels)
    tp = [label for label in labels if label.label == "tp"]
    fp = [label for label in labels if label.label == "fp"]
    corpus = benchmark.load_corpus(args.corpus)
    _sha_to_rule, known_values = build_value_index(corpus)
    label_shas = {label.match_sha256 for label in labels if label.match_sha256}
    tp_shas = {label.match_sha256 for label in tp}
    fp_shas = {label.match_sha256 for label in fp}

    tools = [load_tool(spec) for spec in args.hit]
    found_by: dict[str, set[str]] = {label.match_sha256: set() for label in tp}

    rows = []
    for tool in tools:
        if tool.error:
            rows.append({"name": tool.name, "error": tool.error})
            continue
        counts = {"tp": 0, "fp": 0, "unlabeled": 0}
        seen: set[str] = set()
        for hit in tool.hits:
            digest = match_hit(hit, label_shas, known_values)
            if digest is None:
                counts["unlabeled"] += 1
                continue
            if digest in seen:
                continue
            seen.add(digest)
            if digest in tp_shas:
                counts["tp"] += 1
                found_by[digest].add(tool.name)
            elif digest in fp_shas:
                counts["fp"] += 1
        missed = len(tp_shas - seen)
        precision = counts["tp"] / (counts["tp"] + counts["fp"]) if (counts["tp"] + counts["fp"]) else None
        recall = counts["tp"] / len(tp_shas) if tp_shas else None
        f1 = (2 * precision * recall / (precision + recall)) if precision and recall else None
        rows.append({"name": tool.name, "hits": len(tool.hits), **counts, "missed": missed,
                     "precision": precision, "recall": recall, "f1": f1})

    header = ["工具", "命中", "TP", "FP", "未归类", "漏报", "精确率", "召回率", "F1"]
    print(f"# 整站扫描器对比 · 语料 {corpus.name}（{len(corpus.assets)} 个资产，标注 tp {len(tp_shas)} / fp {len(fp_shas)}）\n")
    print("| " + " | ".join(header) + " |")
    print("|" + "---|" * len(header))
    for row in rows:
        if row.get("error"):
            print(f"| {row['name']} | — | — | — | — | — | — | — | — |")
            continue
        fmt = lambda v: "—" if v is None else (f"{v:.3f}" if isinstance(v, float) else str(v))  # noqa: E731
        print(f"| {row['name']} | {row['hits']} | {row['tp']} | {row['fp']} | {row['unlabeled']} | "
              f"{row['missed']} | {fmt(row['precision'])} | {fmt(row['recall'])} | {fmt(row['f1'])} |")
    for row in rows:
        if row.get("error"):
            print(f"\n- `{row['name']}` 未能参与对比: {row['error']}")

    nobody = [label for label in tp if not found_by.get(label.match_sha256)]
    if nobody:
        print(f"\n## 所有工具都没检出的标注（{len(nobody)} 条）\n")
        for label in nobody:
            print(f"- {label.note or label.asset}")
    partial = [label for label in tp if 0 < len(found_by.get(label.match_sha256, set())) < len(tools)]
    if partial:
        print(f"\n## 只有部分工具检出（{len(partial)} 条）\n")
        for label in partial:
            owners = ", ".join(sorted(found_by[label.match_sha256]))
            print(f"- {label.note or label.asset} — 检出: {owners}")

    if args.markdown:
        Path(args.markdown).write_text("\n".join(["# 整站扫描器对比"]), encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
