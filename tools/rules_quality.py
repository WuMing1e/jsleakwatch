#!/usr/bin/env python3
"""规则质量跑批: 在冻结语料 + 人工标注集上算每条规则的 precision / recall。

用法:
    # 看一眼当前规则表现
    python3.10 tools/rules_quality.py --corpus demo --labels work/labels.jsonl

    # 存基线, 之后改规则再跑, 精度掉太多就报错退出（可以挂到提交前检查里）
    python3.10 tools/rules_quality.py --corpus demo --labels work/labels.jsonl \\
        --baseline work/rules-quality.json --min-precision 0.85 --max-drop 0.05

标注格式与 tools/benchmark.py 一致: 每行 {asset, match_sha256, label: tp|fp}。
规则来源是当前数据库（含开关、等级覆盖与自定义规则），所以调完规则直接重跑就有对比。
"""
from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from app import benchmark, db  # noqa: E402
from app.scanner import build_detector  # noqa: E402


def collect(corpus_name: str, labels_path: str) -> dict:
    corpus = benchmark.load_corpus(corpus_name)
    labels = benchmark.load_labels(labels_path)
    tp_labels = [item for item in labels if item.label == "tp"]
    fp_labels = [item for item in labels if item.label == "fp"]
    detector = build_detector()

    per_rule: dict[str, dict] = {}
    matched_tp: set[int] = set()
    unlabeled = 0

    for asset in corpus.assets:
        try:
            text = benchmark.read_asset(corpus, asset)
        except OSError as exc:
            print(f"  跳过 {asset.url}: {exc}")
            continue
        for det in detector.scan_text(text, target_id=0, asset_url=asset.url, store_raw=True):
            bucket = per_rule.setdefault(det.rule_id, {
                "rule_id": det.rule_id, "rule_name": det.rule_name,
                "severity": det.severity, "hits": 0, "tp": 0, "fp": 0, "unlabeled": 0,
            })
            bucket["hits"] += 1
            digest = hashlib.sha256(det.raw.encode("utf-8", "ignore")).hexdigest()
            hit_tp = next((i for i, label in enumerate(tp_labels)
                           if label.asset in ("", asset.url) and label.matches(asset.url, det.raw)), None)
            if hit_tp is not None:
                bucket["tp"] += 1
                matched_tp.add(hit_tp)
                continue
            if any(label.asset in ("", asset.url) and label.matches(asset.url, det.raw)
                   for label in fp_labels):
                bucket["fp"] += 1
                continue
            bucket["unlabeled"] += 1
            _ = digest

    for bucket in per_rule.values():
        judged = bucket["tp"] + bucket["fp"]
        bucket["precision"] = round(bucket["tp"] / judged, 3) if judged else None
    total_tp = sum(item["tp"] for item in per_rule.values())
    total_fp = sum(item["fp"] for item in per_rule.values())
    judged = total_tp + total_fp
    return {
        "corpus": corpus_name,
        "assets": len(corpus.assets),
        "rules_hit": len(per_rule),
        "labeled_hits": judged,
        "tp": total_tp,
        "fp": total_fp,
        "unlabeled": sum(item["unlabeled"] for item in per_rule.values()),
        "precision": round(total_tp / judged, 3) if judged else None,
        "recall": round(len(matched_tp) / len(tp_labels), 3) if tp_labels else None,
        "missed_tp": len(tp_labels) - len(matched_tp),
        "per_rule": sorted(per_rule.values(),
                           key=lambda item: (item["fp"], -item["hits"]), reverse=True),
    }


def render(report: dict, markdown_path: str = "") -> str:
    lines = [
        f"# 规则质量报告 · 语料 `{report['corpus']}`",
        "",
        f"- 资产 {report['assets']} 个, 命中规则 {report['rules_hit']} 条",
        f"- 有标注的命中 {report['labeled_hits']} 条: 正确 {report['tp']} · 误报 {report['fp']}"
        f" → precision {report['precision']}",
        f"- 标注应命中 {report['tp'] + report['missed_tp']} 条, 漏掉 {report['missed_tp']} 条"
        f" → recall {report['recall']}",
        "",
        "| 规则 | 等级 | 命中 | 正确 | 误报 | precision |",
        "| --- | --- | --- | --- | --- | --- |",
    ]
    for item in report["per_rule"]:
        lines.append(f"| {item['rule_name']} `{item['rule_id']}` | {item['severity']} | "
                     f"{item['hits']} | {item['tp']} | {item['fp']} | "
                     f"{item['precision'] if item['precision'] is not None else '—'} |")
    text = "\n".join(lines) + "\n"
    if markdown_path:
        Path(markdown_path).write_text(text, encoding="utf-8")
    return text


def main() -> int:
    parser = argparse.ArgumentParser(description="规则质量跑批")
    parser.add_argument("--corpus", default="demo", help="冻结语料名 (data/corpus/<name>)")
    parser.add_argument("--labels", default="work/labels.jsonl")
    parser.add_argument("--markdown", default="", help="把报告写到文件")
    parser.add_argument("--baseline", default="", help="基线 JSON: 存在则对比, 不存在则写入")
    parser.add_argument("--min-precision", type=float, default=0.0,
                        help="整体 precision 低于该值就失败退出")
    parser.add_argument("--max-drop", type=float, default=0.05,
                        help="相对基线允许的最大精度下滑")
    args = parser.parse_args()

    if not Path(args.labels).exists():
        print(f"标注文件不存在: {args.labels}", file=sys.stderr)
        return 2

    report = collect(args.corpus, args.labels)
    print(render(report, args.markdown))

    failed = False
    precision = report["precision"] or 0.0
    if args.min_precision and precision < args.min_precision:
        print(f"precision {precision} 低于门槛 {args.min_precision}", file=sys.stderr)
        failed = True

    if args.baseline:
        path = Path(args.baseline)
        if path.exists():
            previous = json.loads(path.read_text(encoding="utf-8"))
            drop = (previous.get("precision") or 0) - precision
            print(f"对比基线 {previous.get('precision')} → {precision} (变化 {round(-drop, 3)})")
            if drop > args.max_drop:
                print(f"精度下滑 {round(drop, 3)} 超过允许的 {args.max_drop}", file=sys.stderr)
                failed = True
        else:
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(json.dumps({k: report[k] for k in
                                        ("corpus", "precision", "recall", "tp", "fp")},
                                       ensure_ascii=False, indent=1), encoding="utf-8")
            print(f"已写入基线 {path}")
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
