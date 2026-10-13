#!/usr/bin/env python3
"""对比评测命令行工具。

典型用法:
    # 1) 冻结一份语料（只做一次，之后完全离线）
    python3.10 tools/benchmark.py freeze --target-id 1 --name demo

    # 2) 生成标注模板，把 unlabeled 改成 tp / fp，再手工补 label=tp 的漏报项
    python3.10 tools/benchmark.py export-labels --corpus demo -o labels.jsonl

    # 3) 在同一批样本上跑多个分析器
    python3.10 tools/benchmark.py run --corpus demo --labels labels.jsonl \
        --analyzer builtin --analyzer cli:jshawk --analyzer cli:jscanner2 \
        --markdown report.md

外部分析器通过 settings 表的 `analyzers` 配置声明，例如:
    {"cli_analyzers": {"jshawk": {"command": ["jshawk", "scan", "--json", "{file}"],
                                  "timeout": 180,
                                  "field_map": {"raw": "secret", "rule_id": "type"}}}}
"""
from __future__ import annotations

import argparse
import asyncio
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from app import benchmark, db  # noqa: E402
from app.analyzers import analyzer_specs  # noqa: E402


def main() -> int:
    parser = argparse.ArgumentParser(description="多分析器对比评测")
    sub = parser.add_subparsers(dest="cmd", required=True)

    freeze = sub.add_parser("freeze", help="抓取并冻结语料")
    freeze.add_argument("--target-id", type=int, required=True)
    freeze.add_argument("--name", required=True)
    freeze.add_argument("--max-assets", type=int, default=300)

    export = sub.add_parser("export-labels", help="生成标注模板")
    export.add_argument("--corpus", required=True)
    export.add_argument("--analyzer", default="builtin")
    export.add_argument("-o", "--out", default="labels.jsonl")

    run = sub.add_parser("run", help="跑对比评测")
    run.add_argument("--corpus", required=True)
    run.add_argument("--labels", default="")
    run.add_argument("--analyzer", action="append", default=[])
    run.add_argument("--json-out", default="")
    run.add_argument("--markdown", default="")

    sub.add_parser("list", help="列出已有语料与可用后端")

    add = sub.add_parser("add-analyzer", help="登记一个外部分析器(CLI)")
    add.add_argument("--name", required=True, help="例如 jshawk / jscanner2")
    add.add_argument("--command", required=True,
                     help='命令模板, {file} 占位资产文件, 例如 "jshawk scan --json {file}"')
    add.add_argument("--label", default="")
    add.add_argument("--timeout", type=int, default=180)
    add.add_argument("--severity-default", default="medium")
    add.add_argument("--field-map", default="", help='JSON, 例如 {"raw":"secret","rule_id":"type"}')

    args = parser.parse_args()
    db.init_db()

    if args.cmd == "freeze":
        row = db.query_one("SELECT * FROM targets WHERE id=?", (args.target_id,))
        if row is None:
            print(f"找不到站点 id={args.target_id}", file=sys.stderr)
            return 1
        target = {k: row[k] for k in row.keys()}
        corpus = asyncio.run(benchmark.freeze_corpus(target, args.name, args.max_assets))
        print(f"语料已冻结: {corpus.name} -> {corpus.dir}")
        print(f"资产数 {len(corpus.assets)}")
        for asset in corpus.assets:
            print(f"  [{asset.kind:7}] {asset.size:>7}  {asset.url}")
        return 0

    if args.cmd == "export-labels":
        corpus = benchmark.load_corpus(args.corpus)
        labels = benchmark.export_labels(corpus, args.analyzer)
        benchmark.save_labels(labels, args.out)
        print(f"已写出 {len(labels)} 条标注模板 -> {args.out}")
        print("请把 label 从 unlabeled 改成 tp 或 fp；遗漏的凭证请手工加一行 "
              '{"asset":"<地址>","pattern":"<正则>","label":"tp","note":"漏报"}')
        return 0

    if args.cmd == "run":
        corpus = benchmark.load_corpus(args.corpus)
        labels = benchmark.load_labels(args.labels) if args.labels else []
        specs = args.analyzer or ["builtin"]
        report = benchmark.run_benchmark(corpus, specs, labels)
        print(benchmark.render_markdown(report))
        if args.json_out:
            Path(args.json_out).write_text(json.dumps(report, ensure_ascii=False, indent=2),
                                           encoding="utf-8")
            print(f"JSON 报告 -> {args.json_out}")
        if args.markdown:
            Path(args.markdown).write_text(benchmark.render_markdown(report), encoding="utf-8")
            print(f"Markdown 报告 -> {args.markdown}")
        return 0

    if args.cmd == "add-analyzer":
        config = db.get_setting("analyzers") or {}
        entries = config.get("cli_analyzers") or {}
        entry: dict = {
            "command": args.command.split(),
            "timeout": args.timeout,
            "severity_default": args.severity_default,
        }
        if args.label:
            entry["label"] = args.label
        if args.field_map:
            entry["field_map"] = json.loads(args.field_map)
        entries[args.name] = entry
        config["cli_analyzers"] = entries
        db.set_setting("analyzers", config)
        spec = f"cli:{args.name}"
        probe = analyzer_specs()["analyzer"].get(spec, {})
        print(f"已登记 {spec}: {' '.join(entry['command'])}")
        print(f"可用性: {'可用' if probe.get('available') else '不可用(检查命令是否在 PATH 中)'}")
        return 0

    print("已有语料:")
    for item in benchmark.list_corpora():
        print(f"  {item['name']:20} {item['assets']:>4} 个资产  {item['created_at']}  {item['target_url']}")
    print("\n可用后端:")
    for group, entries in analyzer_specs().items():
        for key, meta in entries.items():
            flag = "可用" if meta.get("available") else "不可用"
            print(f"  [{group}] {key:10} {flag:4} {meta.get('label', '')}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
