"""多分析器对比评测。

回答"哪个分析器更好"必须靠同一批样本上的可复现数字，而不是印象。所以这里做三件事：

1. 冻结语料：把一次采集结果落到磁盘，所有分析器看到**完全相同的输入**；
2. 标注：以 JSONL 记录每条"真实凭证 / 误报 / 应检出但都漏了"，人工可编辑；
3. 打分：对每个分析器算 TP/FP/FN、精确率/召回率/F1，并给出**独有命中**与**漏报清单**。

一个刻意的取舍：没有标注的命中不计入误报，而是单列 `unlabeled`。
否则召回率越高的分析器精确率会被系统性压低，对比就失真了。
"""
from __future__ import annotations

import asyncio
import hashlib
import json
import re
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Iterable

from . import db
from .analyzers import AnalyzerBackend, RawHit, build_analyzer, kind_from_url
from .config import DATA_DIR, ScanConfig
from .discover import Extractor, Candidate
from .fetcher import Fetcher
from .rules import SEVERITY_ORDER, mask_value
from .scanner import scan_config_from_settings

CORPUS_ROOT = DATA_DIR / "corpus"
LABEL_VALUES = ("tp", "fp", "unlabeled")


# ------------------------------------------------------------------ 语料

@dataclass
class CorpusAsset:
    url: str
    kind: str
    file: str
    sha256: str
    size: int


@dataclass
class Corpus:
    name: str
    dir: str
    target_url: str
    created_at: str
    assets: list[CorpusAsset] = field(default_factory=list)

    @property
    def manifest_path(self) -> Path:
        return Path(self.dir) / "manifest.json"


def corpus_dir(name: str) -> Path:
    safe = re.sub(r"[^A-Za-z0-9_.-]+", "-", name).strip("-") or "corpus"
    return CORPUS_ROOT / safe


async def freeze_corpus(
    target: dict[str, Any], name: str, max_assets: int = 300, overrides: dict[str, Any] | None = None
) -> Corpus:
    """抓取并冻结一份语料。此后所有对比都在同一批文件上进行, 不再联网。"""
    cfg = scan_config_from_settings(overrides)
    root = corpus_dir(name)
    (root / "assets").mkdir(parents=True, exist_ok=True)
    extractor = Extractor(
        base_url=target["base_url"],
        scope=target.get("scope") or "same-origin",
        follow_sourcemaps=bool(target.get("include_sourcemaps", 1)) and cfg.follow_sourcemaps,
    )
    assets: list[CorpusAsset] = []
    seen: set[str] = set()

    async with Fetcher(cfg) as fetcher:
        frontier: list[Candidate] = [Candidate(url=target["base_url"], kind="html", depth=0)]
        max_depth = min(int(target.get("max_depth") or cfg.max_depth), 4)
        while frontier and len(assets) < max_assets:
            batch = [c for c in frontier if c.url not in seen][: max_assets - len(assets)]
            frontier = []
            if not batch:
                break
            responses = await asyncio.gather(*[fetcher.get(c.url) for c in batch])
            nxt: dict[str, Candidate] = {}
            for cand, resp in zip(batch, responses):
                seen.add(cand.url)
                if not resp.ok or not resp.text:
                    continue
                digest = hashlib.sha256(resp.text.encode("utf-8", "ignore")).hexdigest()
                filename = f"{digest[:16]}.txt"
                path = root / "assets" / filename
                if not path.exists():
                    path.write_text(resp.text, encoding="utf-8")
                assets.append(CorpusAsset(url=cand.url, kind=cand.kind, file=filename,
                                          sha256=digest, size=len(resp.text)))
                if cand.kind in ("html", "config"):
                    for child in extractor.from_html(cand.url, resp.text, cand.depth):
                        nxt.setdefault(child.url, child)
                    if cand.depth < max_depth:
                        for page in extractor.pages_from_html(cand.url, resp.text, cand.depth + 1):
                            nxt.setdefault(page.url, page)
                else:
                    for child in extractor.from_js(cand.url, resp.text, cand.depth):
                        nxt.setdefault(child.url, child)
            frontier = [c for url, c in nxt.items() if url not in seen]

    corpus = Corpus(name=name, dir=str(root), target_url=target["base_url"],
                    created_at=db.utcnow(), assets=assets)
    save_corpus(corpus)
    return corpus


def save_corpus(corpus: Corpus) -> None:
    corpus.manifest_path.write_text(
        json.dumps(asdict(corpus), ensure_ascii=False, indent=2), encoding="utf-8"
    )


def load_corpus(name: str) -> Corpus:
    path = corpus_dir(name) / "manifest.json"
    if not path.exists():
        raise FileNotFoundError(f"语料 {name} 不存在, 请先执行 freeze")
    data = json.loads(path.read_text(encoding="utf-8"))
    return Corpus(
        name=data["name"], dir=data["dir"], target_url=data["target_url"],
        created_at=data["created_at"],
        assets=[CorpusAsset(**item) for item in data.get("assets", [])],
    )


def list_corpora() -> list[dict[str, Any]]:
    if not CORPUS_ROOT.exists():
        return []
    out: list[dict[str, Any]] = []
    for path in sorted(CORPUS_ROOT.iterdir()):
        manifest = path / "manifest.json"
        if not manifest.exists():
            continue
        try:
            data = json.loads(manifest.read_text(encoding="utf-8"))
        except json.JSONDecodeError:
            continue
        out.append({"name": data.get("name", path.name), "assets": len(data.get("assets", [])),
                    "created_at": data.get("created_at", ""), "target_url": data.get("target_url", "")})
    return out


def read_asset(corpus: Corpus, asset: CorpusAsset) -> str:
    return (Path(corpus.dir) / "assets" / asset.file).read_text(encoding="utf-8", errors="replace")


# ------------------------------------------------------------------ 标注

@dataclass
class Label:
    asset: str = ""
    match_sha256: str = ""
    pattern: str = ""
    label: str = "unlabeled"     # tp | fp | unlabeled
    severity: str = ""
    note: str = ""

    def matches(self, url: str, raw: str) -> bool:
        if self.pattern:
            try:
                if re.search(self.pattern, raw):
                    return True
            except re.error:
                pass
        if self.match_sha256 and raw:
            if hashlib.sha256(raw.encode("utf-8", "ignore")).hexdigest() == self.match_sha256:
                return True
        return False


def load_labels(path: str | Path) -> list[Label]:
    labels: list[Label] = []
    for line in Path(path).read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        try:
            item = json.loads(line)
        except json.JSONDecodeError:
            continue
        labels.append(Label(
            asset=str(item.get("asset", "")),
            match_sha256=str(item.get("match_sha256", "")),
            pattern=str(item.get("pattern", "")),
            label=str(item.get("label", "unlabeled")).lower(),
            severity=str(item.get("severity", "")),
            note=str(item.get("note", "")),
        ))
    return labels


def save_labels(labels: Iterable[Label], path: str | Path) -> None:
    lines = []
    for label in labels:
        item = {"asset": label.asset, "match_sha256": label.match_sha256, "pattern": label.pattern,
                "label": label.label, "severity": label.severity, "note": label.note}
        lines.append(json.dumps({k: v for k, v in item.items() if v not in ("", None)},
                                ensure_ascii=False))
    Path(path).write_text("\n".join(lines) + "\n", encoding="utf-8")


def export_labels(corpus: Corpus, analyzer_spec: str = "builtin",
                  config: dict[str, Any] | None = None) -> list[Label]:
    """用某个分析器的结果生成标注模板, 人工把 label 改成 tp/fp 再补一条 fn。"""
    config = config if config is not None else (db.get_setting("analyzers") or {})
    analyzer = build_analyzer(analyzer_spec, config)
    labels: list[Label] = []
    seen: set[str] = set()
    for asset in corpus.assets:
        text = read_asset(corpus, asset)
        for hit in analyzer.analyze_text(text, asset.url):
            if not hit.raw:
                continue
            digest = hashlib.sha256(hit.raw.encode("utf-8", "ignore")).hexdigest()
            if digest in seen:
                continue
            seen.add(digest)
            labels.append(Label(asset=asset.url, match_sha256=digest,
                                label="unlabeled", severity=hit.severity,
                                note=f"{hit.rule_id} | {hit.masked or mask_value(hit.raw)}"))
    return labels


# ------------------------------------------------------------------ 打分

@dataclass
class AnalyzerMetrics:
    name: str
    available: bool = True
    hits: int = 0
    tp: int = 0
    fp: int = 0
    unlabeled: int = 0
    missed: int = 0
    unique: int = 0
    runtime_ms: int = 0
    error: str = ""
    by_severity: dict[str, int] = field(default_factory=dict)

    @property
    def precision(self) -> float | None:
        decided = self.tp + self.fp
        return round(self.tp / decided, 4) if decided else None

    @property
    def recall(self) -> float | None:
        total = self.tp + self.missed
        return round(self.tp / total, 4) if total else None

    @property
    def f1(self) -> float | None:
        p, r = self.precision, self.recall
        if p is None or r is None or (p + r) == 0:
            return None
        return round(2 * p * r / (p + r), 4)


def _analyzer_hits(analyzer: AnalyzerBackend, corpus: Corpus) -> tuple[list[tuple[str, RawHit]], int]:
    out: list[tuple[str, RawHit]] = []
    started = time.monotonic()
    for asset in corpus.assets:
        text = read_asset(corpus, asset)
        if hasattr(analyzer, "analyze_file"):
            hits = asyncio.run(analyzer.analyze_file(  # type: ignore[attr-defined]
                str(Path(corpus.dir) / "assets" / asset.file), asset.url, corpus.dir))
        else:
            hits = analyzer.analyze_text(text, asset.url)
        for hit in hits:
            out.append((asset.url, hit))
    return out, int((time.monotonic() - started) * 1000)


def run_benchmark(corpus: Corpus, analyzer_specs: list[str], labels: list[Label],
                  config: dict[str, Any] | None = None) -> dict[str, Any]:
    """在冻结语料上跑多个分析器并打分。labels 为空时退化为"各分析器命中对比"。"""
    # 未显式传入时, 从设置里读取已登记的外部分析器
    config = config if config is not None else (db.get_setting("analyzers") or {})
    tp_labels = [label for label in labels if label.label == "tp"]
    fp_labels = [label for label in labels if label.label == "fp"]
    results: list[AnalyzerMetrics] = []
    hit_map: dict[str, list[tuple[str, RawHit]]] = {}
    tp_owners: dict[int, set[str]] = {index: set() for index in range(len(tp_labels))}

    for spec in analyzer_specs:
        analyzer = build_analyzer(spec, config)
        metrics = AnalyzerMetrics(name=spec, available=analyzer.available())
        if not metrics.available:
            metrics.error = "工具不可用（未安装或命令缺失）"
            results.append(metrics)
            continue
        try:
            hits, runtime = _analyzer_hits(analyzer, corpus)
        except Exception as exc:  # noqa: BLE001
            metrics.error = f"{type(exc).__name__}: {exc}"[:200]
            results.append(metrics)
            continue
        if not hits and getattr(analyzer, "last_error", ""):
            metrics.error = f"执行异常: {analyzer.last_error}"
        metrics.runtime_ms = runtime
        metrics.hits = len(hits)
        hit_map[spec] = hits

        for _url, hit in hits:
            matched = False
            for index, label in enumerate(tp_labels):
                if label.matches(_url, hit.raw):
                    metrics.tp += 1
                    tp_owners[index].add(spec)
                    matched = True
                    break
            if matched:
                continue
            if any(label.matches(_url, hit.raw) for label in fp_labels):
                metrics.fp += 1
                continue
            metrics.unlabeled += 1
        results.append(metrics)

    available_specs = [m.name for m in results if m.available and not m.error]
    for metrics in results:
        if not metrics.available or metrics.error:
            continue
        metrics.missed = sum(1 for owners in tp_owners.values() if metrics.name not in owners)
        metrics.unique = sum(1 for owners in tp_owners.values() if owners == {metrics.name})
        for _url, hit in hit_map.get(metrics.name, []):
            metrics.by_severity[hit.severity] = metrics.by_severity.get(hit.severity, 0) + 1

    # 谁独有、谁共有: 这是"对比"最直接的证据
    fingerprint_sets = {
        spec: {hashlib.sha256(hit.raw.encode("utf-8", "ignore")).hexdigest()
               for _url, hit in hits if hit.raw}
        for spec, hits in hit_map.items()
    }
    exclusive: dict[str, int] = {}
    for spec, digests in fingerprint_sets.items():
        others: set[str] = set()
        for other_spec, other in fingerprint_sets.items():
            if other_spec != spec:
                others |= other
        exclusive[spec] = len(digests - others)

    missed_detail = []
    for index, label in enumerate(tp_labels):
        owners = sorted(tp_owners[index])
        if len(owners) < max(1, len(available_specs)):
            missed_detail.append({
                "asset": label.asset,
                "note": label.note,
                "severity": label.severity,
                "found_by": owners,
                "missed_by": [spec for spec in available_specs if spec not in owners],
            })

    return {
        "corpus": {"name": corpus.name, "assets": len(corpus.assets),
                   "target_url": corpus.target_url, "created_at": corpus.created_at},
        "created_at": db.utcnow(),
        "labels": {"total": len(labels), "tp": len(tp_labels), "fp": len(fp_labels),
                   "unlabeled": sum(1 for label in labels if label.label == "unlabeled")},
        "analyzers": [{**asdict(m), "precision": m.precision, "recall": m.recall, "f1": m.f1,
                       "exclusive_hits": exclusive.get(m.name, 0)} for m in results],
        "missed": missed_detail,
        "notes": [] if tp_labels else ["没有 tp 标注, 无法计算召回率; 先用 export-labels 生成模板再标注"],
    }


def render_markdown(report: dict[str, Any]) -> str:
    lines = [
        f"# 分析器对比报告 · 语料 `{report['corpus']['name']}`",
        "",
        f"- 资产数: {report['corpus']['assets']}  |  入口: {report['corpus']['target_url']}",
        f"- 标注: tp {report['labels']['tp']} · fp {report['labels']['fp']} · 未标注 {report['labels']['unlabeled']}",
        f"- 生成时间: {report['created_at']}",
        "",
        "| 分析器 | 命中 | TP | FP | 未标注 | 漏报 | 精确率 | 召回率 | F1 | 独有命中 | 耗时 |",
        "| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |",
    ]
    for item in report["analyzers"]:
        def fmt(value: Any) -> str:
            return "—" if value is None else (f"{value:.3f}" if isinstance(value, float) else str(value))
        lines.append(
            f"| {item['name']} | {item['hits']} | {item['tp']} | {item['fp']} | {item['unlabeled']} | "
            f"{item['missed']} | {fmt(item['precision'])} | {fmt(item['recall'])} | {fmt(item['f1'])} | "
            f"{item['exclusive_hits']} | {item['runtime_ms']} ms |"
        )
    if report["missed"]:
        lines += ["", "## 漏报明细（标注为真凭证但未全部检出）", ""]
        for item in report["missed"]:
            lines.append(f"- `{item['asset']}` {item['note']} — 检出: {', '.join(item['found_by']) or '无'}"
                         f" / 漏掉: {', '.join(item['missed_by'])}")
    failed = [item for item in report["analyzers"] if item.get("error")]
    if failed:
        lines += ["", "## 未能参与对比的分析器", ""]
        for item in failed:
            lines.append(f"- `{item['name']}` — {item['error']}")
    if report.get("notes"):
        lines += ["", "> " + "；".join(report["notes"])]
    return "\n".join(lines) + "\n"


_ = (ScanConfig, SEVERITY_ORDER, kind_from_url)
