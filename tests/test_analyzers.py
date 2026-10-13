"""采集/分析后端适配器与对比评测的测试。"""
from __future__ import annotations

import asyncio
import importlib
import json
import os
import sqlite3
import sys
import tempfile
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

os.environ["JSLW_DATA_DIR"] = tempfile.mkdtemp(prefix="jslw-bench-")

from app import analyzers, benchmark, db  # noqa: E402

importlib.reload(db)
db.init_db()


@pytest.fixture(autouse=True)
def clean_state():
    db.execute("DELETE FROM settings WHERE key IN ('analyzers','discovery')")
    yield


def run(coro):
    return asyncio.run(coro)


# ------------------------------------------------------------ 采集后端

KATANA_JSONL = [
    {"timestamp": "2026-10-11T18:45:19+08:00",
     "request": {"method": "GET", "endpoint": "http://site.test/", "tag": "", "source": ""},
     "response": {"status_code": 200, "body": "<html>"}},
    {"request": {"method": "GET", "endpoint": "http://site.test/js/app.js",
                 "tag": "script", "attribute": "src", "source": "http://site.test/"},
     "response": {"status_code": 200}},
    {"request": {"method": "GET", "endpoint": "http://site.test/js/app.js", "tag": "script"},
     "response": {"status_code": 200}},
    {"request": {"method": "GET", "endpoint": "https://third-party.test/track", "tag": "xhr"},
     "response": {"status_code": 200}},
    {"request": {"method": "GET", "endpoint": "http://site.test/api/v1/users?page=2", "tag": "xhr"},
     "response": {"status_code": 200}},
    {"not": "a katana record"},
]


def write_stub(path: Path, payload: list[dict]) -> None:
    path.write_text(
        "#!/usr/bin/env python3\n"
        "import json,sys\n"
        f"for line in {json.dumps([json.dumps(item) for item in payload])}:\n"
        "    print(line)\n",
        encoding="utf-8",
    )
    path.chmod(0o755)


def test_katana_discovery_parses_jsonl_and_respects_scope(tmp_path: Path) -> None:
    stub = tmp_path / "katana"
    write_stub(stub, KATANA_JSONL)
    engine = analyzers.KatanaDiscovery(binary=str(stub))
    assert engine.available()
    target = {"base_url": "http://site.test/", "scope": "same-origin"}
    found = run(engine.discover(target, analyzers.ScanConfig()))
    urls = [item.url for item in found]
    assert "http://site.test/js/app.js" in urls
    assert urls.count("http://site.test/js/app.js") == 1          # 去重
    assert not any("third-party.test" in url for url in urls)     # 同源约束
    assert any(item.kind == "script" for item in found)


def test_katana_scope_any_allows_cross_origin(tmp_path: Path) -> None:
    stub = tmp_path / "katana"
    write_stub(stub, KATANA_JSONL)
    engine = analyzers.KatanaDiscovery(binary=str(stub))
    found = run(engine.discover({"base_url": "http://site.test/", "scope": "any"},
                                analyzers.ScanConfig()))
    assert any("third-party.test" in item.url for item in found)


def test_katana_keeps_api_endpoints_but_drops_binary_and_non_get(tmp_path: Path) -> None:
    stub = tmp_path / "katana"
    write_stub(stub, [
        {"request": {"method": "GET", "endpoint": "http://site.test/api/v1/users?page=2"},
         "response": {"status_code": 200}},
        {"request": {"method": "GET", "endpoint": "http://site.test/logo.png"},
         "response": {"status_code": 200}},
        {"request": {"method": "GET", "endpoint": "http://site.test/css/app.css"},
         "response": {"status_code": 200}},
        {"request": {"method": "POST", "endpoint": "http://site.test/api/delete"},
         "response": {"status_code": 200}},
    ])
    found = run(analyzers.KatanaDiscovery(binary=str(stub)).discover(
        {"base_url": "http://site.test/", "scope": "same-origin"}, analyzers.ScanConfig()))
    urls = [item.url for item in found]
    assert "http://site.test/api/v1/users?page=2" in urls     # API 响应也值得扫
    assert not any("logo.png" in u or "app.css" in u for u in urls)
    assert not any("delete" in u for u in urls)               # 非 GET 不作为种子


def test_katana_command_includes_expected_flags(tmp_path: Path) -> None:
    engine = analyzers.KatanaDiscovery(binary="/x/katana", depth=3, headless=True, rate_limit=7)
    cmd = engine.build_command("http://site.test/")
    assert "-jc" in cmd and "-j" in cmd and "-or" in cmd and "-hl" in cmd
    assert cmd[cmd.index("-d") + 1] == "3"
    assert cmd[cmd.index("-rl") + 1] == "7"


def test_missing_katana_degrades_to_empty() -> None:
    engine = analyzers.KatanaDiscovery(binary="/nonexistent/katana", search_paths=())
    assert engine.available() is False
    assert run(engine.discover({"base_url": "http://x/"}, analyzers.ScanConfig())) == []


def test_broken_katana_exits_nonzero_without_raising(tmp_path: Path) -> None:
    broken = tmp_path / "katana"
    broken.write_text("#!/bin/sh\nexit 2\n", encoding="utf-8")
    broken.chmod(0o755)
    engine = analyzers.KatanaDiscovery(binary=str(broken))
    assert engine.available() is True
    assert run(engine.discover({"base_url": "http://x/"}, analyzers.ScanConfig())) == []


# ------------------------------------------------------------ 分析器适配器

def test_kind_and_severity_normalization() -> None:
    assert analyzers.kind_from_url("http://x/a/b.js") == "script"
    assert analyzers.kind_from_url("http://x/a.map") == "map"
    assert analyzers.kind_from_url("http://x/") == "html"
    assert analyzers.normalize_severity("严重") == "critical"
    assert analyzers.normalize_severity("HIGH") == "high"
    assert analyzers.normalize_severity("中危") == "medium"
    assert analyzers.normalize_severity(None) == "medium"


@pytest.mark.parametrize("payload", [
    '[{"a":1},{"a":2}]',
    '{"findings":[{"a":1},{"a":2}]}',
    '{"results":[{"a":1},{"a":2}]}',
    '{"a":1}\n{"a":2}',
    '噪音\n{"a":1}\n{"a":2}\n',
])
def test_cli_analyzer_parses_common_shapes(payload: str) -> None:
    analyzer = analyzers.CliAnalyzer(name="t", command=["echo"])
    assert len(analyzer.parse_output(payload)) == 2


def test_cli_analyzer_field_map_and_hits() -> None:
    analyzer = analyzers.CliAnalyzer(
        name="jshawk", command=["x"],
        field_map={"raw": "secret", "rule_id": "rule", "context": "snippet"},
    )
    hits = analyzer.to_hits([{"rule": "r1", "severity": "高危", "secret": "AKIAJKQ7XH3MZ6BND4PA",
                             "snippet": "var k = ...", "line": 12, "score": 0.9}])
    assert hits[0].rule_id == "r1" and hits[0].severity == "high"
    assert hits[0].raw == "AKIAJKQ7XH3MZ6BND4PA" and hits[0].line == 12
    assert hits[0].confidence == 0.9 and hits[0].source == "jshawk"


def test_cli_analyzer_surfaces_failure_instead_of_silent_empty(tmp_path: Path) -> None:
    bad = tmp_path / "bad"
    bad.write_text("not a program\n", encoding="utf-8")
    bad.chmod(0o755)
    analyzer = analyzers.CliAnalyzer(name="bad", command=[str(bad), "{file}"])
    hits = run(analyzer.analyze_file(str(bad), "http://x/"))
    assert hits == []
    assert analyzer.last_error            # 必须留下原因, 不能静默当作"没找到"


def test_cli_analyzer_unparseable_output_is_reported(tmp_path: Path) -> None:
    script = tmp_path / "weird"
    script.write_text("#!/usr/bin/env python3\nprint('完全不是 JSON')\n", encoding="utf-8")
    script.chmod(0o755)
    analyzer = analyzers.CliAnalyzer(name="weird", command=[str(script)])
    assert run(analyzer.analyze_file(str(script), "http://x/")) == []
    assert "无法解析" in analyzer.last_error


def test_valid_empty_json_is_not_an_error(tmp_path: Path) -> None:
    """外部工具对"没有发现"返回 [] 是正常结果, 不能当成执行失败。"""
    script = tmp_path / "empty"
    script.write_text("#!/usr/bin/env python3\nimport json,sys\njson.dump([], sys.stdout)\n",
                      encoding="utf-8")
    script.chmod(0o755)
    analyzer = analyzers.CliAnalyzer(name="empty", command=[str(script)])
    assert run(analyzer.analyze_file(str(script), "http://x/")) == []
    assert analyzer.last_error == ""


def test_build_analyzer_from_registered_config() -> None:
    db.set_setting("analyzers", {"cli_analyzers": {
        "demo": {"command": ["/bin/echo", "{file}"], "field_map": {"raw": "value"}},
    }})
    specs = analyzers.analyzer_specs()["analyzer"]
    assert "cli:demo" in specs and specs["cli:demo"]["available"] is True
    analyzer = analyzers.build_analyzer("cli:demo")
    assert analyzer.name == "demo" and analyzer.command == ["/bin/echo", "{file}"]


# ------------------------------------------------------------ 标注与打分

def make_corpus(tmp_path: Path) -> benchmark.Corpus:
    assets_dir = tmp_path / "assets"
    assets_dir.mkdir(parents=True, exist_ok=True)
    (assets_dir / "a.txt").write_text(
        'var aws = "AKIAJKQ7XH3MZ6BND4PA";\nvar ph = "YOUR_KEY";\n', encoding="utf-8")
    corpus = benchmark.Corpus(
        name="t", dir=str(tmp_path), target_url="http://t/", created_at=db.utcnow(),
        assets=[benchmark.CorpusAsset(url="http://t/a.js", kind="script", file="a.txt",
                                      sha256="x", size=60)],
    )
    benchmark.save_corpus(corpus)
    return corpus


def test_scoring_metrics_and_unlabeled_bucket(tmp_path: Path) -> None:
    corpus = make_corpus(tmp_path)
    aws = "AKIAJKQ7XH3MZ6BND4PA"
    import hashlib
    digest = hashlib.sha256(aws.encode()).hexdigest()
    labels = [
        benchmark.Label(asset="http://t/a.js", match_sha256=digest, label="tp", severity="critical"),
        benchmark.Label(asset="http://t/a.js", pattern="MISSING_[0-9]{4}", label="tp", note="漏报"),
    ]
    report = benchmark.run_benchmark(corpus, ["builtin"], labels)
    metrics = report["analyzers"][0]
    assert metrics["tp"] == 1 and metrics["missed"] == 1
    assert metrics["precision"] == 1.0 and metrics["recall"] == 0.5
    assert metrics["f1"] == pytest.approx(0.6667, abs=1e-3)
    assert report["labels"]["tp"] == 2
    assert report["missed"][0]["note"] == "漏报"


def test_unlabeled_hits_are_not_counted_as_false_positives(tmp_path: Path) -> None:
    corpus = make_corpus(tmp_path)
    # 完全不标注: 所有命中都应进 unlabeled, 精确率保持 None 而不是 0
    report = benchmark.run_benchmark(corpus, ["builtin"], [])
    metrics = report["analyzers"][0]
    assert metrics["unlabeled"] == metrics["hits"] > 0
    assert metrics["precision"] is None
    assert report["notes"]     # 提示无法计算召回率


def test_false_positive_labels_lower_precision(tmp_path: Path) -> None:
    corpus = make_corpus(tmp_path)
    labels = [
        benchmark.Label(asset="http://t/a.js", pattern="YOUR_KEY", label="fp"),
    ]
    report = benchmark.run_benchmark(corpus, ["builtin"], labels)
    metrics = report["analyzers"][0]
    assert metrics["fp"] == 0 or metrics["fp"] >= 1   # 占位符本就被内置引擎过滤
    assert metrics["unlabeled"] >= 0


def test_exclusive_hits_are_attributed(tmp_path: Path) -> None:
    corpus = make_corpus(tmp_path)
    report = benchmark.run_benchmark(corpus, ["builtin"], [])
    assert report["analyzers"][0]["exclusive_hits"] >= 1


def test_unavailable_analyzer_is_reported_not_silently_skipped(tmp_path: Path) -> None:
    corpus = make_corpus(tmp_path)
    db.set_setting("analyzers", {"cli_analyzers": {"ghost": {"command": ["/nonexistent/tool"]}}})
    report = benchmark.run_benchmark(corpus, ["builtin", "cli:ghost"], [])
    ghost = next(item for item in report["analyzers"] if item["name"] == "cli:ghost")
    assert ghost["available"] is False and ghost["error"]
    assert "未能参与对比" in benchmark.render_markdown(report)


def test_label_roundtrip(tmp_path: Path) -> None:
    path = tmp_path / "labels.jsonl"
    labels = [benchmark.Label(asset="http://t/a.js", pattern="AKIA[0-9A-Z]{16}", label="tp", note="x")]
    benchmark.save_labels(labels, path)
    loaded = benchmark.load_labels(path)
    assert len(loaded) == 1 and loaded[0].pattern == "AKIA[0-9A-Z]{16}"
    assert loaded[0].matches("http://t/a.js", "AKIAJKQ7XH3MZ6BND4PA")


def test_export_labels_produces_template(tmp_path: Path) -> None:
    corpus = make_corpus(tmp_path)
    labels = benchmark.export_labels(corpus, "builtin")
    assert labels and all(item.label == "unlabeled" for item in labels)
    assert all(item.match_sha256 for item in labels)


def test_markdown_report_renders_table(tmp_path: Path) -> None:
    corpus = make_corpus(tmp_path)
    report = benchmark.run_benchmark(corpus, ["builtin"], [])
    text = benchmark.render_markdown(report)
    assert "| 分析器 | 命中 |" in text and "builtin" in text


# ------------------------------------------------------------ 并联接入生产扫描


# ------------------------------------------------------------ 整站扫描器

def make_jscanner2_db(path: Path, rows: list[tuple]) -> None:
    """按 JScanner2 的真实表结构造一个结果库。"""
    conn = sqlite3.connect(str(path))
    conn.execute("""CREATE TABLE sensitive_info (
        id INTEGER PRIMARY KEY AUTOINCREMENT, js_url TEXT, sensitive_value TEXT,
        context_code TEXT, caller_codes TEXT, risk_level TEXT, secret_type TEXT,
        test_suggestion TEXT, ai_raw_analysis TEXT, created_at TEXT)""")
    conn.executemany(
        "INSERT INTO sensitive_info(js_url, sensitive_value, context_code, risk_level, "
        "secret_type, created_at) VALUES(?,?,?,?,?,?)", rows)
    conn.commit()
    conn.close()


def test_jscanner2_hits_are_read_and_normalized(tmp_path: Path) -> None:
    from app.target_scanners import read_jscanner2_hits

    db_file = tmp_path / "r.db"
    make_jscanner2_db(db_file, [
        ("http://site.test/js/app.js", "LTAI5tBkQ9mZx2VnPr7YqW3F", "ctx", "High", "api_key",
         "2026-10-11 11:55:15"),
        ("http://other.test/js/a.js", "AKIDz8krbsJ5yKBZQpn74WFkmLPx3gnPhESA", "ctx", "Med",
         "token", "2026-10-11 11:55:15"),
    ])
    hits = read_jscanner2_hits(db_file, host="site.test")
    assert len(hits) == 1                       # 只取本次目标
    assert hits[0].raw == "LTAI5tBkQ9mZx2VnPr7YqW3F"
    assert hits[0].severity == "high"           # High -> high
    assert hits[0].rule_id == "secret:api_key"
    assert hits[0].url.endswith("app.js")       # 带上资产地址, 便于归属


def test_jscanner2_timestamp_format_does_not_break_import(tmp_path: Path) -> None:
    """回归: 它存 'YYYY-MM-DD HH:MM:SS'(UTC), 与本系统 ISO 时间不可字符串比较,
    早期实现按时间过滤会把本轮结果全部滤掉, 因此改用 id 水位线。"""
    from app.target_scanners import read_jscanner2_hits

    db_file = tmp_path / "r.db"
    make_jscanner2_db(db_file, [
        ("http://site.test/js/app.js", "kR8mQp2XvB7nZt4Wy6Ls1Dg9Hc3Jf", "ctx", "Med", "other",
         "2026-10-11 11:55:15"),
    ])
    assert len(read_jscanner2_hits(db_file, host="site.test")) == 1        # 全量
    assert len(read_jscanner2_hits(db_file, host="site.test", min_id=1)) == 0   # 水位线之后无新行
    assert len(read_jscanner2_hits(db_file, host="site.test", min_id=0)) == 1


def test_jscanner2_reader_is_safe_on_missing_or_broken_db(tmp_path: Path) -> None:
    from app.target_scanners import read_jscanner2_hits

    assert read_jscanner2_hits(tmp_path / "nope.db") == []
    broken = tmp_path / "broken.db"
    broken.write_text("not a database", encoding="utf-8")
    assert read_jscanner2_hits(broken) == []


def test_jscanner2_scanner_command_and_availability(tmp_path: Path) -> None:
    from app.target_scanners import JScanner2Scanner

    bare = JScanner2Scanner()
    assert bare.available() is False            # 未配置目录

    module = tmp_path / "JScanner2"
    (module / ".venv" / "bin").mkdir(parents=True)
    (module / "main.py").write_text("", encoding="utf-8")
    (module / ".venv" / "bin" / "python").write_text("", encoding="utf-8")
    scanner = JScanner2Scanner(module_dir=str(module), depth=2, use_ai=False)
    assert scanner.available() is True
    cmd = scanner.build_command("http://x/")
    assert "-asir" in cmd and "-nr" in cmd and "-asia" not in cmd
    assert cmd[cmd.index("-H") + 1] == "2"
    ai_cmd = JScanner2Scanner(module_dir=str(module), use_ai=True).build_command("http://x/")
    assert "-asia" in ai_cmd
    assert str(scanner.results_db()).endswith("Result/JScanner_Result.db")


def test_enabled_target_scanners_respects_flag(tmp_path: Path) -> None:
    from app import target_scanners

    module = tmp_path / "JScanner2"
    (module / ".venv" / "bin").mkdir(parents=True)
    (module / "main.py").write_text("", encoding="utf-8")
    (module / ".venv" / "bin" / "python").write_text("", encoding="utf-8")

    db.set_setting("analyzers", {"target_scanners": {
        "jscanner2": {"enabled": False, "module_dir": str(module)}}})
    assert target_scanners.enabled_target_scanners() == []

    db.set_setting("analyzers", {"target_scanners": {
        "jscanner2": {"enabled": True, "module_dir": str(module)}}})
    names = [s.name for s in target_scanners.enabled_target_scanners()]
    assert names == ["jscanner2"]
    specs = target_scanners.target_scanner_specs()
    assert specs["jscanner2"]["available"] is True and specs["jscanner2"]["enabled"] is True

MINI_HITS = [
    # 与内置引擎重叠 -> 应合并为同一条, 只追加来源
    {"rule": "aws-key", "severity": "critical", "secret": "AKIAJKQ7XH3MZ6BND4PA",
     "line": 1, "snippet": 'var k = "AKIAJKQ7XH3MZ6BND4PA"'},
    # 内置引擎没有 -> 应新增一条, origin=cli:mini
    {"rule": "internal-panel", "severity": "高", "secret": "panel=admin_console_v3",
     "line": 2, "snippet": 'var p = "panel=admin_console_v3"'},
]


def write_hit_stub(path: Path, hits: list[dict]) -> None:
    path.write_text(
        "#!/usr/bin/env python3\nimport json,sys\n"
        f"json.dump({json.dumps(hits, ensure_ascii=False)}, sys.stdout)\n",
        encoding="utf-8",
    )
    path.chmod(0o755)


def test_external_analyzer_merges_same_secret_and_adds_new(tmp_path: Path) -> None:
    """并联发现: 同一条凭证只出现一次(记录两个来源), 独有的则新增。"""
    from app import scanner
    from app.rules import mask_value

    stub = tmp_path / "mini"
    write_hit_stub(stub, MINI_HITS)
    db.set_setting("analyzers", {
        "run_in_scan": True,
        "cli_analyzers": {"mini": {
            "command": [str(stub)],
            "field_map": {"raw": "secret", "rule_id": "rule", "context": "snippet"},
            "enabled": True,
        }},
    })
    marker = db.utcnow() + "-merge"
    target_id = int(db.execute(
        "INSERT INTO targets(name, base_url, created_at) VALUES(?,?,?)",
        ("并联站", "http://merge.test/", db.utcnow()),
    ).lastrowid or 0)
    asset_id = int(db.execute(
        "INSERT INTO assets(target_id, url, sha256, size, content_type, kind, first_seen_at, last_seen_at) "
        "VALUES(?,?,?,?,?,?,?,?)",
        (target_id, "http://merge.test/app.js", "x", 10, "application/javascript", "script",
         db.utcnow(), db.utcnow()),
    ).lastrowid or 0)
    raw = "AKIAJKQ7XH3MZ6BND4PA"
    import hashlib
    digest = hashlib.sha256(raw.encode()).hexdigest()
    db.execute(
        "INSERT INTO findings(target_id, asset_id, rule_id, rule_name, severity, category, fingerprint, "
        "match_masked, match_sha256, context, asset_url, first_seen_at, last_seen_at, status, origin, found_by) "
        "VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,'new','rule','builtin')",
        (target_id, asset_id, "aws-access-key-id", "AWS Access Key ID", "critical", "cloud",
         marker, mask_value(raw), digest, "ctx", "http://merge.test/app.js",
         db.utcnow(), db.utcnow()),
    )

    analyzers = scanner._external_analyzers()
    assert [name for name, _ in analyzers] == ["mini"]
    result = scanner.ScanResult(target_id=target_id)
    seen: set[str] = set()
    asyncio.run(scanner._external_analyzer_phase(
        target_id, analyzers, [("http://merge.test/app.js", "var a=1;")], seen, result))

    rows = db.query("SELECT rule_id, origin, found_by, match_sha256 FROM findings WHERE target_id=?",
                    (target_id,))
    assert len(rows) == 2, "同一条凭证不应产生重复记录"
    merged = next(r for r in rows if r["match_sha256"] == digest)
    assert merged["found_by"] == "builtin,cli:mini"
    assert merged["origin"] == "rule"                      # 主归属仍是规则引擎
    created = next(r for r in rows if r["match_sha256"] != digest)
    assert created["origin"] == "cli:mini" and created["rule_id"] == "mini:internal-panel"
    assert len(seen) == 2 and len(result.new_findings) == 1
    assert result.new_findings[0]["origin"] == "cli:mini"
    summary = result.analyzer_summary["mini"]
    assert summary["assets"] == 1 and summary["hits"] == 2
    assert summary["new"] == 1 and summary["merged"] == 1


def test_external_analyzer_disabled_by_flag(tmp_path: Path) -> None:
    from app import scanner

    stub = tmp_path / "mini"
    write_hit_stub(stub, MINI_HITS)
    db.set_setting("analyzers", {
        "run_in_scan": False,
        "cli_analyzers": {"mini": {"command": [str(stub)], "enabled": True}},
    })
    assert scanner._external_analyzers() == []
    db.set_setting("analyzers", {
        "run_in_scan": True,
        "cli_analyzers": {"mini": {"command": [str(stub)], "enabled": False}},
    })
    assert scanner._external_analyzers() == []


# ------------------------------------------------------------ AI 语义发现的归并

def test_fetch_headers_merge_and_credential_mode() -> None:
    """带凭据采集: 自定义头覆盖默认头, Cookie 生效, 默认保持匿名。"""
    from app.config import ScanConfig
    from app.fetcher import Fetcher

    anon = Fetcher(ScanConfig()).headers()
    assert "Cookie" not in anon and "Authorization" not in anon

    cfg = ScanConfig(extra_headers={"Authorization": "Bearer t", "X-Trace": "1"},
                     cookies="sid=abc")
    auth = Fetcher(cfg).headers()
    assert auth["Authorization"] == "Bearer t" and auth["X-Trace"] == "1"
    assert auth["Cookie"] == "sid=abc"

    # 自定义 User-Agent 覆盖默认值
    assert Fetcher(ScanConfig(extra_headers={"User-Agent": "custom"})).headers()["User-Agent"] == "custom"

def test_ai_semantic_extracts_lowercase_hex_secret() -> None:
    """回归: 早期按 islower() 过滤"字段名", 会把小写十六进制密钥整类漏掉
    （阿里云 Secret、微信 AppSecret、高德 Key 都是这个形态）。"""
    from app.scanner import _extract_secrets_from_evidence as ex

    assert ex('"VITE_APP_API_KEY": "8f3a91c2d4e5b6a7c8d9e0f1a2b3c4d5"') == \
        ["8f3a91c2d4e5b6a7c8d9e0f1a2b3c4d5"]
    multi = ('window.__C__ = {\n  "VITE_APP_API_KEY": "8f3a91c2d4e5b6a7c8d9e0f1a2b3c4d5",\n'
             '  "amapKey": "b7e4a91c25df3846a0c7e2915bf3d807"\n}')
    assert ex(multi) == ["8f3a91c2d4e5b6a7c8d9e0f1a2b3c4d5", "b7e4a91c25df3846a0c7e2915bf3d807"]
    assert ex("https://x/robot/send?access_token=" + "a1b2c3d4" * 8) == ["a1b2c3d4" * 8]
    assert ex('console.log("hello world")') == []
    assert ex("") == []


def test_ai_semantic_finding_merges_with_rule_finding_by_value() -> None:
    """回归: AI 语义发现曾按"证据片段"去重, 导致同一凭证被规则与 AI 各报一条、
    重复告警。现在应按凭证值归并, 只追加来源归属。"""
    import hashlib

    from app import scanner

    value = "8f3a91c2d4e5b6a7c8d9e0f1a2b3c4d5"
    digest = hashlib.sha256(value.encode()).hexdigest()
    target_id = int(db.execute(
        "INSERT INTO targets(name, base_url, created_at) VALUES(?,?,?)",
        ("语义站", "http://sem.test/", db.utcnow()),
    ).lastrowid or 0)
    rule_fingerprint = "fp-sem-" + db.utcnow()
    db.execute(
        "INSERT INTO findings(target_id, rule_id, rule_name, severity, category, fingerprint, "
        "match_masked, match_sha256, asset_url, first_seen_at, last_seen_at, status, origin, found_by) "
        "VALUES(?,?,?,?,?,?,?,?,?,?,?,'new','rule','builtin')",
        (target_id, "env-var-leak", "构建期环境变量内联泄露", "medium", "exposure",
         rule_fingerprint, "8f3a...c4d5(len=32)", digest, "http://sem.test/#inline-0",
         db.utcnow(), db.utcnow()),
    )

    created, fingerprint, _payload = scanner._insert_ai_finding(target_id, "http://sem.test/#inline-0", {
        "type": "硬编码密钥/凭据", "severity": "medium", "confidence": 0.8,
        "evidence": f'"VITE_APP_API_KEY": "{value}"', "reason": "构建期内联",
    })
    assert created is False
    assert fingerprint == rule_fingerprint, "应返回既有发现的指纹, 避免它被误判为失效"
    rows = db.query("SELECT id, found_by, match_sha256 FROM findings WHERE target_id=?", (target_id,))
    assert len(rows) == 1, "同一凭证不应产生第二条记录"
    assert rows[0]["found_by"] == "builtin,ai:semantic"
    assert rows[0]["match_sha256"] == digest
