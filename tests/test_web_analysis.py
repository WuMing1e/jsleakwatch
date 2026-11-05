"""Web 前端确定性预分析：编码还原、可疑片段与跨文件引用。"""
from __future__ import annotations

import base64
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from app import web_analysis  # noqa: E402
from app.rules import Detector  # noqa: E402


RAW = "AKIA3XQ7ZP2LMN4KQ7DA"


def test_decodes_string_from_char_code_and_apply_array() -> None:
    direct = "String.fromCharCode(" + ",".join(str(ord(ch)) for ch in RAW) + ")"
    applied = (
        "String.fromCharCode.apply(null, ["
        + ",".join(str(ord(ch)) for ch in RAW)
        + "])"
    )
    direct_views = web_analysis.decode_views(direct)
    applied_views = web_analysis.decode_views(applied)
    assert direct_views[0].value == RAW
    assert "fromCharCode.apply" in applied_views[0].kind
    assert applied_views[0].value == RAW


def test_decodes_hex_and_unicode_escapes() -> None:
    hex_source = 'var a = "' + "".join(f"\\x{ord(ch):02x}" for ch in RAW) + '";'
    unicode_source = 'var b = "' + "".join(f"\\u{ord(ch):04x}" for ch in RAW) + '";'
    hex_views = web_analysis.decode_views(hex_source)
    unicode_views = web_analysis.decode_views(unicode_source)
    assert hex_views[0].value == RAW and "Hex" in hex_views[0].kind
    assert unicode_views[0].value == RAW and "Unicode" in unicode_views[0].kind


def test_decodes_base64_only_when_result_is_sensitive_text() -> None:
    encoded = base64.b64encode(RAW.encode()).decode()
    source = f'const key = atob("{encoded}");'
    views = web_analysis.decode_views(source)
    assert any(view.value == RAW and "Base64" in view.kind for view in views)

    ordinary = base64.b64encode(b"the quick brown fox jumps over").decode()
    assert not web_analysis.decode_views(f'const text = "{ordinary}";')


def test_decoded_corpus_is_scannable_and_ignores_unrelated_number_tables() -> None:
    source = (
        'const k = String.fromCharCode('
        + ",".join(str(ord(ch)) for ch in RAW)
        + "); const chart = [1,2,3,4,5,6,7,8,9,10];"
    )
    corpus = web_analysis.decoded_corpus(source)
    hits = Detector().scan_text(corpus, target_id=1, asset_url="https://x.test/app.js")
    assert any(hit.rule_id == "aws-access-key-id" for hit in hits)
    assert "JSLW_AUTO_DECODED" in corpus
    assert corpus.count("/* JSLW_AUTO_DECODED:") == 1


def test_semantic_excerpt_keeps_middle_sensitive_logic() -> None:
    encoder = "String.fromCharCode(" + ",".join(str(ord(ch)) for ch in RAW) + ")"
    source = ("var noise = 1;\n" * 1000) + encoder + ("\nvar tail = 2;\n" * 1000)
    excerpt = web_analysis.semantic_excerpt(source, max_chars=2200)
    assert len(excerpt) <= 2600
    assert "String.fromCharCode" in excerpt
    assert "片段 @" in excerpt


def test_related_assets_require_same_origin_and_real_reference() -> None:
    primary = "https://app.test/static/js/app.js"
    text = 'import cfg from "./config"; const req = require("./request.js");'
    available = {
        "https://app.test/static/js/config.js": "export const clientSecret='x';",
        "https://app.test/static/js/request.js": "Authorization: Bearer; jdbc:test",
        "https://app.test/static/js/unrelated.js": "const aws='AKIA3XQ7ZP2LMN4KQ7DA';",
        "https://cdn.other.test/static/js/config.js": "clientSecret='external';",
    }
    related = web_analysis.select_related_assets(primary, text, available, max_files=2)
    urls = [item.url for item in related]
    assert "https://app.test/static/js/config.js" in urls
    assert "https://app.test/static/js/request.js" in urls
    assert all("other.test" not in url and "unrelated" not in url for url in urls)
    context = web_analysis.related_context(primary, text, available, max_files=2)
    assert "<related_file" in context and "config.js" in context
