"""检测引擎单元测试。"""
from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from app.rules import (  # noqa: E402
    RULES,
    Detector,
    collapse_string_concat,
    looks_like_code_path,
    looks_placeholder,
    mask_value,
    shannon_entropy,
)

ALL_IDS = {rule.id for rule in RULES}


def scan(text: str) -> list:
    return Detector().scan_text(text, target_id=1, asset_url="https://x/app.js", store_raw=True)


def rule_ids(text: str) -> set[str]:
    return {d.rule_id for d in scan(text)}


def test_rules_compile() -> None:
    detector = Detector()
    default_off = {rule.id for rule in RULES if not rule.default_enabled}
    assert len(detector.compiled) == len(RULES) - len(default_off)
    # 默认关闭的规则可以被显式启用
    assert len(Detector(enabled=default_off).compiled) == len(RULES)


@pytest.mark.parametrize("rule_id, text", [
    ("aws-access-key-id", 'var k = "AKIAJKQ7XH3MZ6BND4PA";'),
    ("aliyun-access-key-id", 'var k = "LTAI5tBkQ9mZx2VnPr7YqW3F";'),
    ("tencent-cloud-secret-id", 'var k = "AKIDz8krbsJ5yKBZQpn74WFkmLPx3gnPhESA";'),
    ("github-token", 'var t = "ghp_R2fXb9KqLm3Tn7Zv4Wd1As6Yc0Eu5Bh8Ij9P";'),
    ("stripe-secret-key", 'var k = "sk_live_51QxT8mKqLp3RnZ7vW2dJfA9bHc4EyU6";'),
    ("stripe-webhook-secret", 'var k = "whsec_5a9d3f1b7c2e8046bd9f3a1c7e5b2084";'),
    ("google-api-key", 'var k = "AIzaSyB3kQ9mZx2VnPr7YqW3FbC8dE1fG4hI6jK";'),
    ("feishu-webhook", 'var u = "https://open.feishu.cn/open-apis/bot/v2/hook/9c1d2e5f-7a8b-4c3d-9e0f-1a2b3c4d5e6f";'),
    ("wecom-webhook", 'var u = "https://qyapi.weixin.qq.com/cgi-bin/webhook/send?key=693a91f6-7aaa-4b1c-9b3f-1e0f0a2b3c4d";'),
    ("private-key-block", 'var k = "-----BEGIN RSA PRIVATE KEY-----";'),
    ("database-url", 'var d = "mysql://root:P8ssw0rd@10.20.30.40:3306/app";'),
    ("jwt-token", 'var j = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U";'),
    # 实测补充: 某站点公开 JS 里的复合型长期令牌
    ("composite-permanent-token",
     'datatalkToken:"f71755aefeb8f5de0bfe5f043dab1ae7_PERMANENT_imur_data_xingxpan_286910_LOGIN"'),
])
def test_rule_matches(rule_id: str, text: str) -> None:
    assert rule_id in ALL_IDS
    assert rule_id in rule_ids(text)


@pytest.mark.parametrize("text", [
    'var k = "YOUR_API_KEY";',
    'var k = "your-api-key-here";',
    'var k = "changeme";',
    'var k = "xxxxxxxxxxxxxxxxxxxx";',
    'const k = process.env.API_KEY;',
    'const k = `${import.meta.env.VITE_KEY}`;',
    'var k = "abcdefghijklmnopqrstuvwxyz";',
])
def test_placeholders_are_ignored(text: str) -> None:
    assert scan(text) == []


def test_static_asset_paths_are_not_secrets() -> None:
    assert looks_like_code_path("static/js/vendor.4f2a1b.js")
    assert not looks_like_code_path("https://open.feishu.cn/open-apis/bot/v2/hook/abcdef123456")


def test_overlap_suppression_keeps_specific_rule() -> None:
    found = rule_ids('var k = "AKIAJKQ7XH3MZ6BND4PA";')
    assert "aws-access-key-id" in found
    assert "high-entropy-string" not in found


def test_database_url_wins_over_basic_auth() -> None:
    found = rule_ids('var d = "redis://cache_admin:P8ssw0rd2024@10.12.4.7:6379/0";')
    assert "database-url" in found
    assert "basic-auth-url" not in found


def test_string_concat_collapse() -> None:
    source = 'var u = "https://oapi.dingtalk.com/robot/send?access_token=" +\n  "' + "a1b2c3d4" * 8 + '";'
    assert 'dingtalk-webhook' in rule_ids(collapse_string_concat(source))
    assert 'dingtalk-webhook' not in rule_ids(source)


def test_allowlist_filters_matches() -> None:
    detector = Detector(allowlist=[r"^AIzaSy"])
    found = {d.rule_id for d in detector.scan_text('var k = "AIzaSyB3kQ9mZx2VnPr7YqW3FbC8dE1fG4hI6jK";', 1)}
    assert "google-api-key" not in found


def test_disable_and_severity_override() -> None:
    detector = Detector(disabled=["aws-access-key-id"])
    assert "aws-access-key-id" not in detector.rule_ids
    overridden = Detector(severity_override={"google-api-key": "critical"})
    found = overridden.scan_text('var k = "AIzaSyB3kQ9mZx2VnPr7YqW3FbC8dE1fG4hI6jK";', 1)
    assert any(d.rule_id == "google-api-key" and d.severity == "critical" for d in found)


def test_fingerprint_is_stable_and_target_scoped() -> None:
    text = 'var k = "AKIAJKQ7XH3MZ6BND4PA";'
    first = Detector().scan_text(text, 1)[0]
    again = Detector().scan_text(text, 1)[0]
    other = Detector().scan_text(text, 2)[0]
    assert first.fingerprint == again.fingerprint
    assert first.fingerprint != other.fingerprint


def test_pii_rules_disabled_by_default() -> None:
    assert "cn-mobile-number" not in rule_ids('var p = "13812345678";')


def test_masking_hides_middle() -> None:
    masked = mask_value("AKIAJKQ7XH3MZ6BND4PA")
    assert masked.startswith("AKIA")
    assert "JKQ7XH3MZ6B" not in masked


def test_entropy_helper() -> None:
    assert shannon_entropy("aaaaaaaa") < shannon_entropy("aB3kQ9mZ")
    assert looks_placeholder("null")


def test_base64_fragment_detection() -> None:
    """命中值夹在连续 Base64 中间 = 从密文里切出来的碎片, 不是独立的值。"""
    from app.rules import looks_like_base64_fragment

    raw = "00ivkbaFBztxUmeHZluXhgQ25PGNZwlzmrBryzsAfB"
    assert looks_like_base64_fragment("xjqV7" + raw + "DhrNt1", raw)
    assert not looks_like_base64_fragment(f'var okta="{raw}";', raw)
    assert not looks_like_base64_fragment("TOKEN=" + raw, raw)
    assert not looks_like_base64_fragment("x=" + raw + ";", raw)
    assert not looks_like_base64_fragment(raw, raw), "整个文本就是命中值, 不该算碎片"


def test_detector_skips_hits_inside_base64_blob() -> None:
    from app.rules import Detector

    detector = Detector()
    key = "AKIA3XQ7ZP2LMN4KQ7DA"
    embedded = "x" * 40 + key + "y" * 40
    quoted = f'const aws = "{key}";'
    assert not any(f.rule_id == "aws-access-key-id"
                   for f in detector.scan_text(embedded, target_id=0)), "密文碎片不该报"
    assert any(f.rule_id == "aws-access-key-id"
               for f in detector.scan_text(quoted, target_id=0)), "正常写法要照报"
