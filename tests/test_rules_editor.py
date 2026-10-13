"""规则编辑器与规则质量统计的测试。"""
from __future__ import annotations

import os
import sys
import tempfile
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

os.environ["JSLW_DATA_DIR"] = tempfile.mkdtemp(prefix="jslw-editor-")

from fastapi import HTTPException  # noqa: E402

from app import db  # noqa: E402
from app.api import (  # noqa: E402
    RuleDraftIn,
    RuleTestIn,
    delete_custom_rule,
    list_rules,
    rules_quality,
    save_custom_rule,
    test_rule as preview_rule,
)
from app.rules import Rule, explain_rule  # noqa: E402

db.init_db()


@pytest.fixture(autouse=True)
def clean():
    db.execute("DELETE FROM settings WHERE key='custom_rules'")
    db.execute("DELETE FROM findings")
    db.execute("DELETE FROM targets")
    yield


ACME = r"acme_[A-Za-z0-9]{16,24}"


def test_explain_rule_says_why_a_match_was_filtered() -> None:
    rule = Rule(id="custom:acme", name="Acme", severity="high", category="imported", pattern=ACME)
    # 命中值全是数字序列, 会被占位符过滤挡掉
    report = explain_rule(rule, 'var k = "acme_0123456789012345";')
    assert report["raw_count"] == 1 and report["count"] == 0
    assert report["rejected"].get("占位符过滤") == 1

    ok = explain_rule(rule, 'var k = "acme_a8F3kQ2zLp91XbS7";')
    assert ok["count"] == 1 and ok["rejected"] == {}
    assert ok["matches"][0].masked.startswith("acme") and ok["matches"][0].raw == "acme_a8F3kQ2zLp91XbS7"

    none = explain_rule(rule, "nothing to see")
    assert none["raw_count"] == 0 and none["count"] == 0


def test_test_rule_endpoint_gives_actionable_feedback() -> None:
    body = preview_rule(RuleTestIn(name="Acme Token", pattern=ACME,
                                   sample='var k = "acme_0123456789012345";'))
    assert body["raw_count"] == 1 and body["count"] == 0
    assert "占位符过滤" in body["hint"]

    good = preview_rule(RuleTestIn(name="Acme Token", pattern=ACME,
                                   sample='var k = "acme_a8F3kQ2zLp91XbS7";'))
    assert good["count"] == 1 and good["matches"][0]["match"] == "acme_a8F3kQ2zLp91XbS7"

    with pytest.raises(HTTPException) as broken:
        preview_rule(RuleTestIn(pattern="([", sample="x"))
    assert broken.value.status_code == 400
    with pytest.raises(HTTPException):
        preview_rule(RuleTestIn(pattern=ACME, sample="   "))


def test_save_custom_rule_and_guard_builtin_ids() -> None:
    saved = save_custom_rule(RuleDraftIn(**{
        "name": "Acme Token", "pattern": ACME, "severity": "high", "description": "内部令牌",
    }))
    assert saved["saved"] == "custom:acme-token"
    assert any(item["id"] == "custom:acme-token" for item in list_rules()["items"])

    # 改等级后保存: 同 id 覆盖, 不会新增一条
    save_custom_rule(RuleDraftIn(id="custom:acme-token", name="Acme Token",
                                 pattern=ACME + "x", severity="medium"))
    custom = [item for item in list_rules()["items"] if not item["builtin"]]
    assert len(custom) == 1 and custom[0]["severity"] == "medium"

    # 带前缀的 id 原样保留: 编辑导入的 gitleaks 规则不会新建出一条
    kept = save_custom_rule(RuleDraftIn(id="gl:acme-internal", name="Acme 导入", pattern=ACME))
    assert kept["saved"] == "gl:acme-internal"
    assert delete_custom_rule("custom:acme-token")["deleted"] == "custom:acme-token"
    assert delete_custom_rule("gl:acme-internal")["deleted"] == "gl:acme-internal"


def test_rules_quality_ranks_by_false_positive_rate() -> None:
    tid = int(db.execute(
        "INSERT INTO targets(name, base_url, created_at) VALUES(?,?,?)",
        ("质量站", "http://q.test/", db.utcnow()),
    ).lastrowid or 0)
    verdicts = [("noisy-rule", "fake"), ("noisy-rule", "fake"), ("noisy-rule", "fake"),
                ("good-rule", "real"), ("good-rule", "real"), ("good-rule", "public"),
                ("few-rule", "fake")]
    for index, (rule_id, verdict) in enumerate(verdicts):
        db.execute(
            "INSERT INTO findings(target_id, rule_id, rule_name, severity, category, fingerprint, "
            "match_masked, match_sha256, asset_url, first_seen_at, last_seen_at, status, ai_verdict) "
            "VALUES(?,?,?,?,?,?,?,?,?,?,?,'new',?)",
            (tid, rule_id, rule_id, "high", "test", f"fp-{index}", "mask", f"sha-{index}",
             "http://q.test/a.js", db.utcnow(), db.utcnow(), verdict),
        )
    body = rules_quality(min_samples=3)
    ranked = {item["rule_id"]: item for item in body["ranked"]}
    assert ranked["noisy-rule"]["fp_rate"] == 1.0 and ranked["noisy-rule"]["advice"].startswith("建议关闭")
    assert ranked["good-rule"]["fp_rate"] == 0.0 and ranked["good-rule"]["advice"] == "信号良好"
    assert "few-rule" not in ranked, "样本不足的规则不进排行"
    assert body["summary"]["fp_rate"] == round(4 / 7, 3)
    db.execute("DELETE FROM targets WHERE id=?", (tid,))
