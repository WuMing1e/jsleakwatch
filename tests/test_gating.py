"""高误报来源 AI 预筛门控的测试。"""
from __future__ import annotations

import importlib
import os
import sys
import tempfile
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

os.environ["JSLW_DATA_DIR"] = tempfile.mkdtemp(prefix="jslw-gate-")

from app import db, gating  # noqa: E402

importlib.reload(db)
db.init_db()


@pytest.fixture(autouse=True)
def clean():
    db.execute("DELETE FROM findings")
    db.execute("DELETE FROM targets")
    db.execute("DELETE FROM settings WHERE key='ai_gate'")
    gating.invalidate()
    yield


_seq = 0


def add_finding(target_id: int, rule_id: str, verdict: str = "") -> int:
    global _seq
    _seq += 1
    return int(db.execute(
        "INSERT INTO findings(target_id, rule_id, rule_name, severity, category, fingerprint, "
        "match_masked, match_sha256, asset_url, first_seen_at, last_seen_at, status, origin, "
        "found_by, ai_verdict) VALUES(?,?,?,?,?,?,?,?,?,?,?,'new','rule','x',?)",
        (target_id, rule_id, rule_id, "medium", "test", f"fp-{rule_id}-{_seq}",
         "mask", f"sha-{rule_id}-{_seq}", "http://t/a.js",
         db.utcnow(), db.utcnow(), verdict),
    ).lastrowid or 0)


def make_target() -> int:
    return int(db.execute(
        "INSERT INTO targets(name, base_url, created_at) VALUES(?,?,?)",
        ("t", "http://t/", db.utcnow()),
    ).lastrowid or 0)


def test_source_stats_and_fp_rate() -> None:
    tid = make_target()
    for verdict in ("fake", "fake", "fake", "real"):
        add_finding(tid, "noisy:rule", verdict)
    add_finding(tid, "clean-rule", "real")
    stats = {item["rule_id"]: item for item in gating.source_stats()}
    assert stats["noisy:rule"]["judged"] == 4 and stats["noisy:rule"]["fake"] == 3
    assert stats["noisy:rule"]["fp_rate"] == 0.75
    assert stats["clean-rule"]["fp_rate"] == 0.0


def test_gate_engages_above_threshold() -> None:
    tid = make_target()
    for _ in range(3):
        add_finding(tid, "noisy:rule", "fake")     # 100% 误报, 3 个样本
    for _ in range(3):
        add_finding(tid, "ok-rule", "real")
    gating.invalidate()
    gated = gating.gated_sources()
    assert "noisy:rule" in gated and "ok-rule" not in gated
    assert gating.is_gated("noisy:rule") and not gating.is_gated("ok-rule")


def test_min_samples_prevents_over_reaction() -> None:
    """实测里 aliyun-access-key-secret 只有 1 个样本且恰好判误报(100%),
    但它显然不该被当成噪声来源闸掉。"""
    tid = make_target()
    add_finding(tid, "aliyun-access-key-secret", "fake")     # 1 个样本, 100% 误报
    gating.invalidate()
    assert gating.is_gated("aliyun-access-key-secret") is False


def test_unjudged_findings_do_not_count_toward_rate() -> None:
    """未判定的样本不能进分母, 否则新来源的误报率会被稀释或误判。"""
    tid = make_target()
    for _ in range(3):
        add_finding(tid, "noisy:rule", "fake")
    for _ in range(10):
        add_finding(tid, "noisy:rule")            # 未判定
    gating.invalidate()
    stats = {item["rule_id"]: item for item in gating.source_stats()}["noisy:rule"]
    assert stats["judged"] == 3 and stats["total"] == 13
    assert stats["fp_rate"] == 1.0                # 而不是 3/13
    assert gating.is_gated("noisy:rule")


def test_exclusion_hides_unjudged_and_fake_but_keeps_passed() -> None:
    tid = make_target()
    for _ in range(3):
        add_finding(tid, "noisy:rule", "fake")
    pending = add_finding(tid, "noisy:rule")            # 待判定 -> 隐藏
    fake = add_finding(tid, "noisy:rule", "fake")       # 判为误报 -> 隐藏
    passed = add_finding(tid, "noisy:rule", "real")     # AI 确认 -> 展示
    uncertain = add_finding(tid, "noisy:rule", "uncertain")  # 未能确认 -> 隐藏
    gating.invalidate()

    sql, params = gating.exclusion("f")
    assert sql
    rows = db.query(f"SELECT id FROM findings f WHERE {sql}", params)
    visible = {row["id"] for row in rows}
    assert passed in visible
    assert pending not in visible and fake not in visible and uncertain not in visible
    # 隐藏的是: 建立误报率的 3 条 + 待判定 + 判为误报 + 未能确认
    assert gating.hidden_count()["hidden"] == 6
    assert gating.hidden_count()["sources"] == 1
    assert gating.hidden_count()["ai_fake"] == 4      # 其中 4 条是 AI 判定的误报


def test_hide_ai_fake_can_be_turned_off() -> None:
    """关掉"隐藏 AI 判定误报"后, 判定为误报的发现应重新可见（门控仍按来源生效）。"""
    tid = make_target()
    for _ in range(3):
        add_finding(tid, "noisy:rule", "fake")
    clean_fake = add_finding(tid, "rare-rule", "fake")   # 来源样本不足, 未被门控
    gating.invalidate()
    sql, params = gating.exclusion("f")
    assert clean_fake not in {r["id"] for r in db.query(f"SELECT id FROM findings f WHERE {sql}", params)}

    gating.save_gate_config({"hide_ai_fake": False})
    sql2, params2 = gating.exclusion("f")
    assert clean_fake in {r["id"] for r in db.query(f"SELECT id FROM findings f WHERE {sql2}", params2)}


def test_gate_can_be_disabled_and_threshold_adjusted() -> None:
    tid = make_target()
    for _ in range(3):
        add_finding(tid, "noisy:rule", "fake")
    gating.invalidate()
    assert gating.is_gated("noisy:rule")

    gating.save_gate_config({"enabled": False})
    assert gating.is_gated("noisy:rule") is False

    gating.save_gate_config({"enabled": True, "fp_threshold": 0.9, "min_samples": 10})
    assert gating.is_gated("noisy:rule") is False      # 阈值/样本数都提高了

    gating.save_gate_config({"fp_threshold": 0.5, "min_samples": 2})
    assert gating.is_gated("noisy:rule") is True


def test_config_persists_and_clamps_nothing_unexpected() -> None:
    saved = gating.save_gate_config({"fp_threshold": 0.75, "min_samples": 5})
    assert saved["fp_threshold"] == 0.75 and saved["min_samples"] == 5
    assert gating.gate_config()["fp_threshold"] == 0.75
