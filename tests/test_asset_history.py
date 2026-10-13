"""资产内容版本与签名的行为测试。"""
from __future__ import annotations

import hashlib
import os
import sys
import tempfile
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

os.environ["JSLW_DATA_DIR"] = tempfile.mkdtemp(prefix="jslw-history-")

from app import asset_history as history  # noqa: E402
from app import db  # noqa: E402

db.init_db()


@pytest.fixture(autouse=True)
def clean():
    db.execute("DELETE FROM asset_versions")
    db.execute("DELETE FROM assets")
    db.execute("DELETE FROM targets")
    yield


def make_asset(url: str = "http://t/app.js") -> tuple[int, int]:
    tid = int(db.execute(
        "INSERT INTO targets(name, base_url, created_at) VALUES(?,?,?)",
        ("站", "http://t/", db.utcnow()),
    ).lastrowid or 0)
    aid = int(db.execute(
        "INSERT INTO assets(target_id, url, sha256, size, first_seen_at, last_seen_at) "
        "VALUES(?,?,?,?,?,?)",
        (tid, url, "sha", 10, db.utcnow(), db.utcnow()),
    ).lastrowid or 0)
    return tid, aid


def test_signature_masks_secrets_but_keeps_urls() -> None:
    secret = "AKIAIOSFODNN7EXAMPLE9"
    text = f'const a = "{secret}"; const b = "https://api.test/v1/x"; const c = "production";'
    sig = history.signature(text, secret_hashes=[hashlib.sha256(secret.encode()).hexdigest()])
    assert "https://api.test/v1/x" in sig, "普通地址要保留, 否则看不出接口变化"
    assert "production" in sig
    assert not any(secret in item for item in sig), "命中规则的密钥不能进签名"
    assert any(item.startswith("AKIA") and "..." in item for item in sig)


def test_signature_masks_high_entropy_strings() -> None:
    random_like = "aG9tZXNlY3JldGtleTEyMzQ1Njc4OTBhYmNkZWY"
    sig = history.signature(f'var k = "{random_like}";', secret_hashes=[])
    assert not any(random_like in item for item in sig), "高熵串即使没命中规则也要掩码"


def test_version_diff_and_dedup() -> None:
    tid, aid = make_asset()
    first = history.record_version(tid, aid, "http://t/app.js", 'var a = "one";', "sha1")
    assert first["changed"] and first["first"]
    assert first["added"] == [] and first["removed"] == [], "基线版只存签名, 不算新增"
    assert db.query_one("SELECT strings FROM asset_versions WHERE asset_id=?", (aid,))["strings"] == '["one"]'

    same = history.record_version(tid, aid, "http://t/app.js", 'var a = "one";', "sha1")
    assert same["changed"] is False, "内容指纹没变就不该再存一版"
    assert db.query_one("SELECT COUNT(*) c FROM asset_versions")["c"] == 1

    second = history.record_version(tid, aid, "http://t/app.js",
                                    'var a = "one"; var b = "https://new.test/x";', "sha2")
    assert second["changed"] and not second["first"]
    assert second["added"] == ["https://new.test/x"]
    assert second["removed"] == []

    third = history.record_version(tid, aid, "http://t/app.js", 'var b = "https://new.test/x";', "sha3")
    assert third["removed"] == ["one"], "消失的字符串要能看出来"


def test_history_is_capped_per_asset() -> None:
    tid, aid = make_asset()
    for index in range(history.MAX_KEEP + 5):
        history.record_version(tid, aid, "http://t/app.js", f'var v = "v{index}";', f"sha{index}")
    rows = history.history(aid, limit=50)
    assert len(rows) == history.MAX_KEEP, "每资产只保留最近 N 版"
    assert rows[0]["sha256"] == f"sha{history.MAX_KEEP + 4}", "保留的应是最近几版"


def test_recent_changes_feed() -> None:
    tid, aid = make_asset()
    history.record_version(tid, aid, "http://t/app.js", 'var a = "one";', "s1")
    history.record_version(tid, aid, "http://t/app.js", 'var a = "two";', "s2")
    feed = history.recent_changes(limit=10, only_diff=True)
    assert len(feed) == 1, "基线版没有差异, 不进变更流"
    assert feed[0]["target_name"] == "站"
    assert feed[0]["added"] == ["two"] and feed[0]["removed"] == ["one"]
