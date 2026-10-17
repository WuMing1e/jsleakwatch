"""飞书告警推送的行为测试（不产生真实网络请求）。"""
from __future__ import annotations

import asyncio
import json
import os
import sys
import tempfile
from pathlib import Path

import httpx
import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

os.environ["JSLW_DATA_DIR"] = tempfile.mkdtemp(prefix="jslw-notify-")

from app import db, notify  # noqa: E402
from app.config import AlertConfig  # noqa: E402

db.init_db()


@pytest.fixture(autouse=True)
def clean():
    db.execute("DELETE FROM findings")
    db.execute("DELETE FROM targets")
    db.execute("DELETE FROM events")
    yield


def alert_cfg(**over) -> AlertConfig:
    base = dict(enabled=True, channel="webhook", webhook_url="https://hook.test/x",
                min_severity="medium", digest_threshold=5, max_alerts_per_run=20)
    base.update(over)
    return AlertConfig(**base)


def add_finding(severity: str = "high", fingerprint: str = "fp-1", verdict: str = "",
                confidence: float = 0.0) -> int:
    tid = int(db.execute(
        "INSERT INTO targets(name, base_url, created_at) VALUES(?,?,?)",
        ("告警站", "http://a.test/", db.utcnow()),
    ).lastrowid or 0)
    return int(db.execute(
        "INSERT INTO findings(target_id, rule_id, rule_name, severity, category, fingerprint, "
        "match_masked, match_sha256, asset_url, first_seen_at, last_seen_at, status, "
        "ai_verdict, ai_confidence) "
        "VALUES(?,?,?,?,?,?,?,?,?,?,?,'new',?,?)",
        (tid, "r-1", "测试规则", severity, "test", fingerprint, "mask", "sha",
         "http://a.test/app.js", db.utcnow(), db.utcnow(), verdict, confidence),
    ).lastrowid or 0)


class FakeClient:
    """替掉 httpx.AsyncClient: 返回预置响应。"""

    response: httpx.Response = httpx.Response(200, json={"code": 0, "msg": "success"})
    posts: list = []

    def __init__(self, *args, **kwargs) -> None:
        pass

    async def __aenter__(self):
        return self

    async def __aexit__(self, *exc) -> bool:
        return False

    async def post(self, url, json=None, **kwargs):
        FakeClient.posts.append({"url": url, "json": json})
        return FakeClient.response


def run(coro):
    return asyncio.run(coro)


def test_send_card_treats_error_codes_as_failure(monkeypatch) -> None:
    monkeypatch.setattr(notify.httpx, "AsyncClient", FakeClient)
    card = {"header": {}}

    FakeClient.response = httpx.Response(200, json={"code": 9499, "msg": "too many request"})
    ok, message = run(notify.FeishuNotifier(alert_cfg()).send_card(card))
    assert not ok and "9499" in message

    # 有的网关只给 StatusCode, 以前只看 code 会误判成功
    FakeClient.response = httpx.Response(200, json={"StatusCode": 19021, "StatusMessage": "sign match fail"})
    ok, message = run(notify.FeishuNotifier(alert_cfg()).send_card(card))
    assert not ok and "19021" in message

    # HTTP 层错误 + 非 JSON 响应体
    FakeClient.response = httpx.Response(502, text="<html>bad gateway</html>")
    ok, message = run(notify.FeishuNotifier(alert_cfg()).send_card(card))
    assert not ok and "502" in message

    FakeClient.response = httpx.Response(200, json={"StatusCode": 0, "StatusMessage": "success"})
    ok, _ = run(notify.FeishuNotifier(alert_cfg()).send_card(card))
    assert ok


def _item(fid: int, fingerprint: str, severity: str = "high", rule_id: str = "r-1") -> dict:
    return {"id": fid, "target_id": 1, "severity": severity, "rule_id": rule_id,
            "rule_name": "测试规则", "masked": "mask",
            "asset_url": "http://a.test/app.js", "fingerprint": fingerprint}


def test_failed_push_is_not_marked_notified() -> None:
    fid = add_finding()
    item = _item(fid, "fp-1")

    failing = notify.FeishuNotifier(alert_cfg())

    async def always_fail(card):
        return False, "HTTP 500"

    failing.send_card = always_fail  # type: ignore[assignment]
    summary = run(failing.notify_findings([item]))
    assert summary["sent"] == 0 and summary["failed"] == 1
    assert db.query_one("SELECT notified_at FROM findings WHERE id=?", (fid,))["notified_at"] is None

    ok_client = notify.FeishuNotifier(alert_cfg())

    async def always_ok(card):
        return True, "已发送"

    ok_client.send_card = always_ok  # type: ignore[assignment]
    summary = run(ok_client.notify_findings([item]))
    assert summary["sent"] == 1
    assert db.query_one("SELECT notified_at FROM findings WHERE id=?", (fid,))["notified_at"]


def test_low_severity_and_disabled_are_logged() -> None:
    n = notify.FeishuNotifier(alert_cfg())
    summary = run(n.notify_findings([_item(1, "fp-low", severity="low")]))
    assert summary["sent"] == 0 and summary["skipped"] == 1
    msg = db.query_one("SELECT message FROM events WHERE kind='alert' ORDER BY id DESC LIMIT 1")["message"]
    assert "低于" in msg and "未推送" in msg

    off = notify.FeishuNotifier(alert_cfg(enabled=False))
    summary = run(off.notify_findings([_item(2, "fp-critical", severity="critical")]))
    assert summary["sent"] == 0
    msg = db.query_one("SELECT message FROM events WHERE kind='alert' ORDER BY id DESC LIMIT 1")["message"]
    assert "告警未启用" in msg


def test_ai_false_positives_are_not_pushed() -> None:
    """AI 研判在推送之前跑完, 判定为误报的就不该发出去。"""
    fake = add_finding(fingerprint="fp-fake", verdict="fake", confidence=0.93)
    real = add_finding(fingerprint="fp-real", verdict="real", confidence=0.88)
    untriaged = add_finding(fingerprint="fp-none")
    items = [_item(fake, "fp-fake"), _item(real, "fp-real"), _item(untriaged, "fp-none")]

    n = notify.FeishuNotifier(alert_cfg())
    cards: list = []

    async def capture(card):
        cards.append(card)
        return True, "已发送"

    n.send_card = capture  # type: ignore[assignment]
    summary = run(n.notify_findings(items))
    assert summary["sent"] == 2, "误报那条不发, 剩下 2 条逐条发"
    assert summary["skipped_fake"] == 1
    body = json.dumps(cards, ensure_ascii=False)
    assert "fp-fake" not in body
    # 每张卡片都有 AI 复核字段: 有结论的写结论, 没结论的写"未复核", 两者照样发送
    assert body.count("AI 复核") == 2
    assert "真凭证 88%" in body
    assert "未复核" in body
    # 误报那条不该被标记成已推送, 未复核的照常标记
    assert db.query_one("SELECT notified_at FROM findings WHERE id=?", (fake,))["notified_at"] is None
    assert db.query_one("SELECT notified_at FROM findings WHERE id=?", (real,))["notified_at"]


def test_public_keys_are_not_pushed() -> None:
    """AI 判为"公开密钥"的别推: 高德/百度地图 key、飞书 App ID 本来就该写在前端。"""
    public = add_finding(fingerprint="fp-pub", verdict="public", confidence=0.9)
    real = add_finding(fingerprint="fp-ok", verdict="real", confidence=0.9)
    n = notify.FeishuNotifier(alert_cfg())
    cards: list = []

    async def capture(card):
        cards.append(card)
        return True, "已发送"

    n.send_card = capture  # type: ignore[assignment]
    summary = run(n.notify_findings([_item(public, "fp-pub"), _item(real, "fp-ok")]))
    assert summary["sent"] == 1 and summary["skipped_public"] == 1
    body = json.dumps(cards, ensure_ascii=False)
    assert "fp-pub" not in body
    assert db.query_one("SELECT notified_at FROM findings WHERE id=?", (public,))["notified_at"] is None


def test_high_false_positive_source_is_not_pushed() -> None:
    """误报率超过门控阈值的来源不推(除非 AI 明确判成真凭证), 与发现列表同一口径。"""
    from app import gating

    db.set_setting("ai_gate", {"enabled": True, "fp_threshold": 0.6, "min_samples": 3})
    tid = int(db.execute(
        "INSERT INTO targets(name, base_url, created_at) VALUES(?,?,?)",
        ("噪声站", "http://b.test/", db.utcnow()),
    ).lastrowid or 0)

    def add(rule: str, fingerprint: str, verdict: str) -> int:
        return int(db.execute(
            "INSERT INTO findings(target_id, rule_id, rule_name, severity, category, fingerprint, "
            "match_masked, match_sha256, asset_url, first_seen_at, last_seen_at, status, "
            "ai_verdict, ai_confidence) VALUES(?,?,?,?,?,?,?,?,?,?,?,'new',?,?)",
            (tid, rule, rule, "high", "test", fingerprint, "mask", fingerprint, "http://b.test/a.js",
             db.utcnow(), db.utcnow(), verdict, 0.5),
        ).lastrowid or 0)

    # 造出"历史误报率很高"的来源: 4 条 fake + 1 条 real
    for i in range(4):
        add("noisy-rule", f"noisy-fake-{i}", "fake")
    add("noisy-rule", "noisy-real", "real")
    gating.invalidate()
    assert gating.is_gated("noisy-rule") is True, "样本够了就该被闸住"

    unreviewed = add("noisy-rule", "noisy-none", "")
    confirmed = add("noisy-rule", "noisy-confirmed", "real")
    n = notify.FeishuNotifier(alert_cfg())
    cards: list = []

    async def capture(card):
        cards.append(card)
        return True, "已发送"

    n.send_card = capture  # type: ignore[assignment]
    summary = run(n.notify_findings([
        _item(unreviewed, "noisy-none", rule_id="noisy-rule"),
        _item(confirmed, "noisy-confirmed", rule_id="noisy-rule"),
    ]))
    assert summary["sent"] == 1, "AI 明确判成真凭证的仍要推"
    assert summary["skipped_gated"] == 1
    # 用"是否被标记已推送"来判断, 比在卡片文本里找指纹可靠
    assert db.query_one("SELECT notified_at FROM findings WHERE id=?", (unreviewed,))["notified_at"] is None
    assert db.query_one("SELECT notified_at FROM findings WHERE id=?", (confirmed,))["notified_at"]


def test_all_fake_round_is_logged_not_sent() -> None:
    fake = add_finding(fingerprint="fp-only-fake", verdict="fake", confidence=0.9)
    n = notify.FeishuNotifier(alert_cfg())
    called: list = []

    async def capture(card):  # pragma: no cover - 不该被调用
        called.append(card)
        return True, "已发送"

    n.send_card = capture  # type: ignore[assignment]
    summary = run(n.notify_findings([_item(fake, "fp-only-fake")]))
    assert summary["sent"] == 0 and not called
    assert summary["skipped_fake"] == 1
    msg = db.query_one("SELECT message FROM events WHERE kind='alert' ORDER BY id DESC LIMIT 1")["message"]
    assert "未推送" in msg and "AI 判定为误报" in msg


def test_digest_batches_many_findings() -> None:
    items = []
    for index in range(6):
        fid = add_finding(fingerprint=f"fp-{index}")
        items.append(_item(fid, f"fp-{index}"))
    n = notify.FeishuNotifier(alert_cfg(digest_threshold=5))
    sent_cards: list = []

    async def capture(card):
        sent_cards.append(card)
        return True, "已发送"

    n.send_card = capture  # type: ignore[assignment]
    summary = run(n.notify_findings(items))
    assert summary["sent"] == 1, "6 条超过汇总阈值时应合并成 1 张卡片"
    assert "6 条新发现" in sent_cards[0]["header"]["title"]["content"]
    assert db.query_one("SELECT COUNT(*) c FROM findings WHERE notified_at IS NULL")["c"] == 0
