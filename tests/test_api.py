"""接口层测试 (不触发真实扫描)。"""
from __future__ import annotations

import os
import sys
import tempfile
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

TMP = tempfile.mkdtemp(prefix="jslw-test-")
os.environ["JSLW_DATA_DIR"] = TMP

from fastapi.testclient import TestClient  # noqa: E402

from app.api import app  # noqa: E402


@pytest.fixture(scope="module")
def client():
    with TestClient(app) as test_client:
        yield test_client


def test_overview_shape(client) -> None:
    res = client.get("/api/overview")
    assert res.status_code == 200
    body = res.json()
    assert set(["kpis", "severity", "timeline", "targets"]).issubset(body)
    assert len(body["timeline"]) == 30


def test_target_crud(client) -> None:
    created = client.post("/api/targets", json={"name": "示例站", "base_url": "example.com"})
    assert created.status_code == 201
    target = created.json()
    assert target["base_url"] == "https://example.com"  # 自动补协议

    listed = client.get("/api/targets").json()
    assert listed["total"] >= 1
    assert any(t["id"] == target["id"] for t in listed["items"])

    patched = client.patch(f"/api/targets/{target['id']}", json={"interval_minutes": 30, "enabled": False})
    assert patched.json()["interval_minutes"] == 30
    assert patched.json()["enabled"] == 0

    assert client.delete(f"/api/targets/{target['id']}").status_code == 200
    assert not any(t["id"] == target["id"] for t in client.get("/api/targets").json()["items"])


def test_targets_pagination_and_search(client) -> None:
    for index in range(3):
        client.post("/api/targets", json={"name": f"分页站{index}", "base_url": f"http://page{index}.test"})
    page = client.get("/api/targets", params={"limit": 2, "offset": 0}).json()
    assert len(page["items"]) == 2 and page["total"] >= 3
    found = client.get("/api/targets", params={"q": "分页站1"}).json()
    assert found["total"] >= 1 and all("分页站1" in t["name"] for t in found["items"])
    # 总数必须是筛选后的数量, 而不是全表行数
    assert found["total"] == len(found["items"])


def test_target_requires_valid_url(client) -> None:
    assert client.post("/api/targets", json={"base_url": "   "}).status_code == 400


def _make_targets(client, count: int) -> list[int]:
    ids = []
    for index in range(count):
        res = client.post("/api/targets", json={"name": f"批量站{index}", "base_url": f"http://bulk{index}.test"})
        ids.append(res.json()["id"])
    return ids


def test_targets_bulk_enable_disable_interval(client) -> None:
    ids = _make_targets(client, 2)
    res = client.post("/api/targets/bulk", json={"ids": ids, "action": "disable"})
    assert res.status_code == 200
    assert res.json() == {"action": "disable", "affected": 2, "requested": 2, "all_matching": False}
    listed = {t["id"]: t for t in client.get("/api/targets", params={"limit": 200}).json()["items"]}
    assert all(listed[i]["enabled"] == 0 for i in ids)
    # 再暂停一次: 状态没变化, affected 应为 0（前端据此提示"本来就是暂停状态"）
    assert client.post("/api/targets/bulk", json={"ids": ids, "action": "disable"}).json()["affected"] == 0

    assert client.post("/api/targets/bulk", json={"ids": ids, "action": "enable"}).json()["affected"] == 2
    assert client.post("/api/targets/bulk", json={"ids": ids, "action": "enable"}).json()["affected"] == 0
    listed = {t["id"]: t for t in client.get("/api/targets", params={"limit": 200}).json()["items"]}
    assert all(listed[i]["enabled"] == 1 for i in ids)

    body = {"ids": ids, "action": "interval", "interval_minutes": 720}
    assert client.post("/api/targets/bulk", json=body).json()["affected"] == 2
    listed = {t["id"]: t for t in client.get("/api/targets", params={"limit": 200}).json()["items"]}
    assert all(listed[i]["interval_minutes"] == 720 for i in ids)


def test_targets_bulk_scan_and_delete(client) -> None:
    ids = _make_targets(client, 2)
    res = client.post("/api/targets/bulk", json={"ids": ids, "action": "scan"})
    assert res.status_code == 200
    body = res.json()
    assert body["action"] == "scan" and body["requested"] == 2
    assert 0 <= body["affected"] <= 2  # 已在队列中的站点不会重复入队

    deleted = client.post("/api/targets/bulk", json={"ids": ids, "action": "delete"})
    assert deleted.json()["affected"] == 2
    remaining = {t["id"] for t in client.get("/api/targets", params={"limit": 200}).json()["items"]}
    assert not set(ids) & remaining


def test_targets_bulk_validation(client) -> None:
    ids = _make_targets(client, 1)
    assert client.post("/api/targets/bulk", json={"ids": [], "action": "delete"}).status_code == 400
    assert client.post("/api/targets/bulk", json={"ids": ids, "action": "purge"}).status_code == 400
    assert client.post("/api/targets/bulk", json={"ids": ids, "action": "interval"}).status_code == 400
    client.post("/api/targets/bulk", json={"ids": ids, "action": "delete"})


def test_targets_bulk_all_matching(client) -> None:
    # 用独立前缀, 避免命中其它用例遗留的站点
    ids = []
    for index in range(2):
        created = client.post("/api/targets", json={"name": f"全匹配站{index}",
                                                    "base_url": f"http://allmatch{index}.test"})
        ids.append(created.json()["id"])
    mismatched = client.post("/api/targets", json={"name": "无关站", "base_url": "http://other.test"}).json()

    res = client.post("/api/targets/bulk", json={"action": "disable", "all_matching": True, "q": "全匹配站"})
    body = res.json()
    assert body["all_matching"] is True and body["affected"] == 2
    listed = {t["id"]: t for t in client.get("/api/targets", params={"limit": 200}).json()["items"]}
    assert all(listed[i]["enabled"] == 0 for i in ids)
    assert listed[mismatched["id"]]["enabled"] == 1

    removed = client.post("/api/targets/bulk", json={"action": "delete", "all_matching": True, "q": "全匹配站"})
    assert removed.json()["affected"] == 2
    client.delete(f"/api/targets/{mismatched['id']}")


def _make_finding(client, fingerprint: str, target_id: int, match_sha: str = "") -> int:
    from app import db

    fid = db.execute(
        "INSERT INTO findings(target_id, rule_id, rule_name, severity, category, fingerprint, "
        "match_masked, match_sha256, asset_url, first_seen_at, last_seen_at, status) "
        "VALUES(?,?,?,?,?,?,?,?,?,?,?,'new')",
        (target_id, "test-rule", "测试规则", "high", "test", fingerprint,
         "abcd...wxyz(len=32)", match_sha or ("sha-" + fingerprint), "http://del.test/app.js",
         db.utcnow(), db.utcnow()),
    ).lastrowid
    return int(fid or 0)


def test_finding_delete_and_bulk_delete(client) -> None:
    from app import db

    target = client.post("/api/targets", json={"name": "发现删除站", "base_url": "http://del.test"}).json()
    fid = _make_finding(client, "fp-del-1", target["id"])
    assert client.get(f"/api/findings/{fid}").status_code == 200
    assert client.delete(f"/api/findings/{fid}").json()["deleted"] == fid
    assert client.get(f"/api/findings/{fid}").status_code == 404
    assert client.delete(f"/api/findings/{fid}").status_code == 404  # 重复删除要有明确 404

    ids = [_make_finding(client, f"fp-del-{i}", target["id"]) for i in range(2, 5)]
    res = client.post("/api/findings/bulk", json={"ids": ids[:2], "action": "delete"})
    assert res.status_code == 200 and res.json()["deleted"] == 2
    left = {row["id"] for row in db.query("SELECT id FROM findings WHERE target_id=?", (target["id"],))}
    assert left == {ids[2]}

    # 批量改状态: 只统计状态真的变了的行
    assert client.post("/api/findings/bulk", json={"ids": [ids[2]], "status": "open"}).json()["updated"] == 1
    assert client.post("/api/findings/bulk", json={"ids": [ids[2]], "status": "open"}).json()["updated"] == 0
    assert client.post("/api/findings/bulk", json={"ids": [ids[2]], "status": "bogus"}).status_code == 400

    client.delete(f"/api/targets/{target['id']}")  # 级联清掉剩下的发现


def test_findings_reuse_across_sites(client) -> None:
    """同一命中值出现在多个站点时, 列表要标出复用站点数, 详情要能互相跳。"""
    from app import db

    first = client.post("/api/targets", json={"name": "复用甲站", "base_url": "http://reuse-a.test"}).json()
    second = client.post("/api/targets", json={"name": "复用乙站", "base_url": "http://reuse-b.test"}).json()
    shared = "same-value-sha"
    fid_a = _make_finding(client, "fp-reuse-a", first["id"], match_sha=shared)
    fid_b = _make_finding(client, "fp-reuse-b", second["id"], match_sha=shared)

    listed = client.get("/api/findings", params={"q": "abcd", "limit": 100}).json()["items"]
    row = next(item for item in listed if item["id"] == fid_a)
    assert row["reuse_count"] == 2 and row["reuse_sites"] == 2

    detail = client.get(f"/api/findings/{fid_a}").json()
    assert [item["id"] for item in detail["reuse"]] == [fid_b]
    assert detail["reuse"][0]["target_name"] == "复用乙站"

    client.delete(f"/api/targets/{first['id']}")
    client.delete(f"/api/targets/{second['id']}")


def test_asset_history_and_changes_api(client) -> None:
    from app import asset_history, db

    target = client.post("/api/targets", json={"name": "变更站", "base_url": "http://diff.test"}).json()
    aid = int(db.execute(
        "INSERT INTO assets(target_id, url, sha256, size, first_seen_at, last_seen_at) "
        "VALUES(?,?,?,?,?,?)",
        (target["id"], "http://diff.test/app.js", "sha-a", 10, db.utcnow(), db.utcnow()),
    ).lastrowid or 0)
    asset_history.record_version(target["id"], aid, "http://diff.test/app.js", 'var a = "one";', "sha-a")
    asset_history.record_version(target["id"], aid, "http://diff.test/app.js",
                                 'var a = "one"; var b = "https://new.test/api";', "sha-b")

    hist = client.get(f"/api/assets/{aid}/history").json()
    assert len(hist["versions"]) == 2
    assert hist["versions"][0]["added"] == ["https://new.test/api"]
    assert hist["asset"]["target_name"] == "变更站"

    feed = client.get("/api/changes", params={"target_id": target["id"]}).json()
    assert feed["total"] == 1 and feed["items"][0]["target_name"] == "变更站"

    assets = client.get("/api/assets", params={"target_id": target["id"]}).json()["items"]
    assert assets[0]["versions"] == 2
    assert client.get("/api/assets", params={"target": target["id"]}).json()["total"] == 1  # 旧参数名兼容

    assert client.get("/api/assets/999999/history").status_code == 404
    client.delete(f"/api/targets/{target['id']}")


def test_targets_bulk_import(client) -> None:
    text = "\n".join([
        "# 注释行会被忽略",
        "imp-a.test",
        "https://imp-a.test/",      # 同一主机的另一种写法, 应去重
        "  ",                       # 空行忽略
        "example.com 备注",          # 一行多个字段, 无效
        "http://",                  # 没有主机名, 无效
    ])
    res = client.post("/api/targets/import", json={"text": text, "interval_minutes": 600, "max_depth": 1})
    assert res.status_code == 200
    body = res.json()
    assert body["created"] == 1
    assert body["invalid"] == 2
    assert {d["line"] for d in body["invalid_detail"]} == {"example.com 备注", "http://"}
    # 批内重复必须报出来, 否则用户只看到"少了 N 条"却不知道为什么
    assert body["duplicate"] == 1
    assert body["duplicate_detail"][0]["host"] == "imp-a.test"
    assert body["duplicate_detail"][0]["same_as"] == "imp-a.test"
    assert body["ignored"] == 2      # 注释行 + 空行
    created = body["items"][0]
    assert created["base_url"] == "https://imp-a.test"  # 自动补协议

    # 再导入一次: 同主机应被跳过而不是重复创建
    again = client.post("/api/targets/import", json={"text": "imp-a.test"}).json()
    assert again["created"] == 0 and again["skipped"] == 1
    assert client.delete(f"/api/targets/{created['id']}").status_code == 200


def test_rules_endpoint_and_toggle(client) -> None:
    body = client.get("/api/rules").json()
    assert body["items"] and body["revision"] >= 1
    rule_id = next(r["id"] for r in body["items"] if r["builtin"])
    res = client.patch(f"/api/rules/{rule_id}", json={"enabled": False, "severity": "low"})
    assert res.json()["revision"] > body["revision"]
    client.patch(f"/api/rules/{rule_id}", json={"enabled": True, "severity": "high"})


def test_import_gitleaks_rules(client) -> None:
    toml = """
[[rules]]
id = "acme-token"
description = "Acme 内部令牌"
regex = '''acme_[a-z0-9]{32}'''
keywords = ["acme_"]
severity = "critical"
"""
    res = client.post("/api/rules/import", json={"toml": toml})
    assert res.status_code == 200
    assert res.json()["imported"] == 1
    items = client.get("/api/rules").json()["items"]
    assert any(r["id"] == "gl:acme-token" for r in items)
    assert client.delete("/api/rules/custom/gl:acme-token").status_code == 200


def test_import_rejects_bad_toml(client) -> None:
    assert client.post("/api/rules/import", json={"toml": "not toml [[["}).status_code == 400


def test_allowlist_crud(client) -> None:
    assert client.post("/api/allowlist", json={"pattern": "^pub-key-"}).status_code == 201
    assert client.post("/api/allowlist", json={"pattern": "("}).status_code == 400
    items = client.get("/api/allowlist").json()
    entry = next(i for i in items if i["pattern"] == "^pub-key-")
    assert client.delete(f"/api/allowlist/{entry['id']}").status_code == 200


def test_settings_roundtrip(client) -> None:
    before = client.get("/api/settings").json()
    res = client.put("/api/settings", json={
        "scan": {"per_host_delay_ms": 123},
        "alert": {"enabled": False, "min_severity": "high", "app_secret": "***"},
    })
    assert res.status_code == 200
    assert res.json()["scan"]["per_host_delay_ms"] == 123
    assert res.json()["alert"]["min_severity"] == "high"
    assert before["server"]["version"]


def test_findings_filters_and_export(client) -> None:
    res = client.get("/api/findings", params={"status": "new,open", "severity": "critical,high", "limit": 10})
    assert res.status_code == 200
    assert "items" in res.json()
    csv_res = client.get("/api/findings/export.csv")
    assert csv_res.status_code == 200
    assert "text/csv" in csv_res.headers["content-type"]
    assert "站点" in csv_res.content.decode("utf-8-sig")


def test_static_console_served(client) -> None:
    index = client.get("/")
    assert index.status_code == 200
    assert "JSLeakWatch" in index.text
    assert client.get("/static/app.js").status_code == 200


def test_alerts_events_and_scans(client) -> None:
    assert client.get("/api/events").status_code == 200
    assert client.get("/api/scans").status_code == 200
    assert client.get("/api/assets").status_code == 200


def test_scan_endpoint_rejects_unknown_target(client) -> None:
    assert client.post("/api/targets/999999/scan").status_code == 404
