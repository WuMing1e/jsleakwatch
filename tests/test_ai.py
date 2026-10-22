"""AI 层测试: 用 httpx MockTransport 模拟 OpenAI 兼容端点 (GLM / vLLM 风格)。"""
from __future__ import annotations

import asyncio
import importlib
import json
import os
import re
import sys
import tempfile
from pathlib import Path

import httpx
import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

os.environ["JSLW_DATA_DIR"] = tempfile.mkdtemp(prefix="jslw-ai-")

from app import ai, db  # noqa: E402

sys.path.insert(0, str(ROOT))


@pytest.fixture(scope="module", autouse=True)
def prepared():
    importlib.reload(db)
    db.init_db()
    yield


@pytest.fixture(autouse=True)
def clean_state(prepared):
    """每个用例都从零开始: 清空响应缓存与当日用量, 避免互相干扰。"""
    db.execute("DELETE FROM ai_cache")
    db.execute("DELETE FROM ai_usage")
    yield


def cfg(**overrides) -> ai.AIConfig:
    base = ai.AIConfig(enabled=True, api_key="sk-test", base_url="http://glm.corp/v1",
                       model="glm-5.2", max_calls_per_day=100)
    for key, value in overrides.items():
        setattr(base, key, value)
    return base


def chat_response(content: str, extra: dict | None = None) -> httpx.Response:
    body = {"choices": [{"message": {"role": "assistant", "content": content}, "finish_reason": "stop"}]}
    if extra:
        body.update(extra)
    return httpx.Response(200, json=body)


def make_transport(handler):
    """handler(request) -> httpx.Response"""

    def wrapped(request: httpx.Request) -> httpx.Response:
        return handler(request)

    return httpx.MockTransport(wrapped)


def run(coro):
    return asyncio.run(coro)


# ------------------------------------------------------------ base_url 兼容

@pytest.mark.parametrize("raw, expected", [
    ("http://glm.corp/v1", "http://glm.corp/v1"),
    ("http://glm.corp/v1/", "http://glm.corp/v1"),
    ("http://glm.corp/v1/chat/completions", "http://glm.corp/v1"),
    ("https://open.bigmodel.cn/api/paas/v4/", "https://open.bigmodel.cn/api/paas/v4"),
    ("http://glm.corp/v1/models", "http://glm.corp/v1"),
])
def test_normalize_base_url(raw: str, expected: str) -> None:
    assert ai.normalize_base_url(raw) == expected


def test_request_goes_to_chat_completions_with_bearer() -> None:
    seen = {}

    def handler(request: httpx.Request) -> httpx.Response:
        seen["url"] = str(request.url)
        seen["auth"] = request.headers.get("authorization")
        seen["body"] = json.loads(request.content)
        return chat_response('{"verdict":"real","confidence":0.9}')

    client = ai.AIClient(cfg(), transport=make_transport(handler))
    run(client.chat("sys", "user"))
    assert seen["url"] == "http://glm.corp/v1/chat/completions"
    assert seen["auth"] == "Bearer sk-test"
    assert seen["body"]["model"] == "glm-5.2"


def test_no_auth_header_when_key_absent() -> None:
    seen = {}

    def handler(request: httpx.Request) -> httpx.Response:
        seen["auth"] = request.headers.get("authorization")
        return chat_response('{"ok":true}')

    client = ai.AIClient(cfg(api_key="", base_url="http://vllm.corp:8000/v1"),
                         transport=make_transport(handler))
    run(client.chat("sys", "user"))
    assert seen["auth"] is None


def test_response_format_stripped_when_endpoint_rejects_it() -> None:
    calls = {"n": 0}

    def handler(request: httpx.Request) -> httpx.Response:
        calls["n"] += 1
        body = json.loads(request.content)
        if "response_format" in body:
            return httpx.Response(400, json={"error": {"message": "response_format is not supported"}})
        return chat_response('{"ok":true}')

    client = ai.AIClient(cfg(), transport=make_transport(handler))
    run(client.chat("sys", "user"))
    assert calls["n"] == 2


def test_max_tokens_fallback_to_max_completion_tokens() -> None:
    seen = {"n": 0, "used_new_name": False}

    def handler(request: httpx.Request) -> httpx.Response:
        seen["n"] += 1
        body = json.loads(request.content)
        if "max_tokens" in body:
            return httpx.Response(400, json={"error": {"message": "Unsupported parameter: max_tokens"}})
        seen["used_new_name"] = "max_completion_tokens" in body
        return chat_response('{"ok":true}')

    client = ai.AIClient(cfg(), transport=make_transport(handler))
    run(client.chat("sys", "user"))
    assert seen["used_new_name"] is True


def test_list_models() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        assert str(request.url) == "http://glm.corp/v1/models"
        return httpx.Response(200, json={"data": [{"id": "glm-5.2"}, {"id": "glm-4.6"},
                                                  {"id": "glm-5.2"}]})

    models = run(ai.AIClient(cfg(), transport=make_transport(handler)).list_models())
    assert models == ["glm-4.6", "glm-5.2"]


def test_anthropic_style_response() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        assert str(request.url) == "http://claude.corp/v1/messages"
        return httpx.Response(200, json={"content": [{"type": "text", "text": '{"ok":true}'}]})

    client = ai.AIClient(cfg(kind="anthropic", base_url="http://claude.corp"),
                         transport=make_transport(handler))
    assert run(client.chat("sys", "user")) == '{"ok":true}'


# ------------------------------------------------------------ JSON 解析

def test_extract_json_tolerates_code_fence_and_prose() -> None:
    text = '好的，结果如下：\n```json\n{"verdict":"fake","confidence":0.8,"reason":"占位符"}\n```\n以上。'
    data = ai.extract_json(text, "object")
    assert data["verdict"] == "fake"


def test_extract_json_handles_nested_and_escaped_braces() -> None:
    text = '{"a":{"b":1},"c":"}"}'
    assert ai.extract_json(text)["a"]["b"] == 1
    arr = '分析：\n[{"type":"硬编码口令","evidence":"admin:123456","confidence":0.9}]'
    assert ai.extract_json(arr, "array")[0]["type"] == "硬编码口令"


def test_normalize_triage_clamps_and_aliases() -> None:
    out = ai.normalize_triage({"verdict": "PUBLIC_BY_DESIGN", "confidence": 3.0, "reason": "x"})
    assert out["verdict"] == "public" and out["confidence"] == 1.0
    assert ai.normalize_triage({"verdict": "乱七八糟"})["verdict"] == "uncertain"
    assert ai.normalize_triage({"confidence": "abc"})["confidence"] == 0.0


def test_normalize_semantic_filters_short_evidence() -> None:
    items = ai.normalize_semantic([
        {"type": "a", "evidence": "short", "severity": "high"},
        {"type": "b", "evidence": "admin_password = 'Sup3rS3cret!'", "severity": "胡说", "confidence": 9},
        "not a dict",
    ])
    assert len(items) == 1
    assert items[0]["severity"] == "medium" and items[0]["confidence"] == 1.0


# ------------------------------------------------------------ 复核任务

def _finding_row() -> dict:
    return {
        "id": 1, "rule_id": "google-api-key", "rule_name": "Google API Key", "category": "cloud",
        "match_masked": "AIza...I6jK(len=39)", "entropy": 4.1,
        "asset_url": "http://x/app.js", "context": 'apiKey: "AIza...I6jK"',
    }


def test_triage_sends_masked_value_by_default() -> None:
    captured = {}

    def handler(request: httpx.Request) -> httpx.Response:
        captured["body"] = json.loads(request.content)
        return chat_response('{"verdict":"public","confidence":0.95,"reason":"Firebase Web Key"}')

    client = ai.AIClient(cfg(), transport=make_transport(handler))
    verdict = run(ai.triage_finding(client, _finding_row(), raw="AIzaSyB3kQ9mZx2VnPr7YqW3FbC8dE1fG4hI6jK"))
    assert verdict["verdict"] == "public"
    content = captured["body"]["messages"][-1]["content"]
    assert "AIzaSyB3kQ9mZx2VnPr7YqW3FbC8dE1fG4hI6jK" not in content   # 明文不出门
    assert "AIza...I6jK" in content
    assert "待分析数据" in content                                  # 提示注入防护说明


def test_triage_sends_raw_when_explicitly_enabled() -> None:
    captured = {}

    def handler(request: httpx.Request) -> httpx.Response:
        captured["body"] = json.loads(request.content)
        return chat_response('{"verdict":"real","confidence":0.9}')

    client = ai.AIClient(cfg(send_raw=True), transport=make_transport(handler))
    run(ai.triage_finding(client, _finding_row(), raw="AIzaSyB3kQ9mZx2VnPr7YqW3FbC8dE1fG4hI6jK"))
    assert "AIzaSyB3kQ9mZx2VnPr7YqW3FbC8dE1fG4hI6jK" in captured["body"]["messages"][-1]["content"]


def test_triage_prompt_includes_decoded_preview() -> None:
    """发明文时, 可逆编码要先还原并写进 prompt, 让模型基于还原结果判断。"""
    import base64

    captured = {}

    def handler(request: httpx.Request) -> httpx.Response:
        captured["body"] = json.loads(request.content)
        return chat_response('{"verdict":"real","confidence":0.9}')

    payload = base64.b64encode(b'{"corpsecret":"real-secret-value"}').decode()
    client = ai.AIClient(cfg(send_raw=True), transport=make_transport(handler))
    run(ai.triage_finding(client, _finding_row(), raw=payload))
    prompt = captured["body"]["messages"][-1]["content"]
    assert "自动预还原" in prompt
    assert "Base64 解码" in prompt
    assert "real-secret-value" in prompt
    # 系统提示要明确要求"先看上下文定角色 + 先解密再研判"
    system = captured["body"]["messages"][0]["content"]
    assert "先定角色" in system and "再还原内容" in system


def test_triage_does_not_leak_decoded_value_when_raw_disabled() -> None:
    import base64

    captured = {}

    def handler(request: httpx.Request) -> httpx.Response:
        captured["body"] = json.loads(request.content)
        return chat_response('{"verdict":"real","confidence":0.9}')

    payload = base64.b64encode(b'{"corpsecret":"real-secret-value"}').decode()
    client = ai.AIClient(cfg(send_raw=False), transport=make_transport(handler))
    run(ai.triage_finding(client, _finding_row(), raw=payload))
    prompt = captured["body"]["messages"][-1]["content"]
    assert "自动预还原" not in prompt
    assert "real-secret-value" not in prompt


def test_decode_preview_handles_common_encodings() -> None:
    import base64

    jwt = ("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9."
           "eyJzdWIiOiJhZG1pbiIsInJvbGUiOiJhZG1pbiJ9.abc123")
    assert "JWT 解码" in ai.decode_preview(jwt)
    assert "Base64 解码" in ai.decode_preview(base64.b64encode(b'{"api_key":"x"}').decode())
    assert "Hex 解码" in ai.decode_preview("7b226b6579223a2276616c7565227d")
    assert "URL 解码" in ai.decode_preview("%7B%22token%22%3A%22abc%22%7D")
    assert ai.decode_preview("dhV2Rlgmkz8QyjiLW4ZlfsAWKrFrbedb5mOHLz2eBYk") == ""


def test_triage_degrades_gracefully_on_bad_output() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return chat_response("模型今天不想说话")

    client = ai.AIClient(cfg(), transport=make_transport(handler))
    verdict = run(ai.triage_finding(client, _finding_row()))
    assert verdict["verdict"] == "uncertain" and verdict.get("failed") is True


def test_cache_prevents_second_call() -> None:
    calls = {"n": 0}

    def handler(request: httpx.Request) -> httpx.Response:
        calls["n"] += 1
        return chat_response('{"verdict":"fake","confidence":0.9}')

    client = ai.AIClient(cfg(), transport=make_transport(handler))
    first = run(ai.triage_finding(client, _finding_row()))
    second = run(ai.triage_finding(client, _finding_row()))
    assert calls["n"] == 1
    assert first == second and client.cache_hits == 1


def test_daily_budget_blocks_calls() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return chat_response('{"verdict":"real","confidence":0.5}')

    client = ai.AIClient(cfg(max_calls_per_day=1), transport=make_transport(handler))
    row = {**_finding_row(), "context": "唯一的上下文-预算测试"}
    run(ai.triage_finding(client, row))
    assert ai.budget_left(client.cfg) == 0
    with pytest.raises(ai.AIError):
        run(client.chat("x", "y", use_cache=False))


# ------------------------------------------------------------ 语义补漏

def test_semantic_scan_redacts_known_secrets_before_sending() -> None:
    captured = {}
    raw = "sk_live_51QxT8mKqLp3RnZ7vW2dJfA9bHc4EyU6"

    def handler(request: httpx.Request) -> httpx.Response:
        captured["content"] = json.loads(request.content)["messages"][-1]["content"]
        return httpx.Response(200, json={"choices": [{"message": {"content":
            '[{"type":"硬编码口令","evidence":"admin:Passw0rd!","confidence":0.9,"severity":"high","reason":"明文口令"}]'}}]})

    client = ai.AIClient(cfg(), transport=make_transport(handler))
    items = run(ai.semantic_scan_text(client, f'var k = "{raw}"; var p = "admin:Passw0rd!";',
                                      "http://x/app.js", redact=[raw]))
    assert raw not in captured["content"]
    assert "[[REDACTED]]" in captured["content"]
    assert items[0]["type"] == "硬编码口令"


def test_suspicion_score_prefers_config_files() -> None:
    config_score = ai.suspicion_score("http://x/config.js", "var a=1; authorization; atob('x')")
    plain_score = ai.suspicion_score("http://x/vendor.js", "x" * 90000)
    assert config_score > plain_score


# ------------------------------------------------------------ 规则生成

def test_validate_rule_accepts_matching_pattern() -> None:
    rule, reason = ai.validate_rule(
        {"id": "Acme Internal Token", "name": "Acme 令牌", "severity": "critical",
         "pattern": r"acme_[a-z0-9]{32}", "secret_group": 1, "keywords": ["acme_"]},
        evidence="token = acme_0123456789abcdef0123456789abcdef",
    )
    assert reason == ""
    assert rule["id"] == "ai:acme-internal-token" and rule["severity"] == "critical"


def test_validate_rule_rejects_non_matching_or_broken_pattern() -> None:
    assert ai.validate_rule({"pattern": "((("}, "x")[0] is None
    assert ai.validate_rule({"pattern": "nomatch_[0-9]+"}, "something else")[0] is None


def test_repair_masked_sample_restores_length_and_charset() -> None:
    repaired = ai.repair_masked_sample('hook = "https://open.feishu.cn/x"; secret = "LTAI...qW3F(len=24)"')
    assert "LTAI" in repaired and "(len=24)" not in repaired
    token = repaired.split('secret = "')[1].rstrip('"')
    assert len(token) == 24
    assert re.fullmatch(r"[A-Za-z0-9]{24}", token)
    # 不含掩码标记时原样返回
    assert ai.repair_masked_sample("no mask here") == "no mask here"


def test_validate_rule_accepts_pattern_when_only_masked_context_available() -> None:
    """我们默认不存明文, 所以只能对着掩码校验: 长度/字符集约束仍应通过。"""
    context = 'var k = "LTAI...qW3F(len=24)";'
    rule, reason = ai.validate_rule(
        {"id": "aliyun-ak", "pattern": r"\bLTAI[A-Za-z0-9]{20}\b", "secret_group": 0},
        evidence=context,
    )
    assert reason == "" and rule is not None
    # 长度不对的正则仍应被拒
    rejected, why = ai.validate_rule({"pattern": r"\bLTAI[A-Za-z0-9]{8}\b"}, evidence=context)
    assert rejected is None and "样例" in why


def test_draft_rule_end_to_end() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return chat_response(json.dumps({
            "id": "acme-token", "name": "Acme 令牌", "severity": "high", "category": "saas",
            "pattern": r"\bacme_[a-z0-9]{32}\b", "secret_group": 1, "keywords": ["acme_"],
        }))

    client = ai.AIClient(cfg(), transport=make_transport(handler))
    result = run(ai.draft_rule(client, _finding_row(), evidence="var t='acme_0123456789abcdef0123456789abcdef'"))
    assert result["ok"] and result["rule"]["pattern"]


# ------------------------------------------------------------ 扫描流程接入

def test_ai_phase_triages_new_findings_and_marks_false_positives() -> None:
    from app import scanner

    target_id = int(db.execute(
        "INSERT INTO targets(name, base_url, created_at) VALUES(?,?,?)",
        ("AI 站点", "http://ai.test/", db.utcnow()),
    ).lastrowid or 0)
    fid = int(db.execute(
        "INSERT INTO findings(target_id, rule_id, rule_name, severity, category, fingerprint, "
        "match_masked, match_sha256, context, asset_url, first_seen_at, last_seen_at, status) "
        "VALUES(?,?,?,?,?,?,?,?,?,?,?,?,'new')",
        (target_id, "generic-secret-assignment", "疑似硬编码密钥", "high", "generic",
         "fp-ai-" + db.utcnow(), "abcd...wxyz(len=32)", "sha", 'apiKey: "abcd...wxyz"',
         "http://ai.test/app.js", db.utcnow(), db.utcnow()),
    ).lastrowid or 0)

    def handler(request: httpx.Request) -> httpx.Response:
        return chat_response('{"verdict":"fake","confidence":0.95,"reason":"占位符",'
                             '"impact":"无","remediation":"忽略"}')

    ai_cfg = cfg(auto_mark_false_positive=True, auto_fp_confidence=0.8, semantic_scan=False,
                 max_calls_per_scan=5)
    original_client = ai.AIClient
    ai.AIClient = lambda c, transport=None: original_client(c, transport=make_transport(handler))  # type: ignore[assignment]
    try:
        result = scanner.ScanResult(target_id=target_id)
        result.new_findings.append({
            "id": fid, "target_id": target_id, "rule_id": "generic-secret-assignment",
            "rule_name": "疑似硬编码密钥", "severity": "high", "masked": "abcd...wxyz(len=32)",
            "asset_url": "http://ai.test/app.js", "context": 'apiKey: "abcd...wxyz"',
        })
        summary = asyncio.run(scanner._ai_phase(
            ai_cfg, target_id, result,
            semantic_pool=[],
            seen_keys=set(),
        ))
    finally:
        ai.AIClient = original_client  # type: ignore[assignment]

    assert summary is False  # 没开语义补漏
    assert result.ai_summary["triaged"] == 1
    assert result.ai_summary["false_positives"] == 1
    row = db.query_one("SELECT status, ai_verdict, ai_confidence, ai_reason FROM findings WHERE id=?", (fid,))
    assert row["status"] == "false_positive"
    assert row["ai_verdict"] == "fake" and row["ai_confidence"] == 0.95
    assert "占位符" in row["ai_reason"]


def test_triage_pending_judges_findings_left_over_by_the_per_scan_cap() -> None:
    """单轮上限之外的新发现, 推送前会被补判, 不该带着"未复核"发出去。"""
    from app import scanner

    target_id = int(db.execute(
        "INSERT INTO targets(name, base_url, created_at) VALUES(?,?,?)",
        ("补判站点", "http://late.test/", db.utcnow()),
    ).lastrowid or 0)
    ids = []
    for index in range(3):
        ids.append(int(db.execute(
            "INSERT INTO findings(target_id, rule_id, rule_name, severity, category, fingerprint, "
            "match_masked, match_sha256, context, asset_url, first_seen_at, last_seen_at, status) "
            "VALUES(?,?,?,?,?,?,?,?,?,?,?,?,'new')",
            (target_id, "database-url", "数据库连接串", "high", "database", f"fp-late-{index}",
             "redi...79/0(len=49)", f"sha-{index}", 'redis: "redis://u:p@h:6379/0"',
             "http://late.test/app.js", db.utcnow(), db.utcnow()),
        ).lastrowid or 0))

    def handler(request: httpx.Request) -> httpx.Response:
        return chat_response('{"verdict":"real","confidence":0.88,"reason":"真实连接串",'
                             '"impact":"可直连数据库","remediation":"改用环境变量"}')

    ai_cfg = cfg(auto_mark_false_positive=False, semantic_scan=False,
                 max_calls_per_scan=1, max_calls_per_day=50)
    original_client, original_config = ai.AIClient, ai.ai_config
    ai.AIClient = lambda c, transport=None: original_client(c, transport=make_transport(handler))  # type: ignore[assignment]
    ai.ai_config = lambda: ai_cfg  # type: ignore[assignment]
    try:
        items = [{"id": fid, "rule_id": "database-url", "severity": "high",
                  "masked": "redi...79/0(len=49)", "asset_url": "http://late.test/app.js"} for fid in ids]
        done = asyncio.run(scanner.triage_pending(items, cap=5))
    finally:
        ai.AIClient, ai.ai_config = original_client, original_config  # type: ignore[assignment]

    assert done == 3, "三条都应被补判"
    assert all(item["ai_verdict"] == "real" for item in items)
    rows = db.query("SELECT ai_verdict, ai_confidence FROM findings WHERE id IN (?,?,?)", tuple(ids))
    assert all(row["ai_verdict"] == "real" and row["ai_confidence"] == 0.88 for row in rows)
