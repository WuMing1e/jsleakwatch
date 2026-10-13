"""模拟公司内网的 GLM 端点 (OpenAI 兼容), 用于端到端验证 AI 链路。

刻意模仿 vLLM/网关的两种常见行为: 不支持 response_format, 以及 /v1/models 暴露模型名。
"""
from __future__ import annotations

import http.server
import json
import os
import re
import socketserver
import sys
import threading
import time

MODELS = ["glm-5.2", "glm-4.6", "glm-4-plus"]
LOG: list[str] = []


class Server(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True


def triage_reply(prompt: str) -> str:
    """按提示里出现的规则名给出不同判定, 让演示更接近真实效果。"""
    if re.search(r"钉钉|飞书|dingtalk|feishu|lark", prompt, re.I):
        return json.dumps({
            "verdict": "real", "confidence": 0.93,
            "reason": "这是可推送消息的机器人 Webhook，拿到即可向群内发消息，属于真实可被滥用的凭据。",
            "secret_type": "IM 机器人 Webhook", "impact": "攻击者可向该群发送任意消息，可用于钓鱼与社工。",
            "remediation": "立即在群设置中重置 Webhook，并改为服务端代理发送，前端只保留业务接口。",
            "rotate": "yes",
        }, ensure_ascii=False)
    if re.search(r"高德|amap|地图", prompt, re.I):
        return json.dumps({
            "verdict": "real", "confidence": 0.81,
            "reason": "高德 Web 服务 Key 未做域名白名单时可直接消耗配额或调用付费接口。",
            "secret_type": "地图服务 Key", "impact": "Key 被刷导致配额耗尽或产生费用。",
            "remediation": "在高德控制台为该 Key 配置域名白名单与配额上限。", "rotate": "yes",
        }, ensure_ascii=False)
    if re.search(r"内网地址|192\.168|10\.", prompt, re.I):
        return json.dumps({
            "verdict": "uncertain", "confidence": 0.4,
            "reason": "仅凭 IP 无法判断有效性，可能是构建期残留的调试地址。",
            "secret_type": "内部地址", "impact": "为内网探测提供线索。",
            "remediation": "确认是否为废弃配置，并从构建产物中移除。", "rotate": "no",
        }, ensure_ascii=False)
    return json.dumps({
        "verdict": "fake", "confidence": 0.9,
        "reason": "该值随机性低且出现在示例配置中，判断为占位符。",
        "secret_type": "占位符", "impact": "无", "remediation": "可加入白名单。", "rotate": "no",
    }, ensure_ascii=False)


def semantic_reply(prompt: str) -> str:
    return json.dumps([
        {
            "type": "硬编码管理口令",
            "evidence": "if (user === 'root' && pass === 'Adm1n@2024') { grantAdmin(); }",
            "confidence": 0.88,
            "severity": "critical",
            "reason": "前端明文比对管理员口令，任何人读取 JS 即可获得后台口令，且该逻辑可被绕过。",
        },
        {
            "type": "隐藏管理入口",
            "evidence": 'const panel = "/admin/console?debug=1";',
            "confidence": 0.62,
            "severity": "medium",
            "reason": "前端硬编码了内部管理入口路径，配合调试参数可能暴露未授权后台。",
        },
    ], ensure_ascii=False)


RULE_TEMPLATES = [
    (r"dingtalk\.com/robot/send", {
        "id": "dingtalk-robot-webhook", "name": "钉钉机器人 Webhook",
        "severity": "high", "category": "im",
        "pattern": r"https://oapi\.dingtalk\.com/robot/send\?access_token=[0-9a-f]{64}",
        "secret_group": 0, "keywords": ["access_token"], "entropy_min": 3.0,
        "description": "钉钉机器人 Webhook 泄露后任何人都能向该群发消息。",
    }),
    (r"feishu|open-apis/bot", {
        "id": "feishu-bot-webhook", "name": "飞书机器人 Webhook",
        "severity": "high", "category": "im",
        "pattern": r"https://open\.feishu\.cn/open-apis/bot/v2/hook/[A-Za-z0-9\-]{20,}",
        "secret_group": 0, "keywords": ["hook"], "entropy_min": 0,
        "description": "飞书自定义机器人 Webhook。",
    }),
    (r"LTAI", {
        "id": "aliyun-ak-id", "name": "阿里云 AccessKey ID",
        "severity": "critical", "category": "cn-cloud",
        "pattern": r"\bLTAI[A-Za-z0-9]{20}\b", "secret_group": 0,
        "keywords": ["ltai"], "entropy_min": 0, "description": "阿里云 AccessKey ID。",
    }),
]


def rule_reply(prompt: str) -> str:
    for hint, template in RULE_TEMPLATES:
        if re.search(hint, prompt, re.I):
            return json.dumps(template, ensure_ascii=False)
    return json.dumps({
        "id": "generic-candidate", "name": "通用候选规则", "severity": "medium",
        "category": "generic", "pattern": r"[A-Za-z0-9]{32,}", "secret_group": 0,
        "keywords": [], "entropy_min": 4.0, "description": "兜底规则",
    }, ensure_ascii=False)


# ---------------------------------------------------------------- JScanner2 判定

PUBLIC_PREFIXES = ("AIza", "6L", "pk_", "pk.")
REAL_PREFIXES = ("AKIA", "ASIA", "LTAI", "AKID", "ghp_", "gho_", "glpat-", "sk_live_",
                 "rk_live_", "whsec_", "xoxb-", "xoxp-", "npm_", "pypi-")
PLACEHOLDER_HINTS = ("your_", "your-", "changeme", "example", "xxxx", "placeholder",
                     "process.env", "${", "test", "demo", "sample")


def judge_value(value: str) -> tuple[int, str, str, float]:
    """返回 (是否密钥, 类型, 风险级别, 置信度)。逻辑对齐一个"合理模型"的判断。"""
    lowered = value.lower().strip()
    if any(lowered.startswith(p.lower()) for p in PUBLIC_PREFIXES):
        return 0, "api_key", "Low", 0.9          # 公开设计中允许暴露
    if any(hint in lowered for hint in PLACEHOLDER_HINTS) or len(value) < 12:
        return 0, "other", "Low", 0.85           # 占位符
    if value.startswith("http") and ("hook" in lowered or "webhook" in lowered):
        return 1, "token", "High", 0.92
    if value.startswith(("redis://", "mysql://", "postgres://", "mongodb")):
        return 1, "password", "High", 0.9
    if any(value.startswith(p) for p in REAL_PREFIXES):
        return 1, "api_key", "High", 0.94
    if value.count(".") == 2 and value.startswith("eyJ"):
        return 1, "token", "Med", 0.8            # JWT
    if value.startswith("http") and "sentry" in lowered:
        return 0, "endpoint", "Low", 0.8         # DSN 属公开上报地址
    if re.search(r"\b(10|192\.168|172\.(1[6-9]|2\d|3[01]))\.\d+\.\d+", value):
        return 0, "endpoint", "Low", 0.7
    return 1, "other", "Med", 0.6


def jscanner_judge(user: str) -> str:
    """应答 JScanner2 的 SECRET_PROMPT: 输入 {id: {value, context, callers}}。"""
    start = user.find("{")
    if start < 0:
        return "{}"
    try:
        candidates = json.loads(user[start:])
    except json.JSONDecodeError:
        return "{}"
    if not isinstance(candidates, dict):
        return "{}"
    out: dict[str, dict] = {}
    for cid, item in candidates.items():
        value = str((item or {}).get("value") or "")
        is_secret, secret_type, risk, confidence = judge_value(value)
        out[str(cid)] = {
            "is_secret": is_secret,
            "secret_type": secret_type,
            "risk_level": risk,
            "confidence": confidence,
            "test_suggestion": ("验证该凭据是否有效并评估可访问范围" if is_secret
                                else "判定为公开或占位值，无需处理"),
        }
    return json.dumps(out, ensure_ascii=False)


class Handler(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def _send(self, status: int, payload: dict) -> None:
        body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self) -> None:  # noqa: N802
        if self.path.rstrip("/").endswith("/models"):
            LOG.append("GET /v1/models")
            self._send(200, {"object": "list", "data": [{"id": m, "object": "model"} for m in MODELS]})
        else:
            self._send(404, {"error": "not found"})

    def do_POST(self) -> None:  # noqa: N802
        length = int(self.headers.get("content-length") or 0)
        raw = self.rfile.read(length).decode("utf-8", "replace")
        try:
            payload = json.loads(raw or "{}")
        except json.JSONDecodeError:
            self._send(400, {"error": {"message": "bad json"}})
            return

        # 需要模拟"网关不支持 response_format"时设 MOCK_REJECT_RESPONSE_FORMAT=1
        if "response_format" in payload and os.getenv("MOCK_REJECT_RESPONSE_FORMAT"):
            LOG.append("400 response_format not supported")
            self._send(400, {"error": {"message": "response_format is not supported by this model"}})
            return

        messages = payload.get("messages", [])
        system = messages[0].get("content", "") if messages else ""
        user = messages[-1].get("content", "") if messages else ""
        time.sleep(0.02)

        if "连通性测试" in system:
            content = '{"ok":true,"model":"glm-5.2"}'
            LOG.append("chat:ping")
        elif "Analyze these hardcoded values" in user:
            content = jscanner_judge(user)
            LOG.append("chat:jscanner-judge")
        elif "复核助手" in system:
            content = triage_reply(user)
            LOG.append("chat:triage")
        elif "安全审计" in system:
            content = semantic_reply(user)
            LOG.append("chat:semantic")
        elif "规则工程师" in system:
            content = rule_reply(user)
            LOG.append("chat:rule")
        else:
            content = '{"ok":true}'
            LOG.append("chat:other")

        self._send(200, {
            "id": "chatcmpl-mock", "object": "chat.completion", "model": payload.get("model", "glm-5.2"),
            "choices": [{"index": 0, "message": {"role": "assistant", "content": content},
                         "finish_reason": "stop"}],
            "usage": {"prompt_tokens": 100, "completion_tokens": 50, "total_tokens": 150},
        })

    def log_message(self, *args) -> None:
        pass


if __name__ == "__main__":
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 8897
    print(f"mock GLM -> http://127.0.0.1:{port}/v1  models={MODELS}")
    threading.Thread(target=lambda: None, daemon=True).start()
    with Server(("127.0.0.1", port), Handler) as httpd:
        httpd.serve_forever()
