"""告警推送: 飞书自定义机器人 / 飞书应用 + 通用 Webhook。

飞书自定义机器人只需一个 webhook 地址, 适合快速接入;
飞书应用模式支持指定群/个人接收, 并可 @ 到具体负责人。
"""
from __future__ import annotations

import asyncio
import json
import time
from datetime import datetime
from typing import Any

import httpx

from . import db, gating
from .ai import VERDICT_LABEL
from .config import SETTINGS, AlertConfig
from .rules import SEVERITY_ORDER

SEVERITY_TEMPLATE = {
    "critical": "red",
    "high": "orange",
    "medium": "yellow",
    "low": "blue",
    "info": "grey",
}

SEVERITY_LABEL = {
    "critical": "严重",
    "high": "高危",
    "medium": "中危",
    "low": "低危",
    "info": "提示",
}

FEISHU_API = "https://open.feishu.cn/open-apis"


def alert_config() -> AlertConfig:
    cfg = AlertConfig(
        enabled=SETTINGS.alert.enabled,
        channel=SETTINGS.alert.channel,
        webhook_url=SETTINGS.alert.webhook_url,
        app_id=SETTINGS.alert.app_id,
        app_secret=SETTINGS.alert.app_secret,
        chat_id=SETTINGS.alert.chat_id,
        min_severity=SETTINGS.alert.min_severity,
        digest_threshold=SETTINGS.alert.digest_threshold,
        max_alerts_per_run=SETTINGS.alert.max_alerts_per_run,
        notify_resolved=SETTINGS.alert.notify_resolved,
        extra_webhooks=list(SETTINGS.alert.extra_webhooks),
        at_user_ids=list(SETTINGS.alert.at_user_ids),
    )
    stored = db.get_setting("alert") or {}
    for key, value in stored.items():
        if hasattr(cfg, key) and value is not None:
            setattr(cfg, key, value)
    return cfg


def _console_base() -> str:
    return f"http://{SETTINGS.host}:{SETTINGS.port}"


class FeishuNotifier:
    def __init__(self, cfg: AlertConfig | None = None) -> None:
        self.cfg = cfg or alert_config()
        self._token: str = ""
        self._token_expire: float = 0.0
        self._last_send: float = 0.0
        self.sent = 0
        self.failed = 0
        self.errors: list[str] = []

    # -------------------------------------------------- 底层发送
    async def _get_token(self, client: httpx.AsyncClient) -> str:
        if self._token and time.time() < self._token_expire:
            return self._token
        resp = await client.post(
            f"{FEISHU_API}/auth/v3/tenant_access_token/internal",
            json={"app_id": self.cfg.app_id, "app_secret": self.cfg.app_secret},
        )
        data = resp.json()
        if data.get("code") != 0:
            raise RuntimeError(f"获取 tenant_access_token 失败: {data.get('msg') or data}")
        self._token = data["tenant_access_token"]
        self._token_expire = time.time() + int(data.get("expire", 7200)) - 120
        return self._token

    async def send_card(self, card: dict[str, Any]) -> tuple[bool, str]:
        async with httpx.AsyncClient(timeout=15.0) as client:
            try:
                if self.cfg.channel == "app":
                    if not (self.cfg.app_id and self.cfg.app_secret and self.cfg.chat_id):
                        return False, "飞书应用模式缺少 app_id / app_secret / chat_id"
                    token = await self._get_token(client)
                    resp = await client.post(
                        f"{FEISHU_API}/im/v1/messages",
                        params={"receive_id_type": "chat_id"},
                        headers={"Authorization": f"Bearer {token}"},
                        json={
                            "receive_id": self.cfg.chat_id,
                            "msg_type": "interactive",
                            "content": json.dumps(card, ensure_ascii=False),
                        },
                    )
                    data = resp.json()
                    problem = self._response_error(resp, data)
                    if problem:
                        return False, problem
                    self.sent += 1
                    return True, "已发送"
                if not self.cfg.webhook_url:
                    return False, "未配置飞书机器人 Webhook 地址"
                resp = await client.post(
                    self.cfg.webhook_url,
                    json={"msg_type": "interactive", "card": card},
                )
                try:
                    data = resp.json()
                except Exception:  # noqa: BLE001 - 网关返回 HTML 之类的非 JSON 响应
                    data = {}
                problem = self._response_error(resp, data)
                if problem:
                    return False, problem
                self.sent += 1
                return True, "已发送"
            except Exception as exc:  # noqa: BLE001
                self.failed += 1
                return False, f"{type(exc).__name__}: {exc}"[:200]

    @staticmethod
    def _response_error(resp: httpx.Response, data: dict[str, Any]) -> str:
        """飞书自定义机器人会同时给 code 与 StatusCode, 有的网关只给其中一个。

        以前只看 `code`, 于是 HTTP 500 / 非 JSON 响应也会被当成"已发送", 现在两者都查。
        """
        if resp.status_code >= 400:
            return f"HTTP {resp.status_code}: {resp.text[:160]}"
        bad = next((c for c in (data.get("code"), data.get("StatusCode")) if c not in (0, None)), None)
        if bad is not None:
            reason = data.get("msg") or data.get("StatusMessage") or ""
            return f"飞书返回错误: {reason} (code={bad})"
        return ""

    async def _throttle(self) -> None:
        gap = 1.1
        wait = gap - (time.monotonic() - self._last_send)
        if wait > 0:
            await asyncio.sleep(wait)
        self._last_send = time.monotonic()

    # -------------------------------------------------- 卡片构造
    @staticmethod
    def _verdict_text(item: dict[str, Any]) -> str:
        """卡片上标注 AI 结论, 让收到告警的人知道这条为什么被推出来。"""
        verdict = item.get("ai_verdict") or ""
        if not verdict:
            return ""
        label = VERDICT_LABEL.get(verdict, verdict)
        confidence = float(item.get("ai_confidence") or 0)
        return f"{label}{f' {round(confidence * 100)}%' if confidence else ''}"

    # lark_md 支持的字体色有限, 只用确认可用的这几个
    SEVERITY_COLOR = {"critical": "red", "high": "orange", "medium": "blue", "low": "grey",
                      "info": "grey"}

    @classmethod
    def _sev_tag(cls, severity: str) -> str:
        label = SEVERITY_LABEL.get(severity, severity)
        return f"<font color='{cls.SEVERITY_COLOR.get(severity, 'grey')}'>{label}</font>"

    @staticmethod
    def _short(text: str, limit: int = 88) -> str:
        text = str(text or "")
        return text if len(text) <= limit else text[: limit - 1] + "…"

    @classmethod
    def _link(cls, text: str, url: str) -> str:
        """飞书卡片里的链接写法和 Markdown 一样, 地址太长时收折显示。"""
        if not url:
            return text
        return f"[{cls._short(text)}]({url})"

    @staticmethod
    def _now_text() -> str:
        return datetime.now().strftime("%Y-%m-%d %H:%M")

    def _detail_card(self, item: dict[str, Any], target: dict[str, Any] | None) -> dict[str, Any]:
        severity = item.get("severity", "info")
        site = (target or {}).get("name") or (target or {}).get("base_url") or f"站点 #{item.get('target_id')}"
        site_url = (target or {}).get("base_url") or ""
        asset_url = item.get("asset_url") or ""
        # 上半部分用两列 fields: 手机上也是整齐的左右对照, 比一长串 "键: 值" 好扫
        fields = [
            {"is_short": True, "text": {"tag": "lark_md",
                                        "content": f"**等级**\n{self._sev_tag(severity)}"}},
            {"is_short": True, "text": {"tag": "lark_md",
                                        "content": f"**AI 复核**\n{self._verdict_text(item) or '未复核'}"}},
            {"is_short": True, "text": {"tag": "lark_md",
                                        "content": f"**站点**\n{self._link(site, site_url)}"}},
            {"is_short": True, "text": {"tag": "lark_md",
                                        "content": f"**规则**\n{item.get('rule_name')}"}},
        ]
        elements: list[dict[str, Any]] = [
            {"tag": "div", "fields": fields},
            {"tag": "div", "text": {"tag": "lark_md",
                                    "content": f"**命中值**\n`{item.get('masked')}`"}},
        ]
        if asset_url:
            elements.append({"tag": "div", "text": {"tag": "lark_md",
                            "content": f"**来源文件**\n{self._link(asset_url, asset_url)}"}})
        if item.get("context"):
            # 代码块里的反引号会把 lark_md 的围栏提前闭合, 先清掉
            snippet = str(item["context"])[:280].replace("```", "''").strip()
            elements.append({"tag": "div", "text": {"tag": "lark_md",
                            "content": f"**命中上下文**\n```\n{snippet}\n```"}})
        rule_id = item.get("rule_id") or ""
        elements += [
            {"tag": "hr"},
            {
                "tag": "action",
                "actions": [{
                    "tag": "button",
                    "text": {"tag": "plain_text", "content": "在控制台查看详情"},
                    "url": (f"{_console_base()}/#/findings?finding={item['id']}"
                            if item.get("id") else
                            f"{_console_base()}/#/findings?target={item.get('target_id')}"),
                    "type": "primary",
                }],
            },
            {"tag": "note", "elements": [{"tag": "lark_md",
             "content": f"JSLeakWatch · {self._now_text()}" + (f" · 规则 `{rule_id}`" if rule_id else "")}]},
        ]
        return {
            "config": {"wide_screen_mode": True},
            "header": {
                "template": SEVERITY_TEMPLATE.get(severity, "grey"),
                "title": {"tag": "plain_text",
                          "content": f"{'复现' if item.get('reopened') else '发现'}硬编码凭证 · {self._short(site, 34)}"},
            },
            "elements": elements,
        }

    def _digest_card(self, items: list[dict[str, Any]], targets: dict[int, dict[str, Any]]) -> dict[str, Any]:
        worst = max(items, key=lambda i: SEVERITY_ORDER.get(i.get("severity", "info"), 0))
        by_site: dict[str, list[dict[str, Any]]] = {}
        for item in items:
            target = targets.get(int(item.get("target_id", 0)))
            name = (target or {}).get("name") or f"站点 #{item.get('target_id')}"
            by_site.setdefault(name, []).append(item)

        counts: dict[str, int] = {}
        for item in items:
            sev = item.get("severity", "info")
            counts[sev] = counts.get(sev, 0) + 1
        tally = " · ".join(
            f"{self._sev_tag(sev)} {counts[sev]}"
            for sev in sorted(counts, key=lambda s: -SEVERITY_ORDER.get(s, 0))
        )
        headline = f"本轮巡检命中 **{len(items)}** 条疑似硬编码凭证, 分布在 {len(by_site)} 个站点"

        # 每个站点一段: 站点名做成链接, 命中逐条列出, 文件单独一行弱化显示
        sections: list[dict[str, Any]] = [{"tag": "div", "text": {"tag": "lark_md",
                                      "content": f"{headline}\n{tally}"}}]
        for name, group in list(by_site.items())[:12]:
            target_id = int(group[0].get("target_id", 0))
            lines = [f"**[{self._short(name, 40)}]"
                     f"({_console_base()}/#/findings?target={target_id})**"
                     f" <font color='grey'>{len(group)} 条</font>"]
            for item in group[:8]:
                verdict = self._verdict_text(item)
                suffix = f" · <font color='grey'>AI {verdict}</font>" if verdict else ""
                lines.append(f"- {self._sev_tag(item.get('severity', 'info'))} "
                             f"{item.get('rule_name')} · `{item.get('masked')}`{suffix}")
                if item.get("asset_url"):
                    lines.append(f"  <font color='grey'>{self._link(item['asset_url'], item['asset_url'])}</font>")
            if len(group) > 8:
                lines.append(f"- <font color='grey'>… 其余 {len(group) - 8} 条请在控制台查看</font>")
            sections.append({"tag": "hr"})
            sections.append({"tag": "div", "text": {"tag": "lark_md", "content": "\n".join(lines)}})

        mentions = " ".join(f'<at user_id="{uid}"></at>' for uid in self.cfg.at_user_ids if uid)
        return {
            "config": {"wide_screen_mode": True},
            "header": {
                "template": SEVERITY_TEMPLATE.get(worst.get("severity", "info"), "grey"),
                "title": {"tag": "plain_text", "content": f"JS 硬编码泄露巡检汇总 · {len(items)} 条新发现"},
            },
            "elements": sections + [
                {"tag": "hr"},
                {
                    "tag": "action",
                    "actions": [{
                        "tag": "button",
                        "text": {"tag": "plain_text", "content": "查看全部发现"},
                        "url": f"{_console_base()}/#/findings",
                        "type": "primary",
                    }],
                },
                {"tag": "note", "elements": [{"tag": "lark_md",
                 "content": f"JSLeakWatch · {self._now_text()} · 已按 AI 复核过滤误报"}]},
            ] + ([{"tag": "div", "text": {"tag": "lark_md", "content": mentions}}] if mentions else []),
        }

    # -------------------------------------------------- 对外接口
    @staticmethod
    def _ai_verdicts(items: list[dict[str, Any]]) -> dict[str, tuple[str, float]]:
        """按指纹取 AI 复核结果: 推送前要先用它把误报滤掉。"""
        prints = [str(i["fingerprint"]) for i in items if i.get("fingerprint")]
        found: dict[str, tuple[str, float]] = {}
        for start in range(0, len(prints), 400):     # SQLite 变量上限 999, 分批查
            chunk = prints[start:start + 400]
            marks = ",".join("?" * len(chunk))
            for row in db.query(
                f"SELECT fingerprint, ai_verdict, ai_confidence FROM findings "
                f"WHERE fingerprint IN ({marks})",
                chunk,
            ):
                found[row["fingerprint"]] = (row["ai_verdict"] or "", float(row["ai_confidence"] or 0))
        return found

    async def notify_findings(self, items: list[dict[str, Any]]) -> dict[str, Any]:
        cfg = self.cfg
        if not items:
            return {"sent": 0, "skipped": 0, "reason": "没有新发现"}
        if not cfg.enabled:
            db.log_event(
                f"检测到 {len(items)} 条新发现, 但告警未启用, 未推送", kind="alert", level="warn"
            )
            return {"sent": 0, "skipped": len(items), "reason": "告警未启用"}

        # 三道过滤, 和发现列表保持同一套口径:
        #   1. AI 判为误报的不推;
        #   2. AI 判为"公开密钥"的不推 —— 高德/百度地图 key、飞书 App ID 这类本来就要写在
        #      前端, 推出去只会让人以为又出事了(实测这类占了飞书噪声的一大半);
        #   3. 误报率超过门控阈值的来源不推, 除非 AI 明确判成真凭证。
        verdicts = self._ai_verdicts(items)
        candidates: list[dict[str, Any]] = []
        skipped_fake = skipped_public = skipped_gated = 0
        for item in items:
            enriched = dict(item)
            verdict, confidence = verdicts.get(str(item.get("fingerprint") or ""), ("", 0.0))
            enriched["ai_verdict"] = verdict
            enriched["ai_confidence"] = confidence
            if verdict == "fake":
                skipped_fake += 1
                continue
            if verdict == "public":
                skipped_public += 1
                continue
            if gating.is_gated(str(item.get("rule_id") or "")) and verdict not in gating.PASS_VERDICTS:
                skipped_gated += 1
                continue
            candidates.append(enriched)

        threshold = SEVERITY_ORDER.get(cfg.min_severity, 0)
        picked = [i for i in candidates if SEVERITY_ORDER.get(i.get("severity", "info"), 0) >= threshold]
        if not picked:
            label = SEVERITY_LABEL.get(cfg.min_severity, cfg.min_severity)
            low = len(candidates) - len(picked)
            bits = []
            if skipped_fake:
                bits.append(f"{skipped_fake} 条 AI 判定为误报")
            if skipped_public:
                bits.append(f"{skipped_public} 条公开密钥")
            if skipped_gated:
                bits.append(f"{skipped_gated} 条来自高误报来源")
            if low:
                bits.append(f"{low} 条低于「{label}」")
            db.log_event(
                f"新发现 {len(items)} 条未推送: {'、'.join(bits) or '没有达到推送条件的条目'}",
                kind="alert",
            )
            return {"sent": 0, "skipped": len(items), "skipped_fake": skipped_fake,
                    "skipped_public": skipped_public, "skipped_gated": skipped_gated,
                    "reason": "、".join(bits) or f"无 >= {cfg.min_severity} 的发现"}

        targets = {
            int(row["id"]): {k: row[k] for k in row.keys()}
            for row in db.query("SELECT * FROM targets")
        }
        capped = picked[: max(1, cfg.max_alerts_per_run)]
        results: list[tuple[bool, str]] = []
        sent_items: list[dict[str, Any]] = []

        if len(capped) > max(1, cfg.digest_threshold):
            await self._throttle()
            ok, message = await self.send_card(self._digest_card(capped, targets))
            results.append((ok, message))
            if ok:
                sent_items = capped
        else:
            for item in capped:
                await self._throttle()
                target = targets.get(int(item.get("target_id", 0)))
                ok, message = await self.send_card(self._detail_card(item, target))
                results.append((ok, message))
                if ok:
                    sent_items.append(item)

        await self._push_generic(capped)

        ok = sum(1 for r, _ in results if r)
        for success, message in results:
            if not success:
                self.errors.append(message)
        # 只给真正发出去的标记"已推送": 失败的留着, 免得日志和列表都显示推过了
        now = db.utcnow()
        for item in sent_items:
            fingerprint = item.get("fingerprint")
            if fingerprint:
                db.execute("UPDATE findings SET notified_at=? WHERE fingerprint=?", (now, fingerprint))
        return {
            "sent": ok,
            "total": len(capped),
            "failed": len(results) - ok,
            "skipped_fake": skipped_fake,
            "skipped_public": skipped_public,
            "skipped_gated": skipped_gated,
            "errors": self.errors[-3:],
        }

    async def _push_generic(self, items: list[dict[str, Any]]) -> None:
        for url in self.cfg.extra_webhooks:
            if not url:
                continue
            try:
                async with httpx.AsyncClient(timeout=10.0) as client:
                    await client.post(url, json={"source": "jsleakwatch", "findings": items})
            except Exception as exc:  # noqa: BLE001
                self.errors.append(f"通用 webhook 失败: {type(exc).__name__}")

    async def send_test(self) -> tuple[bool, str]:
        card = {
            "config": {"wide_screen_mode": True},
            "header": {
                "template": "turquoise",
                "title": {"tag": "plain_text", "content": "JSLeakWatch 连通性测试"},
            },
            "elements": [
                {"tag": "div", "text": {"tag": "lark_md",
                 "content": "这是一条测试消息。收到它说明告警通道已打通。"}},
                {"tag": "div", "text": {"tag": "lark_md", "content": f"发送时间: {db.utcnow()}"}},
            ],
        }
        return await self.send_card(card)
