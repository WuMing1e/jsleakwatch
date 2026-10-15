#!/usr/bin/env python3
"""把所有 HTTP 接口跑一遍并做基本断言, 用于发版前回归。

默认只读 + 自建临时对象: 会起一个本地样例站点(不做任何外部请求), 建一个临时
监测站点跑一轮扫描, 把资产/发现/规则/设置相关接口都打一遍, 最后清理干净。

    python3.10 tools/api_smoke.py                 # 常规回归
    python3.10 tools/api_smoke.py --with-alerts   # 额外发一条飞书测试消息
    python3.10 tools/api_smoke.py --skip-ai       # 不调模型(省额度)

退出码非 0 表示有接口不符合预期。
"""
from __future__ import annotations

import argparse
import functools
import http.server
import json
import os
import socketserver
import sys
import threading
import time
import urllib.error
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
BASE = os.getenv("JSLW_BASE", "http://127.0.0.1:8787")
FIXTURE = ROOT / "fixtures" / "demo_site"

RESULTS: list[tuple[str, str, str, float]] = []   # (endpoint, level, note, ms)


def call(method: str, path: str, body=None, timeout: float = 60.0) -> tuple[int, object, float]:
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(BASE + path, data=data, method=method,
                                headers={"Content-Type": "application/json"})
    started = time.perf_counter()
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            raw = resp.read()
            status = resp.status
    except urllib.error.HTTPError as exc:
        raw, status = exc.read(), exc.code
    elapsed = (time.perf_counter() - started) * 1000
    try:
        payload = json.loads(raw.decode("utf-8"))
    except (ValueError, UnicodeDecodeError):
        payload = raw.decode("utf-8", "replace")
    return status, payload, elapsed


def check(label: str, method: str, path: str, *, body=None, expect=200, shape=None,
          timeout: float = 60.0):
    status, payload, ms = call(method, path, body, timeout=timeout)
    level, note = "ok", ""
    if status != expect:
        level, note = "FAIL", f"期望 HTTP {expect}, 实际 {status}: {str(payload)[:120]}"
    elif shape is not None:
        for key in shape:
            if not isinstance(payload, dict) or key not in payload:
                level, note = "FAIL", f"响应缺少字段 {key}: {str(payload)[:120]}"
                break
    RESULTS.append((f"{method} {path}", level, note, ms))
    return payload


def as_list(payload) -> list:
    """有的接口返回数组, 有的返回 {items: [...]} —— 冒烟脚本自己也抹平一下。"""
    if isinstance(payload, list):
        return payload
    if isinstance(payload, dict) and isinstance(payload.get("items"), list):
        return payload["items"]
    return []


def expect(cond: bool, label: str, note: str) -> None:
    RESULTS.append((label, "ok" if cond else "FAIL", "" if cond else note, 0.0))


class _Server(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True


class _Handler(http.server.SimpleHTTPRequestHandler):
    extensions_map = {**http.server.SimpleHTTPRequestHandler.extensions_map,
                      ".js": "application/javascript", ".map": "application/json"}

    def log_message(self, *args) -> None:
        pass


def serve_fixture() -> tuple[str, socketserver.TCPServer]:
    handler = functools.partial(_Handler, directory=str(FIXTURE))
    server = _Server(("127.0.0.1", 0), handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return f"http://127.0.0.1:{server.server_address[1]}/", server


def wait_scan(target_id: int, timeout: float = 180.0) -> dict:
    deadline = time.time() + timeout
    while time.time() < deadline:
        rows = call("GET", f"/api/scans?target_id={target_id}&limit=1")[1]
        if rows and rows[0]["status"] != "running":
            return rows[0]
        time.sleep(1.5)
    return {}


def main() -> int:
    parser = argparse.ArgumentParser(description="接口冒烟测试")
    parser.add_argument("--with-alerts", action="store_true", help="额外发送飞书测试消息")
    parser.add_argument("--skip-ai", action="store_true", help="跳过需要调用模型的接口")
    parser.add_argument("--with-scanners", action="store_true",
                        help="扫描时保留整站扫描器(默认临时关掉, 否则单轮要几分钟)")
    parser.add_argument("--with-ai-scan", action="store_true",
                        help="扫描时保留逐条 AI 复核(默认临时关掉, 单轮会因此多花 1~3 分钟)")
    parser.add_argument("--scan-timeout", type=float, default=300.0, help="等待扫描完成的秒数")
    parser.add_argument("--keep", action="store_true", help="留下临时站点便于排查")
    args = parser.parse_args()

    site, server = serve_fixture()
    created_target = created_rule = created_finding = None
    saved_analyzers = saved_ai = None
    print(f"目标服务 {BASE} · 样例站点 {site}\n")
    try:
        if not args.with_scanners:
            # 整站扫描器自己会爬一遍, 单轮常有几分钟; 冒烟只关心接口, 先临时关掉
            current = call("GET", "/api/settings")[1]
            saved_analyzers = current.get("analyzers", {}).get("target_scanners")
            if saved_analyzers:
                muted = {name: {**conf, "enabled": False} for name, conf in saved_analyzers.items()}
                call("PUT", "/api/settings", {"analyzers": {"target_scanners": muted}})
        if not args.with_ai_scan:
            # 逐条复核是串行的, 21 条发现要跑两三分钟; 冒烟只关心接口链路
            current = call("GET", "/api/settings")[1]
            saved_ai = {"verify_new_findings": current["ai"]["verify_new_findings"]}
            if saved_ai["verify_new_findings"]:
                call("PUT", "/api/settings", {"ai": {"verify_new_findings": False}})
        # ---------------- 只读类 ----------------
        overview = check("概览", "GET", "/api/overview", shape={"kpis", "severity", "timeline"})
        check("概览分页参数", "GET", "/api/overview?recent_limit=3&targets_limit=2",
              shape={"kpis", "recent", "targets"})
        targets = check("站点列表", "GET", "/api/targets?limit=5", shape={"total", "items"})
        check("站点筛选", "GET", "/api/targets?q=%E6%A0%B7%E4%BE%8B%E7%AB%99")
        findings = check("发现列表", "GET", "/api/findings?limit=5", shape={"total", "items"})
        check("发现按等级筛选", "GET", "/api/findings?severity=critical,high&limit=5")
        check("发现按状态筛选", "GET", "/api/findings?status=new&limit=5")
        check("发现搜索", "GET", "/api/findings?q=redis&limit=5")
        check("发现导出 CSV", "GET", "/api/findings/export.csv")
        assets = check("资产列表", "GET", "/api/assets?limit=5", shape={"total", "items"})
        check("变更流", "GET", "/api/changes?limit=5", shape={"total", "items"})
        check("扫描记录", "GET", "/api/scans?limit=5")
        check("事件日志", "GET", "/api/events?limit=5")
        rules = check("规则列表", "GET", "/api/rules", shape={"items", "revision"})
        check("规则质量", "GET", "/api/rules/quality", shape={"items", "summary"})
        settings = check("设置读取", "GET", "/api/settings", shape={"scan", "alert", "ai", "server"})
        check("白名单", "GET", "/api/allowlist")
        ai_status = check("AI 状态", "GET", "/api/ai/status")
        check("接口文档", "GET", "/api/docs")

        # 只读的一致性断言
        listed = call("GET", "/api/targets?limit=0")[1]
        expect(listed["total"] == overview["kpis"]["targets"],
               "站点总数一致 (列表 vs 概览)", f"{listed['total']} != {overview['kpis']['targets']}")
        expect(all(item["enabled"] in (0, 1) for item in listed["items"]),
               "站点 enabled 字段是 0/1", "出现非常规取值")
        expect(isinstance(findings["total"], int) and findings["total"] >= len(findings["items"]),
               "发现总数 >= 本页条数", "分页总数异常")
        expect(isinstance(assets["total"], int) and assets["total"] >= len(assets["items"]),
               "资产总数 >= 本页条数", "分页总数异常")
        expect(ai_status.get("enabled") is not None, "AI 状态含 enabled", "字段缺失")

        # 404 / 400 行为
        check("发现详情 404", "GET", "/api/findings/99999999", expect=404)
        check("资产历史 404", "GET", "/api/assets/99999999/history", expect=404)
        check("站点不存在 404", "PATCH", "/api/targets/99999999", body={"name": "x"}, expect=404)
        check("批量操作用空 ids 应 400", "POST", "/api/targets/bulk",
              body={"ids": [], "action": "enable"}, expect=400)
        check("非法批量动作 400", "POST", "/api/targets/bulk",
              body={"ids": [1], "action": "nuke"}, expect=400)
        check("非法发现状态 400", "POST", "/api/findings/bulk",
              body={"ids": [1], "status": "bogus"}, expect=400)
        bad_rule = check("坏正则 400", "POST", "/api/rules/test",
                         body={"pattern": "([", "sample": "x"}, expect=400)
        expect("正则无法编译" in str(bad_rule), "坏正则给明确错误", str(bad_rule)[:80])

        # ---------------- 规则编辑器 ----------------
        check("规则试跑", "POST", "/api/rules/test",
              body={"name": "Smoke Token", "pattern": r"smoke_[A-Za-z0-9]{16,24}",
                    "sample": 'var k = "smoke_a8F3kQ2zLp91XbS7";'}, shape={"count", "matches"})
        saved = check("保存自定义规则", "POST", "/api/rules/custom",
                      body={"name": "Smoke Token", "pattern": r"smoke_[A-Za-z0-9]{16,24}",
                            "severity": "low", "description": "冒烟测试用"})
        created_rule = saved.get("saved") if isinstance(saved, dict) else None
        after = call("GET", "/api/rules")[1]["items"]
        expect(any(item["id"] == created_rule for item in after),
               "自定义规则出现在列表里", f"{created_rule} 不在列表")
        check("规则调等级", "PATCH", f"/api/rules/{created_rule}", body={"severity": "medium"})
        check("规则导入 TOML", "POST", "/api/rules/import",
              body={"toml": '[[rules]]\nid = "smoke-import"\nregex = \'\'\'smoke_imp_[a-z0-9]{8}\'\'\''})
        check("删除导入规则", "DELETE", "/api/rules/custom/gl:smoke-import")

        # ---------------- 站点 CRUD + 扫描 ----------------
        target = check("新增站点", "POST", "/api/targets",
                       body={"name": "smoke-临时站", "base_url": site,
                             "interval_minutes": 1440, "max_assets": 30}, expect=201)
        tid = target["id"]
        created_target = tid
        expect(target["base_url"] == site, "新建站点地址正确", target["base_url"])
        check("站点详情(列表回读)", "GET", f"/api/targets?q=smoke-")
        check("改站点周期", "PATCH", f"/api/targets/{tid}", body={"interval_minutes": 4320})
        patched = call("GET", f"/api/targets?q=smoke-")[1]["items"][0]
        expect(patched["interval_minutes"] == 4320, "周期已按分钟落库 (3 天)", str(patched))
        check("暂停站点", "POST", "/api/targets/bulk", body={"ids": [tid], "action": "disable"})
        check("恢复站点", "POST", "/api/targets/bulk", body={"ids": [tid], "action": "enable"})

        check("触发扫描", "POST", f"/api/targets/{tid}/scan?full=true")
        scan = wait_scan(tid, timeout=args.scan_timeout)
        expect(scan.get("status") == "ok", "扫描完成且状态 ok", str(scan)[:120])
        expect(int(scan.get("assets_fetched") or 0) >= 8, "抓到至少 8 个资产", str(scan))
        expect(int(scan.get("findings_new") or 0) >= 10, "命中至少 10 条发现", str(scan))
        check("批量排队扫描", "POST", "/api/targets/scan-batch", body={"ids": [tid], "full": False})

        own_findings = call("GET", f"/api/findings?target_id={tid}&limit=100")[1]
        expect(own_findings["total"] >= 10, "该站点能查到自己的发现", str(own_findings["total"]))
        own_assets = call("GET", f"/api/assets?target_id={tid}&limit=100")[1]
        expect(own_assets["total"] >= 8 and
               all(item["target_id"] == tid for item in own_assets["items"]),
               "资产按站点筛选生效", str(own_assets["total"]))
        expect(all(item["target_id"] == tid for item in own_findings["items"]),
               "发现按站点筛选生效", "混入了其它站点的发现")
        api_assets = [a for a in own_assets["items"] if a["kind"] == "api"]
        expect(bool(api_assets), "接口响应采集生效(样例站有运行时接口)", "没有接口类资产")
        if api_assets:
            hist = check("资产版本历史", "GET", f"/api/assets/{api_assets[0]['id']}/history",
                         shape={"asset", "versions"})
            expect(isinstance(hist["versions"], list), "版本历史是数组", str(hist)[:80])
        changes = call("GET", f"/api/changes?target_id={tid}&limit=10")[1]
        expect(all(item["target_id"] == tid for item in changes["items"]),
               "变更流按站点筛选生效", "混入其它站点")

        # ---------------- 发现详情 / 状态 / 备注 ----------------
        fid = own_findings["items"][0]["id"]
        created_finding = fid
        detail = check("发现详情", "GET", f"/api/findings/{fid}",
                       shape={"id", "rule_id", "match_masked", "reuse"})
        expect(detail.get("target_name"), "详情带站点名", str(detail)[:80])
        check("改发现状态", "PATCH", f"/api/findings/{fid}", body={"status": "open"})
        check("写备注", "PATCH", f"/api/findings/{fid}", body={"notes": "smoke 备注"})
        back = call("GET", f"/api/findings/{fid}")[1]
        expect(back["status"] == "open" and back["notes"] == "smoke 备注",
               "状态与备注都已保存", str(back)[:120])
        if len(own_findings["items"]) >= 2:
            second = own_findings["items"][1]["id"]
            bulk = check("批量改状态", "POST", "/api/findings/bulk",
                         body={"ids": [fid, second], "status": "open"})
            expect("updated" in bulk, "批量改状态有 updated", str(bulk)[:80])

        # ---------------- AI 相关 ----------------
        if args.skip_ai:
            RESULTS.append(("AI 接口", "skip", "--skip-ai", 0.0))
        else:
            check("AI 连通性", "POST", "/api/ai/test", body={"ai": settings["ai"]}, timeout=120)
            check("模型列表", "POST", "/api/ai/models", body={"ai": settings["ai"]}, timeout=120)
            check("单条复核", "POST", f"/api/findings/{fid}/triage", timeout=180)
            check("由样例生成规则", "POST", f"/api/findings/{fid}/draft-rule", timeout=180)
            check("语义补扫", "POST", "/api/ai/semantic-scan",
                  body={"target_id": tid, "limit": 1}, timeout=180)

        # ---------------- 设置写回 ----------------
        keep_scan = dict(settings["scan"])
        check("保存设置", "PUT", "/api/settings",
              body={"scan": {"max_assets_per_scan": keep_scan["max_assets_per_scan"]}})
        reread = call("GET", "/api/settings")[1]
        expect(reread["scan"]["max_assets_per_scan"] == keep_scan["max_assets_per_scan"],
               "设置往返一致", "设置被改动")
        check("白名单新增", "POST", "/api/allowlist", body={"pattern": "^smoke-test-", "reason": "冒烟"},
              expect=201)
        allow = as_list(call("GET", "/api/allowlist")[1])
        entry = next((item for item in allow if item["pattern"] == "^smoke-test-"), None)
        expect(entry is not None, "白名单能查到刚加的条目", str(allow)[:80])
        if entry:
            check("白名单删除", "DELETE", f"/api/allowlist/{entry['id']}")
        if args.with_alerts:
            check("飞书测试消息", "POST", "/api/settings/alert/test", body={}, timeout=60)
        else:
            RESULTS.append(("飞书测试消息", "skip", "未加 --with-alerts", 0.0))

        # ---------------- 发现删除 ----------------
        if created_finding:
            check("删除单条发现", "DELETE", f"/api/findings/{created_finding}")
            check("删掉的发现 404", "GET", f"/api/findings/{created_finding}", expect=404)
        bulk_ids = [item["id"] for item in call("GET", f"/api/findings?target_id={tid}&limit=5")[1]["items"]]
        if bulk_ids:
            deleted = check("批量删除发现", "POST", "/api/findings/bulk",
                            body={"ids": bulk_ids, "action": "delete"})
            expect(deleted.get("deleted") == len(bulk_ids), "批量删除条数正确", str(deleted)[:80])

        # ---------------- SSE ----------------
        try:
            with urllib.request.urlopen(BASE + "/api/stream", timeout=10) as stream:
                line = stream.readline().decode("utf-8", "replace")
            expect(line.startswith("data:"), "SSE 推了第一个事件", line[:60])
        except Exception as exc:  # noqa: BLE001
            RESULTS.append(("GET /api/stream", "FAIL", f"{type(exc).__name__}: {exc}"[:100], 0.0))

    except Exception as exc:  # noqa: BLE001 - 冒烟脚本要跑完并给出汇总, 不能中途炸掉
        RESULTS.append(("脚本执行", "FAIL", f"{type(exc).__name__}: {exc}"[:200], 0.0))
    finally:
        if saved_ai:
            call("PUT", "/api/settings", {"ai": saved_ai})
        if saved_analyzers:
            call("PUT", "/api/settings", {"analyzers": {"target_scanners": saved_analyzers}})
        if created_rule:
            call("DELETE", f"/api/rules/custom/{created_rule}")
        if created_target and not args.keep:
            call("DELETE", f"/api/targets/{created_target}")
        server.shutdown()
        server.server_close()

    # ---------------- 汇总 ----------------
    failures = [row for row in RESULTS if row[1] == "FAIL"]
    width = max(len(row[0]) for row in RESULTS)
    for endpoint, level, note, ms in RESULTS:
        mark = {"ok": "✓", "FAIL": "✗", "skip": "–"}[level]
        print(f"  {mark} {endpoint:<{width}} {ms:7.0f} ms  {note}")
    print(f"\n共 {len(RESULTS)} 项: 通过 {sum(1 for r in RESULTS if r[1] == 'ok')}"
          f" · 跳过 {sum(1 for r in RESULTS if r[1] == 'skip')} · 失败 {len(failures)}")
    for endpoint, _, note, _ in failures:
        print(f"  ✗ {endpoint}: {note}")
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
