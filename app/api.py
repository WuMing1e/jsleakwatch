"""HTTP 接口层 (FastAPI)。"""
from __future__ import annotations

import asyncio
import csv
import io
import json
import re
import time
from contextlib import asynccontextmanager
from datetime import datetime, timedelta, timezone
from typing import Any
from urllib.parse import urlparse

from fastapi import FastAPI, HTTPException, Query
from fastapi.responses import FileResponse, HTMLResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

from . import __version__, ai, asset_history, db, gating
from .config import BASE_DIR, SETTINGS
from .importers.gitleaks import parse_toml, rule_to_dict
from .analyzers import analyzer_specs
from .target_scanners import target_scanner_specs
from .notify import FeishuNotifier, alert_config
from .rules import RULES, SEVERITY_ORDER, explain_rule
from .scanner import (
    bump_rules_revision,
    mark_assets_for_recheck,
    rules_revision,
    scan_config_from_settings,
    semantic_scan_target,
)
from .scheduler import SCHEDULER, scheduler_config
from .verify import available_tools

STATIC_DIR = BASE_DIR / "app" / "static"

# 一次批量导入的上限: 上千站点是常态, 但挡住把整个字典塞进来的误操作
MAX_BULK_IMPORT = 5000

@asynccontextmanager
async def lifespan(app: FastAPI):
    db.init_db()
    await SCHEDULER.start()
    try:
        yield
    finally:
        await SCHEDULER.stop()


app = FastAPI(title="JSLeakWatch", version=__version__, docs_url="/api/docs",
              redoc_url=None, lifespan=lifespan)

# 仪表盘类接口的短 TTL 缓存: 站点上千、发现上十万时, 聚合查询是唯一的瓶颈,
# 而面板容忍几秒的陈旧 —— 缓存比抠 SQL 更有效。任何写操作都会清掉它。
_dash_cache: dict[str, tuple[float, Any]] = {}


def cached(key: str, ttl: float, producer: Any) -> Any:
    now = time.monotonic()
    hit = _dash_cache.get(key)
    if hit is not None and now - hit[0] < ttl:
        return hit[1]
    value = producer()
    _dash_cache[key] = (now, value)
    return value


def invalidate_dash_cache() -> None:
    _dash_cache.clear()


# ---------------------------------------------------------------- 模型

class TargetIn(BaseModel):
    name: str = Field(default="", max_length=120)
    base_url: str
    interval_minutes: int = Field(default=360, ge=1, le=60 * 24 * 30)
    scope: str = "same-origin"
    max_depth: int = Field(default=2, ge=0, le=4)
    max_assets: int = Field(default=400, ge=1, le=5000)
    include_sourcemaps: bool = True
    probe_common_config: bool = True
    enabled: bool = True
    tags: str = ""
    notes: str = ""


class TargetPatch(BaseModel):
    name: str | None = None
    base_url: str | None = None
    interval_minutes: int | None = Field(default=None, ge=1, le=60 * 24 * 30)
    scope: str | None = None
    max_depth: int | None = Field(default=None, ge=0, le=4)
    max_assets: int | None = Field(default=None, ge=1, le=5000)
    include_sourcemaps: bool | None = None
    probe_common_config: bool | None = None
    enabled: bool | None = None
    tags: str | None = None
    notes: str | None = None


class FindingPatch(BaseModel):
    status: str | None = None
    notes: str | None = None


class BulkAction(BaseModel):
    ids: list[int]
    status: str = ""
    action: str = "status"        # status | delete


class SettingsIn(BaseModel):
    scan: dict[str, Any] | None = None
    alert: dict[str, Any] | None = None
    ai: dict[str, Any] | None = None
    ai_gate: dict[str, Any] | None = None
    discovery: dict[str, Any] | None = None
    analyzers: dict[str, Any] | None = None
    scheduler: dict[str, Any] | None = None


class AllowlistIn(BaseModel):
    pattern: str
    reason: str = ""


class TargetImportIn(BaseModel):
    urls: list[str] = Field(default_factory=list)
    text: str = ""
    interval_minutes: int = Field(default=1440, ge=1, le=60 * 24 * 30)
    max_depth: int = Field(default=1, ge=0, le=4)
    max_assets: int = Field(default=60, ge=1, le=5000)
    probe_common_config: bool = False
    enabled: bool = True
    notes: str = ""


class TargetBulkIn(BaseModel):
    ids: list[int] = Field(default_factory=list)
    action: str                      # enable | disable | delete | scan | interval
    interval_minutes: int | None = Field(default=None, ge=1, le=60 * 24 * 30)
    all_matching: bool = False       # True 时忽略 ids, 直接作用于当前筛选下的全部站点
    q: str = ""                      # 配合 all_matching 的筛选词


class RulePatch(BaseModel):
    enabled: bool | None = None
    severity: str | None = None


class RuleImportIn(BaseModel):
    toml: str = ""
    path: str = ""
    deactivate: bool = False


class RuleDraftIn(BaseModel):
    id: str = ""
    name: str = ""
    pattern: str
    severity: str = "high"
    category: str = "imported"
    description: str = ""
    keywords: list[str] = Field(default_factory=list)
    entropy_min: float = 0.0
    secret_group: int = 0
    reference: str = ""


class RuleTestIn(BaseModel):
    pattern: str
    name: str = ""
    severity: str = "high"
    category: str = "imported"
    secret_group: int = 0
    keywords: list[str] = Field(default_factory=list)
    entropy_min: float = 0.0
    sample: str = ""
    limit: int = Field(default=20, ge=1, le=100)


class AITestIn(BaseModel):
    ai: dict[str, Any] | None = None
    message: str = "连通性测试"


class SemanticScanIn(BaseModel):
    target_id: int
    limit: int = Field(default=5, ge=1, le=30)


# ---------------------------------------------------------------- 工具

VALID_STATUS = {"new", "open", "false_positive", "resolved", "ignored"}


def _normalize_url(url: str) -> str:
    url = (url or "").strip()
    if not url:
        raise HTTPException(400, "站点地址不能为空")
    if not url.startswith(("http://", "https://")):
        url = "https://" + url
    parsed = urlparse(url)
    if not parsed.netloc:
        raise HTTPException(400, "站点地址不合法")
    return url


def _target_row(tid: int) -> dict[str, Any]:
    row = db.query_one("SELECT * FROM targets WHERE id=?", (tid,))
    if row is None:
        raise HTTPException(404, "站点不存在")
    return {k: row[k] for k in row.keys()}


# ---------------------------------------------------------------- 概览

@app.get("/api/overview")
def overview(
    recent_limit: int = Query(default=10, ge=1, le=100),
    recent_offset: int = Query(default=0, ge=0),
    targets_limit: int = Query(default=10, ge=1, le=200),
    targets_offset: int = Query(default=0, ge=0),
) -> dict[str, Any]:
    # 两块表格都分页: 站点上千时"站点健康度"不能一次全列出来
    key = f"overview:{recent_limit}:{recent_offset}:{targets_limit}:{targets_offset}"
    return cached(key, 5.0, lambda: _overview_uncached(
        recent_limit, recent_offset, targets_limit, targets_offset))


def _overview_uncached(recent_limit: int = 10, recent_offset: int = 0,
                      targets_limit: int = 10, targets_offset: int = 0) -> dict[str, Any]:
    gate_sql, gate_params = gating.exclusion("f")
    gate_clause = f" AND {gate_sql}" if gate_sql else ""
    target_count = db.query_one("SELECT COUNT(*) c, SUM(enabled) e FROM targets")
    total_targets = target_count["c"] or 0
    enabled_targets = target_count["e"] or 0

    sev_rows = db.query(
        "SELECT f.severity, COUNT(*) c FROM findings f WHERE f.status IN ('new','open')"
        + gate_clause + " GROUP BY f.severity", gate_params)
    severity = {row["severity"]: row["c"] for row in sev_rows}
    for key in SEVERITY_ORDER:
        severity.setdefault(key, 0)

    status_rows = db.query(
        "SELECT f.status, COUNT(*) c FROM findings f WHERE 1=1" + gate_clause
        + " GROUP BY f.status", gate_params)
    status = {row["status"]: row["c"] for row in status_rows}

    day_ago = (datetime.now(timezone.utc) - timedelta(days=1)).isoformat(timespec="seconds")
    week_ago = (datetime.now(timezone.utc) - timedelta(days=7)).isoformat(timespec="seconds")
    new_24h = db.query_one(
        "SELECT COUNT(*) c FROM findings f WHERE f.first_seen_at >= ?" + gate_clause,
        (day_ago, *gate_params))["c"]
    new_7d = db.query_one(
        "SELECT COUNT(*) c FROM findings f WHERE f.first_seen_at >= ?" + gate_clause,
        (week_ago, *gate_params))["c"]

    timeline: list[dict[str, Any]] = []
    buckets: dict[str, int] = {}
    for row in db.query(
        "SELECT substr(f.first_seen_at, 1, 10) d, COUNT(*) c FROM findings f "
        "WHERE f.first_seen_at >= ?" + gate_clause + " GROUP BY d",
        ((datetime.now(timezone.utc) - timedelta(days=29)).isoformat(timespec="seconds"),
         *gate_params),
    ):
        buckets[row["d"]] = row["c"]
    for offset in range(29, -1, -1):
        day = (datetime.now(timezone.utc) - timedelta(days=offset)).strftime("%Y-%m-%d")
        timeline.append({"date": day, "count": buckets.get(day, 0)})

    top_rules = [
        {"rule_id": row["rule_id"], "rule_name": row["rule_name"], "severity": row["severity"],
         "count": row["c"]}
        for row in db.query(
            "SELECT f.rule_id, f.rule_name, f.severity, COUNT(*) c FROM findings f "
            "WHERE f.status IN ('new','open')" + gate_clause
            + " GROUP BY f.rule_id ORDER BY c DESC LIMIT 8", gate_params
        )
    ]

    recent = [
        _finding_dict(row)
        for row in db.query(
            "SELECT f.*, t.name AS target_name, t.base_url AS target_url FROM findings f "
            "LEFT JOIN targets t ON t.id = f.target_id "
            "WHERE f.status IN ('new','open')" + gate_clause
            + " ORDER BY f.first_seen_at DESC LIMIT ? OFFSET ?",
            (*gate_params, recent_limit, recent_offset),
        )
    ]
    recent_total = db.query_one(
        "SELECT COUNT(*) c FROM findings f WHERE f.status IN ('new','open')" + gate_clause,
        gate_params)["c"]

    gate_sql_i, gate_params_i = gating.exclusion("fi")
    gate_and = f" AND {gate_sql_i}" if gate_sql_i else ""
    target_rows = db.query(
        "SELECT t.*, COALESCE(agg.open_count, 0) AS open_count FROM targets t LEFT JOIN ("
        "  SELECT fi.target_id, SUM(CASE WHEN fi.status IN ('new','open')"
        + gate_and + " THEN 1 ELSE 0 END) AS open_count"
        "    FROM findings fi GROUP BY fi.target_id"
        ") agg ON agg.target_id = t.id "
        "ORDER BY open_count DESC, t.name COLLATE NOCASE LIMIT ? OFFSET ?",
        (*gate_params_i, targets_limit, targets_offset),
    )
    targets = [_target_dict(row) for row in target_rows]
    targets_total = db.query_one("SELECT COUNT(*) c FROM targets")["c"]

    aps = db.query_one(
        "SELECT AVG(duration_ms) a, COUNT(*) c FROM scans WHERE finished_at IS NOT NULL"
        " AND started_at >= ?",
        (day_ago,),
    )
    scans_24h = aps["c"] or 0
    avg_ms = int(aps["a"] or 0)

    # 分析器贡献度: 谁发现了多少条凭证 (按 found_by 归属统计)
    contribution: dict[str, int] = {}
    exclusive_contribution: dict[str, int] = {}
    for row in db.query("SELECT found_by, COUNT(*) c FROM findings "
                        "WHERE status IN ('new','open') GROUP BY found_by"):
        labels = [item for item in (row["found_by"] or "").split(",") if item]
        for label in labels:
            contribution[label] = contribution.get(label, 0) + row["c"]
        if len(labels) == 1:
            exclusive_contribution[labels[0]] = exclusive_contribution.get(labels[0], 0) + row["c"]

    return {
        "kpis": {
            "targets": total_targets,
            "targets_enabled": enabled_targets or 0,
            "open_findings": sum(severity.values()),
            "critical_open": (severity.get("critical", 0) + severity.get("high", 0)),
            "new_24h": new_24h,
            "new_7d": new_7d,
            "scans_24h": scans_24h,
            "avg_scan_ms": avg_ms,
        },
        "severity": severity,
        "status": status,
        "timeline": timeline,
        "top_rules": top_rules,
        "recent": recent,
        "recent_total": recent_total,
        "targets": targets,
        "targets_total": targets_total,
        "scheduler": {
            "running": len(SCHEDULER.state.running),
            "queued": len(SCHEDULER.state.queued),
            "completed": SCHEDULER.state.scans_completed,
            "last_tick": SCHEDULER.state.last_tick,
            "alert_enabled": alert_config().enabled,
            "rules_revision": rules_revision(),
        },
        "integrations": {
            "external_tools": available_tools(),
            "gitleaks_supported": True,
            "katana_available": analyzer_specs()["discovery"]["katana"]["available"],
            "analyzer_stats": {
                label: {"total": count, "exclusive": exclusive_contribution.get(label, 0)}
                for label, count in contribution.items()
            },
            "analyzers_run_in_scan": bool(
                (db.get_setting("analyzers") or {}).get("run_in_scan", True)),
            "ai": {"enabled": ai.ai_config().enabled, "model": ai.ai_config().model,
                   "kind": ai.ai_config().kind},
        },
        "analyzers": {
            "contribution": contribution,
            "exclusive": exclusive_contribution,
            "specs": analyzer_specs().get("analyzer", {}),
            "run_in_scan": bool((db.get_setting("analyzers") or {}).get("run_in_scan", True)),
            "target_scanners": target_scanner_specs(),
        },
        "server_time": db.utcnow(),
    }


# ---------------------------------------------------------------- 站点

def _target_dict(row: Any) -> dict[str, Any]:
    data = {k: row[k] for k in row.keys()}
    data["scanning"] = int(data["id"]) in SCHEDULER.state.running
    data["queued"] = any(int(t["id"]) == int(data["id"]) for t in SCHEDULER.state.queued)
    return data


TARGET_LIST_SQL = """
SELECT t.*,
       COALESCE(f.open_count, 0) AS open_count,
       COALESCE(f.new_count, 0)  AS new_count,
       COALESCE(a.asset_count, 0) AS asset_count
  FROM targets t
  LEFT JOIN (
      SELECT target_id,
             SUM(CASE WHEN status IN ('new','open') THEN 1 ELSE 0 END) AS open_count,
             SUM(CASE WHEN status = 'new' THEN 1 ELSE 0 END)           AS new_count
        FROM findings GROUP BY target_id
  ) f ON f.target_id = t.id
  LEFT JOIN (
      SELECT target_id, COUNT(*) AS asset_count FROM assets GROUP BY target_id
  ) a ON a.target_id = t.id
"""


@app.get("/api/targets")
def list_targets(
    limit: int = Query(default=0, ge=0, le=5000),
    offset: int = Query(default=0, ge=0),
    q: str = "",
) -> dict[str, Any]:
    return cached(f"targets:{limit}:{offset}:{q}", 3.0,
                  lambda: _list_targets_uncached(limit, offset, q))


def _list_targets_uncached(limit: int, offset: int, q: str) -> dict[str, Any]:
    # 子查询里的表要单独起别名, 否则门控片段里的 "f." 会指到外层 JOIN 的别名（实测报 no such column）
    gate_sql, gate_params = gating.exclusion("fi")
    gate_expr = (f"({gate_sql})" if gate_sql else "1")
    # 聚合与门控合并到一次扫描里: 避免"每个站点跑 2~3 个子查询"
    sql = f"""
    SELECT t.*,
           COALESCE(f.open_count, 0) AS open_count,
           COALESCE(f.new_count, 0)  AS new_count,
           COALESCE(a.asset_count, 0) AS asset_count
      FROM targets t
      LEFT JOIN (
          SELECT fi.target_id,
                 SUM(CASE WHEN fi.status IN ('new','open') AND {gate_expr} THEN 1 ELSE 0 END) AS open_count,
                 SUM(CASE WHEN fi.status = 'new' AND {gate_expr} THEN 1 ELSE 0 END)           AS new_count
            FROM findings fi GROUP BY fi.target_id
      ) f ON f.target_id = t.id
      LEFT JOIN (
          SELECT target_id, COUNT(*) AS asset_count FROM assets GROUP BY target_id
      ) a ON a.target_id = t.id
    """
    params: list[Any] = [*gate_params, *gate_params]
    where = ""
    count_params: list[Any] = []
    if q:
        where = " WHERE t.name LIKE ? OR t.base_url LIKE ?"
        params.extend([f"%{q}%", f"%{q}%"])
        count_params.extend([f"%{q}%", f"%{q}%"])
    sql += where + " ORDER BY open_count DESC, t.name COLLATE NOCASE"
    if limit:
        sql += " LIMIT ? OFFSET ?"
        params.extend([limit, offset])
    rows = db.query(sql, params)
    # 总数要跟筛选一致, 否则分页条和"选择全部 N 个"都会按全表算
    total = db.query_one("SELECT COUNT(*) c FROM targets t" + where, count_params)["c"]
    return {"total": total, "items": [_target_dict(row) for row in rows],
            "limit": limit or total, "offset": offset}


@app.post("/api/targets", status_code=201)
def create_target(payload: TargetIn) -> dict[str, Any]:
    invalidate_dash_cache()
    url = _normalize_url(payload.base_url)
    name = payload.name.strip() or urlparse(url).netloc
    now = db.utcnow()
    tid = db.execute(
        "INSERT INTO targets(name, base_url, enabled, interval_minutes, scope, max_depth, max_assets, "
        "include_sourcemaps, probe_common_config, tags, notes, created_at, next_scan_at) "
        "VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)",
        (name, url, 1 if payload.enabled else 0, payload.interval_minutes, payload.scope,
         payload.max_depth, payload.max_assets, 1 if payload.include_sourcemaps else 0,
         1 if payload.probe_common_config else 0, payload.tags, payload.notes, now, now),
    ).lastrowid
    db.log_event(f"新增监测站点 {name} ({url})", kind="target", target_id=int(tid or 0))
    return _target_row(int(tid or 0))


@app.post("/api/targets/import")
def import_targets(payload: TargetImportIn) -> dict[str, Any]:
    """批量导入站点。域名、URL、带路径的 URL 都能吃；自动补 https:// 并按主机去重。"""
    raw: list[str] = list(payload.urls)
    if payload.text:
        raw.extend(payload.text.splitlines())
    candidates: list[str] = []
    seen: dict[str, str] = {}          # host → 第一次出现的原始行, 用来解释"为什么这行没导入"
    invalid: list[dict[str, str]] = []
    duplicates: list[dict[str, str]] = []
    ignored = 0
    for line in raw:
        item = (line or "").strip()
        if not item or item.startswith("#"):
            ignored += 1
            continue
        if any(ch.isspace() for ch in item):
            # 一行里塞了备注/多列的 CSV 常见于此, 直接当作无效而不是造出一个假地址
            invalid.append({"line": item[:200], "reason": "一行只能有一个地址"})
            continue
        try:
            url = _normalize_url(item)
        except HTTPException as exc:
            invalid.append({"line": item[:200], "reason": str(exc.detail)})
            continue
        host = urlparse(url).netloc.lower()
        if host in seen:
            # 同一主机只有一条监测目标, 重复行要报出来, 否则用户只会看到"少了 35 条"
            duplicates.append({"line": item[:200], "host": host, "same_as": seen[host]})
            continue
        seen[host] = item[:200]
        candidates.append(url)
    if len(candidates) > MAX_BULK_IMPORT:
        raise HTTPException(400, f"单次最多导入 {MAX_BULK_IMPORT} 个站点, 本次解析出 {len(candidates)} 个")

    existing = {urlparse(row["base_url"]).netloc.lower() for row in db.query("SELECT base_url FROM targets")}
    created: list[dict[str, Any]] = []
    skipped: list[dict[str, str]] = []
    failed: list[dict[str, str]] = []
    now = db.utcnow()
    for url in candidates:
        host = urlparse(url).netloc.lower()
        if host in existing:
            skipped.append({"url": url, "reason": "已存在"})
            continue
        try:
            tid = db.execute(
                "INSERT INTO targets(name, base_url, enabled, interval_minutes, scope, max_depth, max_assets, "
                "include_sourcemaps, probe_common_config, tags, notes, created_at, next_scan_at) "
                "VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)",
                (host, url, 1 if payload.enabled else 0, payload.interval_minutes, "same-origin",
                 payload.max_depth, payload.max_assets, 1, 1 if payload.probe_common_config else 0,
                 "", payload.notes, now, now),
            ).lastrowid
        except Exception as exc:  # noqa: BLE001 - 单条失败不能连累整批
            failed.append({"url": url, "reason": f"{type(exc).__name__}: {exc}"[:160]})
            continue
        existing.add(host)
        created.append({"id": int(tid or 0), "name": host, "base_url": url})
    invalidate_dash_cache()
    db.log_event(
        f"批量导入站点: 新增 {len(created)} 个, 重复 {len(duplicates)} 行, "
        f"跳过 {len(skipped)} 个, 无效 {len(invalid)} 条"
        + (f", 失败 {len(failed)} 个" if failed else ""),
        kind="target",
    )
    return {"created": len(created), "skipped": len(skipped), "invalid": len(invalid),
            "duplicate": len(duplicates), "ignored": ignored, "failed": len(failed),
            "items": created, "skipped_detail": skipped[:50], "invalid_detail": invalid[:50],
            "duplicate_detail": duplicates[:50], "failed_detail": failed[:50]}


@app.post("/api/targets/scan-batch")
def scan_batch(payload: dict[str, Any] | None = None) -> dict[str, Any]:
    """给一批站点排队扫描（默认全部启用中的站点）。"""
    body = payload or {}
    ids = body.get("ids") or []
    full = bool(body.get("full", False))
    if ids:
        rows = [db.query_one("SELECT * FROM targets WHERE id=?", (int(i),)) for i in ids]
    else:
        rows = db.query("SELECT * FROM targets WHERE enabled=1")
    queued = 0
    for row in rows:
        if row is None:
            continue
        target = {k: row[k] for k in row.keys()}
        if SCHEDULER.enqueue(target, full=full):
            queued += 1
    invalidate_dash_cache()
    return {"queued": queued, "total": len(rows)}


@app.post("/api/targets/bulk")
async def bulk_targets(payload: TargetBulkIn) -> dict[str, Any]:
    """站点批量操作: 启用 / 暂停 / 删除 / 立即扫描 / 统一改巡检周期。"""
    action = (payload.action or "").strip().lower()
    if action not in ("enable", "disable", "delete", "scan", "interval"):
        raise HTTPException(400, "action 需为 enable / disable / delete / scan / interval")
    if payload.all_matching:
        # "全选所有匹配": 只信任服务端自己解析出来的 id, 避免前端把上千个 id 全塞进请求体
        if payload.q:
            rows = db.query("SELECT id FROM targets WHERE name LIKE ? OR base_url LIKE ?",
                            (f"%{payload.q}%", f"%{payload.q}%"))
        else:
            rows = db.query("SELECT id FROM targets")
        ids = [int(row["id"]) for row in rows]
    else:
        ids = [int(i) for i in payload.ids]
    if not ids:
        raise HTTPException(400, "未选择任何站点")
    if action == "interval" and not payload.interval_minutes:
        raise HTTPException(400, "请提供 interval_minutes")

    marks = ",".join("?" * len(ids))
    if action == "delete":
        db.query_one(f"SELECT COUNT(*) c FROM targets WHERE id IN ({marks})", ids)  # 校验存在
        for tid in ids:                       # 在跑的扫描一并取消, 别留下"幽灵扫描"
            SCHEDULER.cancel_target(int(tid))
        db.execute(f"DELETE FROM targets WHERE id IN ({marks})", ids)
        affected = len(ids)
    elif action in ("enable", "disable"):
        wanted = 1 if action == "enable" else 0
        # 只改状态确实不同的行: 这样 affected 是"这次真的停了几个", 而不是"点了几个"
        cur = db.execute(f"UPDATE targets SET enabled=? WHERE id IN ({marks}) AND enabled<>?",
                         (wanted, *ids, wanted))
        affected = cur.rowcount if cur.rowcount is not None else len(ids)
    elif action == "interval":
        db.execute(f"UPDATE targets SET interval_minutes=? WHERE id IN ({marks})",
                   (payload.interval_minutes, *ids))
        affected = len(ids)
    else:  # scan
        affected = 0
        for tid in ids:
            row = db.query_one("SELECT * FROM targets WHERE id=?", (tid,))
            if row is None:
                continue
            if SCHEDULER.enqueue({k: row[k] for k in row.keys()}, full=False):
                affected += 1

    invalidate_dash_cache()
    scope = "全部匹配" if payload.all_matching else "已选"
    db.log_event(f"站点批量操作 {action}: {scope} {affected} 个", kind="target")
    return {"action": action, "affected": affected, "requested": len(ids),
            "all_matching": payload.all_matching}


@app.patch("/api/targets/{tid}")
def update_target(tid: int, payload: TargetPatch) -> dict[str, Any]:
    invalidate_dash_cache()
    current = _target_row(tid)
    fields: dict[str, Any] = {}
    for key, value in payload.model_dump(exclude_none=True).items():
        if key == "base_url":
            value = _normalize_url(value)
        if key in ("include_sourcemaps", "probe_common_config", "enabled"):
            value = 1 if value else 0
        fields[key] = value
    if fields:
        sets = ", ".join(f"{key}=?" for key in fields)
        db.execute(f"UPDATE targets SET {sets} WHERE id=?", (*fields.values(), tid))
    if fields.get("enabled") == 1:
        db.execute("UPDATE targets SET next_scan_at=? WHERE id=? AND next_scan_at IS NULL",
                   (db.utcnow(), tid))
    _ = current
    return _target_row(tid)


@app.delete("/api/targets/{tid}")
def delete_target(tid: int) -> dict[str, Any]:
    invalidate_dash_cache()
    target = _target_row(tid)
    # 先取消在跑的扫描: 否则删掉的站点还会继续抓、继续推告警
    cancelled = SCHEDULER.cancel_target(tid)
    db.execute("DELETE FROM targets WHERE id=?", (tid,))
    db.log_event(f"删除监测站点 {target['name']}" + ("（同时取消了正在进行的扫描）" if cancelled else ""),
                 kind="target")
    return {"deleted": tid, "scan_cancelled": cancelled}


@app.post("/api/targets/{tid}/scan")
async def trigger_scan(tid: int, full: bool = Query(default=True)) -> dict[str, Any]:
    invalidate_dash_cache()
    target = _target_row(tid)
    if int(tid) in SCHEDULER.state.running:
        return {"queued": False, "reason": "该站点正在扫描中"}
    ok = await SCHEDULER.run_now(target, full=full)
    if not ok:
        return {"queued": False, "reason": "该站点已在队列中"}
    db.log_event(f"手动触发扫描 {target['name']}", kind="scan", target_id=tid)
    return {"queued": True, "full": full}


# ---------------------------------------------------------------- 发现

def _finding_dict(row: Any) -> dict[str, Any]:
    keys = row.keys()
    data = {k: row[k] for k in keys}
    if "target_name" not in data:
        target = db.query_one("SELECT name, base_url FROM targets WHERE id=?", (row["target_id"],))
        data["target_name"] = target["name"] if target else f"#{row['target_id']}"
        data["target_url"] = target["base_url"] if target else ""
    return data


@app.get("/api/findings")
def list_findings(
    status: str = "",
    severity: str = "",
    target_id: int | None = None,
    rule_id: str = "",
    category: str = "",
    ai_verdict: str = "",
    origin: str = "",
    include_gated: bool = False,
    q: str = "",
    limit: int = Query(default=100, ge=1, le=1000),
    offset: int = Query(default=0, ge=0),
    sort: str = "recent",
) -> dict[str, Any]:
    where: list[str] = []
    params: list[Any] = []
    if status:
        statuses = [s for s in status.split(",") if s in VALID_STATUS]
        if statuses:
            where.append(f"f.status IN ({','.join('?' * len(statuses))})")
            params.extend(statuses)
    if severity:
        sevs = [s for s in severity.split(",") if s in SEVERITY_ORDER]
        if sevs:
            where.append(f"f.severity IN ({','.join('?' * len(sevs))})")
            params.extend(sevs)
    if target_id:
        where.append("f.target_id = ?")
        params.append(target_id)
    if rule_id:
        where.append("f.rule_id = ?")
        params.append(rule_id)
    if category:
        where.append("f.category = ?")
        params.append(category)
    if ai_verdict:
        verdicts = [v for v in ai_verdict.split(",") if v in ai.VERDICTS or v == "none"]
        if verdicts:
            clause_parts = []
            for verdict in verdicts:
                if verdict == "none":
                    clause_parts.append("f.ai_verdict = ''")
                else:
                    clause_parts.append("f.ai_verdict = ?")
                    params.append(verdict)
            where.append("(" + " OR ".join(clause_parts) + ")")
    if origin:
        origins = [o for o in origin.split(",") if o in ("rule", "ai")]
        if origins:
            where.append(f"f.origin IN ({','.join('?' * len(origins))})")
            params.extend(origins)

    # 高误报来源的 AI 预筛: 未被 AI 确认的发现默认不出现在列表里
    gate_sql, gate_params = gating.exclusion("f")
    if gate_sql and not include_gated:
        where.append(gate_sql)
        params.extend(gate_params)
    if q:
        where.append("(f.match_masked LIKE ? OR f.asset_url LIKE ? OR f.rule_name LIKE ? OR f.context LIKE ?)")
        like = f"%{q}%"
        params.extend([like] * 4)
    clause = ("WHERE " + " AND ".join(where)) if where else ""
    order = {
        "recent": "f.first_seen_at DESC",
        "oldest": "f.first_seen_at ASC",
        "severity": "CASE f.severity WHEN 'critical' THEN 4 WHEN 'high' THEN 3 WHEN 'medium' THEN 2 "
                    "WHEN 'low' THEN 1 ELSE 0 END DESC, f.first_seen_at DESC",
        "target": "f.target_id ASC, f.first_seen_at DESC",
    }.get(sort, "f.first_seen_at DESC")

    total = db.query_one(f"SELECT COUNT(*) c FROM findings f {clause}", params)["c"]
    rows = db.query(
        f"SELECT f.*, t.name AS target_name, t.base_url AS target_url FROM findings f "
        f"LEFT JOIN targets t ON t.id = f.target_id {clause} ORDER BY {order} LIMIT ? OFFSET ?",
        (*params, limit, offset),
    )
    items = [_finding_dict(row) for row in rows]
    _attach_reuse_counts(items)
    return {"total": total, "items": items,
            "limit": limit, "offset": offset,
            "gated": {"applied": bool(gate_sql and not include_gated), **gating.hidden_count()}}


def _attach_reuse_counts(items: list[dict[str, Any]]) -> None:
    """给列表页的每一条标注"同一命中值出现在几个站点"。"""
    hashes = {item["match_sha256"] for item in items if item.get("match_sha256")}
    if not hashes:
        return
    marks = ",".join("?" * len(hashes))
    rows = db.query(
        f"SELECT match_sha256, COUNT(*) c, COUNT(DISTINCT target_id) sites "
        f"FROM findings WHERE match_sha256 IN ({marks}) GROUP BY match_sha256",
        list(hashes),
    )
    seen = {row["match_sha256"]: (row["c"], row["sites"]) for row in rows}
    for item in items:
        count, sites = seen.get(item.get("match_sha256"), (1, 1))
        item["reuse_count"] = count
        item["reuse_sites"] = sites


@app.get("/api/findings/export.csv")
def export_findings(status: str = "new,open", include_gated: bool = False) -> StreamingResponse:
    statuses = [s for s in status.split(",") if s in VALID_STATUS] or ["new", "open"]
    marks = ",".join("?" * len(statuses))
    gate_sql, gate_params = gating.exclusion("f")
    gate_clause = f" AND {gate_sql}" if (gate_sql and not include_gated) else ""
    rows = db.query(
        f"SELECT f.*, t.name AS target_name, t.base_url AS target_url FROM findings f "
        f"LEFT JOIN targets t ON t.id=f.target_id WHERE f.status IN ({marks}){gate_clause} "
        f"ORDER BY f.target_id, f.severity",
        (*statuses, *(gate_params if gate_clause else [])),
    )
    buffer = io.StringIO()
    writer = csv.writer(buffer)
    writer.writerow(["站点", "入口", "规则ID", "规则", "等级", "分类", "命中值", "文件地址",
                     "行号", "状态", "验证", "首次发现", "最近出现", "次数"])
    for row in rows:
        writer.writerow([
            row["target_name"], row["target_url"], row["rule_id"], row["rule_name"],
            row["severity"], row["category"], row["match_masked"], row["asset_url"],
            row["line_no"], row["status"], row["verified"], row["first_seen_at"],
            row["last_seen_at"], row["times_seen"],
        ])
    buffer.seek(0)
    filename = f"jsleakwatch-findings-{datetime.now().strftime('%Y%m%d-%H%M')}.csv"
    return StreamingResponse(
        iter([buffer.getvalue().encode("utf-8-sig")]),
        media_type="text/csv; charset=utf-8",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


@app.get("/api/findings/{fid}")
def get_finding(fid: int) -> dict[str, Any]:
    row = db.query_one(
        "SELECT f.*, t.name AS target_name, t.base_url AS target_url FROM findings f "
        "LEFT JOIN targets t ON t.id = f.target_id WHERE f.id=?", (fid,))
    if row is None:
        raise HTTPException(404, "发现不存在")
    data = _finding_dict(row)
    if db.get_setting("store_raw_reveal", False) and row["raw_value"]:
        data["raw_value"] = row["raw_value"]
    data["reuse"] = reuse_of(row["match_sha256"], exclude_id=fid)
    return data


def reuse_of(match_sha256: str, exclude_id: int = 0) -> list[dict[str, Any]]:
    """同一个命中值还出现在哪些站点/文件 —— 同一把密钥被多处复用是最值得追的线索。"""
    if not match_sha256:
        return []
    rows = db.query(
        "SELECT f.id, f.target_id, f.asset_url, f.status, f.severity, f.rule_id, "
        "       f.first_seen_at, t.name AS target_name "
        "  FROM findings f LEFT JOIN targets t ON t.id = f.target_id "
        " WHERE f.match_sha256 = ? AND f.id <> ? ORDER BY f.first_seen_at DESC LIMIT 50",
        (match_sha256, exclude_id),
    )
    return [{k: row[k] for k in row.keys()} for row in rows]


@app.patch("/api/findings/{fid}")
def update_finding(fid: int, payload: FindingPatch) -> dict[str, Any]:
    invalidate_dash_cache()
    fields: dict[str, Any] = {}
    if payload.status is not None:
        if payload.status not in VALID_STATUS:
            raise HTTPException(400, f"状态需为 {sorted(VALID_STATUS)}")
        fields["status"] = payload.status
    if payload.notes is not None:
        fields["notes"] = payload.notes[:2000]
    if fields:
        sets = ", ".join(f"{k}=?" for k in fields)
        db.execute(f"UPDATE findings SET {sets} WHERE id=?", (*fields.values(), fid))
    return get_finding(fid)


@app.post("/api/findings/bulk")
def bulk_findings(payload: BulkAction) -> dict[str, Any]:
    invalidate_dash_cache()
    if not payload.ids:
        return {"updated": 0, "deleted": 0, "requested": 0}
    marks = ",".join("?" * len(payload.ids))
    if (payload.action or "status").strip().lower() == "delete":
        victims = db.query(f"SELECT target_id, asset_url FROM findings WHERE id IN ({marks})",
                           payload.ids)
        cur = db.execute(f"DELETE FROM findings WHERE id IN ({marks})", payload.ids)
        deleted = cur.rowcount if cur.rowcount is not None else len(payload.ids)
        # 让受影响的资产下一轮重新跑规则, 否则删掉的命中永远不会再出现
        rearmed = mark_assets_for_recheck(victims)
        db.log_event(f"批量删除发现: {deleted} 条"
                     + (f", {rearmed} 个资产下轮重新检测" if rearmed else ""), kind="finding")
        return {"deleted": deleted, "requested": len(payload.ids), "rearmed": rearmed}
    if payload.status not in VALID_STATUS:
        raise HTTPException(400, "非法状态")
    # 只统计状态确实变化的行, 前端提示才不会虚报
    cur = db.execute(f"UPDATE findings SET status=? WHERE id IN ({marks}) AND status<>?",
                     (payload.status, *payload.ids, payload.status))
    updated = cur.rowcount if cur.rowcount is not None else len(payload.ids)
    return {"updated": updated, "status": payload.status, "requested": len(payload.ids)}


@app.delete("/api/findings/{fid}")
def delete_finding(fid: int) -> dict[str, Any]:
    invalidate_dash_cache()
    row = db.query_one(
        "SELECT id, target_id, asset_url, rule_name, match_masked FROM findings WHERE id=?", (fid,)
    )
    if row is None:
        raise HTTPException(404, "发现不存在")
    db.execute("DELETE FROM findings WHERE id=?", (fid,))
    rearmed = mark_assets_for_recheck([row])
    db.log_event(f"删除发现 {row['rule_name']} {row['match_masked']}", kind="finding")
    return {"deleted": fid, "rearmed": rearmed}


# ---------------------------------------------------------------- 资产 / 扫描记录 / 事件

@app.get("/api/assets")
def list_assets(target_id: int | None = None, target: int | None = None, q: str = "",
                limit: int = Query(200, ge=1, le=2000), offset: int = 0) -> dict[str, Any]:
    # 前端历史版本用的是 target=, 两个名字都收, 免得筛选静默失效
    target_id = target_id or target
    where, params = [], []
    if target_id:
        where.append("a.target_id = ?")
        params.append(target_id)
    if q:
        where.append("a.url LIKE ?")
        params.append(f"%{q}%")
    clause = ("WHERE " + " AND ".join(where)) if where else ""
    total = db.query_one(f"SELECT COUNT(*) c FROM assets a {clause}", params)["c"]
    rows = db.query(
        f"SELECT a.*, t.name AS target_name FROM assets a LEFT JOIN targets t ON t.id=a.target_id "
        f"{clause} ORDER BY a.last_seen_at DESC LIMIT ? OFFSET ?", (*params, limit, offset),
    )
    items = [{k: row[k] for k in row.keys()} for row in rows]
    ids = [item["id"] for item in items]
    counts: dict[int, int] = {}
    if ids:
        marks = ",".join("?" * len(ids))
        counts = {
            row["asset_id"]: row["c"]
            for row in db.query(
                f"SELECT asset_id, COUNT(*) c FROM asset_versions "
                f"WHERE asset_id IN ({marks}) GROUP BY asset_id", ids)
        }
    for item in items:
        item["versions"] = counts.get(item["id"], 0)
    return {"total": total, "items": items}


@app.get("/api/changes")
def list_changes(
    target_id: int | None = None,
    limit: int = Query(60, ge=1, le=300),
    hours: int = Query(0, ge=0, le=24 * 90),
    only_diff: bool = True,
) -> dict[str, Any]:
    """跨站变更流: 最近哪些 JS 变了、变了什么。"""
    items = asset_history.recent_changes(target_id=target_id, limit=limit, hours=hours,
                                         only_diff=only_diff)
    return {"total": len(items), "items": items}


@app.get("/api/assets/{aid}/history")
def asset_history_endpoint(aid: int, limit: int = Query(12, ge=1, le=50)) -> dict[str, Any]:
    row = db.query_one("SELECT * FROM assets WHERE id=?", (aid,))
    if row is None:
        raise HTTPException(404, "资产不存在")
    target = db.query_one("SELECT name FROM targets WHERE id=?", (row["target_id"],))
    return {
        "asset": {**{k: row[k] for k in row.keys()}, "target_name": target["name"] if target else ""},
        "versions": asset_history.history(aid, limit),
    }


@app.get("/api/scans")
def list_scans(target_id: int | None = None, limit: int = Query(50, ge=1, le=500)) -> list[dict[str, Any]]:
    if target_id:
        rows = db.query(
            "SELECT s.*, t.name AS target_name FROM scans s LEFT JOIN targets t ON t.id=s.target_id "
            "WHERE s.target_id=? ORDER BY s.id DESC LIMIT ?", (target_id, limit))
    else:
        rows = db.query(
            "SELECT s.*, t.name AS target_name FROM scans s LEFT JOIN targets t ON t.id=s.target_id "
            "ORDER BY s.id DESC LIMIT ?", (limit,))
    return [{k: row[k] for k in row.keys()} for row in rows]


@app.get("/api/events")
def list_events(limit: int = Query(80, ge=1, le=500), level: str = "") -> list[dict[str, Any]]:
    if level:
        rows = db.query("SELECT * FROM events WHERE level=? ORDER BY id DESC LIMIT ?", (level, limit))
    else:
        rows = db.query("SELECT * FROM events ORDER BY id DESC LIMIT ?", (limit,))
    return [{k: row[k] for k in row.keys()} for row in rows]


# ---------------------------------------------------------------- 规则

@app.get("/api/rules")
def list_rules() -> dict[str, Any]:
    overrides = {row["rule_id"]: row for row in db.query("SELECT * FROM rule_overrides")}
    hits = {row["rule_id"]: row["c"] for row in db.query(
        "SELECT rule_id, COUNT(*) c FROM findings GROUP BY rule_id")}
    items: list[dict[str, Any]] = []
    custom_ids: set[str] = set()
    for rule in RULES:
        override = overrides.get(rule.id)
        items.append({
            "id": rule.id,
            "name": rule.name,
            "severity": (override["severity"] if override and override["severity"] else rule.severity),
            "default_severity": rule.severity,
            "category": rule.category,
            "description": rule.description,
            "enabled": (override["enabled"] != 0) if override and override["enabled"] is not None
            else rule.default_enabled,
            "builtin": True,
            "hits": hits.get(rule.id, 0),
            "tags": list(rule.tags),
            "reference": rule.reference,
        })
    for item in (db.get_setting("custom_rules") or []):
        custom_ids.add(item.get("id", ""))
        override = overrides.get(item.get("id", ""))
        items.append({
            "id": item.get("id"),
            "name": item.get("name"),
            "severity": (override["severity"] if override and override["severity"] else item.get("severity")),
            "default_severity": item.get("severity"),
            "category": item.get("category", "imported"),
            "description": item.get("description", ""),
            "enabled": (override["enabled"] != 0) if override and override["enabled"] is not None else True,
            "builtin": False,
            "hits": hits.get(item.get("id"), 0),
            "tags": item.get("tags", []),
            "reference": item.get("reference", ""),
        })
    return {"items": items, "revision": rules_revision()}


@app.patch("/api/rules/{rule_id:path}")
def patch_rule(rule_id: str, payload: RulePatch) -> dict[str, Any]:
    invalidate_dash_cache()
    enabled = None if payload.enabled is None else (1 if payload.enabled else 0)
    severity = payload.severity if payload.severity in SEVERITY_ORDER else None
    db.execute(
        "INSERT INTO rule_overrides(rule_id, enabled, severity) VALUES(?,?,?) "
        "ON CONFLICT(rule_id) DO UPDATE SET "
        "enabled=COALESCE(excluded.enabled, rule_overrides.enabled), "
        "severity=COALESCE(excluded.severity, rule_overrides.severity)",
        (rule_id, enabled, severity),
    )
    bump_rules_revision()
    return {"rule_id": rule_id, "enabled": enabled, "severity": severity,
            "revision": rules_revision()}


@app.post("/api/rules/import")
def import_rules(payload: RuleImportIn) -> dict[str, Any]:
    text = payload.toml
    if not text and payload.path:
        try:
            with open(payload.path, encoding="utf-8") as handle:  # noqa: PTH123
                text = handle.read()
        except OSError as exc:
            raise HTTPException(400, f"读取规则文件失败: {exc}") from exc
    if not text.strip():
        raise HTTPException(400, "请提供 gitleaks TOML 内容或本地路径")
    try:
        rules = parse_toml(text, prefix="gl")
    except Exception as exc:  # noqa: BLE001
        raise HTTPException(400, f"解析失败: {exc}") from exc
    if not rules:
        raise HTTPException(400, "未解析到任何规则 (需要 [[rules]] 与 regex 字段)")
    existing = {item["id"]: item for item in (db.get_setting("custom_rules") or [])}
    for rule in rules:
        existing[rule.id] = rule_to_dict(rule)
    db.set_setting("custom_rules", list(existing.values()))
    bump_rules_revision()
    return {"imported": len(rules), "total_custom": len(existing), "revision": rules_revision()}


@app.delete("/api/rules/custom/{rule_id:path}")
def delete_custom_rule(rule_id: str) -> dict[str, Any]:
    items = [item for item in (db.get_setting("custom_rules") or []) if item.get("id") != rule_id]
    db.set_setting("custom_rules", items)
    bump_rules_revision()
    return {"deleted": rule_id, "total_custom": len(items)}


def _rule_from_draft(payload: RuleDraftIn | RuleTestIn, prefix: str = "custom") -> Any:
    """把编辑器的输入变成一条 Rule。

    id 规则: 没带前缀的补 custom:, 已带前缀(gl: / custom:)的原样保留 —— 否则编辑一条
    导入进来的规则会变成新建一条, 老的留在那里。
    """
    from .importers.gitleaks import rule_from_dict

    raw_id = ((payload.id or payload.name or "rule") if isinstance(payload, RuleDraftIn)
              else (payload.name or "rule")).strip()
    if ":" in raw_id:
        head, _, tail = raw_id.partition(":")
        rule_id = f"{head}:{_slugify(tail)}"
    else:
        rule_id = f"{prefix}:{_slugify(raw_id)}"
    if any(rule.id == rule_id for rule in RULES):
        raise HTTPException(400, f"规则 id「{rule_id}」与内置规则重名, 请换一个名字")
    return rule_from_dict({
        "id": rule_id,
        "name": payload.name or rule_id,
        "severity": payload.severity,
        "category": payload.category or "imported",
        "pattern": payload.pattern,
        "description": getattr(payload, "description", ""),
        "secret_group": payload.secret_group,
        "keywords": payload.keywords,
        "entropy_min": payload.entropy_min,
        "reference": getattr(payload, "reference", ""),
        "tags": ["custom"],
    })


def _slugify(value: str) -> str:
    return re.sub(r"[^a-z0-9\u4e00-\u9fff]+", "-", value.lower()).strip("-") or "rule"


@app.post("/api/rules/test")
def test_rule(payload: RuleTestIn) -> dict[str, Any]:
    """拿一段样例当场验证正则: 走的是和真实扫描同一套过滤逻辑。"""
    if not (payload.sample or "").strip():
        raise HTTPException(400, "请粘贴一段样例文本")
    if not (payload.pattern or "").strip():
        raise HTTPException(400, "请填写正则表达式")
    try:
        rule = _rule_from_draft(payload)
    except HTTPException:
        raise
    except Exception as exc:  # noqa: BLE001
        raise HTTPException(400, f"规则不合法: {exc}") from exc
    allowlist = [row["pattern"] for row in db.query("SELECT pattern FROM allowlist")]
    try:
        report = explain_rule(rule, payload.sample, allowlist=allowlist, limit=payload.limit)
    except ValueError as exc:  # 正则写错时给明确报错
        raise HTTPException(400, str(exc)) from exc
    report["matches"] = [{
        "match": item.raw, "masked": item.masked, "line_no": item.line_no,
        "entropy": item.entropy, "context": item.context,
    } for item in report["matches"]]
    if not report["count"] and report["rejected"]:
        report["hint"] = "正则本身能匹配, 但被内置过滤器挡掉了 —— " \
                         + "、".join(f"{name} {count} 处" for name, count in report["rejected"].items())
    elif not report["raw_count"]:
        report["hint"] = "这段样例里正则一处都没匹配上, 检查一下模式是否太严"
    return {**report, "rule_id": rule.id}


@app.post("/api/rules/custom")
def save_custom_rule(payload: RuleDraftIn) -> dict[str, Any]:
    """新建或覆盖一条自定义规则。"""
    if not (payload.pattern or "").strip():
        raise HTTPException(400, "请填写正则表达式")
    rule = _rule_from_draft(payload)
    from .importers.gitleaks import rule_to_dict

    items = {item["id"]: item for item in (db.get_setting("custom_rules") or [])}
    items[rule.id] = rule_to_dict(rule)
    db.set_setting("custom_rules", list(items.values()))
    bump_rules_revision()
    db.log_event(f"新增/更新自定义规则 {rule.id}", kind="rules")
    return {"saved": rule.id, "total_custom": len(items), "revision": rules_revision()}


@app.get("/api/rules/quality")
def rules_quality(min_samples: int = Query(3, ge=1, le=50)) -> dict[str, Any]:
    """用真实命中的 AI 复核结果给规则打分: 谁在制造误报, 一眼看出来。"""
    rows = db.query(
        "SELECT rule_id, rule_name, COUNT(*) hits, COUNT(DISTINCT target_id) sites, "
        "  SUM(CASE WHEN ai_verdict <> '' THEN 1 ELSE 0 END) judged, "
        "  SUM(CASE WHEN ai_verdict = 'fake' THEN 1 ELSE 0 END) fake, "
        "  SUM(CASE WHEN ai_verdict = 'real' THEN 1 ELSE 0 END) real, "
        "  SUM(CASE WHEN ai_verdict = 'public' THEN 1 ELSE 0 END) public, "
        "  SUM(CASE WHEN ai_verdict = 'uncertain' THEN 1 ELSE 0 END) uncertain "
        "  FROM findings GROUP BY rule_id ORDER BY hits DESC"
    )
    items: list[dict[str, Any]] = []
    for row in rows:
        judged = int(row["judged"] or 0)
        fake = int(row["fake"] or 0)
        fp_rate = (fake / judged) if judged else 0.0
        if judged < min_samples:
            advice, tone = "样本不足", "muted"
        elif fp_rate >= 0.8:
            advice, tone = "建议关闭或加白名单", "err"
        elif fp_rate >= 0.6:
            advice, tone = "建议降级 / 交给门控", "warn"
        elif fp_rate <= 0.2:
            advice, tone = "信号良好", "ok"
        else:
            advice, tone = "继续观察", ""
        items.append({
            "rule_id": row["rule_id"], "rule_name": row["rule_name"],
            "hits": int(row["hits"] or 0), "sites": int(row["sites"] or 0),
            "judged": judged, "fake": fake, "real": int(row["real"] or 0),
            "public": int(row["public"] or 0), "uncertain": int(row["uncertain"] or 0),
            "fp_rate": round(fp_rate, 3), "advice": advice, "tone": tone,
        })
    ranked = sorted(
        [item for item in items if item["judged"] >= min_samples],
        key=lambda item: (-item["fp_rate"], -item["judged"]),
    )
    total_judged = sum(item["judged"] for item in items)
    total_fake = sum(item["fake"] for item in items)
    usage = db.query_one("SELECT calls, cached, fails FROM ai_usage WHERE day=?",
                         (db.utcnow()[:10],))
    return {
        "items": items,
        "ranked": ranked,
        "summary": {
            "rules_with_hits": len(items),
            "judged": total_judged,
            "fake": total_fake,
            "fp_rate": round(total_fake / total_judged, 3) if total_judged else 0.0,
            "min_samples": min_samples,
            "ai_today": {k: usage[k] for k in usage.keys()} if usage else None,
        },
    }


# ---------------------------------------------------------------- 设置

def alert_status() -> dict[str, Any]:
    """告警排障用: 最近一次推送结果 + 还没推送过的、达到推送等级的发现数。"""
    rows = db.query("SELECT ts, level, message FROM events WHERE kind='alert' ORDER BY id DESC LIMIT 1")
    last = {k: rows[0][k] for k in rows[0].keys()} if rows else None
    pending = db.query_one(
        "SELECT COUNT(*) c FROM findings WHERE notified_at IS NULL AND status IN ('new','open') "
        "AND severity IN ('critical','high','medium') AND ai_verdict <> 'fake'"
    )
    return {"last_event": last, "pending_alertable": pending["c"] if pending else 0}


@app.get("/api/settings")
def get_settings() -> dict[str, Any]:
    scan = scan_config_from_settings()
    alert = alert_config()
    ai_cfg = ai.ai_config()
    scan_payload = dict(scan.__dict__)
    # 采集凭据属于敏感信息: 只回显"配了哪些头", 不回显值
    scan_payload["extra_headers"] = ""
    scan_payload["cookies"] = ""
    scan_payload["credential_headers"] = sorted((scan.extra_headers or {}).keys())
    scan_payload["has_cookies"] = bool(scan.cookies)
    scan_payload["credential_mode"] = "带凭据采集" if (scan.extra_headers or scan.cookies) else "匿名采集"
    return {
        "scan": scan_payload,
        "alert": {
            **alert.__dict__,
            "app_secret": "***" if alert.app_secret else "",
            "has_app_secret": bool(alert.app_secret),
        },
        "alert_status": alert_status(),
        "ai": {
            **ai_cfg.__dict__,
            "api_key": "***" if ai_cfg.api_key else "",
            "has_api_key": bool(ai_cfg.api_key),
            "presets": ai.AI_PRESETS,
        },
        "ai_gate": {**gating.gate_config(), "summary": gating.summary()},
        "scheduler": scheduler_config(),
        "server": {"host": SETTINGS.host, "port": SETTINGS.port, "version": __version__,
                   "data_dir": str(SETTINGS.db_path.parent)},
        "integrations": {
            "external_tools": available_tools(),
            "gitleaks_supported": True,
            "ai": {"enabled": ai_cfg.enabled, "model": ai_cfg.model, "kind": ai_cfg.kind},
        },
        "discovery": db.get_setting("discovery") or {},
        "analyzer_specs": analyzer_specs(),
        "target_scanners": target_scanner_specs(),
        "target_scanner_config": (db.get_setting("analyzers") or {}).get("target_scanners") or {},
        "rules_revision": rules_revision(),
    }


@app.put("/api/settings")
def put_settings(payload: SettingsIn) -> dict[str, Any]:
    invalidate_dash_cache()
    if payload.scan:
        current = db.get_setting("scan") or {}
        allowed = set(scan_config_from_settings().__dict__.keys())
        for key, value in payload.scan.items():
            if key in allowed:
                current[key] = value
        db.set_setting("scan", current)
    if payload.alert:
        current_alert = db.get_setting("alert") or {}
        for key, value in payload.alert.items():
            if key == "app_secret" and value in ("", "***"):
                continue
            if hasattr(alert_config(), key) and value is not None:
                current_alert[key] = value
        db.set_setting("alert", current_alert)
    if payload.ai:
        current_ai = db.get_setting("ai") or {}
        allowed_ai = set(ai.ai_config().__dict__.keys())
        for key, value in payload.ai.items():
            if key == "api_key" and value in ("", "***"):
                continue
            if key in allowed_ai and value is not None:
                current_ai[key] = value
        db.set_setting("ai", current_ai)
    if payload.ai_gate:
        gating.save_gate_config(payload.ai_gate)
    if payload.scheduler:
        current = db.get_setting("scheduler") or {}
        for key in ("max_parallel_targets", "tick_seconds"):
            value = payload.scheduler.get(key)
            if value is not None:
                current[key] = max(1, int(value))
        db.set_setting("scheduler", current)
        db.log_event(f"更新调度器设置: {current}（重启后生效）", kind="settings")
    if payload.discovery:
        current_discovery = db.get_setting("discovery") or {}
        for key, value in payload.discovery.items():
            if key == "katana" and isinstance(value, dict):
                current_discovery["katana"] = {**(current_discovery.get("katana") or {}), **value}
            elif value is not None:
                current_discovery[key] = value
        db.set_setting("discovery", current_discovery)
    if payload.analyzers:
        current_analyzers = db.get_setting("analyzers") or {}
        incoming = payload.analyzers
        if "run_in_scan" in incoming:
            current_analyzers["run_in_scan"] = bool(incoming["run_in_scan"])
        cli = current_analyzers.get("cli_analyzers") or {}
        for name, patch in (incoming.get("cli_analyzers") or {}).items():
            if isinstance(patch, dict):
                cli[name] = {**(cli.get(name) or {}), **patch}
        current_analyzers["cli_analyzers"] = cli
        target = current_analyzers.get("target_scanners") or {}
        for name, patch in (incoming.get("target_scanners") or {}).items():
            if isinstance(patch, dict):
                target[name] = {**(target.get(name) or {}), **patch}
        current_analyzers["target_scanners"] = target
        db.set_setting("analyzers", current_analyzers)
    db.log_event("更新系统设置", kind="settings")
    return get_settings()


@app.post("/api/settings/alert/test")
async def test_alert() -> dict[str, Any]:
    notifier = FeishuNotifier(alert_config())
    ok, message = await notifier.send_test()
    if ok:
        db.log_event("飞书测试消息发送成功", kind="alert")
    else:
        db.log_event(f"飞书测试消息发送失败: {message}", kind="alert", level="warn")
    return {"ok": ok, "message": message}


# ---------------------------------------------------------------- AI 辅助

def _ai_cfg_from(payload: dict[str, Any] | None) -> ai.AIConfig:
    """用请求里的临时配置覆盖已保存配置, 便于"先测试再保存"。"""
    cfg = ai.ai_config()
    for key, value in (payload or {}).items():
        if key == "api_key" and value in ("", "***"):
            continue
        if hasattr(cfg, key) and value is not None:
            setattr(cfg, key, value)
    return cfg


@app.get("/api/ai/status")
def ai_status() -> dict[str, Any]:
    cfg = ai.ai_config()
    usage = ai.usage_today()
    cache_entries = db.query_one("SELECT COUNT(*) c FROM ai_cache")["c"]
    by_verdict = {
        row["ai_verdict"]: row["c"]
        for row in db.query(
            "SELECT ai_verdict, COUNT(*) c FROM findings WHERE ai_verdict <> '' GROUP BY ai_verdict"
        )
    }
    return {
        "enabled": cfg.enabled,
        "has_api_key": bool(cfg.api_key),
        "kind": cfg.kind,
        "model": cfg.model,
        "base_url": cfg.base_url,
        "presets": ai.AI_PRESETS,
        "usage": usage,
        "budget_left": ai.budget_left(cfg),
        "cache_entries": cache_entries,
        "by_verdict": by_verdict,
        "label": ai.VERDICT_LABEL,
        "capabilities": {
            "verify_new_findings": cfg.verify_new_findings,
            "semantic_scan": cfg.semantic_scan,
            "auto_mark_false_positive": cfg.auto_mark_false_positive,
        },
    }


@app.post("/api/ai/test")
async def ai_test(payload: AITestIn) -> dict[str, Any]:
    cfg = _ai_cfg_from(payload.ai)
    result = await ai.ping(cfg)
    db.log_event(
        f"AI 连通性测试{'成功' if result['ok'] else '失败'}: {cfg.model}",
        kind="ai", level="info" if result["ok"] else "warn",
    )
    return {**result, "model": cfg.model, "kind": cfg.kind}


@app.post("/api/ai/models")
async def ai_models(payload: AITestIn) -> dict[str, Any]:
    """拉取 OpenAI 兼容端点的模型列表, 省去猜内网模型 id。"""
    cfg = _ai_cfg_from(payload.ai)
    try:
        models = await ai.AIClient(cfg).list_models()
    except Exception as exc:  # noqa: BLE001
        raise HTTPException(400, f"拉取失败: {exc}") from exc
    return {"models": models, "count": len(models), "base_url": ai.normalize_base_url(cfg.base_url)}


@app.post("/api/findings/{fid}/triage")
async def triage_finding_endpoint(fid: int) -> dict[str, Any]:
    row = db.query_one("SELECT * FROM findings WHERE id=?", (fid,))
    if row is None:
        raise HTTPException(404, "发现不存在")
    cfg = ai.ai_config()
    if not cfg.enabled:
        raise HTTPException(400, "AI 未启用, 请先在「系统设置 → AI 复核」中开启")
    if ai.budget_left(cfg) <= 0:
        raise HTTPException(429, "已达当日调用上限")
    payload = {k: row[k] for k in row.keys()}
    verdict = await ai.triage_finding(ai.AIClient(cfg), payload, raw=row["raw_value"] or "")
    db.execute(
        "UPDATE findings SET ai_verdict=?, ai_confidence=?, ai_reason=?, ai_impact=?, "
        "ai_remediation=?, ai_model=?, ai_checked_at=? WHERE id=?",
        (verdict["verdict"], verdict["confidence"], verdict["reason"], verdict.get("impact", ""),
         verdict.get("remediation", ""), verdict.get("model", ""), db.utcnow(), fid),
    )
    return {"id": fid, **verdict}


@app.post("/api/findings/{fid}/draft-rule")
async def draft_rule_endpoint(fid: int, save: bool = Query(default=False)) -> dict[str, Any]:
    row = db.query_one("SELECT * FROM findings WHERE id=?", (fid,))
    if row is None:
        raise HTTPException(404, "发现不存在")
    cfg = ai.ai_config()
    if not cfg.enabled:
        raise HTTPException(400, "AI 未启用, 请先在「系统设置 → AI 复核」中开启")
    payload = {k: row[k] for k in row.keys()}
    try:
        result = await ai.draft_rule(ai.AIClient(cfg), payload,
                                     evidence=row["context"] or row["match_masked"] or "")
    except ai.AIError as exc:
        raise HTTPException(400, f"生成失败: {exc}") from exc
    if not result.get("ok"):
        return {"saved": False, "reason": result.get("reason", "未知原因")}
    if save:
        items = {item["id"]: item for item in (db.get_setting("custom_rules") or [])}
        items[result["rule"]["id"]] = result["rule"]
        db.set_setting("custom_rules", list(items.values()))
        bump_rules_revision()
        db.log_event(f"由 AI 生成并保存规则 {result['rule']['id']}", kind="ai")
    return {"saved": bool(save), "rule": result["rule"]}


@app.post("/api/ai/semantic-scan")
async def semantic_scan_endpoint(payload: SemanticScanIn) -> dict[str, Any]:
    target = _target_row(payload.target_id)
    result = await semantic_scan_target(target, limit=payload.limit)
    if not result.get("ok"):
        raise HTTPException(400, result.get("error", "语义审计未执行"))
    return result


# ---------------------------------------------------------------- 白名单

@app.get("/api/allowlist")
def list_allowlist() -> list[dict[str, Any]]:
    return [{k: row[k] for k in row.keys()} for row in db.query("SELECT * FROM allowlist ORDER BY id DESC")]


@app.post("/api/allowlist", status_code=201)
def add_allowlist(payload: AllowlistIn) -> dict[str, Any]:
    import re as _re
    try:
        _re.compile(payload.pattern)
    except _re.error as exc:
        raise HTTPException(400, f"正则不合法: {exc}") from exc
    db.execute(
        "INSERT INTO allowlist(pattern, reason, created_at) VALUES(?,?,?) "
        "ON CONFLICT(pattern) DO UPDATE SET reason=excluded.reason",
        (payload.pattern, payload.reason, db.utcnow()),
    )
    bump_rules_revision()
    return {"ok": True, "revision": rules_revision()}


@app.delete("/api/allowlist/{aid}")
def delete_allowlist(aid: int) -> dict[str, Any]:
    db.execute("DELETE FROM allowlist WHERE id=?", (aid,))
    bump_rules_revision()
    return {"deleted": aid, "revision": rules_revision()}


# ---------------------------------------------------------------- 实时流

@app.get("/api/stream")
async def stream() -> StreamingResponse:
    async def generator():
        last_payload = ""
        while True:
            try:
                gate_sql, gate_params = gating.exclusion("f")
                gate_clause = f" AND {gate_sql}" if gate_sql else ""
                data = {
                    "scheduler": {
                        "running": len(SCHEDULER.state.running),
                        "queued": len(SCHEDULER.state.queued),
                        "completed": SCHEDULER.state.scans_completed,
                    },
                    "counts": {
                        # 与列表口径一致: 侧栏红点也走 AI 预筛, 否则会出现"红点 1139 / 列表 34"
                        "open": db.query_one(
                            "SELECT COUNT(*) c FROM findings f WHERE f.status IN ('new','open')"
                            + gate_clause, gate_params)["c"],
                        "new": db.query_one(
                            "SELECT COUNT(*) c FROM findings f WHERE f.status='new'"
                            + gate_clause, gate_params)["c"],
                        "targets": db.query_one("SELECT COUNT(*) c FROM targets")["c"],
                    },
                    "scanning": sorted(SCHEDULER.state.running.keys()),
                    "ts": db.utcnow(),
                }
                payload = json.dumps(data, ensure_ascii=False)
                if payload != last_payload:
                    last_payload = payload
                    yield f"data: {payload}\n\n"
                else:
                    yield ": keep-alive\n\n"
            except Exception as exc:  # noqa: BLE001
                yield f"event: error\ndata: {json.dumps({'message': str(exc)})}\n\n"
            await asyncio.sleep(3)

    return StreamingResponse(generator(), media_type="text/event-stream",
                             headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"})


# ---------------------------------------------------------------- 静态资源

@app.get("/")
def index() -> HTMLResponse:
    """主页注入静态资源版本号: 前端文件一改, 浏览器缓存立即失效。

    否则每次更新后用户都可能看到旧界面（实测踩过: 改了 JS 但页面行为没变）。
    """
    html = (STATIC_DIR / "index.html").read_text(encoding="utf-8")
    stamp = max(
        (STATIC_DIR / name).stat().st_mtime for name in ("app.js", "styles.css")
        if (STATIC_DIR / name).exists()
    )
    # 页面本身不缓存（资源已带版本号）: 否则换了版本浏览器还会用旧首页
    return HTMLResponse(html.replace("__ASSET_V__", str(int(stamp))),
                        headers={"Cache-Control": "no-store, must-revalidate"})


@app.get("/favicon.ico")
def favicon() -> FileResponse:
    return FileResponse(STATIC_DIR / "favicon.svg", media_type="image/svg+xml")


app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")
