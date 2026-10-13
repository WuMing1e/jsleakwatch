"""SQLite 存储层。

单机场景: 每线程一个连接 + WAL, 写操作用全局锁串行化。
所有时间戳统一为 UTC ISO8601 字符串, 前端按本地时区渲染。
"""
from __future__ import annotations

import json
import sqlite3
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable, Sequence

from .config import DB_PATH

_local = threading.local()
_write_lock = threading.RLock()

SCHEMA = """
CREATE TABLE IF NOT EXISTS settings (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS targets (
    id                   INTEGER PRIMARY KEY AUTOINCREMENT,
    name                 TEXT NOT NULL,
    base_url             TEXT NOT NULL,
    enabled              INTEGER NOT NULL DEFAULT 1,
    interval_minutes     INTEGER NOT NULL DEFAULT 360,
    scope                TEXT NOT NULL DEFAULT 'same-origin',
    max_depth            INTEGER NOT NULL DEFAULT 2,
    max_assets           INTEGER NOT NULL DEFAULT 400,
    include_sourcemaps   INTEGER NOT NULL DEFAULT 1,
    probe_common_config  INTEGER NOT NULL DEFAULT 1,
    tags                 TEXT NOT NULL DEFAULT '',
    notes                TEXT NOT NULL DEFAULT '',
    created_at           TEXT NOT NULL,
    last_scan_at         TEXT,
    next_scan_at         TEXT,
    last_status          TEXT NOT NULL DEFAULT 'pending',
    last_error           TEXT NOT NULL DEFAULT '',
    consecutive_failures INTEGER NOT NULL DEFAULT 0,
    total_scans          INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS assets (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    target_id       INTEGER NOT NULL REFERENCES targets(id) ON DELETE CASCADE,
    url             TEXT NOT NULL,
    sha256          TEXT NOT NULL DEFAULT '',
    size            INTEGER NOT NULL DEFAULT 0,
    content_type    TEXT NOT NULL DEFAULT '',
    kind            TEXT NOT NULL DEFAULT 'script',
    first_seen_at   TEXT NOT NULL,
    last_seen_at    TEXT NOT NULL,
    last_changed_at TEXT,
    scan_count      INTEGER NOT NULL DEFAULT 1,
    revision        INTEGER NOT NULL DEFAULT 0,
    recheck         INTEGER NOT NULL DEFAULT 0,
    UNIQUE (target_id, url)
);

CREATE TABLE IF NOT EXISTS findings (
    id             INTEGER PRIMARY KEY AUTOINCREMENT,
    target_id      INTEGER NOT NULL REFERENCES targets(id) ON DELETE CASCADE,
    asset_id       INTEGER REFERENCES assets(id) ON DELETE SET NULL,
    rule_id        TEXT NOT NULL,
    rule_name      TEXT NOT NULL,
    severity       TEXT NOT NULL,
    category       TEXT NOT NULL,
    fingerprint    TEXT NOT NULL UNIQUE,
    match_masked   TEXT NOT NULL,
    match_sha256   TEXT NOT NULL,
    raw_value      TEXT,
    context        TEXT NOT NULL DEFAULT '',
    line_no        INTEGER NOT NULL DEFAULT 0,
    entropy        REAL NOT NULL DEFAULT 0,
    asset_url      TEXT NOT NULL DEFAULT '',
    first_seen_at  TEXT NOT NULL,
    last_seen_at   TEXT NOT NULL,
    times_seen     INTEGER NOT NULL DEFAULT 1,
    status         TEXT NOT NULL DEFAULT 'new',
    verified       TEXT NOT NULL DEFAULT 'unverified',
    found_by       TEXT NOT NULL DEFAULT '',
    notified_at    TEXT,
    notes          TEXT NOT NULL DEFAULT ''
);

CREATE TABLE IF NOT EXISTS scans (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    target_id       INTEGER NOT NULL REFERENCES targets(id) ON DELETE CASCADE,
    started_at      TEXT NOT NULL,
    finished_at     TEXT,
    status          TEXT NOT NULL DEFAULT 'running',
    duration_ms     INTEGER NOT NULL DEFAULT 0,
    assets_fetched  INTEGER NOT NULL DEFAULT 0,
    assets_new      INTEGER NOT NULL DEFAULT 0,
    assets_failed   INTEGER NOT NULL DEFAULT 0,
    bytes_fetched   INTEGER NOT NULL DEFAULT 0,
    findings_new    INTEGER NOT NULL DEFAULT 0,
    findings_total  INTEGER NOT NULL DEFAULT 0,
    error           TEXT NOT NULL DEFAULT ''
);

CREATE TABLE IF NOT EXISTS ai_cache (
    key        TEXT PRIMARY KEY,
    kind       TEXT NOT NULL DEFAULT '',
    model      TEXT NOT NULL DEFAULT '',
    response   TEXT NOT NULL,
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS ai_usage (
    day              TEXT PRIMARY KEY,
    calls            INTEGER NOT NULL DEFAULT 0,
    fails            INTEGER NOT NULL DEFAULT 0,
    cached           INTEGER NOT NULL DEFAULT 0,
    prompt_chars     INTEGER NOT NULL DEFAULT 0,
    completion_chars INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS events (
    id        INTEGER PRIMARY KEY AUTOINCREMENT,
    ts        TEXT NOT NULL,
    level     TEXT NOT NULL DEFAULT 'info',
    kind      TEXT NOT NULL DEFAULT '',
    message   TEXT NOT NULL,
    target_id INTEGER
);

CREATE TABLE IF NOT EXISTS rule_overrides (
    rule_id  TEXT PRIMARY KEY,
    enabled  INTEGER,
    severity TEXT
);

-- 资产内容版本: 每次内容变化保存一条"字符串签名", 用来回答"这次改动新增了什么"。
-- 不存 JS 原文 —— 明文不外泄是底线, 命中的密钥在签名里已掩码。
CREATE TABLE IF NOT EXISTS asset_versions (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    asset_id   INTEGER NOT NULL REFERENCES assets(id) ON DELETE CASCADE,
    target_id  INTEGER NOT NULL REFERENCES targets(id) ON DELETE CASCADE,
    url        TEXT NOT NULL,
    sha256     TEXT NOT NULL,
    size       INTEGER NOT NULL DEFAULT 0,
    lines      INTEGER NOT NULL DEFAULT 0,
    strings    TEXT NOT NULL DEFAULT '[]',
    added      TEXT NOT NULL DEFAULT '[]',
    removed    TEXT NOT NULL DEFAULT '[]',
    findings   INTEGER NOT NULL DEFAULT 0,
    created_at TEXT NOT NULL,
    UNIQUE (asset_id, sha256)
);

CREATE TABLE IF NOT EXISTS allowlist (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    pattern    TEXT NOT NULL UNIQUE,
    reason     TEXT NOT NULL DEFAULT '',
    created_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_findings_target   ON findings(target_id);
CREATE INDEX IF NOT EXISTS idx_findings_status   ON findings(status);
CREATE INDEX IF NOT EXISTS idx_findings_severity ON findings(severity);
CREATE INDEX IF NOT EXISTS idx_findings_first    ON findings(first_seen_at);
CREATE INDEX IF NOT EXISTS idx_findings_value    ON findings(target_id, match_sha256);
-- 概览的聚合查询按 (状态, 等级) / (状态, 规则) 分组, 站点上千、发现上十万时靠这两个索引
CREATE INDEX IF NOT EXISTS idx_findings_sev_state ON findings(status, severity);
CREATE INDEX IF NOT EXISTS idx_findings_rule_state ON findings(status, rule_id);
CREATE INDEX IF NOT EXISTS idx_scans_target      ON scans(target_id, started_at);
CREATE INDEX IF NOT EXISTS idx_events_ts         ON events(ts);
CREATE INDEX IF NOT EXISTS idx_assets_target     ON assets(target_id);
CREATE INDEX IF NOT EXISTS idx_versions_asset    ON asset_versions(asset_id, id DESC);
CREATE INDEX IF NOT EXISTS idx_versions_target   ON asset_versions(target_id, id DESC);
-- 调度器按"启用 + 到期时间"取站点, 站点上千时这个索引决定 tick 的开销
CREATE INDEX IF NOT EXISTS idx_targets_due       ON targets(enabled, next_scan_at);
"""


def utcnow() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def connect(path: Path | str = DB_PATH) -> sqlite3.Connection:
    conn = sqlite3.connect(str(path), timeout=30.0)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA foreign_keys=ON")
    conn.execute("PRAGMA synchronous=NORMAL")
    return conn


def get_conn() -> sqlite3.Connection:
    conn = getattr(_local, "conn", None)
    if conn is None:
        conn = connect()
        _local.conn = conn
    return conn


def init_db(path: Path | str = DB_PATH) -> None:
    with _write_lock:
        conn = connect(path)
        try:
            conn.executescript(SCHEMA)
            _migrate(conn)
            conn.commit()
        finally:
            conn.close()


# 轻量迁移: 老库缺列时补齐, 避免升级后启动失败
MIGRATIONS: dict[str, list[tuple[str, str]]] = {
    "assets": [("kind", "TEXT NOT NULL DEFAULT 'script'"),
               ("revision", "INTEGER NOT NULL DEFAULT 0"),
               ("recheck", "INTEGER NOT NULL DEFAULT 0")],
    "targets": [("tags", "TEXT NOT NULL DEFAULT ''")],
    "findings": [
        ("verified", "TEXT NOT NULL DEFAULT 'unverified'"),
        ("origin", "TEXT NOT NULL DEFAULT 'rule'"),
        ("found_by", "TEXT NOT NULL DEFAULT ''"),
        ("ai_verdict", "TEXT NOT NULL DEFAULT ''"),
        ("ai_confidence", "REAL NOT NULL DEFAULT 0"),
        ("ai_reason", "TEXT NOT NULL DEFAULT ''"),
        ("ai_impact", "TEXT NOT NULL DEFAULT ''"),
        ("ai_remediation", "TEXT NOT NULL DEFAULT ''"),
        ("ai_model", "TEXT NOT NULL DEFAULT ''"),
        ("ai_checked_at", "TEXT"),
    ],
    "scans": [("duration_ms", "INTEGER NOT NULL DEFAULT 0"),
              ("assets_failed", "INTEGER NOT NULL DEFAULT 0")],
}


def _migrate(conn: sqlite3.Connection) -> None:
    for table, columns in MIGRATIONS.items():
        existing = {row[1] for row in conn.execute(f"PRAGMA table_info({table})")}
        for name, ddl in columns:
            if name not in existing:
                conn.execute(f"ALTER TABLE {table} ADD COLUMN {name} {ddl}")


def query(sql: str, params: Sequence[Any] = ()) -> list[sqlite3.Row]:
    return list(get_conn().execute(sql, params).fetchall())


def query_one(sql: str, params: Sequence[Any] = ()) -> sqlite3.Row | None:
    return get_conn().execute(sql, params).fetchone()


def execute(sql: str, params: Sequence[Any] = ()) -> sqlite3.Cursor:
    with _write_lock:
        conn = get_conn()
        cur = conn.execute(sql, params)
        conn.commit()
        return cur


def executemany(sql: str, seq: Iterable[Sequence[Any]]) -> None:
    with _write_lock:
        conn = get_conn()
        conn.executemany(sql, list(seq))
        conn.commit()


# ---------------------------------------------------------------- settings

def get_setting(key: str, default: Any = None) -> Any:
    try:
        row = query_one("SELECT value FROM settings WHERE key = ?", (key,))
    except sqlite3.OperationalError:  # 尚未建库
        return default
    if row is None:
        return default
    try:
        return json.loads(row["value"])
    except (json.JSONDecodeError, TypeError):
        return default


def set_setting(key: str, value: Any) -> None:
    execute(
        "INSERT INTO settings(key, value) VALUES(?, ?) "
        "ON CONFLICT(key) DO UPDATE SET value = excluded.value",
        (key, json.dumps(value, ensure_ascii=False)),
    )


def all_settings() -> dict[str, Any]:
    out: dict[str, Any] = {}
    for row in query("SELECT key, value FROM settings"):
        try:
            out[row["key"]] = json.loads(row["value"])
        except (json.JSONDecodeError, TypeError):
            continue
    return out


# ---------------------------------------------------------------- events

def log_event(message: str, kind: str = "", level: str = "info", target_id: int | None = None) -> None:
    execute(
        "INSERT INTO events(ts, level, kind, message, target_id) VALUES(?,?,?,?,?)",
        (utcnow(), level, kind, message, target_id),
    )
    # 事件表只保留最近 5000 条
    execute(
        "DELETE FROM events WHERE id <= (SELECT MAX(id) FROM events) - 5000",
    )


# ---------------------------------------------------------------- findings

FINDING_COLUMNS = (
    "id", "target_id", "asset_id", "rule_id", "rule_name", "severity", "category",
    "fingerprint", "match_masked", "match_sha256", "context", "line_no", "entropy",
    "asset_url", "first_seen_at", "last_seen_at", "times_seen", "status", "verified",
    "notified_at", "notes",
)


def finding_as_dict(row: sqlite3.Row, include_raw: bool = False) -> dict[str, Any]:
    data = {k: row[k] for k in FINDING_COLUMNS if k in row.keys()}
    if include_raw:
        data["raw_value"] = row["raw_value"] if "raw_value" in row.keys() else None
    return data
