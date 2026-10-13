"""容量压测: 用合成数据测"上千个站点"时各组件的实际开销。

用法: python3.10 tools/loadtest.py [站点数] [每站发现数]

策略: 1000 个站点全部启用, 但 next_scan_at 设到 30 天后 ——
这样调度器的查询会如实扫描 1000 行(可测), 但不会有任何扫描真的启动(不产生副作用)。
"""
from __future__ import annotations

import os
import sys
import tempfile
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

SCRATCH = Path(tempfile.mkdtemp(prefix="jslw-load-")) / "load.db"
os.environ["JSLW_DB"] = str(SCRATCH)
os.environ["JSLW_DATA_DIR"] = str(SCRATCH.parent)

TARGETS = int(sys.argv[1]) if len(sys.argv) > 1 else 1000
FINDINGS_PER_TARGET = int(sys.argv[2]) if len(sys.argv) > 2 else 8

from app import db  # noqa: E402

db.init_db()


def seed() -> None:
    future = (datetime.now(timezone.utc) + timedelta(days=30)).isoformat(timespec="seconds")
    now = db.utcnow()
    rows = [(f"站点{i}", f"https://site{i}.example.com/", 1, 1440, "same-origin", 2, 400, 1, 1,
             "", "", now, future) for i in range(TARGETS)]
    conn = db.get_conn()
    start = time.perf_counter()
    conn.executemany(
        "INSERT INTO targets(name, base_url, enabled, interval_minutes, scope, max_depth, "
        "max_assets, include_sourcemaps, probe_common_config, tags, notes, created_at, next_scan_at) "
        "VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)", rows)
    conn.commit()
    print(f"写入 {TARGETS} 个站点: {(time.perf_counter()-start)*1000:.0f} ms")

    tids = [r["id"] for r in db.query("SELECT id FROM targets")]
    finding_rows = []
    for tid in tids:
        for j in range(FINDINGS_PER_TARGET):
            finding_rows.append((
                tid, "generic-secret-assignment", "疑似硬编码密钥", "medium", "generic",
                f"fp-{tid}-{j}", "abcd...wxyz(len=32)", f"sha-{tid}-{j}",
                f"https://site{tid}.example.com/js/app.js", now, now, "new", "rule", "builtin"))
    start = time.perf_counter()
    conn.executemany(
        "INSERT INTO findings(target_id, rule_id, rule_name, severity, category, fingerprint, "
        "match_masked, match_sha256, asset_url, first_seen_at, last_seen_at, status, origin, found_by) "
        "VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)", finding_rows)
    conn.commit()
    print(f"写入 {len(finding_rows)} 条发现: {(time.perf_counter()-start)*1000:.0f} ms")


def timeit(label: str, fn, repeat: int = 3) -> float:
    best = 1e9
    for _ in range(repeat):
        start = time.perf_counter()
        fn()
        best = min(best, (time.perf_counter() - start) * 1000)
    print(f"  {label:44} {best:8.1f} ms")
    return best


def main() -> None:
    seed()
    import asyncio

    from app.scheduler import SCHEDULER

    print("\n== 调度器与查询开销 ==")
    timeit("旧写法: 全表捞 enabled=1 再筛选", lambda: db.query(
        "SELECT * FROM targets WHERE enabled=1 ORDER BY COALESCE(next_scan_at,'') ASC"))
    timeit("新写法: 索引定位到期站点 + LIMIT", lambda: db.query(
        "SELECT * FROM targets WHERE enabled=1 AND (next_scan_at IS NULL OR next_scan_at <= ?) "
        "ORDER BY COALESCE(next_scan_at,'') ASC LIMIT ?",
        (datetime.now(timezone.utc).isoformat(timespec="seconds"), 9)))
    timeit("完整 tick (查询 + 入队)", lambda: asyncio.run(SCHEDULER._tick()))

    db.execute("UPDATE targets SET next_scan_at=?", (db.utcnow(),))   # 全部到期
    timeit("全部到期时的一轮 tick(受并行度限制)", lambda: asyncio.run(SCHEDULER._tick()))
    db.execute("UPDATE targets SET next_scan_at=?", (
        (datetime.now(timezone.utc) + timedelta(days=30)).isoformat(timespec="seconds"),))

    timeit("站点列表(带 3 个相关子查询)", lambda: db.query(
        "SELECT t.*, "
        "(SELECT COUNT(*) FROM findings f WHERE f.target_id=t.id AND f.status IN ('new','open')) AS open_count, "
        "(SELECT COUNT(*) FROM findings f WHERE f.target_id=t.id AND f.status='new') AS new_count, "
        "(SELECT COUNT(*) FROM assets a WHERE a.target_id=t.id) AS asset_count "
        "FROM targets t ORDER BY t.name COLLATE NOCASE"))

    print("\n== 接口开销 (TestClient) ==")
    from fastapi.testclient import TestClient

    from app.api import app, invalidate_dash_cache
    with TestClient(app) as client:
        def cold_overview() -> None:
            invalidate_dash_cache()
            client.get("/api/overview")

        def cold_targets() -> None:
            invalidate_dash_cache()
            client.get("/api/targets?limit=100")

        timeit("GET /api/targets  (冷, 100 条/页)", cold_targets)
        timeit("GET /api/targets  (缓存命中)", lambda: client.get("/api/targets?limit=100"))
        timeit("GET /api/overview (冷, 含全部聚合)", cold_overview)
        timeit("GET /api/overview (缓存命中)", lambda: client.get("/api/overview"))
        timeit("GET /api/findings (第 1 页)", lambda: client.get("/api/findings?limit=50"))
        timeit("GET /api/findings (深分页 offset=2000)",
               lambda: client.get("/api/findings?limit=50&offset=2000"))
        timeit("GET /api/events", lambda: client.get("/api/events?limit=80"))

    print("\n== 写入开销 ==")
    timeit("插入 1 条事件(含事件表清理)", lambda: db.log_event("压测事件", kind="load"), repeat=20)
    timeit("插入 100 条发现", lambda: db.executemany(
        "INSERT INTO findings(target_id, rule_id, rule_name, severity, category, fingerprint, "
        "match_masked, match_sha256, asset_url, first_seen_at, last_seen_at, status) "
        "VALUES(?,?,?,?,?,?,?,?,?,?,?,'new')",
        [(1, "r", "n", "low", "c", f"load-{time.time()}-{k}", "m", f"s{k}", "u",
          db.utcnow(), db.utcnow()) for k in range(100)]))

    counts = {t: db.query_one(f"SELECT COUNT(*) c FROM {t}")["c"]
              for t in ("targets", "findings", "assets", "events")}
    print(f"\n数据规模: {counts}")
    print(f"库文件大小: {SCRATCH.stat().st_size/1024/1024:.1f} MB")


if __name__ == "__main__":
    main()
