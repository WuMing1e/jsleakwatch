#!/usr/bin/env python3.10
"""清理历史遗留: 同一站点里内容完全相同的重复资产。

为什么会有这么多重复: 不少站点(SPA / 网关)对任意路径都返回同一个页面,
系统以前按 URL 存资产, 于是一份 2KB 的首页被存成几百个"资产",
同一处命中也被报了成百上千条。

这个脚本按 (站点, 内容 sha256) 分组, 每组只保留最早的一条, 其余的删掉;
被删资产上的发现不丢: 能并进保留下来的那条就并, 已经存在等价发现的就删重复项。

默认只统计不动手, 加 --apply 才真正写库; 写之前会先把数据库备份一份。
"""
from __future__ import annotations

import argparse
import shutil
import sys
from datetime import datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from app import db  # noqa: E402


def plan() -> tuple[list[tuple[int, int]], dict]:
    """返回 [(保留的资产 id, 要删的资产 id), ...] 与统计信息。"""
    groups = db.query("""
        SELECT target_id, sha256, COUNT(*) n, MIN(id) keep_id
        FROM assets
        GROUP BY target_id, sha256
        HAVING n > 1
        ORDER BY n DESC
    """)
    pairs: list[tuple[int, int]] = []
    dup_urls = 0
    for group in groups:
        victims = db.query(
            "SELECT id FROM assets WHERE target_id=? AND sha256=? AND id<>?",
            (group["target_id"], group["sha256"], group["keep_id"]),
        )
        for row in victims:
            pairs.append((int(group["keep_id"]), int(row["id"])))
        dup_urls += len(victims)

    moved = 0
    dropped = 0
    for keep_id, victim_id in pairs:
        for finding in db.query(
            "SELECT id, rule_id, match_sha256 FROM findings WHERE asset_id=?", (victim_id,)
        ):
            twin = db.query_one(
                "SELECT id FROM findings WHERE asset_id=? AND rule_id=? AND match_sha256=?",
                (keep_id, finding["rule_id"], finding["match_sha256"]),
            )
            if twin:
                dropped += 1
            else:
                moved += 1
    stats = {"groups": len(groups), "duplicates": dup_urls,
             "findings_moved": moved, "findings_dropped": dropped}
    return pairs, stats


def apply(pairs: list[tuple[int, int]]) -> None:
    for keep_id, victim_id in pairs:
        keep = db.query_one("SELECT url FROM assets WHERE id=?", (keep_id,))
        keep_url = keep["url"] if keep else ""
        for finding in db.query(
            "SELECT id, rule_id, match_sha256 FROM findings WHERE asset_id=?", (victim_id,)
        ):
            twin = db.query_one(
                "SELECT id FROM findings WHERE asset_id=? AND rule_id=? AND match_sha256=?",
                (keep_id, finding["rule_id"], finding["match_sha256"]),
            )
            if twin:
                db.execute("DELETE FROM findings WHERE id=?", (finding["id"],))
            else:
                db.execute("UPDATE findings SET asset_id=?, asset_url=? WHERE id=?",
                           (keep_id, keep_url, finding["id"]))
        for table in ("asset_versions",):
            db.execute(f"DELETE FROM {table} WHERE asset_id=?", (victim_id,))
        db.execute("DELETE FROM assets WHERE id=?", (victim_id,))


def main() -> int:
    parser = argparse.ArgumentParser(description="清理同站点同内容的重复资产")
    parser.add_argument("--apply", action="store_true", help="真正写库(默认只统计)")
    args = parser.parse_args()

    pairs, stats = plan()
    print(f"重复内容分组 {stats['groups']} 组, 可删重复资产 {stats['duplicates']} 条")
    print(f"其中发现: 可合并 {stats['findings_moved']} 条, 重复可删 {stats['findings_dropped']} 条")
    if not args.apply:
        print("\n这是预演。确认无误后加 --apply 执行。")
        return 0
    if not pairs:
        print("没有需要清理的东西")
        return 0

    backup_dir = ROOT / "data" / "backup"
    backup_dir.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    src = db.SETTINGS.db_path if hasattr(db, "SETTINGS") else ROOT / "data" / "jslw.db"
    backup = backup_dir / f"jslw-before-dedupe-{stamp}.db"
    shutil.copy2(src, backup)
    print(f"已备份数据库: {backup}")

    apply(pairs)
    left = db.query_one("""
        SELECT COUNT(*) c FROM (
            SELECT 1 FROM assets GROUP BY target_id, sha256 HAVING COUNT(*) > 1
        )
    """)["c"]
    print(f"完成: 删掉 {stats['duplicates']} 条重复资产, 剩余重复分组 {left} 组")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
