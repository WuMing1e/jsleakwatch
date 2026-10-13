#!/usr/bin/env python3
"""批量导入站点并排队扫描。

用法:
    python3.10 tools/import_targets.py targets.txt
    python3.10 tools/import_targets.py targets.txt --depth 1 --max-assets 60 --interval 1440
    python3.10 tools/import_targets.py targets.txt --dry-run     # 只解析, 不写库

域名、URL、带路径的 URL 都能吃；自动补 https://，并按主机名去重。
"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path
from urllib.parse import urlparse

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from app import db  # noqa: E402


def normalize(item: str) -> str | None:
    item = item.strip()
    if not item or item.startswith("#"):
        return None
    if not item.startswith(("http://", "https://")):
        item = "https://" + item
    parsed = urlparse(item)
    if not parsed.netloc or "." not in parsed.netloc:
        return None
    return item


def main() -> int:
    parser = argparse.ArgumentParser(description="批量导入站点")
    parser.add_argument("file", help="域名列表文件，每行一个")
    parser.add_argument("--interval", type=int, default=1440, help="巡检周期（分钟，默认每天）")
    parser.add_argument("--depth", type=int, default=1)
    parser.add_argument("--max-assets", type=int, default=60)
    parser.add_argument("--probe-config", action="store_true", help="探测常见配置入口（第三方站点建议关闭）")
    parser.add_argument("--dry-run", action="store_true")
    args = parser.parse_args()

    lines = Path(args.file).read_text(encoding="utf-8", errors="replace").splitlines()
    urls: list[str] = []
    seen: set[str] = set()
    invalid: list[str] = []
    for line in lines:
        url = normalize(line)
        if url is None:
            if line.strip() and not line.strip().startswith("#"):
                invalid.append(line.strip())
            continue
        host = urlparse(url).netloc.lower()
        if host in seen:
            continue
        seen.add(host)
        urls.append(url)

    print(f"文件 {args.file}: {len(lines)} 行 → 解析出 {len(urls)} 个唯一主机"
          + (f"，{len(invalid)} 行格式不合法" if invalid else ""))
    if invalid:
        for item in invalid[:5]:
            print(f"  跳过: {item[:80]}")
    if args.dry_run:
        print("(dry-run, 未写库)")
        return 0

    db.init_db()
    existing = {urlparse(row["base_url"]).netloc.lower() for row in db.query("SELECT base_url FROM targets")}
    now = db.utcnow()
    created = 0
    skipped = 0
    for url in urls:
        host = urlparse(url).netloc.lower()
        if host in existing:
            skipped += 1
            continue
        db.execute(
            "INSERT INTO targets(name, base_url, enabled, interval_minutes, scope, max_depth, max_assets, "
            "include_sourcemaps, probe_common_config, tags, notes, created_at, next_scan_at) "
            "VALUES(?,?,1,?,'same-origin',?,?,1,?,?,?,?,?)",
            (host, url, args.interval, args.depth, args.max_assets,
             1 if args.probe_config else 0, "", "", now, now),
        )
        existing.add(host)
        created += 1
    db.log_event(f"批量导入站点: 新增 {created} 个, 跳过 {skipped} 个", kind="target")
    print(f"导入完成: 新增 {created} 个，跳过 {skipped} 个（已存在）")
    print("提示: 调度器会在几秒内自动接手扫描；也可在控制台「监测站点」页统一触发。")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
