"""端到端冒烟: 起本地样例站点 -> 建库 -> 扫描 -> 打印结果。"""
from __future__ import annotations

import functools
import http.server
import socketserver
import sys
import threading
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

import os
os.environ["JSLW_DATA_DIR"] = str(ROOT / "work" / "data")

from app import db  # noqa: E402
from app.scanner import scan_target  # noqa: E402

FIXTURE = ROOT / "fixtures" / "demo_site"
PORT = 8899


class Handler(http.server.SimpleHTTPRequestHandler):
    extensions_map = {**http.server.SimpleHTTPRequestHandler.extensions_map,
                      ".js": "application/javascript", ".map": "application/json"}

    def log_message(self, *a) -> None:
        pass


class ReusableServer(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True


def start_server():
    handler = functools.partial(Handler, directory=str(FIXTURE))
    httpd = ReusableServer(("127.0.0.1", PORT), handler)
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    return httpd


def main() -> None:
    db.init_db()
    httpd = start_server()
    try:
        db.execute("DELETE FROM targets")
        db.execute("DELETE FROM findings")
        db.execute("DELETE FROM assets")
        db.execute("DELETE FROM scans")
        tid = db.execute(
            "INSERT INTO targets(name, base_url, enabled, interval_minutes, scope, max_depth, "
            "max_assets, include_sourcemaps, probe_common_config, created_at, next_scan_at) "
            "VALUES(?,?,1,60,'same-origin',2,200,1,1,?,?)",
            ("Demo Shop", f"http://127.0.0.1:{PORT}/", db.utcnow(), db.utcnow()),
        ).lastrowid
        target = {k: db.query_one("SELECT * FROM targets WHERE id=?", (tid,))[k]
                  for k in db.query_one("SELECT * FROM targets WHERE id=?", (tid,)).keys()}

        import asyncio
        result = asyncio.run(scan_target(target))
        print(f"\n状态={result.status} 资产={result.assets_fetched} 新增资产={result.assets_new} "
              f"复用={result.assets_skipped} 新发现={len(result.new_findings)} 耗时={result.duration_ms}ms")
        print(f"错误: {result.error[:300]}")
        print("\n抓到的资产:")
        for row in db.query("SELECT url, size, kind FROM assets ORDER BY url"):
            print(f"  [{row['kind']:7}] {row['size']:>7}  {row['url']}")
        print("\n发现明细:")
        for row in db.query(
            "SELECT severity, rule_id, match_masked, asset_url FROM findings "
            "ORDER BY CASE severity WHEN 'critical' THEN 0 WHEN 'high' THEN 1 WHEN 'medium' THEN 2 "
            "WHEN 'low' THEN 3 ELSE 4 END, rule_id"
        ):
            print(f"  {row['severity']:8} {row['rule_id']:32} {row['match_masked']:34} {row['asset_url']}")

        # 第二轮: 验证增量 (不变资产应被跳过, 且不产生重复发现)
        print("\n--- 第二轮扫描 (增量) ---")
        result2 = asyncio.run(scan_target(target))
        print(f"状态={result2.status} 资产={result2.assets_fetched} 复用={result2.assets_skipped} "
              f"新发现={len(result2.new_findings)} 耗时={result2.duration_ms}ms")
    finally:
        httpd.shutdown()


if __name__ == "__main__":
    main()
