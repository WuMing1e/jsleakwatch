#!/usr/bin/env python3
"""JS 覆盖率报告。

回答"这个站点的 JS 我到底覆盖了多少"，不靠感觉。三个口径：

1. 请求完整度 —— 本轮实际取到的资产 vs 请求失败数（404/超时/被拦）；
2. 产物完整度 —— 从已采集的 bundle 里**重新推导** webpack manifest 声明的
   chunk 清单，与库里实际采集到的对比，缺哪些一目了然；
3. 扫描完整度 —— 采集到的资产里有多少真的被扫了（大小未超限、非二进制、
   未被增量跳过），以及 sourcemap 声明与抓取情况。

用法:
    python3.10 tools/coverage.py --target-id 2
    python3.10 tools/coverage.py --target-id 2 --verify   # 额外重推导 manifest（会重新抓入口）
"""
from __future__ import annotations

import argparse
import asyncio
import re
import sys
from pathlib import Path
from urllib.parse import urlparse

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from app import db  # noqa: E402
from app.config import SETTINGS  # noqa: E402
from app.discover import Extractor  # noqa: E402
from app.fetcher import Fetcher  # noqa: E402
from app.scanner import scan_config_from_settings  # noqa: E402

CHUNK_NAME_RE = re.compile(r"^(.+)\.[0-9a-f]{6,20}\.js$", re.I)


def collected(target_id: int) -> list[dict]:
    return [{k: row[k] for k in row.keys()} for row in db.query(
        "SELECT url, kind, size, scan_count, last_seen_at FROM assets WHERE target_id=?",
        (target_id,))]


def chunk_families(urls: list[str]) -> dict[str, list[str]]:
    """按 chunk 名归组（同一名字的不同哈希会归到一起，便于识别多余候选）。"""
    families: dict[str, list[str]] = {}
    for url in urls:
        name = urlparse(url).path.rsplit("/", 1)[-1]
        match = CHUNK_NAME_RE.match(name)
        families.setdefault(match.group(1) if match else name, []).append(name)
    return families


async def derive_manifest(target: dict) -> dict:
    """重新抓入口与入口引用的 bundle，推导该站点声明的 JS 清单。"""
    cfg = scan_config_from_settings()
    extractor = Extractor(base_url=target["base_url"], scope=target.get("scope") or "same-origin")
    expected: set[str] = set()
    sourcemaps: set[str] = set()
    async with Fetcher(cfg) as fetcher:
        entry = await fetcher.get(target["base_url"])
        if not entry.ok:
            return {"error": f"入口不可达: {entry.error or entry.status}"}
        seeds = extractor.from_html(entry.final_url or target["base_url"], entry.text, 0)
        # 只看入口直接引用的脚本（够覆盖 Vue/React 这类"运行时 + 分包"结构）
        for cand in seeds:
            if cand.kind != "script":
                continue
            resp = await fetcher.get(cand.url)
            if not resp.ok or not resp.text:
                continue
            expected.add(cand.url)
            for child in extractor.from_js(cand.url, resp.text, 0):
                if child.kind in ("script", "map"):
                    expected.add(child.url)
                    if child.kind == "map":
                        sourcemaps.add(child.url)
    return {"expected": expected, "sourcemaps": sourcemaps}


async def probe_missing(urls: list[str]) -> tuple[list[str], list[str]]:
    """区分"真实存在但没采到"与"根本不存在（合成出来的多余候选）"。"""
    cfg = scan_config_from_settings()
    real: list[str] = []
    phantom: list[str] = []
    async with Fetcher(cfg) as fetcher:
        responses = await asyncio.gather(*[fetcher.get(url) for url in urls])
    for url, resp in zip(urls, responses):
        (real if resp.status == 200 and resp.text else phantom).append(url)
    return real, phantom


def main() -> int:
    parser = argparse.ArgumentParser(description="JS 覆盖率报告")
    parser.add_argument("--target-id", type=int, required=True)
    parser.add_argument("--verify", action="store_true",
                        help="重新抓入口推导 manifest 并核对缺失项是否真实存在（会产生外部请求）")
    args = parser.parse_args()

    db.init_db()
    row = db.query_one("SELECT * FROM targets WHERE id=?", (args.target_id,))
    if row is None:
        print(f"找不到站点 id={args.target_id}", file=sys.stderr)
        return 1
    target = {k: row[k] for k in row.keys()}

    assets = collected(args.target_id)
    js = [a for a in assets if a["kind"] in ("script", "config")]
    maps = [a for a in assets if a["kind"] == "map"]
    pages = [a for a in assets if a["kind"] in ("html", "inline")]
    cfg = scan_config_from_settings()
    limit = cfg.max_asset_bytes or 0
    truncated = [a for a in assets if limit and a["size"] and a["size"] >= limit]

    scan = db.query_one(
        "SELECT * FROM scans WHERE target_id=? ORDER BY id DESC LIMIT 1", (args.target_id,))

    print(f"# JS 覆盖率报告 · {target['name']}")
    print(f"入口: {target['base_url']}   深度上限 {target['max_depth']}   资产上限 {target['max_assets']}\n")

    print("## 1. 采集")
    print(f"- 资产合计 {len(assets)} 个: 脚本 {len(js)} · 映射 {len(maps)} · 页面/内联 {len(pages)}")
    total_bytes = sum(a['size'] or 0 for a in assets)
    cap = (f"单资产上限 {limit/1024/1024:.0f} MB，超限会被截断: {len(truncated)} 个"
           if limit else "单资产大小不限")
    print(f"- 内容体积 {total_bytes/1024/1024:.2f} MB（{cap}）")
    if scan:
        attempted = (scan["assets_fetched"] or 0) + (scan["assets_failed"] or 0)
        rate = (scan["assets_fetched"] or 0) / attempted * 100 if attempted else 0
        print(f"- 本轮请求 {attempted} 次，取到 {scan['assets_fetched']} 个、失败 "
              f"{scan['assets_failed']} 个 → 请求成功率 {rate:.0f}%")
        print(f"- 状态 {scan['status']}，耗时 {scan['duration_ms']} ms"
              + (f"，错误: {scan['error'][:120]}" if scan["error"] else ""))

    families = chunk_families([a["url"] for a in js])
    multi = {k: v for k, v in families.items() if len(v) > 1}
    print(f"- chunk 家族 {len(families)} 个"
          + (f"，其中 {len(multi)} 个存在多个哈希候选（多试的那几个会 404）" if multi else ""))

    print("\n## 2. 产物完整度" + ("（已重新推导 manifest）" if args.verify else "（加 --verify 可重新推导）"))
    if args.verify:
        derived = asyncio.run(derive_manifest(target))
        if "error" in derived:
            print(f"- {derived['error']}")
        else:
            expected = derived["expected"]
            got = {a["url"] for a in assets}
            missing = sorted(expected - got)
            extra = sorted(u for u in got - expected if u.endswith(".js"))
            covered = len(expected) - len(missing)
            pct = covered / len(expected) * 100 if expected else 0
            print(f"- manifest 声明 {len(expected)} 个（含映射 {len(derived['sourcemaps'])} 个）")
            print(f"- 已采集 {covered} 个 → **覆盖率 {pct:.0f}%**")
            if missing:
                real, phantom = asyncio.run(probe_missing(missing[:40]))
                print(f"- 候选缺失 {len(missing)} 个 → 探测后：真实存在但未采集 **{len(real)}** 个，"
                      f"不存在的候选（合成的多余哈希）{len(phantom)} 个")
                pct_real = (len(expected) - len(phantom) - len(real)) / max(1, len(expected) - len(phantom)) * 100
                print(f"- 去掉幽灵候选后的实际覆盖率：**{pct_real:.0f}%**"
                      f"（真实文件 {len(expected) - len(phantom)} 个）")
                if real:
                    print("- 真实缺口:")
                    for url in real[:10]:
                        print(f"    - {url}")
            if extra:
                print(f"- 额外采集 {len(extra)} 个（不在 manifest 里）")
    else:
        print(f"- 已采集脚本 {len(js)} 个、映射 {len(maps)} 个")

    print("\n## 3. 扫描完整度")
    credentialed = bool(cfg.extra_headers or cfg.cookies)
    if credentialed:
        names = ",".join(sorted(cfg.extra_headers or {}))
        extra = f"自定义头 {names}" if names else ""
        if cfg.cookies:
            extra = (extra + "，含 Cookie") if extra else "含 Cookie"
        print(f"- 采集身份: **带凭据**（{extra}）")
    else:
        print("- 采集身份: **匿名**（不发送任何凭据）")
    if not credentialed:
        print("  - 匿名采集的天花板: 需要登录后才下发的 bundle、运行时拼出的 chunk URL、"
              "以及被 WAF 拦截的资源都取不到")
    print(f"- 增量跳过: 库中资产的累计采集次数 "
          f"{sorted({a['scan_count'] for a in assets}) or '-'}（相同内容不重复检测）")
    print(f"- 二进制/非文本资产按设计跳过；跨域脚本默认不采集"
          f"（当前 allow_cross_origin_js={cfg.allow_cross_origin_js}）")
    print(f"- TLS 校验 {cfg.verify_tls} · 单域限速 {cfg.per_host_delay_ms} ms/请求")
    print("\n> 导致覆盖率不足的常见原因：达到深度/资产上限、请求被拦或 404、"
          "资产超过体积上限被截断、以及**需要登录或用户交互后才会加载的 JS**（无浏览器执行时采不到）。")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
