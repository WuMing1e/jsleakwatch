#!/usr/bin/env python3.10
"""公网资产收集: 公开来源汇聚子域 -> DNS 解析 -> 轻量探活 -> 输出清单。

只碰三样东西: 公开数据(证书透明度日志 crt.sh、urlscan.io、hackertarget、
rapiddns, 以及本系统已监测的站点)、常规 DNS 解析、每个存活主机的一次 GET。
不做端口扫描, 不做目录爆破。

    python3.10 tools/asset_recon.py --domain seres.cn --domain sfmotors.com --from-db
    python3.10 tools/asset_recon.py --domain seres.cn --no-brute     # 只走公开来源
"""
from __future__ import annotations

import argparse
import csv
import json
import re
import socket
import ssl
import sys
import time
import warnings
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from pathlib import Path

import httpx

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

UA = ("Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 "
      "(KHTML, like Gecko) Chrome/124.0 Safari/537.36")

# 常见的三级域名。刻意收得克制: 取的是企业里真实存在的通用系统名, 靠业务词
# 提高命中率, 而不是靠长度穷举(那种做法又吵又慢)。
COMMON_NAMES = (
    "www www2 www3 m mobile app apps web webapp portal oa ehr hr erp crm scm wms tms mes plm "
    "mail mail2 smtp imap pop webmail owa exchange autodiscover lyncdiscover enterpriseregistration "
    "sso sso2 login auth oauth id account passport user member "
    "vpn sslvpn citrix vdi "
    "office work flow workflow bpm "
    "admin administrator manage manager mgmt management console panel dashboard monitor monitoring "
    "ops devops it ithelp helpdesk servicedesk ticket itsm service support help "
    "git gitlab gitlab-ci svn repo code ci jenkins build release deploy nexus harbor registry "
    "wiki docs doc confluence jira zentao tapd knowledge "
    "test test1 test2 uat sit qa stage staging pre prod prd production demo sandbox lab "
    "dev dev1 dev2 dev3 beta alpha new old v1 v2 "
    "api api2 open openapi gateway gw proxy lb ingress "
    "cdn static assets img image images pic file files fs ftp download upload nas backup pan drive "
    "db mysql oracle redis mongo mongodb elasticsearch kibana log logs logger "
    "grafana prometheus zabbix nagios alert alarm apm "
    "k8s kubernetes docker rancher "
    "ai ml model models gpu data bigdata dw bi report reports analytics "
    "iot mqtt gps map maps gis vehicle car tbox telematics ota firmware update charge charging battery "
    "pay payment order shop mall store shopping "
    "news blog press media video live stream meeting conference "
    "partner supplier vendor customer "
    "marketing mkt brand campaign activity promotion promo "
    "survey vote feedback contact callcenter "
    "sip lync skype teams zoom "
    "cert ca pki kms vault secret config conf "
).split()

ENV_SUFFIXES = ["", "-dev", "-test", "-uat", "-sit", "-pre", "-prd", "-prod",
                "-stage", "-staging", "-demo", "-beta", "-admin", "-api", "-app", "-web",
                "-new", "-old", "2"]


def hostname_filter(root: str):
    """只保留这个根域下的正常主机名(丢掉泛解析标记和无关域名)。"""
    root = root.lower()
    pattern = re.compile(rf"^[a-z0-9_][a-z0-9_.\-]*\.{re.escape(root)}$")
    return lambda name: bool(pattern.match((name or "").strip().lower().lstrip(".")))


def _get(url: str, timeout: float = 25.0) -> httpx.Response | None:
    try:
        with httpx.Client(timeout=timeout, follow_redirects=True, verify=False,
                          headers={"User-Agent": UA}) as client:
            return client.get(url)
    except Exception as exc:  # noqa: BLE001 - 单一来源失败不该中断整轮收集
        print(f"    ! {url.split('?')[0]} 取数失败: {type(exc).__name__}: {str(exc)[:80]}")
        return None


# ---------------------------------------------------------------- 公开来源

def from_crt_sh(root: str) -> set[str]:
    """证书透明度日志: 能拿到没有走泛解析证书的那些子域。"""
    resp = _get(f"https://crt.sh/?q=%25.{root}&output=json", timeout=90)
    keep = hostname_filter(root)
    if resp is None or resp.status_code != 200:
        return set()
    try:
        entries = resp.json()
    except Exception:  # noqa: BLE001
        return set()
    return {value.strip().lower() for entry in entries
            for value in (entry.get("name_value") or "").split("\n") if keep(value)}


def from_urlscan(root: str) -> set[str]:
    """urlscan.io 的公开扫描结果: 别人扫过这个域, 域名就会出现在结果里。"""
    resp = _get(f"https://urlscan.io/api/v1/search/?q=domain:{root}&size=1000")
    if resp is None or resp.status_code != 200:
        return set()
    keep = hostname_filter(root)
    names = set()
    for item in (resp.json().get("results") or []):
        page = item.get("page") or {}
        url = page.get("url") or ""
        candidates = [page.get("domain") or "", url.split("//")[-1].split("/")[0]]
        names |= {c.strip().lower() for c in candidates if keep(c)}
    return names


def from_hackertarget(root: str) -> set[str]:
    resp = _get(f"https://api.hackertarget.com/hostsearch/?q={root}")
    if resp is None or resp.status_code != 200:
        return set()
    keep = hostname_filter(root)
    return {line.split(",")[0].strip().lower() for line in resp.text.splitlines()
            if keep(line.split(",")[0].strip())}


def from_rapiddns(root: str) -> set[str]:
    resp = _get(f"https://rapiddns.io/subdomain/{root}?full=1")
    if resp is None or resp.status_code != 200:
        return set()
    keep = hostname_filter(root)
    return {m.lower() for m in re.findall(r"([A-Za-z0-9_.\-]+\.[A-Za-z]{2,})", resp.text)
            if keep(m)}


def from_db() -> set[str]:
    """本系统已监测的站点: 既当种子, 也用来做"业务词 + 环境后缀"的扩展。"""
    from app import db

    hosts = set()
    for row in db.query("SELECT base_url FROM targets"):
        host = (row["base_url"] or "").split("//")[-1].split("/")[0].lower()
        if host and ":" not in host:
            hosts.add(host)
    return hosts


# ---------------------------------------------------------------- 扩展与解析

def expand_candidates(seeds, root: str, brute: bool) -> set[str]:
    """已知业务词 + 常见环境后缀的组合, 比纯字典命中率高得多。

    例: 已知 scrm-test 与 scrm-uat -> 自然要试 scrm、scrm-dev、scrm-prd。
    """
    if not brute:
        return set()
    keep = hostname_filter(root)
    bases = set(COMMON_NAMES)
    for host in seeds:
        if not keep(host):
            continue
        label = host[: -(len(root) + 1)]
        bases.add(label)
        bases.add(re.sub(r"-(dev|test|uat|sit|pre|prd|prod|stage|staging|demo|beta|new|old)$",
                         "", label))
    return {f"{base}{suffix}.{root}" for base in bases if base
            for suffix in ENV_SUFFIXES if keep(f"{base}{suffix}.{root}")}


# 直连 DNS 查询比系统解析器快得多: 同一个 NXDOMAIN, 系统解析器要 5 秒才放弃,
# 这里 0.1 秒就回来了 —— 一轮上千个名字的差别就是二十分钟和一分钟。
try:
    import dns.resolver
    _DNS = dns.resolver.Resolver()
    _DNS.timeout = 2.5
    _DNS.lifetime = 2.5
    _DNS_QUERY = getattr(_DNS, "resolve", None) or getattr(_DNS, "query", None)
except Exception:                       # noqa: BLE001 - 没装 dnspython 就退回系统解析器
    _DNS_QUERY = None


def resolve(host: str, timeout: float = 2.5) -> list[str]:
    if _DNS_QUERY is not None:
        try:
            answer = _DNS_QUERY(host, "A")
        except Exception:               # noqa: BLE001 - NXDOMAIN/超时都当"没解析"
            return []
        return sorted({item.address for item in answer})
    socket.setdefaulttimeout(timeout)
    try:
        infos = socket.getaddrinfo(host, None, proto=socket.IPPROTO_TCP)
    except Exception:  # noqa: BLE001
        return []
    return sorted({info[4][0] for info in infos})


def load_dns_cache() -> dict:
    path = ROOT / "work" / "dns-cache.json"
    if not path.exists():
        return {}
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:  # noqa: BLE001
        return {}


def save_dns_cache(cache: dict) -> None:
    path = ROOT / "work" / "dns-cache.json"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(cache), encoding="utf-8")


def resolve_cached(host: str, cache: dict, ttl_hours: float) -> tuple[list[str], bool]:
    """带缓存的解析。重复跑同一批域名时, 没到期的直接读缓存 ——
    否则每次都要为上万个不存在的名字等超时, 一轮二十分钟。
    """
    entry = cache.get(host)
    if entry and time.time() - entry.get("at", 0) < ttl_hours * 3600:
        return entry.get("ips", []), True
    ips = resolve(host)
    cache[host] = {"ips": ips, "at": time.time()}
    return ips, False


def wildcard_ips(root: str) -> set[str]:
    """泛解析检测: 随便编一个子域, 如果也能解析, 那整个域就是泛解析。"""
    stamp = datetime.now(timezone.utc).strftime("%H%M%S")
    return set(resolve(f"wildcard-{stamp}.{root}"))


# ---------------------------------------------------------------- 探活

def tls_info(host: str, timeout: float = 6.0) -> dict:
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        with socket.create_connection((host, 443), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as tls:
                cert = tls.getpeercert() or {}
        subject = {k: v for item in cert.get("subject", ()) for k, v in item}
        issuer = {k: v for item in cert.get("issuer", ()) for k, v in item}
        return {"cert_cn": subject.get("commonName", ""),
                "cert_issuer": issuer.get("organizationName", ""),
                "cert_not_after": cert.get("notAfter", "")}
    except Exception:  # noqa: BLE001
        return {}


def probe(host: str, timeout: float = 7.0) -> dict:
    """一个主机一次 GET: 状态码、标题、跳到哪、证书。"""
    out = {"host": host, "http_status": "", "title": "", "final_url": "", "server": ""}
    for scheme in ("https", "http"):
        try:
            with httpx.Client(timeout=timeout, follow_redirects=True, verify=False,
                              headers={"User-Agent": UA}) as client:
                resp = client.get(f"{scheme}://{host}/")
        except Exception:  # noqa: BLE001
            continue
        out["http_status"] = resp.status_code
        out["final_url"] = str(resp.url)
        out["server"] = resp.headers.get("server", "")
        title = re.search(r"<title[^>]*>(.*?)</title>", resp.text[:20000], re.I | re.S)
        if title:
            out["title"] = re.sub(r"\s+", " ", title.group(1)).strip()[:120]
        break
    if out["http_status"] != "":
        out.update(tls_info(host))
    return out


# ---------------------------------------------------------------- 主流程

def collect(root: str, args) -> list[dict]:
    print(f"\n### {root}")
    started = time.monotonic()
    keep = hostname_filter(root)
    sources: dict[str, set[str]] = {}
    for label, fn in (("crt.sh", from_crt_sh), ("urlscan", from_urlscan),
                      ("hackertarget", from_hackertarget), ("rapiddns", from_rapiddns)):
        if label in args.skip_source:
            continue
        found = fn(root)
        sources[label] = found
        print(f"  {label:<14} {len(found):>5} 个")
    if args.from_db:
        known = {h for h in from_db() if keep(h)}
        sources["已监测站点"] = known
        print(f"  {'已监测站点':<12} {len(known):>5} 个")

    public = set().union(*sources.values()) if sources else set()
    candidates = expand_candidates(public, root, brute=not args.no_brute)
    print(f"  {'扩展候选':<14} {len(candidates):>5} 个 (业务词 + 环境后缀)")

    wildcard = wildcard_ips(root)
    if wildcard:
        print(f"  ! 存在泛解析, 随便编的子域也会指向 {', '.join(sorted(wildcard))}")

    targets_to_resolve = sorted(candidates | public)
    print(f"  {'待解析':<14} {len(targets_to_resolve):>5} 个")
    # DNS 这一阶段最慢(上千个不存在的名字要等超时), 所以边跑边报进度,
    # 否则终端上十几分钟没有任何输出, 会以为是卡死了
    ip_map: dict[str, list[str]] = {}
    cache = load_dns_cache()
    cached_hits = 0
    with ThreadPoolExecutor(max_workers=args.concurrency) as pool:
        futures = {pool.submit(resolve_cached, host, cache, args.dns_ttl): host
                   for host in targets_to_resolve}
        done = 0
        for future in as_completed(futures):
            host = futures[future]
            try:
                ip_map[host], from_cache = future.result()
                cached_hits += int(from_cache)
            except Exception:  # noqa: BLE001
                ip_map[host] = []
            done += 1
            if done % 500 == 0 or done == len(targets_to_resolve):
                hit = sum(1 for v in ip_map.values() if v)
                print(f"    解析进度 {done}/{len(targets_to_resolve)}（已命中 {hit}，"
                      f"缓存 {cached_hits}，{time.monotonic() - started:.0f}s）")
    save_dns_cache(cache)
    live = {h: ips for h, ips in ip_map.items() if ips and (set(ips) - wildcard)}
    print(f"  {'解析成功':<14} {len(live):>5} 个")

    with ThreadPoolExecutor(max_workers=max(4, args.concurrency // 2)) as pool:
        probed = list(pool.map(probe, live))

    rows = []
    for item in probed:
        host = item["host"]
        rows.append({
            "host": host,
            "ips": " ".join(ip_map.get(host, [])),
            "reachable": "是" if item["http_status"] != "" else "否",
            "http_status": item["http_status"],
            "title": item["title"],
            "final_url": item["final_url"],
            "server": item["server"],
            "cert_cn": item.get("cert_cn", ""),
            "cert_issuer": item.get("cert_issuer", ""),
            "cert_not_after": item.get("cert_not_after", ""),
            "sources": ",".join(sorted(l for l, names in sources.items() if host in names))
                       or "DNS 扩展",
        })
    rows.sort(key=lambda r: (r["reachable"] != "是", r["host"]))
    print(f"  {'存活':<14} {sum(1 for r in rows if r['reachable'] == '是'):>5} 个")
    return rows


def root_of(host: str, roots: list[str]) -> str:
    """归属到本次收集的根域名(取最长的那个匹配), 否则按最后两段显示。"""
    matched = [r for r in roots if host == r or host.endswith("." + r)]
    if matched:
        return max(matched, key=len)
    return ".".join(host.split(".")[-2:])


def write_outputs(rows: list[dict], outdir: Path, stamp: str,
                  roots: list[str] | None = None) -> tuple[Path, Path]:
    outdir.mkdir(parents=True, exist_ok=True)
    fields = ["host", "ips", "reachable", "http_status", "title", "final_url",
              "server", "cert_cn", "cert_issuer", "cert_not_after", "sources"]
    csv_path = outdir / f"seres-assets-{stamp}.csv"

    # 同一天可以分几次跑不同域名(比如先 seres.cn 再补几个相邻域), 这里按主机名合并,
    # 否则后一次会直接把前一次的结果覆盖掉。
    merged: dict[str, dict] = {}
    if csv_path.exists():
        with csv_path.open(encoding="utf-8-sig") as fh:
            for old in csv.DictReader(fh):
                if old.get("host"):
                    merged[old["host"]] = old
    for row in rows:
        previous = merged.get(row["host"])
        if previous and not row["reachable"] == "是" and previous.get("reachable") == "是":
            row = {**previous, "sources": _union_sources(previous.get("sources", ""),
                                                         row["sources"])}
        elif previous:
            row = {**row, "sources": _union_sources(previous.get("sources", ""), row["sources"])}
        merged[row["host"]] = row
    rows = sorted(merged.values(), key=lambda r: (r["reachable"] != "是", r["host"]))

    with csv_path.open("w", newline="", encoding="utf-8-sig") as fh:
        writer = csv.DictWriter(fh, fieldnames=fields)
        writer.writeheader()
        writer.writerows(rows)

    by_root: dict[str, list[dict]] = {}
    for row in rows:
        by_root.setdefault(root_of(row["host"], roots or []), []).append(row)

    alive = sum(1 for r in rows if r["reachable"] == "是")
    lines = [f"# 赛力斯公网资产清单（{stamp}）", "",
             f"存活 **{alive}** 个 / 解析成功 **{len(rows)}** 个", "", "## 按根域名", ""]
    for root_name, items in sorted(by_root.items()):
        lines.append(f"- `{root_name}`：{len(items)} 个（存活 "
                     f"{sum(1 for i in items if i['reachable'] == '是')}）")
    lines += ["", "## 明细", ""]
    for root_name, items in sorted(by_root.items()):
        lines += [f"### {root_name}", "",
                  "| 主机 | IP | 状态 | 标题 | 来源 |",
                  "| --- | --- | --- | --- | --- |"]
        for row in items:
            ip = (row["ips"].split(" ") or ["—"])[0]
            title = (row["title"] or "").replace("|", "/")[:60]
            lines.append(f"| {row['host']} | {ip} | {row['http_status'] or '不通'} | "
                         f"{title} | {row['sources']} |")
        lines.append("")
    md_path = outdir / f"seres-assets-{stamp}.md"
    md_path.write_text("\n".join(lines), encoding="utf-8")
    return csv_path, md_path


def _union_sources(left: str, right: str) -> str:
    parts = [p for p in (left + "," + right).split(",") if p]
    return ",".join(sorted(dict.fromkeys(parts)))


def main() -> int:
    parser = argparse.ArgumentParser(description="公网资产收集(公开来源 + DNS, 不做端口扫描)")
    parser.add_argument("--domain", action="append", required=True, help="根域名, 可重复")
    parser.add_argument("--out", default=str(ROOT / "outputs" / "assets"))
    # 并发别开太大: 上千次查询轰过去, 内网 DNS 会开始丢包, 表现成"全都解析不出来",
    # 反而比慢慢来更慢。12 左右是实测比较稳的值。
    parser.add_argument("--concurrency", type=int, default=12)
    parser.add_argument("--no-brute", action="store_true", help="只用公开来源, 不做名称扩展")
    parser.add_argument("--from-db", action="store_true", help="带上本系统已监测的站点")
    parser.add_argument("--skip-source", action="append", default=[],
                        help="跳过某个来源: crt.sh / urlscan / hackertarget / rapiddns")
    parser.add_argument("--dns-ttl", type=float, default=12.0,
                        help="DNS 结果缓存多少小时(默认 12), 重复跑同一批域名时省掉大量等待")
    args = parser.parse_args()

    warnings.filterwarnings("ignore")     # 内网自签证书的告警不用刷屏
    stamp = datetime.now().strftime("%Y-%m-%d")
    rows: list[dict] = []
    for domain in args.domain:
        # 每跑完一个根域名就先落盘: DNS 那一阶段动辄十几分钟, 全跑完才写文件的话,
        # 中途想看进度就只能干等。
        rows += collect(domain, args)
        csv_path, md_path = write_outputs(rows, Path(args.out), stamp, args.domain)
        print(f"  已写盘: {csv_path.name}（累计 {len(rows)} 条）")
    if not rows:
        print("没收集到任何资产, 先看看网络或来源是否可用")
        return 1
    print(f"\n清单: {csv_path}\n报告: {md_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
