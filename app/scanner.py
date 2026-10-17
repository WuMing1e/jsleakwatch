"""单站点扫描编排。

流程: 抓取入口 -> 广度优先展开脚本/chunk/sourcemap -> 规则匹配
      -> 与历史结果比对 (新增/复现/消失) -> 落库 -> 产出需要告警的条目。
"""
from __future__ import annotations

import asyncio
import hashlib
import json
import re
import tempfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable

from . import ai, asset_history, db, gating
from .config import SETTINGS, ScanConfig
from .discover import Extractor, Candidate, config_probe_candidates
from .fetcher import Fetcher
from .analyzers import kind_from_url
from .rules import (
    CONCAT_RE,
    Detection,
    Detector,
    RULES,
    SEVERITY_ORDER,
    collapse_string_concat,
    looks_like_base64_fragment,
    shannon_entropy,
)
from .verify import passive_verify
from .target_scanners import enabled_target_scanners


@dataclass
class ScanResult:
    target_id: int
    scan_id: int = 0
    status: str = "ok"
    assets_fetched: int = 0
    assets_new: int = 0
    assets_skipped: int = 0
    assets_duplicate: int = 0
    assets_failed: int = 0
    assets_changed: int = 0
    bytes_fetched: int = 0
    findings_total: int = 0
    new_findings: list[dict[str, Any]] = field(default_factory=list)
    resolved: int = 0
    error: str = ""
    duration_ms: int = 0
    ai_summary: dict[str, Any] = field(default_factory=dict)
    discovery_backend: str = "builtin"
    discovery_seeds: int = 0
    runtime_seeds: int = 0
    render_note: str = ""      # 无头渲染的失败原因; 只是可选增强没跑成, 不算扫描失败
    analyzer_summary: dict[str, Any] = field(default_factory=dict)
    target_scanner_summary: dict[str, Any] = field(default_factory=dict)


# ------------------------------------------------------------ 设置装配

def scan_config_from_settings(overrides: dict[str, Any] | None = None) -> ScanConfig:
    cfg = ScanConfig(
        user_agent=SETTINGS.scan.user_agent,
        timeout_seconds=SETTINGS.scan.timeout_seconds,
        max_retries=SETTINGS.scan.max_retries,
        max_concurrency=SETTINGS.scan.max_concurrency,
        per_host_delay_ms=SETTINGS.scan.per_host_delay_ms,
        max_assets_per_scan=SETTINGS.scan.max_assets_per_scan,
        max_asset_bytes=SETTINGS.scan.max_asset_bytes,
        max_depth=SETTINGS.scan.max_depth,
        follow_sourcemaps=SETTINGS.scan.follow_sourcemaps,
        allow_cross_origin_js=SETTINGS.scan.allow_cross_origin_js,
        verify_tls=SETTINGS.scan.verify_tls,
        probe_common_config=SETTINGS.scan.probe_common_config,
        store_raw_secrets=SETTINGS.scan.store_raw_secrets,
        scan_api_endpoints=SETTINGS.scan.scan_api_endpoints,
        max_api_endpoints=SETTINGS.scan.max_api_endpoints,
        headless_render=SETTINGS.scan.headless_render,
        max_render_pages=SETTINGS.scan.max_render_pages,
        render_wait_ms=SETTINGS.scan.render_wait_ms,
    )
    stored = db.get_setting("scan") or {}
    for key, value in stored.items():
        if hasattr(cfg, key) and value is not None:
            setattr(cfg, key, value)
    for key, value in (overrides or {}).items():
        if hasattr(cfg, key) and value is not None:
            setattr(cfg, key, value)
    return cfg


def build_detector() -> Detector:
    overrides = {row["rule_id"]: row for row in db.query("SELECT * FROM rule_overrides")}
    disabled = [rid for rid, row in overrides.items() if row["enabled"] == 0]
    explicitly_enabled = [rid for rid, row in overrides.items() if row["enabled"] == 1]
    severity = {rid: row["severity"] for rid, row in overrides.items() if row["severity"]}
    allowlist = [row["pattern"] for row in db.query("SELECT pattern FROM allowlist")]
    custom: list[Any] = []
    try:
        from .importers.gitleaks import rule_from_dict
        custom = [rule_from_dict(item) for item in (db.get_setting("custom_rules") or [])]
    except Exception:  # noqa: BLE001 - 自定义规则异常不应影响主流程
        custom = []
    return Detector(
        rules=RULES,
        disabled=disabled,
        enabled=explicitly_enabled,
        severity_override=severity,
        allowlist=allowlist,
        custom_rules=custom,
    )


def rules_revision() -> int:
    """规则/白名单变更时自增, 用于让存量资产重新扫描。"""
    return int(db.get_setting("rules_revision", 1) or 1)


def bump_rules_revision() -> int:
    rev = rules_revision() + 1
    db.set_setting("rules_revision", rev)
    return rev


# ------------------------------------------------------------ 主流程

async def collect_runtime_seeds(
    target: dict[str, Any], cfg: ScanConfig, extractor: Extractor
) -> tuple[list[Candidate], list[str]]:
    """用无头浏览器把入口页面真跑一遍, 补出静态抓不到的东西。

    两样收获: 执行后 DOM 里新出现的脚本引用, 以及运行时才拼出来的接口地址。
    浏览器不存在时直接返回空, 扫描照常继续。
    """
    from .runtime import find_chrome, render_page, same_origin

    if not find_chrome():
        return [], ["未找到 Chrome/Chromium, 无头渲染已跳过 (可用 JSLW_CHROME_PATH 指定)"]
    base = target["base_url"]
    seeds: list[Candidate] = []
    notes: list[str] = []
    pages = [base]
    seen: set[str] = set()
    api_budget = max(0, int(cfg.max_api_endpoints or 0))
    for page in pages[: max(1, int(cfg.max_render_pages or 1))]:
        result = await render_page(page, timeout=max(10.0, cfg.timeout_seconds + 15),
                                   wait_ms=max(500, int(cfg.render_wait_ms or 4000)))
        if not result.ok:
            notes.append(f"无头渲染失败: {result.error}")
            continue
        for cand in extractor.from_html(page, result.dom, 0):
            if cand.url not in seen:
                seen.add(cand.url)
                seeds.append(cand)
        for method, url in result.requests:
            if method != "GET" or not same_origin(url, base) or url.split("#")[0] in seen:
                continue
            if url.split("#")[0] == base:
                continue
            kind = kind_from_url(url)
            if kind == "json":
                if api_budget <= 0:
                    continue
                api_budget -= 1
                kind = "api"
            seen.add(url.split("#")[0])
            seeds.append(Candidate(url=url, kind=kind, depth=0, label="无头渲染运行时请求"))
    return seeds, notes


async def scan_target(target: dict[str, Any], full: bool = False) -> ScanResult:
    import time

    started = time.monotonic()
    target_id = int(target["id"])
    cfg = scan_config_from_settings()
    result = ScanResult(target_id=target_id)
    revision = rules_revision()

    scan_id = db.execute(
        "INSERT INTO scans(target_id, started_at, status) VALUES(?,?, 'running')",
        (target_id, db.utcnow()),
    ).lastrowid
    result.scan_id = scan_id or 0

    detector = build_detector()
    extractor = Extractor(
        base_url=target["base_url"],
        scope=target.get("scope") or "same-origin",
        follow_sourcemaps=bool(target.get("include_sourcemaps", 1)) and cfg.follow_sourcemaps,
        scan_api=bool(cfg.scan_api_endpoints),
        max_api=max(0, int(cfg.max_api_endpoints or 0)),
    )

    seen_keys: set[str] = set()          # 本轮出现过的 fingerprint
    stored_assets: dict[str, dict[str, Any]] = {
        row["url"]: {k: row[k] for k in row.keys()}
        for row in db.query("SELECT * FROM assets WHERE target_id = ?", (target_id,))
    }
    detections: list[tuple[str, str, Detection]] = []   # (asset_url, kind, detection)
    errors: list[str] = []
    ai_cfg = ai.ai_config()
    # 语义补漏的候选池: (可疑度, 资产地址, 文本, 已命中明文)
    semantic_pool: list[tuple[float, str, str, list[str]]] = []
    # 外部分析器(并联发现)的候选池: (资产地址, 文本)
    analyzer_pool: list[tuple[str, str]] = []
    external_analyzers = _external_analyzers()

    try:
        # 可选: 用外部采集器(Katana)补充种子。它给的是额外入口, 资产内容与展开
        # 仍然走本系统的 Fetcher/Extractor, 因此限速、chunk 展开、sourcemap 跟随、
        # 跨轮差异全部照常生效。
        discovery_cfg = db.get_setting("discovery") or {}
        backend = str(discovery_cfg.get("backend") or "builtin")
        result.discovery_backend = backend
        extra_seeds: list[Candidate] = []
        if backend == "katana":
            from .analyzers import build_discovery, kind_from_url
            engine = build_discovery("katana", discovery_cfg)
            try:
                for item in await engine.discover(target, cfg):
                    extra_seeds.append(Candidate(url=item.url, kind=kind_from_url(item.url),
                                                 depth=0, label=f"{item.source}:{item.note}"))
            except Exception as exc:  # noqa: BLE001 - 外部工具失败不应中断扫描
                errors.append(f"katana: {type(exc).__name__}: {exc}"[:200])
            result.discovery_seeds = len(extra_seeds)

        # 可选: 无头浏览器把页面真跑一遍, 补出"执行后才出现"的脚本与运行时接口地址
        runtime_seeds: list[Candidate] = []
        if cfg.headless_render:
            runtime_seeds, runtime_notes = await collect_runtime_seeds(target, cfg, extractor)
            result.runtime_seeds = len(runtime_seeds)
            # 无头渲染只是"增强": 它失败说明没拿到运行时地址, 但静态采集该做的都做完了。
            # 记成告警事件而不是扫描错误, 否则半个站点池都会显示成"部分成功"。
            if runtime_notes:
                result.render_note = "; ".join(runtime_notes)[:300]
                db.log_event(f"无头渲染未完成: {result.render_note}",
                             kind="runtime", level="warn", target_id=target_id)

        async with Fetcher(cfg) as fetcher:
            frontier: list[Candidate] = [
                Candidate(url=target["base_url"], kind="html", depth=0, label="入口页面")
            ]
            frontier.extend(extra_seeds)
            frontier.extend(runtime_seeds)
            if target.get("probe_common_config", 1) and cfg.probe_common_config:
                frontier.extend(config_probe_candidates(target["base_url"]))

            visited: set[str] = set()
            max_assets = int(target.get("max_assets") or cfg.max_assets_per_scan)
            max_depth = min(int(target.get("max_depth") or cfg.max_depth), 4)
            fetched = 0
            entry_challenge = ""        # 入口就是人机校验页 -> 整站没得扫, 直接收工
            seen_content: dict[str, str] = {}   # 内容哈希 -> 第一次见到它的地址
            stop_scan = False
            # 留一份有上限的原文, 只为了给外部工具的命中截取真实上下文
            context_texts: dict[str, str] = {}
            context_bytes = 0

            while frontier and fetched < max_assets and not stop_scan:
                # 同一批内也要去重: 外部采集器给出的地址可能与内置入口重叠
                batch: list[Candidate] = []
                batch_urls: set[str] = set()
                for cand in frontier:
                    if cand.url in visited or cand.url in batch_urls:
                        continue
                    batch.append(cand)
                    batch_urls.add(cand.url)
                    if len(batch) >= max_assets - fetched:
                        break
                frontier = []
                if not batch:
                    break
                responses = await asyncio.gather(*[fetcher.get(c.url) for c in batch])
                next_batch: dict[str, Candidate] = {}
                for cand, resp in zip(batch, responses):
                    visited.add(cand.url)
                    if not resp.ok:
                        result.assets_failed += 1
                        if resp.error and resp.error != "binary" and len(errors) < 25:
                            errors.append(f"{cand.url}: {resp.error or f'HTTP {resp.status}'}")
                        continue
                    # 人机校验页不是站点自己的内容: 存下来会变成一堆假资产,
                    # 里面的 WAF 随机串还会被规则当成密钥(误报已经实际发生过)
                    if resp.challenge:
                        if cand.url == target["base_url"]:
                            entry_challenge = resp.challenge
                            stop_scan = True
                        elif not entry_challenge and len(errors) < 25:
                            errors.append(f"{cand.url}: {resp.challenge} 人机校验页")
                        continue
                    if not resp.text:
                        continue

                    sha = hashlib.sha256(resp.text.encode("utf-8", "ignore")).hexdigest()
                    # 同一份内容只存一次、只扫一次。大量 SPA / 网关对任意路径都返回
                    # 同一个页面, 不去重就会把一份内容存成几百个资产, 同一处命中报成几百条
                    first_seen_url = seen_content.get(sha)
                    if first_seen_url is not None and first_seen_url != cand.url:
                        result.assets_duplicate += 1
                        if result.assets_duplicate >= max_assets:
                            stop_scan = True
                        continue
                    seen_content.setdefault(sha, cand.url)

                    fetched += 1
                    result.assets_fetched += 1
                    if (len(resp.text) <= CONTEXT_TEXT_MAX_FILE
                            and context_bytes + len(resp.text) <= CONTEXT_TEXT_BUDGET):
                        context_texts[cand.url] = resp.text
                        context_bytes += len(resp.text)
                    prev = stored_assets.get(cand.url)
                    # recheck: 发现被手动删除后, 资产要重新过一遍规则, 否则删掉的命中永远不会回来
                    unchanged = (bool(prev) and prev["sha256"] == sha
                                 and prev.get("revision") == revision
                                 and not prev.get("recheck"))
                    asset_id, is_new_asset = _upsert_asset(target_id, cand, resp, sha)
                    if is_new_asset:
                        result.assets_new += 1

                    if unchanged and not full:
                        result.assets_skipped += 1
                        for row in db.query(
                            "SELECT fingerprint FROM findings WHERE asset_id = ? AND status IN ('new','open')",
                            (asset_id,),
                        ):
                            seen_keys.add(row["fingerprint"])
                    else:
                        if prev and prev.get("recheck"):
                            db.execute("UPDATE assets SET recheck=0 WHERE id=?", (asset_id,))
                        # 正则检测是纯 CPU: 丢到线程里跑, 别把整个控制台的事件循环堵住
                        asset_dets = await asyncio.to_thread(
                            _detect, detector, resp.text, target_id, cand.url,
                            cfg.store_raw_secrets,
                        )
                        # 接口响应常带时间戳/随机串, 每轮都不一样, 记版本只会把变更流刷满
                        if cand.kind != "api":
                            recorded = asset_history.record_version(
                                target_id, asset_id, cand.url, resp.text, sha,
                                secret_hashes=[det.sha256 for det in asset_dets],
                                findings=len(asset_dets),
                            )
                            if recorded.get("changed"):
                                result.assets_changed += 1
                        for det in asset_dets:
                            detections.append((cand.url, cand.kind, det))
                        if (external_analyzers
                                and len(analyzer_pool) < _analyzer_asset_budget(external_analyzers)):
                            analyzer_pool.append((cand.url, resp.text))
                        if (ai_cfg.enabled and ai_cfg.semantic_scan
                                and len(resp.text) <= max(int(ai_cfg.semantic_max_chars) * 3, 60_000)):
                            semantic_pool.append((
                                ai.suspicion_score(cand.url, resp.text),
                                cand.url,
                                resp.text,
                                [d.raw for d in asset_dets if d.raw],
                            ))

                    # 展开下一层
                    if cand.kind in ("html", "config"):
                        for child in extractor.from_html(cand.url, resp.text, cand.depth):
                            next_batch.setdefault(child.url, child)
                        if cand.depth < max_depth:
                            for page in extractor.pages_from_html(cand.url, resp.text, cand.depth + 1):
                                next_batch.setdefault(page.url, page)
                    elif cand.kind != "api":
                        # 接口响应只扫内容, 不再从里面展开引用（JSON 里的 .js 多半是数据不是引用）
                        for child in extractor.from_js(cand.url, resp.text, cand.depth):
                            next_batch.setdefault(child.url, child)

                frontier = [c for url, c in next_batch.items() if url not in visited]

            result.bytes_fetched = fetcher.bytes_fetched

        if entry_challenge:
            # 明确说清"不是站点挂了, 是匿名请求被 WAF 挡在门外", 否则只会显示成一条无头无脑的超时
            errors.insert(0, f"入口返回 {entry_challenge} 人机校验页, 匿名采集拿不到真实内容"
                             f"(需要带 Cookie 采集, 或改用允许的来源 IP)")
            # 整站都被挡在外面: 再跑 AI 复核、逐资产分析器、整站扫描器都是白烧时间
            # (实测 JScanner2 会在这个校验页上耗到自己的 600 秒超时)
            db.log_event(f"跳过外部分析: 入口是 {entry_challenge} 人机校验页, 没有可分析的内容",
                         kind="scan", level="warn", target_id=target_id)
            result.status = "failed"
            result.error = "; ".join(errors[:5])
            return result

        # ---- 落库比对
        for asset_url, kind, det in detections:
            row = db.query_one("SELECT id FROM assets WHERE target_id=? AND url=?", (target_id, asset_url))
            asset_id = row["id"] if row else None
            is_new, reopened, finding_id = _upsert_finding(target_id, asset_id, asset_url, det)
            seen_keys.add(det.fingerprint)
            if is_new or reopened:
                result.new_findings.append(
                    _finding_payload(target_id, det, asset_url, reopened, finding_id))

        semantic_ran = False
        if ai_cfg.enabled:
            semantic_ran = await _ai_phase(ai_cfg, target_id, result, semantic_pool, seen_keys)

        # 并联发现: 外部分析器只跑在"新增或内容变化"的资产上, 稳态开销接近零
        if external_analyzers and analyzer_pool:
            await _external_analyzer_phase(target_id, external_analyzers, analyzer_pool,
                                           seen_keys, result)

        # 整站型扫描器: 由本系统按站点调起, 结果并入同一套发现
        target_scanners = enabled_target_scanners()
        if target_scanners:
            await _target_scanner_phase(target, target_scanners, seen_keys, result, context_texts)

        # AI 判定放在最后: 规则、逐资产分析器、整站扫描器的命中一起判, 口径统一
        semantic_ran = False
        if ai_cfg.enabled:
            semantic_ran = await _ai_phase(ai_cfg, target_id, result, semantic_pool, seen_keys)

        if result.assets_fetched > 0:
            result.resolved = _resolve_missing(target_id, seen_keys, include_ai=semantic_ran)

        result.findings_total = db.query_one(
            "SELECT COUNT(*) AS c FROM findings WHERE target_id=? AND status IN ('new','open')",
            (target_id,),
        )["c"]
        result.status = "ok" if not errors else ("partial" if result.assets_fetched else "failed")
        result.error = "; ".join(errors[:5])
    except Exception as exc:  # noqa: BLE001
        result.status = "failed"
        result.error = f"{type(exc).__name__}: {exc}"[:500]
    finally:
        result.duration_ms = int((time.monotonic() - started) * 1000)
        finished = db.utcnow()
        db.execute(
            "UPDATE scans SET finished_at=?, status=?, duration_ms=?, assets_fetched=?, assets_new=?, "
            "assets_failed=?, bytes_fetched=?, findings_new=?, findings_total=?, error=? WHERE id=?",
            (finished, result.status, result.duration_ms, result.assets_fetched, result.assets_new,
             result.assets_failed, result.bytes_fetched, len(result.new_findings), result.findings_total,
             result.error, scan_id),
        )
        interval = int(target.get("interval_minutes") or 360)
        failures = int(target.get("consecutive_failures") or 0)
        if result.status == "ok" or result.status == "partial":
            failures = 0
            next_scan = _plus_minutes(interval)
        else:
            failures += 1
            backoff = min(interval, 15 * (2 ** min(failures - 1, 4)))
            next_scan = _plus_minutes(max(5, backoff))
        db.execute(
            "UPDATE targets SET last_scan_at=?, next_scan_at=?, last_status=?, last_error=?, "
            "consecutive_failures=?, total_scans=total_scans+1 WHERE id=?",
            (finished, next_scan, result.status, result.error, failures, target_id),
        )
    return result


def _plus_minutes(minutes: int) -> str:
    from datetime import datetime, timedelta, timezone
    return (datetime.now(timezone.utc) + timedelta(minutes=max(1, minutes))).isoformat(timespec="seconds")


def _detect(detector: Detector, text: str, target_id: int, url: str, store_raw: bool) -> list[Detection]:
    findings = detector.scan_text(text, target_id=target_id, asset_url=url, store_raw=store_raw)
    if CONCAT_RE.search(text):
        collapsed = collapse_string_concat(text)
        if collapsed != text:
            findings.extend(
                detector.scan_text(collapsed, target_id=target_id, asset_url=url, store_raw=store_raw)
            )
    seen: set[str] = set()
    unique: list[Detection] = []
    for item in findings:
        if item.fingerprint in seen:
            continue
        seen.add(item.fingerprint)
        unique.append(item)
    return unique


def _upsert_asset(target_id: int, cand: Candidate, resp: Any, sha: str) -> tuple[int, bool]:
    now = db.utcnow()
    size = len(cand.inline.encode("utf-8")) if cand.kind == "inline" and cand.inline else resp.size
    row = db.query_one("SELECT id, sha256 FROM assets WHERE target_id=? AND url=?", (target_id, cand.url))
    revision = rules_revision()
    if row is None:
        new_id = int(db.execute(
            "INSERT INTO assets(target_id, url, sha256, size, content_type, kind, first_seen_at, "
            "last_seen_at, scan_count, revision) VALUES(?,?,?,?,?,?,?,?,1,?)",
            (target_id, cand.url, sha, size, resp.content_type, cand.kind, now, now, revision),
        ).lastrowid or 0)
        return new_id, True
    changed_at = now if row["sha256"] != sha else None
    if changed_at:
        db.execute("UPDATE assets SET last_changed_at=? WHERE id=?", (changed_at, row["id"]))
    db.execute(
        "UPDATE assets SET sha256=?, size=?, content_type=?, kind=?, last_seen_at=?, "
        "scan_count=scan_count+1, revision=? WHERE id=?",
        (sha, size, resp.content_type, cand.kind, now, revision, row["id"]),
    )
    return int(row["id"]), False


def mark_assets_for_recheck(rows: Iterable[Any]) -> int:
    """把(站点, 资产地址)对应的资产标成"下轮必须重新检测"。

    删除发现时调用: 增量扫描默认跳过内容未变的资产, 不标记的话被删掉的命中
    下一轮根本不会重新跑规则。
    """
    seen: set[tuple[int, str]] = set()
    armed = 0
    for row in rows:
        url = str(row["asset_url"] or "").strip()
        target_id = int(row["target_id"] or 0)
        if not url or (target_id, url) in seen:
            continue
        seen.add((target_id, url))
        cur = db.execute("UPDATE assets SET recheck=1 WHERE target_id=? AND url=?", (target_id, url))
        armed += cur.rowcount or 0
    return armed


def _upsert_finding(
    target_id: int, asset_id: int | None, asset_url: str, det: Detection
) -> tuple[bool, bool, int]:
    """返回 (是否新增, 是否复现, 记录 id)。"""
    now = db.utcnow()
    verified = passive_verify(det.rule_id, det.raw) if det.raw else "unverified"

    # 值级合并: 同一条凭证已经由别的分析器发现过, 就不再新增一条, 只追加"由谁发现"
    twin = db.query_one(
        "SELECT id, status FROM findings WHERE target_id=? AND match_sha256=?",
        (target_id, det.sha256),
    )
    if twin is not None:
        _append_found_by(int(twin["id"]), "builtin")
        reopened = twin["status"] == "resolved"
        db.execute(
            "UPDATE findings SET last_seen_at=?, times_seen=times_seen+1, "
            "asset_id=COALESCE(?, asset_id), asset_url=?, status=? WHERE id=?",
            (now, asset_id, asset_url, "new" if reopened else twin["status"], twin["id"]),
        )
        return False, reopened, int(twin["id"])

    existing = db.query_one("SELECT id, status FROM findings WHERE fingerprint=?", (det.fingerprint,))
    if existing:
        reopened = existing["status"] == "resolved"
        db.execute(
            "UPDATE findings SET last_seen_at=?, times_seen=times_seen+1, asset_id=COALESCE(?, asset_id), "
            "asset_url=?, status=?, verified=CASE WHEN ?<>'unverified' THEN ? ELSE verified END "
            "WHERE id=?",
            (now, asset_id, asset_url, "new" if reopened else existing["status"], verified, verified,
             existing["id"]),
        )
        return False, reopened, int(existing["id"])
    new_id = int(db.execute(
        "INSERT INTO findings(target_id, asset_id, rule_id, rule_name, severity, category, fingerprint, "
        "match_masked, match_sha256, raw_value, context, line_no, entropy, asset_url, first_seen_at, "
        "last_seen_at, times_seen, status, verified, found_by) "
        "VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,1,'new',?,?)",
        (target_id, asset_id, det.rule_id, det.rule_name, det.severity, det.category, det.fingerprint,
         det.masked, det.sha256, det.raw or None, det.context, det.line_no, det.entropy, asset_url,
         now, now, verified, "builtin"),
    ).lastrowid or 0)
    return True, False, new_id


def _append_found_by(finding_id: int, label: str) -> None:
    """把发现来源追加到 found_by(逗号分隔, 去重)。"""
    row = db.query_one("SELECT found_by FROM findings WHERE id=?", (finding_id,))
    if row is None:
        return
    labels = [item for item in (row["found_by"] or "").split(",") if item]
    if label in labels:
        return
    labels.append(label)
    db.execute("UPDATE findings SET found_by=? WHERE id=?", (",".join(labels), finding_id))


def _finding_payload(
    target_id: int, det: Detection, asset_url: str, reopened: bool, finding_id: int = 0
) -> dict[str, Any]:
    return {
        "id": finding_id,
        "target_id": target_id,
        "fingerprint": det.fingerprint,
        "rule_id": det.rule_id,
        "rule_name": det.rule_name,
        "severity": det.severity,
        "category": det.category,
        "masked": det.masked,
        "asset_url": asset_url,
        "context": det.context,
        "line_no": det.line_no,
        "reopened": reopened,
    }


def _resolve_missing(target_id: int, seen: set[str], include_ai: bool = True) -> int:
    rows = db.query(
        "SELECT id, fingerprint, origin FROM findings WHERE target_id=? AND status IN ('new','open')",
        (target_id,),
    )
    stale = [
        row["id"] for row in rows
        if row["fingerprint"] not in seen and (include_ai or row["origin"] != "ai")
    ]
    if not stale:
        return 0
    for fid in stale:
        db.execute("UPDATE findings SET status='resolved' WHERE id=?", (fid,))
    return len(stale)


# ------------------------------------------------------------ AI 复核 / 补漏

def _can_call(client: "ai.AIClient", cfg: "ai.AIConfig") -> bool:
    return ai.budget_left(cfg) > 0


async def _apply_triage(client: "ai.AIClient", cfg: "ai.AIConfig",
                        item: dict[str, Any]) -> tuple[bool, bool]:
    """复核一条发现并落库。返回 (是否判定过, 是否被自动标成误报)。"""
    finding_id = item.get("id")
    row = db.query_one("SELECT * FROM findings WHERE id=?", (finding_id,)) if finding_id else None
    if row is None:
        return False, False
    payload = {k: row[k] for k in row.keys()}
    verdict = await ai.triage_finding(client, payload, raw=row["raw_value"] or "")
    status = row["status"]
    marked_fp = False
    if (cfg.auto_mark_false_positive and verdict["verdict"] == "fake"
            and verdict["confidence"] >= float(cfg.auto_fp_confidence)):
        status = "false_positive"
        marked_fp = True
    db.execute(
        "UPDATE findings SET ai_verdict=?, ai_confidence=?, ai_reason=?, ai_impact=?, "
        "ai_remediation=?, ai_model=?, ai_checked_at=?, status=? WHERE id=?",
        (verdict["verdict"], verdict["confidence"], verdict["reason"],
         verdict.get("impact", ""), verdict.get("remediation", ""),
         verdict.get("model", ""), db.utcnow(), status, row["id"]),
    )
    item.update({"ai_verdict": verdict["verdict"], "ai_confidence": verdict["confidence"],
                 "ai_reason": verdict["reason"], "status": status})
    return True, marked_fp


async def triage_pending(items: list[dict[str, Any]], cap: int = 50) -> int:
    """把还没有 AI 结论的发现补判掉（推送前的最后一次机会）。

    单轮复核上限是为了控制成本，但一条新发现如果没来得及判定就推送，卡片上只能写
    "未复核" —— 用户看到的第一反应就是"为什么没判就发了"。所以在推送前补一轮，
    仍然受当日总预算约束，判定结果与正常复核完全一致（共用缓存）。
    """
    cfg = ai.ai_config()
    if not (cfg.enabled and cfg.verify_new_findings):
        return 0
    pending = [item for item in items if item.get("id") and not item.get("ai_verdict")]
    if not pending:
        return 0
    budget = min(max(0, cap), ai.budget_left(cfg))
    if budget <= 0:
        return 0
    client = ai.AIClient(cfg)
    done = 0
    for item in pending[:budget]:
        if ai.budget_left(cfg) <= 0:
            break
        try:
            triaged, _ = await _apply_triage(client, cfg, item)
        except Exception as exc:  # noqa: BLE001 - 补判失败不该影响推送
            db.log_event(f"推送前补复核失败: {type(exc).__name__}: {exc}"[:200],
                         kind="ai", level="warn")
            break
        if triaged:
            done += 1
    if done:
        db.log_event(f"推送前补复核 {done} 条(超出单轮复核上限的部分)", kind="ai")
    return done


# ------------------------------------------------------------ 外部分析器(并联)

def _external_analyzers() -> list[tuple[str, Any]]:
    """读取已登记且启用、且命令可用的外部分析器。"""
    from .analyzers import build_analyzer

    config = db.get_setting("analyzers") or {}
    if not config.get("run_in_scan", True):
        return []
    out: list[tuple[str, Any]] = []
    for name, entry in (config.get("cli_analyzers") or {}).items():
        if entry.get("enabled") is False:
            continue
        analyzer = build_analyzer(f"cli:{name}", config)
        if analyzer.available():
            out.append((name, analyzer))
    return out


def _analyzer_asset_budget(analyzers: list[tuple[str, Any]]) -> int:
    config = db.get_setting("analyzers") or {}
    budgets = []
    for name, _ in analyzers:
        entry = (config.get("cli_analyzers") or {}).get(name) or {}
        budgets.append(int(entry.get("max_assets") or 80))
    return max(budgets) if budgets else 0


async def _external_analyzer_phase(
    target_id: int,
    analyzers: list[tuple[str, Any]],
    pool: list[tuple[str, str]],
    seen_keys: set[str],
    result: ScanResult,
) -> None:
    """在已采集的资产上并联跑外部分析器, 命中并入同一套发现体系。"""
    config = db.get_setting("analyzers") or {}
    summary: dict[str, Any] = {}
    for name, _ in analyzers:
        entry = (config.get("cli_analyzers") or {}).get(name) or {}
        summary[name] = {"assets": 0, "hits": 0, "new": 0, "merged": 0, "fragments": 0,
                         "max_bytes": max(0, int(entry.get("max_bytes") or 0)), "errors": []}

    with tempfile.TemporaryDirectory(prefix="jslw-analyzers-") as tmp:
        for index, (url, text) in enumerate(pool):
            for name, analyzer in analyzers:
                info = summary[name]
                if info["assets"] >= int((config.get("cli_analyzers") or {}).get(name, {})
                                         .get("max_assets") or 80):
                    continue
                if info["max_bytes"] and len(text.encode("utf-8", "ignore")) > info["max_bytes"]:
                    continue
                path = Path(tmp) / f"{index}-{abs(hash(url)) % 10**8}.txt"
                if not path.exists():
                    path.write_text(text, encoding="utf-8", errors="replace")
                info["assets"] += 1
                hits = await analyzer.analyze_file(str(path), url, tmp)
                if not hits and getattr(analyzer, "last_error", ""):
                    error = f"{url}: {analyzer.last_error}"
                    if len(info["errors"]) < 3:
                        info["errors"].append(error[:200])
                    continue
                for hit in hits:
                    # 夹在连续 Base64 中间的命中是切出来的碎片, 不是独立的值
                    if looks_like_base64_fragment(text, getattr(hit, "raw", "")):
                        info["fragments"] += 1
                        continue
                    info["hits"] += 1
                    created, fingerprint, payload = _upsert_external_hit(
                        target_id, url, name, hit)
                    seen_keys.add(fingerprint)
                    if created:
                        info["new"] += 1
                        result.new_findings.append(payload)
                    else:
                        info["merged"] += 1

    result.analyzer_summary = summary
    parts = [
        f"{name} 资产 {info['assets']} 新增 {info['new']} 归属合并 {info['merged']}"
        + (f" 跳过碎片 {info['fragments']}" if info.get("fragments") else "")
        for name, info in summary.items()
    ]
    if parts:
        errors = [err for info in summary.values() for err in info["errors"]]
        db.log_event(
            "外部分析器并联: " + "; ".join(parts)
            + (f"; 错误 {errors[0]}" if errors else ""),
            kind="analyzer", level="warn" if errors else "info", target_id=target_id,
        )


def _upsert_external_hit(
    target_id: int, asset_url: str, analyzer_name: str, hit: Any,
    channel: str = "cli", found_by_label: str = "",
) -> tuple[bool, str, dict[str, Any]]:
    """外部分析器的命中并入发现体系; 同值已存在则只追加来源归属。"""
    from .rules import mask_value

    raw = (hit.raw or "").strip()
    digest = hashlib.sha256(raw.encode("utf-8", "ignore")).hexdigest() if raw else ""
    asset = db.query_one("SELECT id FROM assets WHERE target_id=? AND url=?", (target_id, asset_url))
    asset_id = asset["id"] if asset else None
    label = found_by_label or f"cli:{analyzer_name}"
    origin = f"{channel}:{analyzer_name}"
    now = db.utcnow()

    if digest:
        twin = db.query_one(
            "SELECT id, fingerprint, status, found_by FROM findings "
            "WHERE target_id=? AND match_sha256=?",
            (target_id, digest),
        )
        if twin is not None:
            _append_found_by(int(twin["id"]), label)
            reopened = twin["status"] == "resolved"
            db.execute(
                "UPDATE findings SET last_seen_at=?, times_seen=times_seen+1, status=? WHERE id=?",
                (now, "new" if reopened else twin["status"], twin["id"]),
            )
            if reopened:
                row = db.query_one("SELECT * FROM findings WHERE id=?", (twin["id"],))
                return False, str(twin["fingerprint"]), _row_payload(row, asset_url, reopened=True)
            return False, str(twin["fingerprint"]), {}

    rule_id = f"{analyzer_name}:{hit.rule_id}"[:80]
    fingerprint = hashlib.sha256(f"{rule_id}|{target_id}|{digest}".encode()).hexdigest()
    masked = hit.masked or (mask_value(raw) if raw else "—")
    finding_id = int(db.execute(
        "INSERT INTO findings(target_id, asset_id, rule_id, rule_name, severity, category, fingerprint, "
        "match_masked, match_sha256, context, line_no, entropy, asset_url, first_seen_at, last_seen_at, "
        "times_seen, status, verified, origin, found_by) "
        "VALUES(?,?,?,?,?,?,?,?,?,?,?,0,?,?,?,1,'new','unverified',?,?)",
        (target_id, asset_id, rule_id, f"[{analyzer_name}] {hit.rule_id}"[:80],
         hit.severity if hit.severity in SEVERITY_ORDER else "medium", "external", fingerprint,
         masked, digest, (hit.context or "")[:1200], hit.line, asset_url, now, now,
         origin, label),
    ).lastrowid or 0)
    return True, fingerprint, {
        "id": finding_id, "target_id": target_id, "fingerprint": fingerprint,
        "rule_id": rule_id, "rule_name": f"[{analyzer_name}] {hit.rule_id}",
        "severity": hit.severity, "category": "external", "masked": masked,
        "asset_url": asset_url, "context": hit.context, "reopened": False,
        "origin": origin,
    }


CONTEXT_WIDTH = 120
CONTEXT_TEXT_BUDGET = 24 * 1024 * 1024      # 单站最多留多少原文用于截上下文
CONTEXT_TEXT_MAX_FILE = 2 * 1024 * 1024     # 超过这个大小的文件不留(内存)


def _context_around(text: str, raw: str, width: int = CONTEXT_WIDTH) -> str:
    """截命中值前后各 width 个字符, 压缩空白(压缩代码里换行没意义)。"""
    if not text or not raw:
        return ""
    index = text.find(raw)
    if index < 0:
        return ""
    start = max(0, index - width)
    end = min(len(text), index + len(raw) + width)
    snippet = re.sub(r"\s+", " ", text[start:end]).strip()
    return f"…{snippet}…" if start or end < len(text) else snippet


def _refine_hit_context(hit: Any, text: str) -> None:
    """把外部分析器给的上下文换成就地截取的那一段, 并丢掉完全对不上的片段。"""
    snippet = _context_around(text, getattr(hit, "raw", ""))
    if snippet:
        hit.context = snippet
    elif getattr(hit, "raw", "") and getattr(hit, "raw", "") not in (getattr(hit, "context", "") or ""):
        # 工具给的片段里根本没有命中值, 留着等于误导
        hit.context = ""


async def _target_scanner_phase(
    target: dict[str, Any],
    scanners: list[Any],
    seen_keys: set[str],
    result: ScanResult,
    context_texts: dict[str, str] | None = None,
) -> None:
    """调起整站型扫描器(JSHawk / JScanner2 等), 把结果并入发现体系。"""
    target_id = int(target["id"])
    summary: dict[str, Any] = {}
    for scanner in scanners:
        try:
            run = await scanner.scan(target)
        except Exception as exc:  # noqa: BLE001 - 外部工具异常不应中断扫描
            summary[scanner.name] = {"hits": 0, "new": 0, "merged": 0, "runtime_ms": 0,
                                     "error": f"{type(exc).__name__}: {exc}"[:200], "note": ""}
            continue
        info = {"hits": len(run.hits), "new": 0, "merged": 0, "fragments": 0,
                "runtime_ms": run.runtime_ms, "error": run.error, "note": run.note}
        for hit in run.hits:
            asset_url = getattr(hit, "url", "") or target["base_url"]
            # 外部工具给的"上下文"未必在命中位置: JSHawk 给的是文件开头 200 字符,
            # 展示出来只会让人更糊涂。能从原文里定位就用真正的前后文替换。
            text = (context_texts or {}).get(asset_url, "")
            _refine_hit_context(hit, text)
            # 命中值夹在连续 Base64 中间 -> 是切出来的碎片(实测一个随机串被当成 Okta token)
            if looks_like_base64_fragment(text, getattr(hit, "raw", "")):
                info["fragments"] += 1
                continue
            created, fingerprint, payload = _upsert_external_hit(
                target_id, asset_url, scanner.name, hit,
                channel="scanner", found_by_label=scanner.name)
            seen_keys.add(fingerprint)
            if created:
                info["new"] += 1
                result.new_findings.append(payload)
            else:
                info["merged"] += 1
        summary[scanner.name] = info

    result.target_scanner_summary = summary
    parts = [
        f"{name} 命中 {info['hits']} 新增 {info['new']} 合并 {info['merged']}"
        + (f" 跳过碎片 {info['fragments']}" if info.get("fragments") else "")
        for name, info in summary.items()
    ]
    errors = [f"{name}: {info['error']}" for name, info in summary.items() if info["error"]]
    if parts:
        db.log_event("整站扫描器: " + "; ".join(parts)
                     + (f"; 错误 {errors[0][:120]}" if errors else ""),
                     kind="scanner", level="warn" if errors else "info", target_id=target_id)


def _row_payload(row: Any, asset_url: str, reopened: bool) -> dict[str, Any]:
    return {
        "id": row["id"], "target_id": row["target_id"], "fingerprint": row["fingerprint"],
        "rule_id": row["rule_id"], "rule_name": row["rule_name"], "severity": row["severity"],
        "category": row["category"], "masked": row["match_masked"], "asset_url": asset_url,
        "context": row["context"], "reopened": reopened, "origin": row["origin"],
    }


async def _ai_phase(
    ai_cfg: "ai.AIConfig",
    target_id: int,
    result: ScanResult,
    semantic_pool: list[tuple[float, str, str, list[str]]],
    seen_keys: set[str],
) -> bool:
    """新发现复核 + 语义补漏。返回语义扫描是否真正执行过。"""
    client = ai.AIClient(ai_cfg)
    summary: dict[str, Any] = {
        "enabled": True, "triaged": 0, "false_positives": 0,
        "semantic_findings": 0, "calls": 0, "cached": 0, "errors": [],
    }
    limit = int(ai_cfg.max_calls_per_scan)

    if ai_cfg.verify_new_findings and result.new_findings and limit > 0:
        # 高误报来源的发现优先判定: 它们会被门控挡在列表之外, 卡住它们最影响可见性
        ordered = sorted(result.new_findings,
                         key=lambda i: 0 if gating.is_gated(str(i.get("rule_id") or "")) else 1)
        for item in ordered[:limit]:
            if not _can_call(client, ai_cfg):
                summary["errors"].append("已达当日调用上限, 剩余发现未复核")
                break
            triaged, marked_fp = await _apply_triage(client, ai_cfg, item)
            if triaged:
                summary["triaged"] += 1
                if marked_fp:
                    summary["false_positives"] += 1
        overflow = len(result.new_findings) - limit
        if overflow > 0:
            # 这些会在推送前补判（triage_pending）, 这里先记一笔让原因可见
            summary["errors"].append(f"{overflow} 条超出单轮复核上限")

    semantic_ran = False
    if ai_cfg.semantic_scan and semantic_pool:
        ranked = sorted(semantic_pool, key=lambda item: item[0], reverse=True)
        for _score, url, text, raws in ranked[: max(0, int(ai_cfg.semantic_max_assets))]:
            if not _can_call(client, ai_cfg):
                summary["errors"].append("已达当日调用上限, 语义补漏中断")
                break
            semantic_ran = True
            for candidate in await ai.semantic_scan_text(client, text, url, redact=raws):
                created, fingerprint, payload = _insert_ai_finding(target_id, url, candidate)
                seen_keys.add(fingerprint)
                if created:
                    summary["semantic_findings"] += 1
                    result.new_findings.append(payload)

    summary["calls"] = client.calls
    summary["cached"] = client.cache_hits
    summary["errors"].extend(client.errors[-3:])
    result.ai_summary = summary
    if summary["triaged"] or summary["semantic_findings"] or summary["errors"]:
        db.log_event(
            f"AI 复核: 判定 {summary['triaged']} 条, 语义补漏 {summary['semantic_findings']} 条, "
            f"调用 {summary['calls']} 次(缓存 {summary['cached']})",
            kind="ai", level="warn" if summary["errors"] else "info", target_id=target_id,
        )
    return semantic_ran


def _insert_ai_finding(
    target_id: int, asset_url: str, item: dict[str, Any]
) -> tuple[bool, str, dict[str, Any]]:
    """把语义补漏结果写成一等公民的"发现", 复用已有的去重/告警/状态流转。"""
    evidence = item["evidence"]
    # AI 给出的是一段证据文本, 先尽力从中还原出"凭证本体":
    # 这样它就能与规则/外部分析器的结果按同一个值归并, 而不是重复报一条。
    secrets = _extract_secrets_from_evidence(evidence)
    evidence_digest = hashlib.sha256(evidence.encode("utf-8", "ignore")).hexdigest()
    digest = (hashlib.sha256(secrets[0].encode("utf-8", "ignore")).hexdigest()
              if secrets else evidence_digest)
    fingerprint = hashlib.sha256(f"ai:semantic|{target_id}|{digest}".encode()).hexdigest()
    now = db.utcnow()

    # 证据里出现的凭证可能已被规则引擎发现过: 按值并入, 而不是再报一条
    merged: list[str] = []
    for value in secrets:
        value_digest = hashlib.sha256(value.encode("utf-8", "ignore")).hexdigest()
        twin = db.query_one(
            "SELECT id, fingerprint, status FROM findings WHERE target_id=? AND match_sha256=?",
            (target_id, value_digest),
        )
        if twin is None:
            continue
        _append_found_by(int(twin["id"]), "ai:semantic")
        db.execute(
            "UPDATE findings SET last_seen_at=?, times_seen=times_seen+1, status=? WHERE id=?",
            (now, "new" if twin["status"] == "resolved" else twin["status"], twin["id"]),
        )
        merged.append(str(twin["fingerprint"]))
    if merged:
        # 返回既有发现的指纹, 让调用方把它一并计入"本轮已见", 避免被误判为失效
        return False, merged[0], {}

    existing = db.query_one("SELECT id, status FROM findings WHERE fingerprint=?", (fingerprint,))
    if existing is not None:
        reopened = existing["status"] == "resolved"
        db.execute(
            "UPDATE findings SET last_seen_at=?, times_seen=times_seen+1, status=? WHERE id=?",
            (now, "new" if reopened else existing["status"], existing["id"]),
        )
        return False, fingerprint, {}

    confidence = float(item.get("confidence") or 0)
    asset = db.query_one("SELECT id FROM assets WHERE target_id=? AND url=?", (target_id, asset_url))
    label = f"[AI] {item['type']}"[:60]
    context = f"{evidence}\n\n判定依据: {item.get('reason', '')}".strip()[:1200]
    finding_id = int(db.execute(
        "INSERT INTO findings(target_id, asset_id, rule_id, rule_name, severity, category, fingerprint, "
        "match_masked, match_sha256, context, line_no, entropy, asset_url, first_seen_at, last_seen_at, "
        "times_seen, status, verified, origin, ai_verdict, ai_confidence, ai_reason, ai_model, ai_checked_at) "
        "VALUES(?,?,?,?,?,?,?,?,?,?,0,?,?,?,?,1,'new','unverified','ai',?,?,?,?,?)",
        (target_id, asset["id"] if asset else None, "ai:semantic",
         f"AI 语义发现 · {item['type']}"[:80], item["severity"], "ai", fingerprint,
         label, digest, context, 0.0, asset_url, now, now,
         "real" if confidence >= 0.8 else "uncertain", confidence,
         item.get("reason", "")[:600], "semantic", now),
    ).lastrowid or 0)
    return True, fingerprint, {
        "id": finding_id,
        "target_id": target_id,
        "fingerprint": fingerprint,
        "rule_id": "ai:semantic",
        "rule_name": f"AI 语义发现 · {item['type']}",
        "severity": item["severity"],
        "category": "ai",
        "masked": label,
        "asset_url": asset_url,
        "context": context,
        "reopened": False,
        "origin": "ai",
    }


QUOTED_RE = re.compile(r"""["'`]([^"'`\s]{8,400})["'`]""")


def _extract_secrets_from_evidence(evidence: str) -> list[str]:
    """从 AI 的证据片段里尽力还原凭证本体, 可能不止一个。

    跳过的是**字段名/文案**（无数字且低熵, 如 VITE_APP_API_KEY / amapKey / debug）,
    而不是"全小写"——小写十六进制正是阿里云 Secret、微信 AppSecret、高德 Key 的形态,
    早期按 islower() 过滤会把这类真实密钥整类漏掉。
    """
    if not evidence:
        return []
    candidates: list[str] = []
    for match in QUOTED_RE.finditer(evidence):
        value = match.group(1).strip()
        if value.startswith(("http", "/", "./")):
            candidates.append(value.rstrip("/"))
            continue
        if len(value) < 12:
            continue
        if not re.search(r"\d", value) and shannon_entropy(value) < 3.5:
            continue          # 无数字且低随机度 => 字段名或普通文案
        candidates.append(value)
    for match in re.finditer(r"""(?:access_token|key|token|secret|password|passwd)=([^\s&"']{12,200})""",
                             evidence, re.I):
        candidates.append(match.group(1))
    # 去重并保持出现顺序
    seen: set[str] = set()
    out: list[str] = []
    for value in candidates:
        if value not in seen:
            seen.add(value)
            out.append(value)
    return out


def severity_at_least(severity: str, threshold: str) -> bool:
    return SEVERITY_ORDER.get(severity, 0) >= SEVERITY_ORDER.get(threshold, 0)


async def semantic_scan_target(target: dict[str, Any], limit: int = 5) -> dict[str, Any]:
    """对某站点已采集的资产做一次按需语义审计(不跑完整规则扫描)。

    优先挑配置类与体积小的脚本, 并在发送前把规则已命中的明文替换掉。
    """
    ai_cfg = ai.ai_config()
    if not ai_cfg.enabled:
        return {"ok": False, "error": "AI 未启用, 请先在「系统设置 → AI 复核」中开启"}
    target_id = int(target["id"])
    rows = db.query(
        "SELECT url, kind, size FROM assets WHERE target_id=? "
        "ORDER BY CASE kind WHEN 'config' THEN 0 WHEN 'inline' THEN 1 WHEN 'html' THEN 2 "
        "WHEN 'map' THEN 4 ELSE 3 END, size ASC LIMIT ?",
        (target_id, max(1, limit * 4)),
    )
    detector = build_detector()
    store_raw = scan_config_from_settings().store_raw_secrets
    scanned = 0
    inserted: list[dict[str, Any]] = []

    if not rows:
        return {"ok": False, "error": "该站点还没有采集到资产, 请先执行一次扫描"}

    async with Fetcher(scan_config_from_settings()) as fetcher:
        guard = 0
        for row in rows:
            if scanned >= limit or not _can_call(ai.AIClient(ai_cfg), ai_cfg):
                break
            guard += 1
            if guard > limit * 4:
                break
            result = await fetcher.get(row["url"])
            if not result.ok or not result.text:
                continue
            scanned += 1
            detected = await asyncio.to_thread(
                _detect, detector, result.text, target_id, row["url"], store_raw
            )
            raws = [d.raw for d in detected if d.raw]
            client = ai.AIClient(ai_cfg)
            for candidate in await ai.semantic_scan_text(client, result.text, row["url"], redact=raws):
                created, _fingerprint, payload = _insert_ai_finding(target_id, row["url"], candidate)
                if created:
                    inserted.append(payload)

    db.log_event(
        f"按需语义审计: {target.get('name')} 扫描 {scanned} 个资产, 新增 {len(inserted)} 条发现",
        kind="ai", target_id=target_id,
    )
    return {"ok": True, "assets_scanned": scanned, "findings": inserted, "count": len(inserted)}
