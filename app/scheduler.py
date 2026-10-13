"""持续监测调度器。

- 每 5 秒检查一次到期站点, 到期的按 next_scan_at 顺序入队;
- 全局并发上限 (默认 3 个站点同时扫描), 手动触发与定时任务共用队列;
- 失败退避: 连续失败按 15 * 2^n 分钟退避, 成功后恢复站点自身周期。
"""
from __future__ import annotations

import asyncio
import contextlib
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

from . import db
from .notify import FeishuNotifier
from .scanner import ScanResult, scan_target

MAX_PARALLEL_TARGETS = 3          # 默认值, 可在设置里覆盖
TICK_SECONDS = 5
BACKLOG_FACTOR = 3                # 队列里最多堆积 并行度 × 该倍数


def scheduler_config() -> dict[str, int]:
    """站点级并行度与 tick 间隔: 上千站点时最需要调的两个数。"""
    cfg = {"max_parallel_targets": MAX_PARALLEL_TARGETS, "tick_seconds": TICK_SECONDS}
    for key, value in (db.get_setting("scheduler") or {}).items():
        if key in cfg and value is not None:
            cfg[key] = max(1, int(value))
    return cfg


@dataclass
class SchedulerState:
    running: dict[int, str] = field(default_factory=dict)   # target_id -> 开始时间
    queued: list[dict[str, Any]] = field(default_factory=list)
    last_tick: str = ""
    scans_completed: int = 0
    last_summary: dict[str, Any] = field(default_factory=dict)


class Scheduler:
    def __init__(self) -> None:
        self.state = SchedulerState()
        self._task: asyncio.Task[None] | None = None
        self._queue: asyncio.Queue[tuple[dict[str, Any], bool]] = asyncio.Queue()
        self._sem = asyncio.Semaphore(MAX_PARALLEL_TARGETS)
        self._workers_configured = 0
        self.tick_seconds = TICK_SECONDS
        self._workers: list[asyncio.Task[None]] = []
        self._stop = asyncio.Event()
        self._notifier_instance: FeishuNotifier | None = None

    @property
    def notifier(self) -> FeishuNotifier:
        """延迟创建: 数据库在建库之前可能还不可用。"""
        if self._notifier_instance is None:
            self._notifier_instance = FeishuNotifier()
        return self._notifier_instance

    def invalidate_notifier(self) -> None:
        self._notifier_instance = None

    # ------------------------------------------------------- 生命周期
    async def start(self) -> None:
        if self._task is not None:
            return
        cfg = scheduler_config()
        parallel = cfg["max_parallel_targets"]
        self.tick_seconds = cfg["tick_seconds"]
        self._sem = asyncio.Semaphore(parallel)
        self._stop.clear()
        self._workers = [asyncio.create_task(self._worker(i)) for i in range(parallel)]
        self._workers_configured = parallel
        self._task = asyncio.create_task(self._loop())
        db.log_event(f"调度器已启动: 站点并行 {parallel}, tick {self.tick_seconds}s", kind="scheduler")

    async def stop(self) -> None:
        self._stop.set()
        for worker in self._workers:
            worker.cancel()
        if self._task is not None:
            self._task.cancel()
        for task in [*self._workers, self._task]:
            if task is not None:
                with contextlib.suppress(asyncio.CancelledError):
                    await task
        self._workers = []
        self._task = None

    async def _loop(self) -> None:
        while not self._stop.is_set():
            try:
                await self._tick()
            except Exception as exc:  # noqa: BLE001
                db.log_event(f"调度循环异常: {exc}", kind="scheduler", level="error")
            await asyncio.sleep(self.tick_seconds)

    async def _tick(self) -> None:
        self.state.last_tick = db.utcnow()
        now = datetime.now(timezone.utc).isoformat(timespec="seconds")
        busy = set(self.state.running.keys()) | {t["id"] for t in self.state.queued}
        parallel = self._workers_configured or MAX_PARALLEL_TARGETS
        # 只捞"到期"的站点, 走 (enabled, next_scan_at) 索引, 不再全表扫
        rows = db.query(
            "SELECT * FROM targets WHERE enabled=1 AND (next_scan_at IS NULL OR next_scan_at <= ?) "
            "ORDER BY COALESCE(next_scan_at, '') ASC LIMIT ?",
            (now, max(parallel * BACKLOG_FACTOR, 1)),
        )
        for row in rows:
            target = {k: row[k] for k in row.keys()}
            if target["id"] in busy:
                continue
            self.enqueue(target)
            busy.add(target["id"])
            if len(busy) >= parallel * BACKLOG_FACTOR:
                break

    def enqueue(self, target: dict[str, Any], full: bool = False) -> bool:
        tid = int(target["id"])
        if tid in self.state.running or any(t["id"] == tid for t in self.state.queued):
            return False
        self.state.queued.append(target)
        self._queue.put_nowait((target, full))
        return True

    # ------------------------------------------------------- 工作线程
    async def _worker(self, index: int) -> None:
        while True:
            target, full = await self._queue.get()
            async with self._sem:
                tid = int(target["id"])
                self.state.queued = [t for t in self.state.queued if int(t["id"]) != tid]
                self.state.running[tid] = db.utcnow()
                try:
                    result = await scan_target(target, full=full)
                    self.state.scans_completed += 1
                    self.state.last_summary[tid] = {
                        "at": db.utcnow(),
                        "status": result.status,
                        "assets": result.assets_fetched,
                        "new": len(result.new_findings),
                        "duration_ms": result.duration_ms,
                    }
                    await self._after_scan(target, result)
                except asyncio.CancelledError:
                    raise
                except Exception as exc:  # noqa: BLE001
                    db.log_event(
                        f"扫描 {target.get('name')} 失败: {exc}", kind="scan", level="error",
                        target_id=tid,
                    )
                finally:
                    self.state.running.pop(tid, None)
                    self._queue.task_done()

    async def _after_scan(self, target: dict[str, Any], result: ScanResult) -> None:
        name = target.get("name") or target.get("base_url")
        level = "info" if result.status == "ok" else "warn"
        db.log_event(
            f"{name} 扫描完成: 资产 {result.assets_fetched} 个"
            f"(新增 {result.assets_new}, 复用 {result.assets_skipped}), "
            f"新发现 {len(result.new_findings)} 条, 失效 {result.resolved} 条"
            + (f", {result.discovery_backend} 补充种子 {result.discovery_seeds} 个"
               if result.discovery_seeds else ""),
            kind="scan", level=level, target_id=int(target["id"]),
        )
        if result.new_findings:
            self.invalidate_notifier()
            summary = await self.notifier.notify_findings(result.new_findings)
            if summary.get("sent"):
                skipped = summary.get("skipped_fake") or 0
                db.log_event(
                    f"已推送 {summary['sent']} 条告警到飞书"
                    + (f", 跳过 {skipped} 条 AI 判定为误报" if skipped else ""),
                    kind="alert", target_id=int(target["id"]),
                )
            elif summary.get("failed"):
                db.log_event(
                    f"告警推送失败: {summary.get('errors')}", kind="alert", level="warn",
                    target_id=int(target["id"]),
                )

    async def run_now(self, target: dict[str, Any], full: bool = True) -> bool:
        return self.enqueue(target, full=full)


SCHEDULER = Scheduler()
