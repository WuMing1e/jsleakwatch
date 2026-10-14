"""整站扫描器适配层。

与 `analyzers.CliAnalyzer` 的区别：

  CliAnalyzer     资产文本 → 命中   （我们喂文件，工具只做分析）
  TargetScanner   站点 URL → 命中   （工具自带抓取，我们负责调度与并入）

JSHawk / JScanner2 / Katana 这类工具属于后者：输入是域名，自己爬、自己分析、
结果写进自己的库或报告文件。集成方式因此是"由本系统按站点调起它跑一轮，
再把结果读回来并入发现体系"——调度、增量比对、AI 复核、告警、界面全部复用。

两条硬规则：
1. 只导入**本次目标**的结果（按主机名过滤 + 按起始时间过滤），避免把历史或
   其他站点的数据混进来；
2. 工具失败/超时/库缺失一律降级为"本轮没有外部结果"，不能影响主扫描。
"""
from __future__ import annotations

import asyncio
import sqlite3
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Protocol, runtime_checkable
from urllib.parse import urlparse

from . import db
from .analyzers import RawHit, normalize_severity


@dataclass
class ScanRunResult:
    hits: list[RawHit] = field(default_factory=list)
    runtime_ms: int = 0
    error: str = ""
    note: str = ""


@runtime_checkable
class TargetScanner(Protocol):
    name: str
    label: str

    def available(self) -> bool: ...

    async def scan(self, target: dict[str, Any]) -> ScanRunResult: ...


# ------------------------------------------------------------------ JScanner2

RISK_TO_SEVERITY = {"high": "high", "med": "medium", "medium": "medium", "low": "low"}


def _db_max_id(path: Path) -> int:
    """结果库当前最大行 id, 用作"只导入本轮新增"的水位线。"""
    if not path.exists():
        return 0
    conn = sqlite3.connect(f"file:{path}?mode=ro", uri=True)
    try:
        return int(conn.execute("SELECT COALESCE(MAX(id), 0) FROM sensitive_info").fetchone()[0])
    except sqlite3.Error:
        return 0
    finally:
        conn.close()


def read_jscanner2_hits(db_path: str | Path, host: str = "", min_id: int = 0) -> list[RawHit]:
    """读取 JScanner2 的结果库。

    用 id 水位线而不是时间戳: 它存的是 `YYYY-MM-DD HH:MM:SS`(UTC), 与本系统的
    ISO 时间不可直接比较, 按字符串比会把本轮新结果全部滤掉(实测踩过)。
    """
    path = Path(db_path)
    if not path.exists():
        return []
    conn = sqlite3.connect(f"file:{path}?mode=ro", uri=True)
    conn.row_factory = sqlite3.Row
    try:
        columns = {row[1] for row in conn.execute("PRAGMA table_info(sensitive_info)")}
        if not columns:
            return []
        where, params = [], []
        if host:
            where.append("js_url LIKE ?")
            params.append(f"%{host}%")
        if min_id:
            where.append("id > ?")
            params.append(int(min_id))
        clause = ("WHERE " + " AND ".join(where)) if where else ""
        rows = conn.execute(
            f"SELECT id, sensitive_value, context_code, risk_level, secret_type, js_url "
            f"FROM sensitive_info {clause} ORDER BY id", params).fetchall()
    except sqlite3.Error:
        return []
    finally:
        conn.close()

    hits: list[RawHit] = []
    for row in rows:
        value = (row["sensitive_value"] or "").strip()
        if len(value) < 6:
            continue
        hits.append(RawHit(
            rule_id=f"secret:{row['secret_type'] or 'unknown'}",
            severity=RISK_TO_SEVERITY.get(str(row["risk_level"] or "").lower(),
                                          normalize_severity(row["risk_level"])),
            raw=value,
            context=(row["context_code"] or "")[:600],
            source="jscanner2",
            url=row["js_url"] or "",
        ))
    return hits


@dataclass
class JScanner2Scanner:
    """secr0t/JScanner2（Apache-2.0，tree-sitter AST + AI 判定）。

    mode=run    : 按站点调起它跑一轮, 然后读结果库
    mode=import : 只读已有结果库（适合手动跑完再导入）
    use_ai=False: 只让它做正则/AST 候选提取, 判定交给本系统的 AI 层
                  （一处预算、一套判定口径, 也避免双份 AI 成本）
    """

    module_dir: str = ""
    python: str = ""
    mode: str = "run"
    depth: int = 1
    use_ai: bool = False
    timeout: int = 300        # 单站最长等待; 大站点单轮十几分钟会拖住整个队列
    db_path: str = "Result/JScanner_Result.db"
    name = "jscanner2"
    label = "JScanner2 (AST + AI 判定)"

    def root(self) -> Path:
        return Path(self.module_dir).expanduser() if self.module_dir else Path()

    def interpreter(self) -> str:
        if self.python:
            return self.python
        candidate = self.root() / ".venv" / "bin" / "python"
        return str(candidate) if candidate.exists() else "python3"

    def results_db(self) -> Path:
        path = Path(self.db_path)
        return path if path.is_absolute() else self.root() / path

    def available(self) -> bool:
        root = self.root()
        return bool(self.module_dir) and (root / "main.py").exists() and Path(
            self.interpreter()).exists()

    def build_command(self, target_url: str) -> list[str]:
        cmd = [self.interpreter(), "main.py", "-u", target_url, "-H", str(max(1, self.depth))]
        cmd.append("-asir")          # 正则/AST 候选提取
        if self.use_ai:
            cmd.append("-asia")      # 交给它自己的模型判定
        cmd.append("-nr")            # 禁止主动验证请求（不向第三方发流量）
        return cmd

    async def scan(self, target: dict[str, Any]) -> ScanRunResult:
        if not self.available():
            return ScanRunResult(error="未配置 module_dir 或 main.py 不存在")
        started = time.monotonic()
        host = urlparse(target["base_url"]).netloc
        db_file = self.results_db()
        watermark = _db_max_id(db_file)

        if self.mode == "run":
            cmd = self.build_command(target["base_url"])
            try:
                proc = await asyncio.create_subprocess_exec(
                    *cmd, cwd=str(self.root()),
                    stdout=asyncio.subprocess.DEVNULL, stderr=asyncio.subprocess.PIPE,
                )
                _, stderr = await asyncio.wait_for(proc.communicate(), timeout=self.timeout)
            except asyncio.TimeoutError:
                proc.kill()
                return ScanRunResult(error=f"执行超时 (>{self.timeout}s)",
                                     runtime_ms=int((time.monotonic() - started) * 1000))
            except OSError as exc:
                return ScanRunResult(error=f"无法执行: {exc}")
            if proc.returncode not in (0, None):
                tail = (stderr or b"").decode("utf-8", "replace").strip().splitlines()
                return ScanRunResult(
                    error=f"退出码 {proc.returncode}: {tail[-1][:160] if tail else ''}",
                    runtime_ms=int((time.monotonic() - started) * 1000))
        if self.mode == "import":
            watermark = 0          # 导入模式: 不做水位线过滤, 只按主机名筛选
        elif _db_max_id(db_file) <= watermark:
            watermark = 0          # 结果库被轮换/重建过, 退化为按主机名全量导入

        hits = read_jscanner2_hits(db_file, host=host, min_id=watermark)
        return ScanRunResult(
            hits=hits, runtime_ms=int((time.monotonic() - started) * 1000),
            note=f"{len(hits)} 条命中 (模式 {self.mode}, AI {'由它判定' if self.use_ai else '由本系统判定'})")


# ------------------------------------------------------------------ 注册与装配

BUILDERS = {
    "jscanner2": JScanner2Scanner,
}


def _config() -> dict[str, Any]:
    return (db.get_setting("analyzers") or {}).get("target_scanners") or {}


def build_target_scanner(name: str, entry: dict[str, Any] | None = None) -> TargetScanner | None:
    entry = entry if entry is not None else (_config().get(name) or {})
    builder = BUILDERS.get(name)
    if builder is None:
        return None
    allowed = {key: value for key, value in entry.items()
               if key in builder.__dataclass_fields__}
    return builder(**allowed)


def enabled_target_scanners() -> list[TargetScanner]:
    out: list[TargetScanner] = []
    for name, entry in _config().items():
        if not entry.get("enabled"):
            continue
        scanner = build_target_scanner(name, entry)
        if scanner is not None and scanner.available():
            out.append(scanner)
    return out


def target_scanner_specs() -> dict[str, dict[str, Any]]:
    """给界面用的清单（含不可用原因）。"""
    out: dict[str, dict[str, Any]] = {}
    for name, builder in BUILDERS.items():
        entry = _config().get(name) or {}
        scanner = build_target_scanner(name, entry)
        out[name] = {
            "label": getattr(builder, "label", name) if isinstance(
                getattr(builder, "label", ""), str) else name,
            "enabled": bool(entry.get("enabled")),
            "mode": entry.get("mode", "run"),
            "module_dir": entry.get("module_dir", ""),
            "use_ai": bool(entry.get("use_ai")),
            "available": bool(scanner and scanner.available()),
        }
    return out
