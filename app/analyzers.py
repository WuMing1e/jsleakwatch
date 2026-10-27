"""采集后端与分析器后端的可插拔接口。

为什么要有这层：Katana / JSHawk / JScanner2 这类工具各有自己的 CLI、输出格式和运行前提，
如果直接把它们编进主流程，核心逻辑就会被外部进程绑架——换工具等于重写。
所以这里只定义两个最小契约，内置实现是默认路径，外部工具一律走适配器，
二进制/客户端缺失时自动降级并在界面上如实标出。

  DiscoveryBackend: 入口 URL  ->  候选资产 URL
  AnalyzerBackend:  资产文本  ->  候选命中

关键设计：外部采集后端只负责"多找到一些 URL"，资产内容和后续展开仍走本系统的
Fetcher / Extractor，这样限速、体积截断、chunk 映射展开、sourcemap 跟随、
指纹去重、跨轮差异这些能力对所有后端都生效。
"""
from __future__ import annotations

import asyncio
import json
import re
import shutil
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Protocol, runtime_checkable
from urllib.parse import urlparse

from .config import ScanConfig
from .discover import NON_PAGE_EXT, same_origin
from . import db


# ------------------------------------------------------------------ 数据契约

@dataclass
class AssetCandidate:
    url: str
    kind: str = "script"      # script | html | map | config
    source: str = "builtin"   # 哪个后端发现它的, 便于对比贡献度
    note: str = ""


@dataclass
class RawHit:
    rule_id: str
    severity: str
    raw: str = ""
    masked: str = ""
    context: str = ""
    line: int = 0
    confidence: float | None = None
    source: str = "builtin"
    note: str = ""
    url: str = ""      # 命中所在资产地址（整站型工具会带上）


def kind_from_url(url: str) -> str:
    path = urlparse(url).path.lower()
    if path.endswith(".map"):
        return "map"
    if path.endswith((".json",)):
        return "json"
    if path.endswith((".html", ".htm")) or path.endswith("/"):
        return "html"
    return "script"


# ------------------------------------------------------------------ 采集后端

@runtime_checkable
class DiscoveryBackend(Protocol):
    name: str

    def available(self) -> bool: ...

    async def discover(self, target: dict[str, Any], cfg: ScanConfig) -> list[AssetCandidate]: ...


class BuiltinDiscovery:
    """内置发现逻辑（HTML/JS 引用 + chunk 映射 + sourcemap），由扫描器本体承担。"""

    name = "builtin"

    def available(self) -> bool:
        return True

    async def discover(self, target: dict[str, Any], cfg: ScanConfig) -> list[AssetCandidate]:
        return []  # 内置路径不需要额外种子


@dataclass
class KatanaDiscovery:
    """ProjectDiscovery 的 Katana（Go，MIT），用其 JSONL 输出补种子。

    实测（本地样例站）：静态模式下 Katana 只给出 HTML 里直接引用的 5 个地址，
    webpack 的按需 chunk 与 sourcemap 都不在里面；因此这里定位为"额外种子来源"，
    而不是替换内置的展开逻辑。
    """

    binary: str = "katana"
    depth: int = 2
    headless: bool = False
    rate_limit: int = 30
    timeout: int = 20
    max_urls: int = 2000
    extra_args: tuple[str, ...] = ()
    # 额外搜索位置(除 PATH 外), 可覆盖以便测试
    search_paths: tuple[str, ...] = (
        "~/Tools/katana/katana", "/usr/local/bin/katana", "/opt/homebrew/bin/katana",
    )
    name = "katana"

    def resolve_binary(self) -> str | None:
        found = shutil.which(self.binary)
        if found:
            return found
        for raw in self.search_paths:
            candidate = Path(raw).expanduser()
            if candidate.exists():
                return str(candidate)
        return None

    def available(self) -> bool:
        return self.resolve_binary() is not None

    def build_command(self, url: str) -> list[str]:
        binary = self.resolve_binary() or self.binary
        cmd = [
            binary, "-u", url, "-jc", "-d", str(self.depth),
            "-silent", "-nc", "-j", "-or",
            "-timeout", str(self.timeout), "-rl", str(max(1, self.rate_limit)),
        ]
        if self.headless:
            cmd.append("-hl")
        cmd.extend(self.extra_args)
        return cmd

    async def discover(self, target: dict[str, Any], cfg: ScanConfig) -> list[AssetCandidate]:
        if not self.available():
            return []
        base_url = target["base_url"]
        scope = target.get("scope") or "same-origin"
        cmd = self.build_command(base_url)
        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.DEVNULL,
            )
            stdout, _ = await asyncio.wait_for(
                proc.communicate(), timeout=max(30, self.timeout * 8)
            )
        except (asyncio.TimeoutError, OSError):
            if proc.returncode is None:  # type: ignore[possibly-undefined]
                proc.kill()
            return []

        out: dict[str, AssetCandidate] = {}
        for line in (stdout or b"").decode("utf-8", "replace").splitlines():
            line = line.strip()
            if not line.startswith("{"):
                continue
            try:
                item = json.loads(line)
            except json.JSONDecodeError:
                continue
            request = item.get("request") or {}
            # 只用 GET 发现的地址, 避免把可能改变状态的接口拿来当种子
            if str(request.get("method") or "GET").upper() != "GET":
                continue
            endpoint = (request.get("endpoint") or "").strip()
            if not endpoint.startswith(("http://", "https://")):
                continue
            if not _in_scope(endpoint, base_url, scope):
                continue
            if is_static_asset(endpoint):
                continue
            key = endpoint.split("#")[0]
            if key in out:
                continue
            out[key] = AssetCandidate(
                url=endpoint,
                kind=kind_from_url(endpoint),
                source=self.name,
                note=(request.get("tag") or ""),
            )
            if len(out) >= self.max_urls:
                break
        return list(out.values())


def _in_scope(url: str, base_url: str, scope: str) -> bool:
    if scope == "any":
        return True
    if scope == "same-host":
        return urlparse(url).netloc.lower() == urlparse(base_url).netloc.lower()
    return same_origin(url, base_url)


# 明确不需要抓的静态资源(图片/字体/样式/压缩包等), 其余一律保留
SKIP_ASSET_EXT = re.compile(
    r"\.(?:png|jpe?g|gif|svg|webp|ico|bmp|avif|woff2?|ttf|eot|otf|css|mp4|webm|mp3|wav|"
    r"pdf|zip|gz|tgz|rar|7z|exe|dmg|apk|iso|bin)(?:$|\?)", re.I)


def is_static_asset(url: str) -> bool:
    """返回 True 表示该 URL 不承载可扫描的 JS/配置内容。"""
    return bool(SKIP_ASSET_EXT.search(urlparse(url).path + "?" + (urlparse(url).query or "")))


# ------------------------------------------------------------------ 分析器后端

@runtime_checkable
class AnalyzerBackend(Protocol):
    name: str

    def available(self) -> bool: ...

    def analyze_text(self, text: str, url: str, target_id: int = 0) -> list[RawHit]: ...


class BuiltinAnalyzer:
    """内置规则引擎（正则 + 熵 + 消歧 + 拼接还原）。"""

    name = "builtin"

    def __init__(self, detector: Any | None = None) -> None:
        if detector is None:
            from .scanner import build_detector
            detector = build_detector()
        self.detector = detector

    def available(self) -> bool:
        return True

    def analyze_text(self, text: str, url: str, target_id: int = 0) -> list[RawHit]:
        hits: list[RawHit] = []
        for det in self.detector.scan_text(text, target_id=target_id, asset_url=url, store_raw=True):
            hits.append(RawHit(
                rule_id=det.rule_id, severity=det.severity, raw=det.raw,
                masked=det.masked, context=det.context, line=det.line_no, source=self.name,
            ))
        # 与线上扫描保持一致：拼接规避写法再跑一遍
        from .rules import CONCAT_RE, collapse_string_concat
        if CONCAT_RE.search(text):
            collapsed = collapse_string_concat(text)
            if collapsed != text:
                seen = {h.rule_id + h.raw for h in hits}
                for det in self.detector.scan_text(collapsed, target_id=target_id,
                                                   asset_url=url, store_raw=True):
                    if det.rule_id + det.raw in seen:
                        continue
                    hits.append(RawHit(
                        rule_id=det.rule_id, severity=det.severity, raw=det.raw,
                        masked=det.masked, context=det.context, line=det.line_no, source=self.name,
                    ))
        return hits


SEVERITY_ALIASES = {
    "critical": "critical", "严重": "critical", "致命": "critical", "blocker": "critical",
    "high": "high", "高危": "high", "高": "high", "error": "high", "major": "high",
    "medium": "medium", "moderate": "medium", "中危": "medium", "中": "medium",
    "warning": "medium", "warn": "medium",
    "low": "low", "低危": "low", "低": "low", "minor": "low", "info": "low",
    "info": "info", "informational": "info", "提示": "info", "note": "info",
}


def normalize_severity(value: Any) -> str:
    text = str(value if value is not None else "").strip().lower()
    return SEVERITY_ALIASES.get(text, "medium")


@dataclass
class CliAnalyzer:
    """把任何"输出 JSON 的检测工具"接进来的通用适配器。

    命令模板占位符：{file} 资产文件路径、{url} 资产地址、{corpus} 语料目录。
    输出解析自动兼容三种形态：整体 JSON 数组 / 含 results|items|findings 字段的对象 / JSONL。
    字段名可通过 field_map 覆盖，便于接入 JSHawk / JScanner2 这类工具。
    """

    name: str
    command: list[str]
    timeout: int = 180
    field_map: dict[str, str] = field(default_factory=lambda: {
        "rule_id": "rule_id", "severity": "severity", "raw": "match",
        "context": "context", "line": "line", "confidence": "confidence",
    })
    severity_default: str = "medium"
    last_error: str = ""          # 最近一次执行的 stderr 摘要, 便于在评测报告里暴露失败原因

    def available(self) -> bool:
        if not self.command:
            return False
        binary = self.command[0]
        return shutil.which(binary) is not None or Path(binary).exists()

    def build_command(self, file_path: str, url: str, corpus_dir: str = "") -> list[str]:
        return [
            part.format(file=file_path, url=url, corpus=corpus_dir) if "{" in part else part
            for part in self.command
        ]

    def parse_output(self, text: str) -> list[dict[str, Any]]:
        return self._parse(text)[0]

    def _parse(self, text: str) -> tuple[list[dict[str, Any]], bool]:
        """返回 (条目, 是否解析成功)。合法但为空的输出不算失败。"""
        text = (text or "").strip()
        if not text:
            return [], True
        try:
            data = json.loads(text)
        except json.JSONDecodeError:
            items: list[dict[str, Any]] = []
            for line in text.splitlines():
                line = line.strip()
                if not line.startswith("{"):
                    continue
                try:
                    parsed = json.loads(line)
                except json.JSONDecodeError:
                    continue
                if isinstance(parsed, dict):
                    items.append(parsed)
            # 有 JSONL 条目, 或者整体结构看得出是 JSON, 都算解析成功
            return items, bool(items) or text.startswith(("{", "["))
        if isinstance(data, list):
            return [item for item in data if isinstance(item, dict)], True
        if isinstance(data, dict):
            for key in ("findings", "results", "items", "matches", "data", "issues"):
                value = data.get(key)
                if isinstance(value, list):
                    return [item for item in value if isinstance(item, dict)], True
            return [data], True
        return [], True

    def _pick(self, item: dict[str, Any], field_name: str, *fallbacks: str) -> Any:
        keys = [self.field_map.get(field_name, field_name), *fallbacks]
        for key in keys:
            if key and key in item and item[key] not in (None, ""):
                return item[key]
        return None

    def to_hits(self, items: list[dict[str, Any]]) -> list[RawHit]:
        hits: list[RawHit] = []
        for item in items:
            raw = str(self._pick(item, "raw", "secret", "value", "matched", "evidence") or "")
            rule_id = str(self._pick(item, "rule_id", "id", "rule", "name", "type") or "cli-hit")
            context = str(self._pick(item, "context", "snippet", "code", "line_content") or "")
            confidence = self._pick(item, "confidence", "score")
            try:
                confidence_value = float(confidence) if confidence is not None else None
            except (TypeError, ValueError):
                confidence_value = None
            try:
                line = int(self._pick(item, "line", "line_number", "lineno") or 0)
            except (TypeError, ValueError):
                line = 0
            hits.append(RawHit(
                rule_id=rule_id,
                severity=normalize_severity(self._pick(item, "severity", "level", "risk") or self.severity_default),
                raw=raw.strip(), context=context.strip()[:600], line=line,
                confidence=confidence_value, source=self.name,
            ))
        return hits

    async def analyze_file(self, file_path: str, url: str, corpus_dir: str = "") -> list[RawHit]:
        if not self.available():
            self.last_error = "命令不可用"
            return []
        cmd = self.build_command(file_path, url, corpus_dir)
        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
            )
            stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=self.timeout)
        except asyncio.TimeoutError:
            self.last_error = f"执行超时 (>{self.timeout}s)"
            return []
        except OSError as exc:
            self.last_error = f"无法执行: {exc}"
            return []
        text = (stdout or b"").decode("utf-8", "replace")
        items, parsed_ok = self._parse(text)
        hits = self.to_hits(items)
        if not hits and not parsed_ok:
            # 没有命中时, 把 stderr 留下来 —— 否则外部工具失败会被当成"什么都没找到"
            tail = (stderr or b"").decode("utf-8", "replace").strip()
            if tail:
                self.last_error = tail.splitlines()[-1][:200]
            elif text.strip():
                self.last_error = f"输出无法解析: {text.strip()[:160]}"
        elif not hits and not (stderr or b"").strip():
            self.last_error = ""
        return hits


# ------------------------------------------------------------------ 注册与装配

def analyzer_specs() -> dict[str, dict[str, Any]]:
    """当前可用的分析器/采集后端清单，供界面展示。"""
    katana = KatanaDiscovery()
    configured = (db.get_setting("analyzers") or {}).get("cli_analyzers") or {}
    cli_entries: dict[str, dict[str, Any]] = {}
    for name, entry in configured.items():
        probe = CliAnalyzer(name=name, command=list(entry.get("command") or []))
        cli_entries[f"cli:{name}"] = {
            "label": entry.get("label") or f"外部分析器 {name}",
            "available": probe.available(),
            "command": " ".join(probe.command),
        }
    return {
        "discovery": {
            "builtin": {"label": "内置展开 (HTML/JS 引用 + chunk 映射 + sourcemap)", "available": True},
            "katana": {
                "label": "Katana 额外种子", "available": katana.available(),
                "binary": katana.resolve_binary() or "",
                "note": "实测静态模式无法发现 webpack 按需 chunk 与 sourcemap，因此作为补充而非替换",
            },
        },
        "analyzer": {
            "builtin": {"label": "内置规则引擎 (正则 + 熵 + 消歧)", "available": True},
            **cli_entries,
        },
    }


def _resolve_config(config: dict[str, Any] | None) -> dict[str, Any]:
    if config is None:
        return db.get_setting("analyzers") or {}
    return config


def build_analyzer(spec: str, config: dict[str, Any] | None = None) -> AnalyzerBackend:
    """spec 支持: builtin | cli:<name>（命令从 config["cli_analyzers"][name] 读取）。

    config 为 None 时自动读取 settings；显式传 {} 表示不带任何外部分析器。
    """
    config = _resolve_config(config)
    if spec.startswith("cli:"):
        name = spec.split(":", 1)[1]
        entry = (config.get("cli_analyzers") or {}).get(name) or {}
        command = entry.get("command") or []
        if isinstance(command, str):
            command = command.split()
        return CliAnalyzer(
            name=name, command=list(command),
            timeout=int(entry.get("timeout") or 180),
            severity_default=str(entry.get("severity_default") or "medium"),
            field_map={**CliAnalyzer("x", []).field_map, **(entry.get("field_map") or {})},
        )
    return BuiltinAnalyzer()


def build_discovery(spec: str, config: dict[str, Any] | None = None) -> DiscoveryBackend:
    config = _resolve_config(config)
    if spec == "katana":
        entry = config.get("katana") or {}
        return KatanaDiscovery(
            binary=str(entry.get("binary") or "katana"),
            depth=int(entry.get("depth") or 2),
            headless=bool(entry.get("headless")),
            rate_limit=int(entry.get("rate_limit") or 30),
            timeout=int(entry.get("timeout") or 20),
            extra_args=tuple(entry.get("extra_args") or ()),
        )
    return BuiltinDiscovery()


def looks_like_js(url: str) -> bool:
    return not NON_PAGE_EXT.search(urlparse(url).path) or urlparse(url).path.lower().endswith(
        (".js", ".mjs", ".cjs", ".json", ".map"))


_ = re  # 保留 re 导入以备后续适配器扩展
