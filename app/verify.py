"""被动验证 + 外部开源工具桥接。

被动验证只做本地解析, 不向第三方发起任何请求 —— 主动打第三方接口验证凭据
存在授权与合规风险, 因此这里只留出扩展位 (见 verify.py 末尾的 CLI 桥接)。

桥接说明: 若环境中安装了 gitleaks / trufflehog, 可以把命中的文本片段交给它们
做二次确认, 二者都是成熟的开源实现, 可作为本系统检测能力的补充。
"""
from __future__ import annotations

import base64
import json
import re
import shutil
import subprocess
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlparse


def _b64url_decode(part: str) -> bytes:
    pad = "=" * (-len(part) % 4)
    return base64.urlsafe_b64decode(part + pad)


def verify_jwt(raw: str) -> str:
    parts = raw.split(".")
    if len(parts) != 3:
        return "invalid"
    try:
        header = json.loads(_b64url_decode(parts[0]))
        payload = json.loads(_b64url_decode(parts[1]))
    except Exception:  # noqa: BLE001
        return "invalid"
    alg = str(header.get("alg", "")).upper()
    if alg in ("NONE", ""):
        return "高危: alg=none"
    exp = payload.get("exp")
    if isinstance(exp, (int, float)):
        now = datetime.now(timezone.utc).timestamp()
        if exp < now:
            return "已过期"
        days = int((exp - now) / 86400)
        return f"格式有效, 剩余 {days} 天"
    return "格式有效, 无 exp 声明"


def verify_pem(raw: str) -> str:
    header = re.sub(r"\s+", " ", raw).strip()
    return "PEM 头有效" if header.startswith("-----BEGIN") else "invalid"


def verify_url(raw: str) -> str:
    try:
        parts = urlparse(raw)
    except ValueError:
        return "invalid"
    host = parts.hostname or "?"
    if parts.scheme and parts.username:
        port = f":{parts.port}" if parts.port else ""
        return f"内嵌凭据 -> {host}{port}"
    return f"目标 {host}"


def looks_like_aws_key(raw: str) -> str:
    return "格式有效 (20 位, 前缀 " + raw[:4] + ")" if re.fullmatch(r"[A-Z0-9]{20}", raw) else "invalid"


def looks_like_google_key(raw: str) -> str:
    return "格式有效 (39 位)" if re.fullmatch(r"AIza[0-9A-Za-z\-_]{35}", raw) else "invalid"


PASSIVE_VERIFIERS = {
    "jwt-token": verify_jwt,
    "private-key-block": verify_pem,
    "alipay-private-key": verify_pem,
    "basic-auth-url": verify_url,
    "database-url": verify_url,
    "aws-access-key-id": looks_like_aws_key,
    "google-api-key": looks_like_google_key,
}


def passive_verify(rule_id: str, raw: str) -> str:
    fn = PASSIVE_VERIFIERS.get(rule_id)
    if fn is None:
        return "unverified"
    try:
        return fn(raw)
    except Exception:  # noqa: BLE001
        return "invalid"


# ------------------------------------------------------------ 外部工具桥接

EXTERNAL_TOOLS = {
    "gitleaks": "gitleaks",
    "trufflehog": "trufflehog",
}


def available_tools() -> dict[str, str]:
    """返回本机可用的开源扫描器路径, 用于在设置页展示可接入能力。"""
    found: dict[str, str] = {}
    for name, binary in EXTERNAL_TOOLS.items():
        path = shutil.which(binary)
        if path:
            found[name] = path
    return found


def run_gitleaks_on_text(text: str, timeout: int = 60) -> list[dict]:
    """把文本交给 gitleaks (MIT) 做二次确认。

    仅在设置中显式开启且本机存在 gitleaks 时调用; 明文只写入临时目录并立即清理。
    """
    binary = shutil.which("gitleaks")
    if not binary:
        return []
    with tempfile.TemporaryDirectory(prefix="jslw-gitleaks-") as tmp:
        target = Path(tmp) / "asset.js"
        target.write_text(text, encoding="utf-8", errors="replace")
        report = Path(tmp) / "report.json"
        try:
            subprocess.run(  # noqa: S603
                [binary, "detect", "--no-git", "-s", tmp, "-f", "json", "-r", str(report), "--exit-code", "0"],
                capture_output=True, timeout=timeout, check=False,
            )
        except (subprocess.SubprocessError, OSError):
            return []
        if not report.exists():
            return []
        try:
            data = json.loads(report.read_text(encoding="utf-8", errors="replace") or "[]")
        except json.JSONDecodeError:
            return []
        return data if isinstance(data, list) else []
