"""运行配置。

优先级: 环境变量 > 数据库 settings 表 > 默认值。
"""
from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent
DATA_DIR = Path(os.getenv("JSLW_DATA_DIR", BASE_DIR / "data"))
DATA_DIR.mkdir(parents=True, exist_ok=True)

DB_PATH = Path(os.getenv("JSLW_DB", DATA_DIR / "jslw.db"))


def _env_int(name: str, default: int) -> int:
    try:
        return int(os.getenv(name, default))
    except (TypeError, ValueError):
        return default


def _env_float(name: str, default: float) -> float:
    try:
        return float(os.getenv(name, default))
    except (TypeError, ValueError):
        return default


@dataclass
class ScanConfig:
    """采集侧默认参数, 可在设置页覆盖。"""

    user_agent: str = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0 Safari/537.36"
    timeout_seconds: float = 15.0
    max_retries: int = 1               # 连接类失败(连接超时/被掐断)的重试次数, 0 = 不重试
    max_concurrency: int = 6           # 全局并发请求数
    per_host_delay_ms: int = 350       # 同一站点请求间隔, 做基本的礼貌限速
    max_assets_per_scan: int = 400    # 单次扫描最多抓取的 JS 资产数
    max_asset_bytes: int = 0           # 单个资产字节上限, 0 = 不限制(整份下载并扫描)
    max_depth: int = 2                 # HTML 页面递归深度
    follow_sourcemaps: bool = True     # 抓取 .map 并扫描 sourcesContent
    allow_cross_origin_js: bool = False
    verify_tls: bool = True
    proxy: str = ""                    # 例如 http://127.0.0.1:8080
    probe_common_config: bool = True   # 探测 /config.js /env.js 等常见配置入口
    store_raw_secrets: bool = False    # 默认只存掩码值, 不落库明文
    scan_api_endpoints: bool = False   # 顺带 GET 同源接口响应并扫描（默认关, 属于额外请求）
    max_api_endpoints: int = 20        # 单站最多抓几个接口
    headless_render: bool = False      # 用无头浏览器渲染页面, 补运行时才出现的地址（默认关）
    max_render_pages: int = 1          # 单站最多渲染几个页面
    render_wait_ms: int = 4000         # 渲染等待时间（虚拟时间预算）
    # 带凭据采集（仅用于已授权目标）：额外请求头与 Cookie，
    # 用来覆盖"登录后才下发"的 JS；留空即匿名采集。
    extra_headers: dict[str, str] = field(default_factory=dict)
    cookies: str = ""


@dataclass
class AlertConfig:
    enabled: bool = False
    channel: str = "webhook"           # webhook | app
    webhook_url: str = ""
    app_id: str = ""
    app_secret: str = ""
    chat_id: str = ""                  # app 模式下接收方 (oc_ 群 / ou_ 用户 / 邮箱)
    min_severity: str = "medium"       # 只推送 >= 该等级的发现
    digest_threshold: int = 5          # 单次新发现超过该数量时合并成一条汇总卡片
    max_alerts_per_run: int = 20
    notify_resolved: bool = False
    at_user_ids: list[str] = field(default_factory=list)
    extra_webhooks: list[str] = field(default_factory=list)  # 通用 webhook (JSON POST)


@dataclass
class Settings:
    host: str = os.getenv("JSLW_HOST", "127.0.0.1")
    port: int = _env_int("JSLW_PORT", 8787)
    scan: ScanConfig = field(default_factory=ScanConfig)
    alert: AlertConfig = field(default_factory=AlertConfig)

    @property
    def db_path(self) -> Path:
        return DB_PATH


SETTINGS = Settings()

# 环境变量兜底: 让无人值守部署不必改数据库即可配置飞书
if os.getenv("JSLW_FEISHU_WEBHOOK"):
    SETTINGS.alert.webhook_url = os.environ["JSLW_FEISHU_WEBHOOK"]
    SETTINGS.alert.enabled = True
if os.getenv("JSLW_FEISHU_APP_ID"):
    SETTINGS.alert.channel = "app"
    SETTINGS.alert.enabled = True
    SETTINGS.alert.app_id = os.environ["JSLW_FEISHU_APP_ID"]
    SETTINGS.alert.app_secret = os.getenv("JSLW_FEISHU_APP_SECRET", "")
    SETTINGS.alert.chat_id = os.getenv("JSLW_FEISHU_CHAT_ID", "")
if os.getenv("JSLW_STORE_RAW"):
    SETTINGS.scan.store_raw_secrets = os.environ["JSLW_STORE_RAW"] not in ("0", "false", "")
