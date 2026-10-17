"""检测规则与扫描引擎。

规则形态参考 gitleaks 的规则定义方式 (id / description / regex / keywords /
entropy / allowlist), 并针对国内常见云厂商、IM、支付平台做了扩充。
新增规则时只需往 RULES 里追加一条, 无需改动扫描逻辑。
"""
from __future__ import annotations

import hashlib
import math
import re
from bisect import bisect_left
from dataclasses import dataclass, field
from typing import Iterable, Iterator

# ---------------------------------------------------------------- 数据模型

SEVERITY_ORDER = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}

# 上下文截断对齐用的分隔符
SEPARATORS = set(" \t\n\r;{}()[]<>,:=\"'`/+*&|!?")


@dataclass(frozen=True)
class Rule:
    id: str
    name: str
    severity: str
    category: str
    pattern: str
    description: str = ""
    secret_group: int = 0          # 0 = 整个匹配, >0 = 取该捕获组
    keywords: tuple[str, ...] = ()  # 命中窗口内必须出现其中之一 (降噪)
    window: int = 80               # keywords 检查窗口 (字符)
    entropy_min: float = 0.0       # 对 secret 计算香农熵的下限
    min_length: int = 0
    allowlist: tuple[str, ...] = ()  # 命中值命中这些正则时忽略
    reference: str = ""
    tags: tuple[str, ...] = ()
    default_enabled: bool = True


@dataclass
class Detection:
    rule_id: str
    rule_name: str
    severity: str
    category: str
    raw: str
    masked: str
    sha256: str
    entropy: float
    line_no: int
    context: str
    fingerprint: str
    start: int = 0
    end: int = 0


# 重叠消歧优先级: 数值大的优先, 用于压掉同一段文本上的低置信度命中
PRECEDENCE: dict[str, int] = {
    "high-entropy-string": 1,
    "generic-secret-assignment": 2,
    "basic-auth-url": 3,
    "sourcemap-reference": 4,
    "database-url": 8,
}
DEFAULT_PRECEDENCE = 5


# ---------------------------------------------------------------- 工具函数

def shannon_entropy(value: str) -> float:
    if not value:
        return 0.0
    counts: dict[str, int] = {}
    for ch in value:
        counts[ch] = counts.get(ch, 0) + 1
    length = len(value)
    return -sum((c / length) * math.log2(c / length) for c in counts.values())


def mask_value(value: str) -> str:
    """只保留首尾少量字符, 用于界面与通知中的展示。"""
    if len(value) <= 8:
        return value[0] + "***" + value[-1] if len(value) > 2 else "***"
    head, tail = value[:4], value[-4:]
    return f"{head}...{tail}(len={len(value)})"


PLACEHOLDER_HINTS = (
    "your_", "your-", "yourapi", "mysecret", "example", "sample", "placeholder",
    "changeme", "change_me", "change-me", "xxxx", "aaaa", "****", "dummy",
    "foobar", "lorem", "todo", "fixme", "redacted", "process.env", "${", "{{",
    "%s", "insert_", "replace_", "notreal", "fake", "test_key", "testkey",
    "apitest", "undefined", "null", "none", "abcdefg", "1234567890", "0123456789",
    "insert_your", "add_your", "enter_your", "put_your", "secret_key_here",
    "access_key_here", "token_here", "password_here", "<", ">", "\\u",
)

PLACEHOLDER_EXACT = {
    "null", "undefined", "true", "false", "none", "nil", "nan", "0", "1",
    "password", "secret", "token", "apikey", "api_key", "accesskey",
    "access_key", "secretkey", "secret_key", "xxxxxxxx", "aaaaaaaa",
    "changeme", "test", "demo", "string", "value", "your", "empty", "todo",
}


def looks_placeholder(value: str) -> bool:
    lowered = value.strip().lower()
    if lowered in PLACEHOLDER_EXACT:
        return True
    if len(set(value)) <= 2 and len(value) > 3:
        return True
    if re.fullmatch(r"(ab|abc|abcd|xyz|xyz0|01|0123)+", lowered):
        return True
    for hint in PLACEHOLDER_HINTS:
        if hint in lowered:
            return True
    return False


def looks_like_code_path(value: str) -> bool:
    """形如 static/js/vendor.abc123.js 的路径不是密钥。"""
    if "://" in value:
        return False  # 带协议的地址按 URL 处理, 不能当资源路径丢掉
    if re.fullmatch(r"[\w./\-]+\.(js|mjs|css|json|png|jpg|jpeg|svg|webp|woff2?|ttf|map)", value, re.I):
        return True
    if value.count("/") >= 2 and not re.search(r"[A-Z]", value):
        return True
    return False


# 压缩产物里常见 `"a" + "b"` 形式的字符串拼接, 用于规避朴素扫描
CONCAT_RE = re.compile(r"""(["'`])\s*\+\s*(["'`])""")


def collapse_string_concat(text: str) -> str:
    """把相邻字符串字面量拼起来, 便于在内联拼接的代码里发现密钥。

    ``"a" + "b"`` -> ``"ab"``: 删掉相邻字面量之间的 收尾引号 + 加号 + 起始引号。
    """
    return CONCAT_RE.sub("", text)


# ---------------------------------------------------------------- 规则表

def _r(*args, **kwargs) -> Rule:  # 简写
    return Rule(*args, **kwargs)


RULES: list[Rule] = [
    # ============ 通用云 / AWS / GCP ============
    _r("aws-access-key-id", "AWS Access Key ID", "critical", "cloud",
       r"\b((?:AKIA|ASIA|ABIA|ACCA|AGPA|AIDA|AIPA|ANPA|ANVA|APKA|AROA)[0-9A-Z]{16})\b",
       description="AWS 访问密钥 ID, 若 Secret 同时泄露即可接管云上资源。",
       reference="https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_access-keys.html",
       tags=("aws", "credential")),
    _r("aws-secret-access-key", "AWS Secret Access Key", "critical", "cloud",
       r"""(?:aws|s3|amazon)[^\n]{0,60}?["'\s=:]([A-Za-z0-9/+=]{40})["'\s]""",
       keywords=("aws", "s3", "amazon", "secret"), secret_group=1, entropy_min=3.2,
       description="AWS 私有访问密钥, 需与 Access Key ID 配对使用。",
       tags=("aws", "credential")),
    _r("google-api-key", "Google API Key", "high", "cloud",
       r"\b(AIza[0-9A-Za-z\-_]{35})\b",
       description="Google Cloud / Firebase API Key, 常在受限不严时被滥用。",
       tags=("google", "api-key")),
    _r("google-oauth-client-secret", "Google OAuth Client Secret", "high", "cloud",
       r"\b(GOCSPX-[A-Za-z0-9\-_]{28,})\b", tags=("google", "oauth")),
    _r("google-service-account", "Google 服务账号私钥", "critical", "cloud",
       r"(?s)-----BEGIN PRIVATE KEY-----.{0,400}?\"private_key_id\"|"
       r"\"type\"\s*:\s*\"service_account\"",
       description="服务账号 JSON 密钥文件内容泄露。", tags=("google", "private-key")),
    _r("firebase-server-key", "Firebase Cloud Messaging 服务器密钥", "high", "cloud",
       r"\b(AAAA[A-Za-z0-9_\-]{7}:[A-Za-z0-9_\-]{140,})\b", tags=("firebase",)),
    _r("firebase-db-url", "Firebase 实时数据库地址", "info", "cloud",
       r"https://[a-z0-9\-]+(?:-[a-z0-9]+)?\.firebaseio\.com",
       description="数据库地址本身不敏感, 但可用于确认后端归属。", tags=("firebase",)),

    # ============ 代码托管 / CI ============
    _r("github-token", "GitHub 访问令牌", "critical", "scm",
       r"\b(gh[pousr]_[A-Za-z0-9]{36,255})\b", tags=("github", "token")),
    _r("github-fine-grained-pat", "GitHub 细粒度令牌", "critical", "scm",
       r"\b(github_pat_[A-Za-z0-9_]{82})\b", tags=("github", "token")),
    _r("gitlab-token", "GitLab 访问令牌", "critical", "scm",
       r"\b(glpat-[A-Za-z0-9_\-]{20,})\b", tags=("gitlab", "token")),
    _r("npm-token", "NPM 发布令牌", "high", "scm",
       r"\b(npm_[A-Za-z0-9]{36})\b", tags=("npm", "token")),
    _r("pypi-token", "PyPI 上传令牌", "high", "scm",
       r"\b(pypi-AgEIcHlwaS5vcmc[A-Za-z0-9\-_]{50,})\b", tags=("pypi", "token")),
    _r("dockerhub-pat", "Docker Hub 访问令牌", "high", "scm",
       r"\b(dckr_pat_[A-Za-z0-9\-_]{27,})\b", tags=("docker",)),
    _r("heroku-api-key", "Heroku API Key", "medium", "cloud",
       r"heroku[^\n]{0,40}?([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})",
       keywords=("heroku",), secret_group=1, tags=("heroku",)),
    _r("digitalocean-token", "DigitalOcean Token", "high", "cloud",
       r"\b(dop_v1_[a-f0-9]{64})\b", tags=("digitalocean",)),
    _r("terraform-cloud-token", "Terraform Cloud Token", "high", "cloud",
       r"\b([A-Za-z0-9]{14}\.atlasv1\.[A-Za-z0-9\-_]{60,})\b", tags=("terraform",)),
    _r("cloudflare-token", "Cloudflare API Token", "high", "cloud",
       r"cloudflare[^\n]{0,60}?([A-Za-z0-9_\-]{40})",
       keywords=("cloudflare",), secret_group=1, tags=("cloudflare",)),
    _r("netlify-token", "Netlify Token", "medium", "cloud",
       r"netlify[^\n]{0,60}?([A-Za-z0-9\-_]{40,})",
       keywords=("netlify",), secret_group=1, tags=("netlify",)),
    _r("vercel-token", "Vercel Token", "medium", "cloud",
       r"vercel[^\n]{0,60}?([A-Za-z0-9]{24})",
       keywords=("vercel",), secret_group=1, tags=("vercel",)),
    _r("shopify-access-token", "Shopify Access Token", "high", "cloud",
       r"\b(shpat_[a-f0-9]{32})\b", tags=("shopify",)),

    # ============ 支付 ============
    _r("stripe-secret-key", "Stripe 私钥", "critical", "payment",
       r"\b(sk_live_[0-9a-zA-Z]{24,})\b", tags=("stripe", "payment")),
    _r("stripe-restricted-key", "Stripe 受限私钥", "critical", "payment",
       r"\b(rk_live_[0-9a-zA-Z]{24,})\b", tags=("stripe", "payment")),
    _r("stripe-webhook-secret", "Stripe Webhook 签名密钥", "high", "payment",
       r"\b(whsec_[A-Za-z0-9]{32,})\b",
       description="泄露后可用于伪造 webhook 事件, 直接影响订单/支付状态。",
       tags=("stripe", "payment")),
    _r("square-access-token", "Square 访问令牌", "high", "payment",
       r"\b(sq0atp-[0-9A-Za-z\-_]{22}|sq0csp-[0-9A-Za-z\-_]{43})\b", tags=("square",)),
    _r("paypal-client-secret", "PayPal Client Secret", "high", "payment",
       r"paypal[^\n]{0,80}?(?:secret|client_secret)[^\n]{0,20}?[:\s=][\"']?([A-Za-z0-9\-_]{40,})",
       keywords=("paypal",), secret_group=1, tags=("paypal", "payment")),

    # ============ 邮件 / 短信 ============
    _r("sendgrid-api-key", "SendGrid API Key", "high", "email",
       r"\b(SG\.[A-Za-z0-9_\-]{22}\.[A-Za-z0-9_\-]{43})\b", tags=("sendgrid",)),
    _r("mailgun-api-key", "Mailgun API Key", "medium", "email",
       r"mailgun[^\n]{0,60}?(?:key-)?([0-9a-zA-Z]{32}-?[0-9a-zA-Z]{0,8})",
       keywords=("mailgun",), secret_group=1, tags=("mailgun",)),
    _r("mailchimp-api-key", "Mailchimp API Key", "medium", "email",
       r"\b([0-9a-f]{32}-us\d{1,2})\b", tags=("mailchimp",)),
    _r("twilio-account-sid", "Twilio Account SID", "medium", "sms",
       r"\b(AC[0-9a-fA-F]{32})\b", keywords=("twilio",), tags=("twilio",)),
    _r("twilio-auth-token", "Twilio Auth Token", "high", "sms",
       r"twilio[^\n]{0,60}?(?:auth_token|token)[^\n]{0,20}?[:\s=][\"']?([0-9a-f]{32})",
       keywords=("twilio",), secret_group=1, tags=("twilio",)),

    # ============ IM / 协作 ============
    _r("slack-token", "Slack Token", "high", "im",
       r"\b(xox[abprs]-[0-9A-Za-z\-]{10,})\b", tags=("slack",)),
    _r("slack-webhook", "Slack Incoming Webhook", "high", "im",
       r"https://hooks\.slack\.com/services/T[A-Z0-9]{8,}/B[A-Z0-9]{8,}/[A-Za-z0-9]{20,}",
       tags=("slack",)),
    _r("discord-bot-token", "Discord Bot Token", "high", "im",
       r"\b([MNO][A-Za-z0-9\-_]{23}\.[A-Za-z0-9\-_]{6}\.[A-Za-z0-9\-_]{27,})\b", tags=("discord",)),
    _r("discord-webhook", "Discord Webhook", "medium", "im",
       r"https://(?:ptb\.|canary\.)?discord(?:app)?\.com/api/webhooks/\d{15,}/[A-Za-z0-9\-_]{60,}",
       tags=("discord",)),
    _r("telegram-bot-token", "Telegram Bot Token", "high", "im",
       r"\b(\d{8,10}:AA[A-Za-z0-9\-_]{33})\b", tags=("telegram",)),
    _r("facebook-access-token", "Facebook Access Token", "high", "social",
       r"\b(EAA[A-Za-z0-9]{60,})\b", tags=("facebook",)),

    # ============ 国内云厂商 ============
    _r("aliyun-access-key-id", "阿里云 AccessKey ID", "critical", "cn-cloud",
       r"\b(LTAI[A-Za-z0-9]{12,20})\b",
       description="阿里云 AccessKey ID, 配合 Secret 可直接操作 ECS/OSS/RDS 等。",
       tags=("aliyun", "credential")),
    _r("aliyun-access-key-secret", "阿里云 AccessKey Secret", "critical", "cn-cloud",
       r"(?:accesskeysecret|access_key_secret|aliyun|aliyunsdk)[^\n]{0,60}?[\"'\s=:]([A-Za-z0-9]{28,44})[\"'\s]",
       keywords=("aliyun", "accesskeysecret", "oss", "ecs"), secret_group=1,
       entropy_min=3.0, tags=("aliyun", "credential")),
    _r("tencent-cloud-secret-id", "腾讯云 SecretId", "critical", "cn-cloud",
       r"\b(AKID[A-Za-z0-9]{13,40})\b", tags=("tencent", "credential")),
    _r("tencent-cloud-secret-key", "腾讯云 SecretKey", "critical", "cn-cloud",
       r"(?:secretkey|secret_key|tencent|qcloud)[^\n]{0,60}?[\"'\s=:]([A-Za-z0-9]{32})[\"'\s]",
       keywords=("tencent", "qcloud", "secretkey", "cos"), secret_group=1,
       entropy_min=3.0, tags=("tencent", "credential")),
    _r("huawei-cloud-ak", "华为云 AK/SK", "high", "cn-cloud",
       r"(?:huaweicloud|hw_ak|huawei)[^\n]{0,60}?[\"'\s=:]([A-Z0-9]{20})[\"'\s]",
       keywords=("huawei", "hwcloud"), secret_group=1, tags=("huawei",)),
    _r("qiniu-ak-sk", "七牛云 AK/SK", "high", "cn-cloud",
       r"(?:qiniu|qbox)[^\n]{0,80}?([A-Za-z0-9_\-]{40})",
       keywords=("qiniu", "qbox", "七牛"), secret_group=1, entropy_min=3.2, tags=("qiniu",)),
    _r("upyun-credentials", "又拍云操作员密钥", "medium", "cn-cloud",
       r"(?:upyun)[^\n]{0,80}?([A-Za-z0-9]{40,})",
       keywords=("upyun",), secret_group=1, entropy_min=3.2, tags=("upyun",)),
    _r("baidu-cloud-ak", "百度云 AK/SK", "high", "cn-cloud",
       r"(?:baidubce|bce_ak|baidu)[^\n]{0,60}?[\"'\s=:]([A-Za-z0-9]{32})[\"'\s]",
       keywords=("baidu", "bce", "百度"), secret_group=1, tags=("baidu",)),
    _r("jpush-app-key", "极光推送 AppKey/MasterSecret", "medium", "cn-cloud",
       r"(?:jpush|jiguang)[^\n]{0,80}?([0-9a-f]{24})",
       keywords=("jpush", "jiguang", "极光"), secret_group=1, tags=("jpush",)),

    # ============ 国内地图 / 语音 / 风控 ============
    _r("amap-key", "高德地图 Key", "medium", "cn-service",
       r"(?:amap|高德|gaode)[^\n]{0,60}?([0-9a-f]{32})",
       keywords=("amap", "gaode", "高德"), secret_group=1, tags=("amap",)),
    _r("tencent-lbs-key", "腾讯位置服务 Key", "medium", "cn-service",
       r"(?:apis\.map\.qq|lbs\.qq|tencentmap)[^\n]{0,80}?key=([A-Za-z0-9\-_]{20,})",
       keywords=("map.qq", "lbs.qq", "tencentmap"), secret_group=1, tags=("qqmap",)),
    _r("baidu-map-ak", "百度地图 AK", "medium", "cn-service",
       r"(?:api\.map\.baidu\.com|baidumap)[^\n]{0,80}?ak=([A-Za-z0-9]{24,})",
       keywords=("map.baidu", "baidumap", "百度地图"), secret_group=1, tags=("baidumap",)),
    _r("xfyun-credentials", "科大讯飞 AppId/Key/Secret", "high", "cn-service",
       r"(?:xfyun|iflytek|讯飞)[^\n]{0,100}?([0-9a-f]{8})",
       keywords=("xfyun", "iflytek", "讯飞"), secret_group=1, tags=("iflytek",)),

    # ============ 微信 / 支付宝 ============
    _r("wechat-appsecret", "微信 AppSecret", "critical", "cn-payment",
       r"(?:appsecret|app_secret|wechat|wx)[^\n]{0,60}?[\"'\s=:]([0-9a-f]{32})[\"'\s]",
       keywords=("appsecret", "wechat", "微信", "wx"), secret_group=1,
       entropy_min=3.0, tags=("wechat", "credential")),
    _r("wechat-mch-apiv3", "微信支付 APIv3 密钥", "critical", "cn-payment",
       r"(?:apiv3|mch|wechatpay|pay_)[^\n]{0,60}?[\"'\s=:]([A-Za-z0-9]{32})[\"'\s]",
       keywords=("apiv3", "mch", "wechatpay", "微信支付"), secret_group=1,
       entropy_min=3.0, tags=("wechatpay",)),
    _r("alipay-private-key", "支付宝应用私钥", "critical", "cn-payment",
       r"MIIEv[QwT][A-Za-z0-9+/=\s]{80,}",
       keywords=("alipay", "支付宝", "private_key", "app_private"), tags=("alipay",)),

    # ============ 飞书 / 钉钉 / 企业微信 ============
    _r("feishu-webhook", "飞书自定义机器人 Webhook", "high", "im",
       r"https://open\.(?:feishu\.cn|larksuite\.com)/open-apis/bot/v2/hook/[A-Za-z0-9\-]{20,}",
       description="泄露后任何人都能向该群发送消息。", tags=("feishu", "lark")),
    _r("feishu-app-secret", "飞书应用 App Secret", "critical", "im",
       r"(?:app_secret|appsecret|feishu|lark)[^\n]{0,60}?[\"'\s=:]([A-Za-z0-9]{32})[\"'\s]",
       keywords=("feishu", "lark", "app_secret", "飞书"), secret_group=1,
       entropy_min=3.0, tags=("feishu", "lark")),
    _r("feishu-app-id", "飞书应用 App ID", "low", "im",
       r"\b(cli_[a-z0-9]{16})\b", tags=("feishu", "lark")),
    _r("dingtalk-webhook", "钉钉机器人 Webhook", "high", "im",
       r"https://oapi\.dingtalk\.com/robot/send\?access_token=[a-f0-9]{64}",
       tags=("dingtalk",)),
    _r("wecom-webhook", "企业微信机器人 Webhook", "high", "im",
       r"https://qyapi\.weixin\.qq\.com/cgi-bin/webhook/send\?key=[A-Za-z0-9\-]{30,}",
       tags=("wecom",)),
    _r("wecom-corpsecret", "企业微信 CorpSecret", "critical", "im",
       r"(?:corpsecret|qyapi|企业微信)[^\n]{0,60}?[\"'\s=:]([A-Za-z0-9\-_]{43})[\"'\s]",
       keywords=("corpsecret", "qyapi", "wecom"), secret_group=1, tags=("wecom",)),

    # ============ 私有密钥 / 凭据串 ============
    _r("private-key-block", "私钥文件内容", "critical", "private-key",
       r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP |ENCRYPTED )?PRIVATE KEY-----",
       description="前端不应出现任何形式的私钥。", tags=("private-key",)),
    _r("basic-auth-url", "URL 内嵌账号密码", "high", "credential",
       r"\b[a-z][a-z0-9+.\-]{2,20}://[^/\s:@'\"]{2,64}:[^/\s:@'\"]{3,64}@[^\s/\"'<>]+",
       allowlist=(r"://(?:localhost|127\.0\.0\.1|\$\{)",),
       tags=("credential",)),
    _r("database-url", "数据库连接串 (含凭据)", "high", "database",
       r"\b(?:postgres(?:ql)?|mysql|mariadb|mongodb(?:\+srv)?|redis|rediss|amqp|mssql|clickhouse|jdbc:[a-z]+)://[^\s\"'<>]{8,200}",
       allowlist=(r"://(?:localhost|127\.0\.0\.1|example)", r"://[^:]+@?\$\{"),
       tags=("database",)),
    _r("jwt-token", "JWT 令牌", "medium", "credential",
       r"\beyJ[A-Za-z0-9_\-]{10,}\.eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}",
       description="硬编码 JWT 可用于越权测试, 也可能是长期有效的服务令牌。",
       tags=("jwt",)),
    _r("supabase-service-role", "Supabase service_role 密钥", "critical", "cloud",
       r"service_role[^\n]{0,40}?(eyJ[A-Za-z0-9_\-]{20,}\.[A-Za-z0-9_\-]{20,}\.[A-Za-z0-9_\-]{20,})",
       keywords=("service_role", "supabase"), secret_group=1, tags=("supabase",)),
    _r("notion-token", "Notion 集成密钥", "high", "saas",
       r"\b(secret_[A-Za-z0-9]{40,}|ntn_[A-Za-z0-9]{40,})\b", tags=("notion",)),
    _r("airtable-key", "Airtable API Key", "medium", "saas",
       r"\b(key[A-Za-z0-9]{14}|pat[A-Za-z0-9]{14}\.[A-Za-z0-9]{64})\b", tags=("airtable",)),
    _r("linear-api-key", "Linear API Key", "medium", "saas",
       r"\b(lin_api_[A-Za-z0-9]{40})\b", tags=("linear",)),
    _r("clerk-secret", "Clerk Secret Key", "high", "saas",
       r"\b(sk_(?:live|test)_[A-Za-z0-9]{24,})\b", keywords=("clerk",), tags=("clerk",)),
    _r("algolia-admin-key", "Algolia Admin Key", "high", "saas",
       r"algolia[^\n]{0,80}?(?:admin|api)[^\n]{0,20}?[\"'\s=:]([A-Za-z0-9]{32})[\"'\s]",
       keywords=("algolia",), secret_group=1, tags=("algolia",)),
    _r("mapbox-token", "Mapbox 访问令牌", "medium", "saas",
       r"\b((?:pk|sk)\.[A-Za-z0-9\-_]{60,})\b", tags=("mapbox",)),
    _r("sentry-dsn", "Sentry DSN", "info", "saas",
       r"https://[0-9a-f]{32}@[a-z0-9.\-]*sentry[a-z0-9.\-]*/\d+",
       tags=("sentry",)),
    _r("recaptcha-site-key", "reCAPTCHA Site Key", "info", "saas",
       r"\b(6L[0-9A-Za-z_\-]{38})\b", description="站点密钥本身是公开的, 仅作资产标记。",
       tags=("recaptcha",)),

    # ============ 前端通用泄露 ============
    _r("sourcemap-reference", "Source Map 引用暴露", "info", "exposure",
       r"//[#@]\s*sourceMappingURL=([^\s'\"]+\.map)",
       description="构建产物引用了 sourcemap, 若 .map 可访问则等价于源码泄露。",
       secret_group=1, tags=("sourcemap",)),
    _r("internal-ip", "内网地址泄露", "low", "exposure",
       r"\b(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3})(?::\d{2,5})?\b",
       description="可作为后续内网渗透的入口信息。", tags=("exposure",)),
    _r("generic-secret-assignment", "疑似硬编码密钥 (上下文匹配)", "high", "generic",
       r"""(?i)\b(?:api[_-]?key|secret[_-]?key|secretkey|access[_-]?key|auth[_-]?token|access[_-]?token|client[_-]?secret|private[_-]?key|app[_-]?secret|api[_-]?secret|webhook[_-]?secret|signing[_-]?secret|sign[_-]?key|authkey|passwd|password|credential)\b[\"']?\s*[:=]\s*[\"']([A-Za-z0-9+/=_\-.]{16,200})[\"']""",
       secret_group=1, entropy_min=3.4,
       description="变量名像密钥且赋值了高熵字符串, 需人工确认。",
       tags=("generic",)),
    _r("high-entropy-string", "高熵字符串 (疑似密钥)", "low", "generic",
       r"""(?i)(?:key|token|secret|signature|sign|salt|nonce|iv|cipher|encrypt)\w{0,12}[\"']?\s*[:=]\s*[\"']([A-Za-z0-9+/=]{32,120})[\"']""",
       secret_group=1, entropy_min=4.2,
       description="低置信度提示, 建议结合上下文判断。", tags=("generic",)),
    # 实测补充: 某站点公开 JS 里硬编码了
    #   datatalkToken: "<32位hex>_PERMANENT_<业务名>_<账号>_LOGIN"
    # 这种"多段拼成的长期令牌"既不是标准厂商前缀, 也不是纯高熵串, 早期规则整类漏掉。
    _r("composite-permanent-token", "复合型长期令牌", "high", "generic",
       r"""\b([A-Za-z0-9+/=_\-]{20,120}_(?:PERMANENT|TEMPORARY|LONGTERM|LONG_TERM)[A-Za-z0-9_\-]{4,120})\b""",
       description="形如 <随机段>_PERMANENT_<业务>_<账号>_LOGIN 的长期令牌, 通常可直接调用内部服务。",
       tags=("token", "internal")),
    _r("internal-service-name-in-token", "内部服务名拼进令牌", "medium", "exposure",
       r"""(?i)(?:token|key|secret|auth)\w{0,12}["']?\s*[:=]\s*["']([A-Za-z0-9+/=_\-]{24,160}_(?:LOGIN|LOGOUT|AUTH|SIGNIN|SERVICE)[A-Za-z0-9_\-]*)["']""",
       description="令牌里直接拼了 LOGIN/AUTH 等语义段, 常见于内部系统的长期访问凭证。",
       secret_group=1, tags=("token", "internal")),
    _r("env-var-leak", "构建期环境变量内联泄露", "medium", "exposure",
       r"""(?i)"(?:REACT_APP|VITE|NEXT_PUBLIC|VUE_APP|NUXT_ENV)_[A-Z0-9_]*(?:KEY|TOKEN|SECRET|PASSWORD|PASSWD)[A-Z0-9_]*"\s*:\s*"([^"]{8,200})""",
       secret_group=1, tags=("exposure",)),

    # ============ 个人信息 (默认关闭, 合规风险) ============
    _r("cn-mobile-number", "中国大陆手机号", "low", "pii",
       r"(?<!\d)(1[3-9]\d{9})(?!\d)",
       description="默认关闭: 涉及个人信息, 仅在获得授权时启用。",
       tags=("pii",), default_enabled=False),
    _r("cn-id-card", "中国大陆身份证号", "medium", "pii",
       r"(?<!\d)([1-9]\d{5}(?:19|20)\d{2}(?:0[1-9]|1[0-2])(?:0[1-9]|[12]\d|3[01])\d{3}[\dXx])(?!\d)",
       description="默认关闭: 涉及个人信息, 仅在获得授权时启用。",
       tags=("pii",), default_enabled=False),
]

RULE_INDEX: dict[str, Rule] = {r.id: r for r in RULES}


# ---------------------------------------------------------------- 扫描引擎

# 单份文本最多扫多少字节; 0 = 不限制。默认不限制: 大 bundle 里照样可能藏着密钥,
# 截掉尾巴等于漏检。真嫌慢可以在构造 Detector 时传一个上限。
MAX_SCAN_BYTES = 0

_NEWLINE_RE = re.compile("\n")

_BASE64_CHAR = re.compile(r"[A-Za-z0-9+/=]")


def looks_like_base64_fragment(text: str, raw: str, start: int | None = None) -> bool:
    """命中值是不是从一段更长的 Base64 里"切"出来的碎片。

    判据只有一条: 前后紧邻的字符也都是 Base64 字符 —— 说明它属于一个连续的字串,
    而不是独立的值。真实的密钥不会写成这样:

        ...C/xjqV7  00ivkbaFBztxUmeHZluXhgQ25PGNZwlzmrBryzsAfB  DhrNt1r3z...
        （左边 7、右边 D 都是 base64 字符 → 碎片）

    而正常写法两边是引号、等号、逗号、分号这类分隔符:

        var okta="00iv..."    → 左边引号, 不算
        AKIA...=token         → 右边不是 base64, 不算
    """
    if not text or not raw:
        return False
    index = text.find(raw) if start is None else start
    if index <= 0 or index + len(raw) >= len(text):
        return False
    return bool(_BASE64_CHAR.match(text[index - 1]) and _BASE64_CHAR.match(text[index + len(raw)]))


def explain_rule(rule: Rule, text: str, allowlist: Iterable[str] = (), limit: int = 20) -> dict:
    """给规则编辑器用: 跑一遍这条规则, 说明"匹配到几处、被哪些过滤器挡掉多少"。

    过滤顺序与 Detector.scan_text 保持一致, 只是这里把每一步的拦截数记下来 ——
    否则用户写了个能匹配的正则却看到 0 结果, 会以为是规则没生效。
    """
    import re as _re

    try:
        pattern = _re.compile(rule.pattern, _re.MULTILINE)
    except _re.error as exc:
        raise ValueError(f"正则无法编译: {exc}") from exc

    allowed = []
    for item in allowlist:
        try:
            allowed.append(_re.compile(item, _re.I))
        except _re.error:
            continue

    rejected: dict[str, int] = {}
    kept: list[Detection] = []

    def reject(reason: str) -> None:
        rejected[reason] = rejected.get(reason, 0) + 1

    raw_count = 0
    for match in pattern.finditer(text or ""):
        raw_count += 1
        if rule.secret_group and match.lastindex and match.lastindex >= rule.secret_group:
            raw, start = match.group(rule.secret_group), match.start(rule.secret_group)
        else:
            raw, start = match.group(0), match.start(0)
        if raw is None:
            reject("空匹配")
            continue
        raw = raw.strip()
        if rule.min_length and len(raw) < rule.min_length:
            reject("短于 min_length")
            continue
        if len(raw) > 400:
            reject("超过 400 字符")
            continue
        if looks_placeholder(raw):
            reject("占位符过滤")
            continue
        if looks_like_code_path(raw):
            reject("代码路径过滤")
            continue
        if rule.keywords:
            window = text[max(0, start - rule.window):start + rule.window].lower()
            if not any(k.lower() in window for k in rule.keywords):
                reject("关键词不在窗口内")
                continue
        entropy = shannon_entropy(raw)
        if rule.entropy_min and entropy < rule.entropy_min:
            reject(f"熵值低于 {rule.entropy_min}")
            continue
        if any(item.search(raw) for item in allowed) or any(item.search(raw) for item in rule.allowlist):
            reject("命中白名单")
            continue
        masked = mask_value(raw)
        kept.append(Detection(
            rule_id=rule.id, rule_name=rule.name, severity=rule.severity, category=rule.category,
            raw=raw[:160], masked=masked, sha256=hashlib.sha256(raw.encode("utf-8", "ignore")).hexdigest(),
            entropy=round(entropy, 2), line_no=text.count("\n", 0, start) + 1,
            context=(text[max(0, start - 60):start + len(raw) + 60] or "").replace("\n", " ")[:200],
            fingerprint="", start=start, end=start + len(raw),
        ))
    return {
        "raw_count": raw_count,
        "count": len(kept),
        "matches": kept[:limit],
        "rejected": rejected,
        "rule_id": rule.id,
    }


class Detector:
    """把规则表编译成可复用的扫描器。"""

    def __init__(
        self,
        rules: Iterable[Rule] | None = None,
        disabled: Iterable[str] = (),
        enabled: Iterable[str] = (),
        severity_override: dict[str, str] | None = None,
        allowlist: Iterable[str] = (),
        custom_rules: Iterable[Rule] = (),
        max_scan_bytes: int | None = None,
    ) -> None:
        self.max_scan_bytes = MAX_SCAN_BYTES if max_scan_bytes is None else max(0, max_scan_bytes)
        disabled_set = set(disabled)
        enabled_set = set(enabled)
        overrides = severity_override or {}
        ruleset = list(rules if rules is not None else RULES) + list(custom_rules)
        self.compiled: list[tuple[Rule, re.Pattern[str]]] = []
        for rule in ruleset:
            if rule.id in disabled_set:
                continue
            # 默认关闭的规则 (如个人信息检测) 需显式启用
            if not rule.default_enabled and rule.id not in enabled_set:
                continue
            flags = re.MULTILINE
            try:
                pat = re.compile(rule.pattern, flags)
            except re.error:
                continue
            severity = overrides.get(rule.id, rule.severity)
            if severity != rule.severity:
                rule = Rule(**{**rule.__dict__, "severity": severity})
            self.compiled.append((rule, pat))

        self.allowed: list[re.Pattern[str]] = []
        for pat in allowlist:
            try:
                self.allowed.append(re.compile(pat, re.I))
            except re.error:
                continue

    @property
    def rule_ids(self) -> list[str]:
        return [r.id for r, _ in self.compiled]

    def _is_allowlisted(self, value: str, rule: Rule) -> bool:
        for pat in rule.allowlist:
            if re.search(pat, value, re.I):
                return True
        for pat in self.allowed:
            if pat.search(value):
                return True
        return False

    def scan_text(
        self,
        text: str,
        target_id: int,
        asset_url: str = "",
        store_raw: bool = False,
    ) -> list[Detection]:
        if not text:
            return []
        if self.max_scan_bytes and len(text) > self.max_scan_bytes:
            text = text[: self.max_scan_bytes]
        lowered = text.lower()
        # 行号用"换行符位置表 + 二分"算: 以前每条命中都 text.count("\n") 一遍,
        # 大文件上成千上万条命中时这一项就吃掉两成检测耗时
        newlines = [match.start() for match in _NEWLINE_RE.finditer(text)]
        results: list[Detection] = []

        for rule, pattern in self.compiled:
            # 关键词预过滤: 大幅降低多兆字节压缩代码上的正则开销
            if rule.keywords and not any(k.lower() in lowered for k in rule.keywords):
                continue
            for match in pattern.finditer(text):
                if rule.secret_group and match.lastindex and match.lastindex >= rule.secret_group:
                    raw = match.group(rule.secret_group)
                    start = match.start(rule.secret_group)
                else:
                    raw = match.group(0)
                    start = match.start(0)
                if not raw:
                    continue
                raw = raw.strip()
                if rule.min_length and len(raw) < rule.min_length:
                    continue
                if len(raw) > 400:
                    continue
                if looks_placeholder(raw) or looks_like_code_path(raw):
                    continue
                # 夹在连续 Base64 中间的命中是"切"出来的碎片, 不是独立的值
                if looks_like_base64_fragment(text, raw, start):
                    continue
                if rule.keywords:
                    window_start = max(0, start - rule.window)
                    window_text = text[window_start:start + rule.window].lower()
                    if not any(k.lower() in window_text for k in rule.keywords):
                        continue
                entropy = shannon_entropy(raw)
                if rule.entropy_min and entropy < rule.entropy_min:
                    continue
                if self._is_allowlisted(raw, rule):
                    continue

                masked = mask_value(raw)
                context = self._context(text, start, raw, masked)
                line_no = bisect_left(newlines, start) + 1
                digest = hashlib.sha256(raw.encode("utf-8", "ignore")).hexdigest()
                fingerprint = hashlib.sha256(
                    f"{rule.id}|{target_id}|{digest}".encode()
                ).hexdigest()
                results.append(
                    Detection(
                        rule_id=rule.id,
                        rule_name=rule.name,
                        severity=rule.severity,
                        category=rule.category,
                        raw=raw if store_raw else "",
                        masked=masked,
                        sha256=digest,
                        entropy=round(entropy, 2),
                        line_no=line_no,
                        context=context,
                        fingerprint=fingerprint,
                        start=start,
                        end=start + len(raw),
                    )
                )
        return self._dedupe(self._suppress_overlaps(results))

    @staticmethod
    def _suppress_overlaps(items: list[Detection]) -> list[Detection]:
        """同一段文本被多条规则命中时, 只保留更有价值的那条。

        典型场景: 一个 redis://user:pass@host 既命中 basic-auth-url 又命中
        database-url; 一个 AWS AK 既命中专用规则又命中通用高熵规则。

        判定规则不变（被更高优先级的重叠命中压掉），但先按位置切成互不重叠的簇:
        不同簇之间不可能重叠，于是大文件里成千上万条命中不再两两比较 —— 这是
        扫描慢的头号开销（2MB 压缩产物上实测占检测总耗时的 7 成）。
        """
        if len(items) < 2:
            return items
        def rank(item: Detection) -> tuple[int, int]:
            return (SEVERITY_ORDER.get(item.severity, 0), PRECEDENCE.get(item.rule_id, DEFAULT_PRECEDENCE))

        clusters: list[list[int]] = []
        current: list[int] = []
        cluster_end = -1
        for index in sorted(range(len(items)), key=lambda i: (items[i].start, items[i].end)):
            item = items[index]
            if current and item.start >= cluster_end:
                clusters.append(current)
                current, cluster_end = [], -1
            current.append(index)
            cluster_end = max(cluster_end, item.end)
        if current:
            clusters.append(current)

        drop: set[int] = set()
        for cluster in clusters:
            if len(cluster) < 2:
                continue
            for index in cluster:
                item = items[index]
                for other_index in cluster:
                    other = items[other_index]
                    if other_index == index or other.end <= item.start or other.start >= item.end:
                        continue
                    if rank(other) > rank(item):
                        drop.add(index)
                        break
        return [item for index, item in enumerate(items) if index not in drop]

    @staticmethod
    def _context(text: str, start: int, raw: str, masked: str, span: int = 160) -> str:
        snippet_start = max(0, start - span)
        snippet = text[snippet_start: start + len(raw) + span]
        snippet = snippet.replace(raw, masked)
        snippet = re.sub(r"\s+", " ", snippet).strip()
        # 前截断点落在词中间时丢掉这段残片, 避免出现 "cript>" 这类开头
        head = snippet.split(" ", 1)[0]
        if (head and head != masked and len(snippet) > len(head) + 1 and snippet_start > 0
                and text[snippet_start - 1] not in SEPARATORS):
            snippet = snippet[len(head) + 1:]
        if len(snippet) > 360:
            idx = snippet.find(masked)
            begin = max(0, idx - 160)
            snippet = snippet[begin: begin + 360]
        return snippet

    @staticmethod
    def _dedupe(items: list[Detection]) -> list[Detection]:
        seen: set[str] = set()
        out: list[Detection] = []
        for item in items:
            key = f"{item.rule_id}:{item.sha256}"
            if key in seen:
                continue
            seen.add(key)
            out.append(item)
        return out

    def iter_rule_meta(self) -> Iterator[tuple[Rule, bool]]:
        compiled_ids = set(self.rule_ids)
        for rule in RULES:
            yield rule, rule.id in compiled_ids
