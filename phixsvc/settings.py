"""phix 服务端 · Django 配置。

设计取舍：
- 服务端**只做三件事**：管账号、发令牌、存不透明密文对象。它没有任何密码学依赖，
  看不懂用户上传的任何内容。
- 不用 session/cookie（纯 Bearer 令牌），因此不启用 CSRF 中间件——没有 cookie
  就没有 CSRF 面。所有 API 视图也不读 cookie。
- SECRET_KEY：优先环境变量 PHIX_SECRET_KEY → 否则读/生成 BASE_DIR/secret_key.txt
  （0600）。该文件已在 .gitignore 里，绝不入库。
"""
import os
import secrets
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent


def _env_bool(name, default=False):
    v = os.environ.get(name)
    if v is None:
        return default
    return v.strip().lower() in ("1", "true", "yes", "on")


def _load_secret_key():
    env = os.environ.get("PHIX_SECRET_KEY", "").strip()
    if env:
        return env, False
    path = BASE_DIR / "secret_key.txt"
    if path.exists():
        v = path.read_text(encoding="utf-8").strip()
        if v:
            return v, False
    v = secrets.token_urlsafe(64)
    try:
        path.write_text(v + "\n", encoding="utf-8")
        os.chmod(path, 0o600)
    except OSError:
        pass
    return v, True


SECRET_KEY, _SECRET_GENERATED = _load_secret_key()

DEBUG = _env_bool("PHIX_DEBUG", False)

# 局域网 / 本机默认值；接 Cloudflare 域名时用 PHIX_ALLOWED_HOSTS 追加。
# 公网两个域名（**含带 www 的**）也放进默认值：Cloudflare 回源带的是域名 Host，
# 少了 www 就会 400 DisallowedHost。生产 env 里本来也有，这里保证没有 env 时同样能用。
_default_hosts = "127.0.0.1,localhost,192.168.5.41,phix.ing,www.phix.ing"
ALLOWED_HOSTS = [
    h.strip()
    for h in os.environ.get("PHIX_ALLOWED_HOSTS", _default_hosts).split(",")
    if h.strip()
]
if DEBUG and "*" not in ALLOWED_HOSTS:
    ALLOWED_HOSTS.append("*")

# 反代（Cloudflare / Nginx）后面跑时，识别真实协议
SECURE_PROXY_SSL_HEADER = ("HTTP_X_FORWARDED_PROTO", "https")
USE_X_FORWARDED_HOST = True

INSTALLED_APPS = [
    "django.contrib.contenttypes",
    "django.contrib.auth",
    "api",
]

MIDDLEWARE = [
    "django.middleware.security.SecurityMiddleware",
    "django.middleware.common.CommonMiddleware",
    "api.middleware.ProtocolErrorMiddleware",
    "api.middleware.E2EEnvelopeMiddleware",
]

ROOT_URLCONF = "phixsvc.urls"
WSGI_APPLICATION = "phixsvc.wsgi.application"

TEMPLATES = [
    {
        "BACKEND": "django.template.backends.django.DjangoTemplates",
        "DIRS": [BASE_DIR / "templates"],
        "APP_DIRS": True,
        "OPTIONS": {"context_processors": []},
    }
]

DATABASES = {
    "default": {
        "ENGINE": "django.db.backends.sqlite3",
        "NAME": os.environ.get("PHIX_DB", str(BASE_DIR / "db.sqlite3")),
        "OPTIONS": {
            "timeout": 20,
            # **关键**：Django 默认用 DEFERRED 事务 —— 这种事务先当读者、写的时候
            # 才升级成写者；在 WAL 模式下升级失败会**立刻**返回 SQLITE_BUSY，
            # `busy_timeout` 对它无效（实测并发同步时仍然间歇性
            # `OperationalError: database is locked`，整批 500）。
            # IMMEDIATE 让写事务一开始就拿到写锁，于是正常排队等锁、不再撞。
            # （Django 5.1 起支持这个选项；本项目用 5.2。）
            "transaction_mode": "IMMEDIATE",
        },
    }
}

AUTH_PASSWORD_VALIDATORS = []  # 规则在视图里显式实现，错误文案统一走中文

LANGUAGE_CODE = "zh-hans"
TIME_ZONE = "Asia/Shanghai"
USE_I18N = True
USE_TZ = True

DEFAULT_AUTO_FIELD = "django.db.models.BigAutoField"

# 同步限额（与 phix-协议规范.md §4.7 一致）
PHIX_MAX_PAYLOAD_BYTES = int(os.environ.get("PHIX_MAX_PAYLOAD_BYTES", 8 * 1024 * 1024))
PHIX_MAX_OBJECTS = int(os.environ.get("PHIX_MAX_OBJECTS", 2000))
PHIX_MAX_TOTAL_BYTES = int(os.environ.get("PHIX_MAX_TOTAL_BYTES", 200 * 1024 * 1024))
PHIX_MAX_BATCH = int(os.environ.get("PHIX_MAX_BATCH", 50))
PHIX_KEEP_REVISIONS = int(os.environ.get("PHIX_KEEP_REVISIONS", 10))

# **必须比单对象上限大**：Django 默认只允许 2.5 MB 的请求体，比协议里的 8 MiB 小 ——
# 不放开的话，大对象（比如很长的 AI 会话）还没进到业务层就被 Django 拒了，
# 而且抛的是 500 HTML 而不是 JSON。这里给信封 + JSON 包装留 4 MB 余量。
DATA_UPLOAD_MAX_MEMORY_SIZE = PHIX_MAX_PAYLOAD_BYTES + 4 * 1024 * 1024

# 心履等服务端到服务端调用（/auth/verify）用的共享密钥
PHIX_SERVICE_KEY = os.environ.get("PHIX_SERVICE_KEY", "").strip()

# 限流（生产保持默认值；本地反复压测时可用环境变量放大）
PHIX_REGISTER_LIMIT = int(os.environ.get("PHIX_REGISTER_LIMIT", 10))    # 每 IP 每小时
PHIX_RECOVER_LIMIT = int(os.environ.get("PHIX_RECOVER_LIMIT", 8))       # 每 IP 每小时
PHIX_KEYMATERIAL_LIMIT = int(os.environ.get("PHIX_KEYMATERIAL_LIMIT", 60))  # 每 IP 每小时

# 应用内自动更新：清单文件（发布脚本生成，见 deploy/deploy.py 的 upload 部分）
PHIX_UPDATES_FILE = os.environ.get("PHIX_UPDATES_FILE", str(BASE_DIR / "updates.json"))

# ---------------- 应用层加密传输（对应 加密链路思路.md §3） ----------------
# 打开后，带 X-Phix-Enc: 1 的请求体与响应体都是密文 —— **不接 TLS 也不怕被嗅探**。
# 没带这个头的请求完全走原来的明文路径（老客户端、curl 调试、心履的服务间调用都不受影响）。
PHIX_E2E_ENABLED = _env_bool("PHIX_E2E_ENABLED", True)
PHIX_E2E_KEY_FILE = os.environ.get("PHIX_E2E_KEY_FILE", str(BASE_DIR / "e2e_key.txt"))

# v2 账号却收到"口令原文"凭据时是否放行（只影响 migrate 过渡期）。
#   1（默认）= 记一条 warning 后放行 —— 兼容还没升级完的旧客户端；
#   0         = 硬拒绝（bad_request），彻底杜绝"漏发 auth_hash 静默写坏凭证"。
# 生产建议：等两端客户端都发 AuthHash 之后，在 ~/.config/phix/env 里设成 0。
PHIX_V2_PLAINTEXT_OK = _env_bool("PHIX_V2_PLAINTEXT_OK", True)

# ---------------- P3：令牌体系（对应 加密链路思路.md §7） ----------------
# 访问令牌是 Ed25519 签名的 JWT，寿命短；refresh 令牌寿命长、只能续期、用一次换一次。
PHIX_JWT_ALG = "EdDSA"
PHIX_JWT_ACCESS_TTL = int(os.environ.get("PHIX_JWT_ACCESS_TTL", 900))          # 15 分钟
PHIX_JWT_LEEWAY = int(os.environ.get("PHIX_JWT_LEEWAY", 60))                   # 时钟余量
# `iat` 的宽松容差：见 api/tokens.py `_iat_leeway()` 的说明（时钟没对准时不至于全拒）
PHIX_JWT_IAT_LEEWAY = int(os.environ.get("PHIX_JWT_IAT_LEEWAY", 300))
PHIX_REFRESH_TTL = int(os.environ.get("PHIX_REFRESH_TTL", 30 * 24 * 3600))     # 30 天
PHIX_REFRESH_GRACE = int(os.environ.get("PHIX_REFRESH_GRACE", 120))            # 轮换宽限
PHIX_REFRESH_LIMIT = int(os.environ.get("PHIX_REFRESH_LIMIT", 120))            # 每 IP 每小时
PHIX_DPOP_WINDOW = int(os.environ.get("PHIX_DPOP_WINDOW", 300))                # DPoP jti 窗口
# 签名私钥（Ed25519）。**首次启动自动生成，权限 600，绝不入库、绝不下发**
PHIX_JWT_KEY_FILE = os.environ.get("PHIX_JWT_KEY_FILE", str(BASE_DIR / "jwt_key.txt"))
# 还接受老式长期令牌（40 位 hex）吗？兼容期开着；两端客户端都升级后设 0 关掉。
PHIX_LEGACY_TOKENS = _env_bool("PHIX_LEGACY_TOKENS", True)

# ---------------- 跨站免密登录：一次性 SSO 码（见 api/sso.py） ----------------
# 用途：让"在官网 / PHL 网页端 / 心履 任一端登录 → 其余端自动登录"。
# 码本身不含任何凭据（256 位随机串，服务端只存摘要），120 秒、单次、绑站点。
PHIX_SSO_TTL = int(os.environ.get("PHIX_SSO_TTL", 120))                # 秒（本地验过期可调小）
PHIX_SSO_AUDIENCES = tuple(x.strip() for x in os.environ.get(
    "PHIX_SSO_AUDIENCES", "phix-site,xinlv").split(",") if x.strip())
# 兑换时必须带服务密钥吗？**默认开**：两个合法兑换方（官网后端、心履后端）都持有它，
# 于是"码被路人捡到"也换不走令牌。关掉只适合本地调试。
PHIX_SSO_REQUIRE_SERVICE_KEY = _env_bool("PHIX_SSO_REQUIRE_SERVICE_KEY", True)
# IP 绑定：off（默认）| prefix（IPv4 /24）| exact。
# **默认 off 是有意的**：签发方看到的是用户浏览器 IP，兑换方看到的是另一台服务器
# （心履 192.168.5.35），绑死会把正常流程也挡掉。审计用的前缀无论如何都会记。
PHIX_SSO_IP_BIND = os.environ.get("PHIX_SSO_IP_BIND", "off").strip().lower()
PHIX_SSO_MINT_LIMIT = int(os.environ.get("PHIX_SSO_MINT_LIMIT", 30))    # 每 IP/每用户 每小时
PHIX_SSO_MINT_WINDOW = int(os.environ.get("PHIX_SSO_MINT_WINDOW", 3600))
PHIX_SSO_LIVE_PER_USER = int(os.environ.get("PHIX_SSO_LIVE_PER_USER", 10))  # 同时待兑换上限
PHIX_SSO_REDEEM_LIMIT = int(os.environ.get("PHIX_SSO_REDEEM_LIMIT", 60))    # 每 IP 每小时
PHIX_SSO_REDEEM_WINDOW = int(os.environ.get("PHIX_SSO_REDEEM_WINDOW", 3600))
PHIX_SSO_FAIL_LIMIT = int(os.environ.get("PHIX_SSO_FAIL_LIMIT", 20))        # 每 IP 失败上限
PHIX_SSO_FAIL_WINDOW = int(os.environ.get("PHIX_SSO_FAIL_WINDOW", 900))     # 失败观察窗（秒）

LOG_DIR = BASE_DIR / "logs"
LOG_DIR.mkdir(exist_ok=True)

LOGGING = {
    "version": 1,
    "disable_existing_loggers": False,
    "formatters": {
        "simple": {"format": "[%(asctime)s] [%(levelname)s] %(message)s",
                   "datefmt": "%Y-%m-%d %H:%M:%S"},
    },
    "handlers": {
        "console": {"class": "logging.StreamHandler", "formatter": "simple"},
        "file": {
            "class": "logging.handlers.RotatingFileHandler",
            "filename": str(LOG_DIR / "phix.log"),
            "maxBytes": 2 * 1024 * 1024,
            "backupCount": 5,
            "encoding": "utf-8",
            "formatter": "simple",
        },
    },
    "root": {"handlers": ["console", "file"], "level": "INFO"},
    "loggers": {
        "django.request": {"handlers": ["console", "file"], "level": "WARNING",
                           "propagate": False},
    },
}

if _SECRET_GENERATED:
    import logging

    logging.getLogger("phix").warning(
        "首次启动：已生成 secret_key.txt（仅本机，勿入库、勿外发）"
    )
