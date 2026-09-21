"""一次性 SSO 兑换码 —— 让"在任一端登录，其余端自动登录"成为可能。

## 为什么需要它

`phix.ing` 官网与 Pinghe Launcher 网页端（`/app/`）**同域同 cookie**，天生互通，
不需要任何新机制。但**心履网页端（xin-lv.com）是另一个注册域**，浏览器绝不会把
`phix.ing` 的 cookie 发给它。跨注册域搬登录态只有两条路：

1. **一次性码（本模块）**：签发方把"某用户已登录"这件事压缩成一枚短命随机码，
   兑换方拿码 + 服务密钥换一套令牌；
2. 把心履挪到 `xinlv.phix.ing` 并让 cookie 域设为 `.phix.ing`（见
   `D:\\phix\\website\\SSO-跨域与子域方案.md`，那是纯部署改动，不走本接口）。

两条路都做了；本模块是第一条。

    POST /api/v1/auth/sso/code      换码：Bearer 会话 **或** 服务密钥（服务端到服务端）
    POST /api/v1/auth/sso/redeem    兑换：码 → 与 `/auth/login` **完全同构**的响应

## 设计要点（每条都对应一个真实的攻击面）

1. **码本身不是凭据**：256 位随机串（`secrets.token_urlsafe(32)`），服务端**只存
   SHA-256 摘要**。码里不含用户名、令牌、DEK —— 它只是一把"取号牌"。
   光拿到码还不够：兑换还要 `X-Phix-Service-Key`（`PHIX_SSO_REQUIRE_SERVICE_KEY`，
   默认开）——两个合法兑换方（官网后端、心履后端）本来就都持有服务密钥。
2. **用后即焚**：兑换在锁内 `pop`，同一个码第二次必然失败（不是"标脏"而是"删掉"）。
3. **短命**：默认 120 秒（`PHIX_SSO_TTL`）；过期条目在下一次操作时顺手清掉，
   不需要后台线程。
4. **绑定来源站点**：码里写死 `audience`（`phix-site` / `xinlv`），兑换时 `site`
   必须一字不差。站点不匹配**不消耗**码（否则拿着别人码的人只要发一次错站点请求
   就能把码烧掉，等于拒绝服务）。
5. **可选绑定 IP 前缀**：`PHIX_SSO_IP_BIND = off | prefix | exact`，**默认 off**。
   为什么默认关：签发方与兑换方常常不是同一个 IP —— 官网签发时看到的是**用户浏览器**
   的地址（经代理），心履兑换时看到的是**心履服务器 192.168.5.35**。绑死会把正常流程
   也挡掉。只有"签发与兑换同源"的部署（同一台机/同一个 /24）才该打开。
   无论开关如何，签发时的 IP 前缀都记在条目里，便于审计。
6. **限流**：签发按 IP/按用户，兑换按 IP，失败另有更严的独立窗口
   （`PHIX_SSO_FAIL_LIMIT`）——爆破码的空间是 2^256，这里防的是把服务打爆。
7. **码不落日志**：日志里只出现摘要前 8 位（`sid=ab12cd34`），全文绝不写日志、
   绝不进审计文件。

## 存储取舍（诚实记录）

进程内存（dict + 锁），与 `utils.RateLimiter` 同一取舍：生产 waitress 是
**单进程 8 线程**（见 `deploy/phix.service`），所以够用。代价是**重启即全部失效**——
最坏后果是用户重按一次按钮，没有任何安全损失。将来若改多进程部署，
这里必须换成共享存储（Redis / 数据库表），否则"存于 A 进程、兑于 B 进程"会失败。
"""
from __future__ import annotations

import hashlib
import logging
import secrets
import threading
import time

from django.conf import settings
from django.contrib.auth import get_user_model
from django.views.decorators.http import require_POST

from .utils import (client_ip, current_token, err, json_body, legacy_tokens_enabled,
                    limiter, ok, resolve_jwt, service_key_ok)

log = logging.getLogger("phix.auth")

#: 允许的兑换方（站点标识）。写错/不认识的站点一律拒绝。
DEFAULT_AUDIENCES = ("phix-site", "xinlv")
DEFAULT_AUDIENCE = "phix-site"


def audiences() -> tuple:
    raw = getattr(settings, "PHIX_SSO_AUDIENCES", None)
    if not raw:
        return DEFAULT_AUDIENCES
    if isinstance(raw, str):
        return tuple(x.strip() for x in raw.split(",") if x.strip())
    return tuple(raw)


def ttl_seconds() -> int:
    return int(getattr(settings, "PHIX_SSO_TTL", 120))


def require_service_key() -> bool:
    return bool(getattr(settings, "PHIX_SSO_REQUIRE_SERVICE_KEY", True))


def _digest(code: str) -> str:
    """码的查找用摘要。**对外/log 只允许用它的前 8 位。**"""
    return hashlib.sha256((code or "").encode("utf-8")).hexdigest()


def _ip_prefix(ip: str) -> str:
    """IP 的审计/绑定前缀。IPv4 取 /24，IPv6 取前 4 段，其它原样。"""
    ip = (ip or "").strip()
    if not ip or ip == "?":
        return ""
    if ":" in ip:                       # IPv6：取前 4 组
        return ":".join(ip.split(":")[:4])
    parts = ip.split(".")
    if len(parts) == 4 and all(p.isdigit() for p in parts):
        return ".".join(parts[:3])
    return ip


def _ip_matches(stored_prefix: str, stored_full: str, got: str, mode: str) -> bool:
    """``exact`` 比完整地址，``prefix`` 比 /24 前缀。"""
    if mode == "exact":
        return bool(stored_full) and stored_full == (got or "").strip()
    return bool(stored_prefix) and stored_prefix == _ip_prefix(got)


class _CodeStore:
    """一次性码的内存表。键是**码的摘要**，不是码本身。"""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._items: dict[str, dict] = {}

    # ---- 内部 ----

    def _gc_locked(self, now: float) -> None:
        for d in [d for d, e in self._items.items() if e["expires_at"] <= now]:
            self._items.pop(d, None)

    def gc(self) -> None:
        with self._lock:
            self._gc_locked(time.time())

    # ---- 对外 ----

    def live_for_user(self, user_id: int) -> int:
        with self._lock:
            self._gc_locked(time.time())
            return sum(1 for e in self._items.values() if e["user_id"] == user_id)

    def mint(self, user_id: int, username: str, audience: str, ip: str = "",
             device: str = "", issued_via: str = "", ttl: int | None = None,
             next_url: str = "") -> tuple[str, int]:
        """签发一枚码。返回 ``(code, ttl_seconds)``。**这是唯一一次明文码出现的地方。**"""
        ttl = int(ttl_seconds() if ttl is None else ttl)
        ttl = max(1, ttl)
        code = secrets.token_urlsafe(32)
        now = time.time()
        entry = {
            "user_id": int(user_id),
            "username": username,
            "audience": audience,
            "issued_via": issued_via,
            "device": (device or "")[:100],
            "next_url": (next_url or "")[:500],
            "ip_prefix": _ip_prefix(ip),
            "ip_full": (ip or "").strip(),
            "created_at": now,
            "expires_at": now + ttl,
        }
        with self._lock:
            self._gc_locked(now)
            self._items[_digest(code)] = entry
        return code, ttl

    def pop(self, code: str, audience: str, ip: str = "") -> tuple[dict | None, str]:
        """兑换：**成功即删**。返回 ``(entry, "")`` 或 ``(None, 原因)``。

        原因取值：``invalid``（不存在/已用过/超过条数上限被清）·``expired``（过期）
        ·``audience``（站点不匹配，**不消耗码**）·``ip``（IP 绑定不符）。
        """
        if not isinstance(code, str) or not (16 <= len(code) <= 200):
            return None, "invalid"
        d = _digest(code)
        now = time.time()
        mode = (getattr(settings, "PHIX_SSO_IP_BIND", "off") or "off").strip().lower()
        with self._lock:
            self._gc_locked(now)
            entry = self._items.get(d)
            if entry is None:
                return None, "invalid"
            if entry["expires_at"] <= now:          # 理论上前面的 gc 已清掉，双保险
                self._items.pop(d, None)
                return None, "expired"
            if entry["audience"] != audience:
                return None, "audience"             # **不 pop**：别让人用错站点把码烧掉
            if mode in ("prefix", "exact") and not _ip_matches(
                    entry["ip_prefix"], entry.get("ip_full", ""), ip, mode):
                return None, "ip"
            self._items.pop(d, None)                # 用后即焚
            return entry, ""

    def clear(self) -> None:
        """只给测试用。"""
        with self._lock:
            self._items.clear()

    def size(self) -> int:
        with self._lock:
            self._gc_locked(time.time())
            return len(self._items)


codes = _CodeStore()


# ---------------- 身份：谁能签发码 ----------------

def _resolve_issuer(request, data):
    """返回 ``(user, how, 错误响应或 None)``。

    两条路（顺序即优先级）：

    - **服务密钥**（`X-Phix-Service-Key` + `user_id`/`username`）：服务端到服务端。
      心履 .35 用它给"已在本站登录、且已关联 phix 账号"的人换码。
      *带了这个头但值不对 → 直接 401，绝不悄悄退回会话路径。*
    - **Bearer 会话**：官网后端拿着 cookie 里的 access 令牌来换码。
    """
    if request.META.get("HTTP_X_PHIX_SERVICE_KEY"):
        if not service_key_ok(request):
            return None, "", err("unauthorized", "服务密钥不正确", 401)
        uid = data.get("user_id")
        uname = data.get("username")
        User = get_user_model()
        user = None
        if uid not in (None, "", 0, "0"):
            try:
                user = User.objects.filter(id=int(uid)).first()
            except (TypeError, ValueError):
                return None, "", err("bad_request", "user_id 不是整数")
        elif isinstance(uname, str) and uname.strip():
            user = User.objects.filter(username=uname.strip()).first()
        else:
            return None, "", err("bad_request",
                                 "服务密钥调用必须带 user_id 或 username")
        if user is None:
            return None, "", err("not_found", "没有这个账号", 404)
        if not user.is_active:
            return None, "", err("forbidden", "这个账号已被停用", 403)
        return user, "service_key", None

    sess, why = resolve_jwt(request)
    if sess is not None:
        if not sess.user.is_active:
            return None, "", err("forbidden", "这个账号已被停用", 403)
        return sess.user, "session", None
    if why != "not_jwt":
        # 是 JWT 但没通过（过期/已注销/DPoP 不符）—— 如实回报，别静默降级
        msg = {"expired": "登录状态已过期，请用 refresh 令牌续期",
               "session_revoked": "这个会话已被注销",
               "session_expired": "这个会话已过期，请重新登录"}.get(
                   why, "登录状态无效，请重新登录")
        return None, "", err("token_expired" if why == "expired" else "unauthorized",
                             msg, 401)
    if legacy_tokens_enabled():
        tok = current_token(request)
        if tok is not None:
            if not tok.user.is_active:
                return None, "", err("forbidden", "这个账号已被停用", 403)
            return tok.user, "legacy", None
    return None, "", err("unauthorized", "未登录", 401)


def _mint_limited(request, user) -> bool:
    """签发限流：同一 IP 与同一用户各自计数。返回 True 表示已超限。"""
    ip = client_ip(request)
    limit = int(getattr(settings, "PHIX_SSO_MINT_LIMIT", 30))
    window = int(getattr(settings, "PHIX_SSO_MINT_WINDOW", 3600))
    over_ip = limiter.hit(f"sso_code:{ip}", limit=limit, window_seconds=window)
    over_user = limiter.hit(f"sso_code:u{user.id}", limit=limit, window_seconds=window)
    return over_ip or over_user


# ---------------- 视图 ----------------

@require_POST
def sso_code(request):
    """`POST /api/v1/auth/sso/code` —— 换一枚一次性码（120 秒、单次、绑站点）。"""
    data = json_body(request)
    if data is None:
        return err("bad_request", "请求格式错误（需要 JSON 对象）")

    user, how, bad = _resolve_issuer(request, data)
    if bad is not None:
        return bad
    if _mint_limited(request, user):
        return err("rate_limited", "换码太频繁了，请稍后再试", 429)

    audience = data.get("audience") or DEFAULT_AUDIENCE
    if not isinstance(audience, str) or audience not in audiences():
        return err("bad_request", "不认识的站点标识（audience）")

    live = codes.live_for_user(user.id)
    cap = int(getattr(settings, "PHIX_SSO_LIVE_PER_USER", 10))
    if live >= cap:
        return err("rate_limited", "待兑换的码太多了，请稍后再试", 429)

    code, ttl = codes.mint(user.id, user.username, audience, ip=client_ip(request),
                           device=data.get("device", ""), issued_via=how,
                           next_url=data.get("next", ""))
    # **码全文绝不写日志**：只留摘要前 8 位，够用来串日志、不够用来兑换。
    log.info("签发 SSO 码 sid=%s user_id=%s audience=%s via=%s ttl=%ss",
             _digest(code)[:8], user.id, audience, how, ttl)
    return ok({"code": code, "expires_in": ttl, "audience": audience,
               "single_use": True, "issued_via": how})


@require_POST
def sso_redeem(request):
    """`POST /api/v1/auth/sso/redeem` —— 用码换令牌（**与 /auth/login 同构**）。

    body：``{"code": "...", "site": "xinlv", "device": "心履网页端"}``
    """
    ip = client_ip(request)
    limit = int(getattr(settings, "PHIX_SSO_REDEEM_LIMIT", 60))
    window = int(getattr(settings, "PHIX_SSO_REDEEM_WINDOW", 3600))
    if limiter.hit(f"sso_redeem:{ip}", limit=limit, window_seconds=window):
        return err("rate_limited", "兑换太频繁了，请稍后再试", 429)

    data = json_body(request)
    if data is None:
        return err("bad_request", "请求格式错误（需要 JSON 对象）")

    code = data.get("code")
    site = data.get("site") or data.get("audience")
    if not isinstance(site, str) or not site.strip():
        return err("bad_request", "缺少 site（站点标识）")
    site = site.strip()
    if site not in audiences():
        return err("bad_request", "不认识的站点标识（site）")

    if require_service_key() and not service_key_ok(request):
        _note_failure(ip, "no_service_key", site, code)
        return err("unauthorized", "兑换需要服务密钥", 401)

    entry, reason = codes.pop(code if isinstance(code, str) else "", site, ip)
    if entry is None:
        over = _note_failure(ip, reason, site, code)
        if over:
            return err("rate_limited", "兑换失败次数过多，请稍后再试", 429)
        msg = {
            "invalid": "这个码无效或已经被用过了",
            "expired": "这个码已过期，请重新发起",
            "audience": "这个码不是发给本站的",
            "ip": "兑换来源与签发来源不一致",
        }.get(reason, "这个码不可用")
        return err("unauthorized", msg, 401)

    User = get_user_model()
    user = User.objects.filter(id=entry["user_id"]).first()
    if user is None or not user.is_active:
        log.warning("SSO 兑换时账号不可用 sid=%s user_id=%s",
                    _digest(code)[:8], entry["user_id"])
        return err("forbidden", "这个账号不可用", 403)
    if user.username != entry["username"]:
        # 用户名改过（本服务端目前不允许改名，留个护栏）
        log.warning("SSO 兑换用户名校验不符 sid=%s", _digest(code)[:8])
        return err("unauthorized", "这个码不可用", 401)

    limiter.clear(f"sso_redeem_fail:{ip}")
    out = _auth_payload_of(user)
    creds, sess, _copy = _issue_session_of(user, data.get("device", ""))
    out.update(creds)
    out["sso"] = {
        "audience": entry["audience"],
        "issued_via": entry["issued_via"],
        "single_use": True,
        "minted_ago": max(0, int(time.time() - entry["created_at"])),
    }
    # 这里**没有** DEK：码里从不携带 DEK，服务端也从来没有 DEK。
    # 兑换方拿到的 key_wrap 是"包裹后的 DEK"，只有知道口令的一方才解得开。
    log.info("SSO 兑换成功 sid=%s user_id=%s site=%s device=%s",
             _digest(code)[:8], user.id, site, data.get("device", ""))
    return ok(out)


def _note_failure(ip: str, reason: str, site: str, code) -> bool:
    """记一次兑换失败；返回 True 表示已经该限流了。**绝不记录码本身。**"""
    limit = int(getattr(settings, "PHIX_SSO_FAIL_LIMIT", 20))
    window = int(getattr(settings, "PHIX_SSO_FAIL_WINDOW", 900))
    over = limiter.hit(f"sso_redeem_fail:{ip}", limit=limit, window_seconds=window)
    log.warning("SSO 兑换失败 sid=%s site=%s ip=%s 原因=%s%s",
                _digest(code)[:8] if isinstance(code, str) else "-",
                site, ip, reason, "（已超失败上限，开始限流）" if over else "")
    return over


# 延迟 import：避免与 views_auth 形成模块级循环依赖（views_auth 不 import 本模块）
def _auth_payload_of(user):
    from .views_auth import _auth_payload
    return _auth_payload(user)


def _issue_session_of(user, device):
    from .views_auth import _issue_session
    return _issue_session(user, device)
