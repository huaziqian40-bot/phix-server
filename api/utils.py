"""phix 服务端公共工具：JSON 收发、统一错误、Bearer 认证、限流、对象名校验。"""
import functools
import hmac
import json
import logging
import re
import threading
import time

from django.conf import settings
from django.http import JsonResponse
from django.utils import timezone

from .models import DeviceToken, TokenSession

log = logging.getLogger("phix.auth")

# 对象名：字母数字开头，可含 . _ : -  （会进 HKDF info 与 AAD，改动即换密钥）
OBJECT_NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")

ERROR_CODES = {
    "bad_request", "unauthorized", "bad_credentials", "forbidden", "not_found",
    "revision_conflict", "quota_exceeded", "payload_too_large",
    "rate_limited", "server_error", "name_invalid",
    # P3：把"该续期"和"该重新登录"分开，客户端才好自动处理
    "token_expired",
}


# ---------------- JSON 收发 ----------------

def json_body(request):
    """解析 JSON 请求体；失败返回 None。"""
    try:
        raw = request.body.decode("utf-8")
    except (UnicodeDecodeError, AttributeError):
        return None
    if not raw:
        return {}
    try:
        data = json.loads(raw)
    except json.JSONDecodeError:
        return None
    return data if isinstance(data, dict) else None


def ok(data=None, status=200):
    payload = {"ok": True}
    if isinstance(data, dict):
        payload.update(data)
    elif data is not None:
        payload["data"] = data
    return JsonResponse(payload, status=status, json_dumps_params={"ensure_ascii": False})


def err(code, message, status=400, **extra):
    if code not in ERROR_CODES:
        code = "bad_request"
    payload = {"ok": False, "error": {"code": code, "message": message}}
    payload.update(extra)
    return JsonResponse(payload, status=status,
                        json_dumps_params={"ensure_ascii": False})


def iso(dt):
    return dt.isoformat() if dt else None


# ---------------- 限流（进程内存，与心履 core/ratelimit.py 同思路） ----------------

class RateLimiter:
    """滑动窗口限流。waitress 单进程够用；将来多进程部署需换成共享存储。"""

    def __init__(self):
        self._hits = {}
        self._lock = threading.Lock()

    def hit(self, key, limit, window_seconds):
        """记一次；返回 True 表示已超限（本次应拒绝）。"""
        now = time.time()
        with self._lock:
            arr = [t for t in self._hits.get(key, []) if now - t < window_seconds]
            arr.append(now)
            self._hits[key] = arr
            return len(arr) > limit

    def clear(self, key=None):
        with self._lock:
            if key is None:
                self._hits.clear()
            else:
                self._hits.pop(key, None)

    def gc(self, max_age=3600):
        now = time.time()
        with self._lock:
            for k in list(self._hits):
                arr = [t for t in self._hits[k] if now - t < max_age]
                if arr:
                    self._hits[k] = arr
                else:
                    self._hits.pop(k, None)


limiter = RateLimiter()


def client_ip(request):
    xff = request.META.get("HTTP_X_FORWARDED_FOR", "")
    if xff:
        return xff.split(",")[0].strip()
    return request.META.get("REMOTE_ADDR", "?")


# ---------------- 认证（P3：JWT 优先，老式长期令牌兼容） ----------------

def bearer_value(request):
    auth = request.META.get("HTTP_AUTHORIZATION", "")
    if not auth.startswith("Bearer "):
        return ""
    return auth[7:].strip()


def current_token(request):
    """**老式**长期令牌（40 位 hex）。P3 之后仅用于兼容老客户端。"""
    key = bearer_value(request)
    if not key:
        return None
    return (
        DeviceToken.objects.select_related("user")
        .filter(key=key, revoked_at__isnull=True)
        .first()
    )


def legacy_tokens_enabled():
    return bool(getattr(settings, "PHIX_LEGACY_TOKENS", True))


def resolve_jwt(request):
    """按 Bearer 里的 JWT 认证。返回 (session, claims)；任何一步不过关返回 (None, 原因)。

    检查顺序（每一步失败都给出可区分的理由）：
      1. 验签 + `exp`/`iat`/`iss`/`aud`
      2. 会话必须存在且未注销、未过期（**注销立即生效**，不等 JWT 过期）
      3. `jti` 黑名单
      4. DPoP 绑定：会话有 `jkt` 就必须带匹配的证明（否则谁捡到令牌都能用）
    """
    from . import tokens as T

    from .models import JtiBlacklist, TokenSession

    raw = bearer_value(request)
    if not raw or not T.looks_like_jwt(raw):
        return None, "not_jwt"
    try:
        claims = T.verify_access(raw)
    except T.TokenExpired:
        return None, "expired"
    except T.TokenError:
        return None, "bad_signature"

    sid = claims.get("sid")
    sess = (TokenSession.objects.select_related("user").filter(id=sid).first()
            if sid else None)
    if sess is None:
        return None, "no_session"
    if not sess.alive:
        return None, ("session_revoked" if sess.revoked_at else "session_expired")
    if str(sess.user_id) != str(claims.get("sub")):
        return None, "subject_mismatch"
    if JtiBlacklist.blocked(claims.get("jti")):
        return None, "jti_revoked"

    if sess.jkt:
        proof = request.META.get("HTTP_DPOP", "") or ""
        if not proof:
            return None, "dpop_required"
        try:
            jkt = T.verify_dpop(proof, request.method, request.path, raw)
        except T.TokenError as exc:
            return None, f"dpop_invalid:{exc}"
        if jkt != sess.jkt:
            return None, "dpop_key_mismatch"
    return sess, claims


def require_token(view):
    """Bearer 认证装饰器。通过后 `request.phix_user` 等可用。

    兼容两种凭据：
    - **JWT**（P3 起）：`request.phix_session` / `request.phix_claims` 有值，
      `request.phix_token` 为 None。
    - **老式长期令牌**：`request.phix_token` 有值（老客户端与新客户端混用期）。
    """

    @functools.wraps(view)
    def wrapper(request, *args, **kwargs):
        result = resolve_jwt(request)
        sess, claims = result
        if sess is not None:
            TokenSession.objects.filter(id=sess.id).update(
                last_seen_at=timezone.now(),
                last_ip=client_ip(request)[:64],
            )
            request.phix_session = sess
            request.phix_claims = claims
            request.phix_user = sess.user
            request.phix_token = None
            return view(request, *args, **kwargs)

        if claims != "not_jwt":
            # 是 JWT 但没通过 —— 别悄悄退回老路径，客户端要能分辨"该续期"还是"该重登"
            why = claims
            code = "token_expired" if why == "expired" else "unauthorized"
            msg = {
                "expired": "登录状态已过期，请用 refresh 令牌续期",
                "session_revoked": "这个会话已被注销",
                "session_expired": "这个会话已过期，请重新登录",
                "dpop_required": "这个会话绑定了客户端密钥，请求必须带 DPoP 证明",
            }.get(why, "登录状态无效，请重新登录")
            if why.startswith("dpop_invalid") or why in (
                    "dpop_key_mismatch", "jti_revoked", "subject_mismatch",
                    "no_session", "bad_signature"):
                code, msg = "unauthorized", "登录状态无效，请重新登录"
                log.warning("JWT 被拒 user_path=%s ip=%s 原因=%s",
                            request.path, client_ip(request), why)
            return err(code, msg, 401)

        if not legacy_tokens_enabled():
            return err("unauthorized", "未登录（本服务器只接受 JWT）", 401)

        token = current_token(request)
        if token is None:
            return err("unauthorized", "未登录或令牌无效", 401)
        token.last_used_at = timezone.now()
        token.save(update_fields=["last_used_at"])
        request.phix_token = token
        request.phix_session = None
        request.phix_claims = {}
        request.phix_user = token.user
        return view(request, *args, **kwargs)

    return wrapper


def service_key_ok(request):
    """心履等服务端到服务端调用用的共享密钥（常量时间比较）。"""
    expect = getattr(settings, "PHIX_SERVICE_KEY", "") or ""
    got = request.META.get("HTTP_X_PHIX_SERVICE_KEY", "") or ""
    if not expect:
        return False
    return hmac.compare_digest(expect, got)


# ---------------- 校验 ----------------

def check_object_name(name):
    if not isinstance(name, str) or not OBJECT_NAME_RE.match(name):
        return False
    return True


def sha256_hex(text):
    import hashlib

    return hashlib.sha256(text.encode("utf-8")).hexdigest()
