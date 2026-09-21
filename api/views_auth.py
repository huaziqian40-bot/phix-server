"""phix 认证视图：注册 / 登录 / 令牌 / 密钥材料 / 恢复。

服务端职责边界：
- 它**存**密钥材料，但从不解析、从不解密、也从不需要解密。
- 唯一的"服务端验证"是 `/auth/verify`（心履等服务端到服务端调用）。
- 「证明你持有 DEK」：客户端把服务端存的 `key_check` 信封解开，报回里面那串
  **服务端已知、但任何接口都不下发的随机明文**。只有真正持有 DEK 的一方能做到。
"""
import hmac
import logging
from datetime import timedelta

from django.conf import settings
from django.contrib.auth import authenticate, get_user_model
from django.contrib.auth.validators import UnicodeUsernameValidator
from django.core.exceptions import ValidationError
from django.db import IntegrityError, transaction
from django.utils import timezone
from django.views.decorators.http import require_GET, require_POST

from . import tokens
from .models import (DeviceToken, SyncObject, TokenSession, UserKeyMaterial,
                     refresh_digest)
from .utils import (check_object_name, client_ip, err, iso, json_body, legacy_tokens_enabled,
                    limiter, ok, require_token, service_key_ok)

log = logging.getLogger("phix.auth")

ENVELOPE_PREFIX = "PHIX1."
VALID_KEY_MODES = ("password", "syncphrase")
KDF_ALGOS = ("scrypt-n15-r8-p1", "scrypt-hkdf-v2")

_username_validator = UnicodeUsernameValidator()


# ---------------- 身份凭证（v1 口令原文 / v2 AuthHash） ----------------

def _credential(data, prefix: str = ""):
    """取客户端发来的"身份凭证"。

    **服务端不关心它是哪一代**：v2 客户端发的是 `AuthHash`
    （由口令派生、但反推不出口令、更推不出 KEK），v1 客户端发的就是口令原文。
    两者在这里都只是"一串字符串"——服务器对它做 PBKDF2 存起来、登录时比对。
    所以服务端代码几乎不用改，而**新账号从注册那一刻起，服务器就再没见过用户的口令**。

    返回 (凭证字符串, 种类)；取不到时是 (None, None)。
    """
    key = f"{prefix}auth_hash"
    val = data.get(key)
    if isinstance(val, str):
        val = val.strip()
        if val:
            if len(val) != 64:
                return "", "auth_hash_bad"
            try:
                int(val, 16)
            except ValueError:
                return "", "auth_hash_bad"
            return val, "auth_hash"
    pw = data.get(f"{prefix}password")
    if isinstance(pw, str) and pw:
        return pw, "password"
    return None, None


def _credential_guard(user, kind, field, allow_plaintext=False, can_migrate=False):
    """v2 账号（**服务端从未见过口令**）收到 `password` 原文时的护栏。

    背景（真踩过的坑）：v2 客户端的凭证是 `AuthHash`。若某个客户端漏发
    `auth_hash` 只发了 `password`，服务端会**照收不误**——因为 `_credential()`
    压根不关心它是哪一代，于是把"口令原文"当成新凭证存了下去，
    新旧口令与同步口令随即全部失效，而且**不报任何错**。
    这类静默降级最难查，所以在这里显式拦下来：

    - ``field``：出错时该提醒客户端补哪个字段（如 ``old_auth_hash``）。
    - ``allow_plaintext=True``：v1 账号的既有行为，放行但记一条 warning。
    - ``can_migrate=True``：调用点手里**已经有**该账号的 AuthHash（`recover`），
      所以可以直接写回 AuthHash 完成迁移，不必让用户再来一次。
    - ``phix_v2_plaintext_ok`` 是运维开关：v2 客户端全部升级完后设成
      ``0``，把"发口令原文"从警告升级成硬拒绝。
    """
    if kind != "password":
        return None, False
    algo = getattr(getattr(user, "phix_keys", None), "kdf_algo", None)
    if algo != "scrypt-hkdf-v2":
        return None, False
    log.warning("v2 账号收到口令原文凭据 user_id=%s field=%s —— "
                "客户端漏发 auth_hash（本该发派生凭证）",
                getattr(user, "id", None), field)
    if not getattr(settings, "PHIX_V2_PLAINTEXT_OK", True):
        return ("bad_request",
                f"这个账号是 v2 账号，请改用 {field}（64 位十六进制派生凭证），"
                "不要发口令原文"), False
    if not allow_plaintext:
        return ("bad_request",
                f"这个账号是 v2 账号，缺少 {field}（64 位十六进制派生凭证）；"
                "为免写坏凭证，服务端拒绝用口令原文继续"), False
    return None, bool(can_migrate)


# ---------------- 校验辅助 ----------------

def _valid_envelope(v, max_len=200000):
    return isinstance(v, str) and v.startswith(ENVELOPE_PREFIX) and 20 <= len(v) <= max_len


def _valid_salt(v):
    if not isinstance(v, str) or not (16 <= len(v) <= 64):
        return False
    try:
        int(v, 16)
    except ValueError:
        return False
    return True


def _key_material_error(data, require_recovery=True, require_wrap=True):
    """校验客户端送来的密钥材料（全是客户端本地生成的）。返回错误信息或 None。

    ``require_wrap=False``：**只改登录密码、不动 DEK 包裹**的场景
    （账号处于 syncphrase 模式时，DEK 由独立同步口令包裹，改登录密码与它无关）。
    """
    if require_wrap:
        if not _valid_envelope(data.get("key_wrap")):
            return "key_wrap 格式不正确"
        if not _valid_salt(data.get("kdf_salt")):
            return "kdf_salt 必须是十六进制"
    else:
        if data.get("key_wrap") is not None and not _valid_envelope(data.get("key_wrap")):
            return "key_wrap 格式不正确"
        if data.get("kdf_salt") is not None and not _valid_salt(data.get("kdf_salt")):
            return "kdf_salt 必须是十六进制"
    if data.get("kdf_algo", KDF_ALGOS[0]) not in KDF_ALGOS:
        return "不支持的 kdf_algo"
    if data.get("key_mode", "password") not in VALID_KEY_MODES:
        return "key_mode 只能是 password 或 syncphrase"
    if require_recovery:
        # 注册：四样都必须给全
        if not _valid_envelope(data.get("key_check")):
            return "key_check 格式不正确"
        plain = data.get("key_check_plain")
        if not isinstance(plain, str) or not (16 <= len(plain) <= 128):
            return "key_check_plain 不正确"
        try:
            bytes.fromhex(plain)
        except ValueError:
            return "key_check_plain 必须是十六进制"
        if not _valid_envelope(data.get("recovery_wrap")):
            return "recovery_wrap 格式不正确"
        if not _valid_salt(data.get("recovery_salt")):
            return "recovery_salt 必须是十六进制"
        algo = data.get("kdf_algo", KDF_ALGOS[0])
        if algo != "scrypt-n15-r8-p1":
            if not _valid_salt(data.get("auth_salt")):
                return "auth_salt 必须是十六进制（v2 账号的登录凭证盐）"
    else:
        # 换密码 / 重新包裹：key_check 只取决于 DEK 与用户名，本来就该不变，可省略
        if data.get("key_check") is not None and not _valid_envelope(data.get("key_check")):
            return "key_check 格式不正确"
    return None


def _apply_key_material(kmat, data, bump_version=False):
    """只写客户端**确实送来了**的字段。没送的一律保持原样。

    这条很重要：syncphrase 模式下改登录密码，DEK 包裹必须原封不动，
    否则会把"用同步口令包裹"的那份悄悄换成"用新登录密码包裹"，
    下次拿同步口令就解不开了（这块曾真的写错过）。
    """
    if data.get("kdf_algo"):
        kmat.kdf_algo = data["kdf_algo"]
    if data.get("kdf_salt"):
        kmat.kdf_salt = data["kdf_salt"]
    # auth_salt **永不改写**：它决定 AuthHash，改了用户就登不进来了
    if not kmat.auth_salt and data.get("auth_salt"):
        kmat.auth_salt = data["auth_salt"]
    if data.get("key_wrap"):
        kmat.key_wrap = data["key_wrap"]
    if data.get("key_check"):
        kmat.key_check = data["key_check"]
    if data.get("key_mode"):
        kmat.key_mode = data["key_mode"]
    if data.get("recovery_wrap"):
        kmat.recovery_wrap = data["recovery_wrap"]
        kmat.recovery_salt = data["recovery_salt"]
    if bump_version:
        kmat.key_version = (kmat.key_version or 0) + 1
    kmat.save()
    return kmat


def _auth_payload(user):
    kmat = UserKeyMaterial.objects.filter(user=user).first()
    if kmat is None:
        # 理论上不该发生；兜底建一个占位，避免客户端拿到 None 崩掉
        kmat = UserKeyMaterial.objects.create(
            user=user, kdf_salt="0" * 32, key_wrap="PHIX1.invalid.invalid",
            recovery_salt="0" * 32, recovery_wrap="PHIX1.invalid.invalid",
            key_check="PHIX1.invalid.invalid", key_check_plain="",
            auth_salt="0" * 32,
        )
    out = {"user_id": user.id, "username": user.username}
    out.update(kmat.as_public_dict())
    # 管理后台需要的角色标记（只回布尔，绝不回任何密钥/哈希）
    out["is_staff"] = bool(getattr(user, "is_staff", False))
    out["is_superuser"] = bool(getattr(user, "is_superuser", False))
    return out


# ---------------- P3：会话 + JWT ----------------

def _issue_session(user, device="", jkt="", with_legacy=None):
    """开一个会话并返回令牌组（对应 `加密链路思路.md` §7）。

    - `access`：Ed25519 签名的 JWT，**15 分钟**，只作会话凭证。
    - `refresh`：**30 天**、只能换新 access，**用一次换一次**。
    - `token`：兼容字段。老客户端把 `token` 当长期 Bearer 用，所以默认同时
      签一个长期令牌（`PHIX_LEGACY_TOKENS=0` 时不再发）。
    """
    legacy = legacy_tokens_enabled() if with_legacy is None else bool(with_legacy)
    sess, refresh = TokenSession.start(user, device=device, jkt=jkt)
    access, claims = tokens.sign_access(user.id, sess.id, device=device, jkt=jkt)
    out = {
        "session_id": sess.id,
        "token_type": "Bearer",
        "access_token": access,
        "refresh_token": refresh,
        "expires_in": int(claims["exp"]) - int(claims["iat"]),
        "expires_at": claims["exp"],
        "refresh_expires_at": int(sess.expires_at.timestamp()),
        "refresh_expires_in": int(
            getattr(settings, "PHIX_REFRESH_TTL", 30 * 24 * 3600)),
    }
    if legacy:
        # 老路径的长期令牌：**挂在同一个会话下**，将来注销会话时一起失效
        tok = DeviceToken.mint(user, device)
        out["token"] = tok.key
        out["legacy_token"] = tok.key
        out["legacy_token_id"] = tok.id
        out["legacy"] = True
    return out, sess, {**out}      # 第二份副本给内部用（不含 refresh 明文以外的秘密）


def _rotate_access(request):
    """`POST /auth/refresh`：用 refresh 令牌换新的 access（并轮换 refresh）。"""
    data = json_body(request)
    if data is None:
        return err("bad_request", "请求格式错误")
    raw = data.get("refresh_token") or data.get("refresh") or ""
    if not isinstance(raw, str) or len(raw) < 20:
        return err("bad_request", "缺少 refresh_token")
    # refresh 是 40 字节 url-safe 随机串；先粗筛再逐个比对（哈希比对是常量时间）
    ip = client_ip(request)
    if limiter.hit(f"refresh:{ip}", limit=getattr(settings, "PHIX_REFRESH_LIMIT", 120),
                   window_seconds=3600):
        return err("rate_limited", "续期太频繁了，请稍后再试", 429)

    User = get_user_model()
    # 用摘要**直接索引查找**（不是遍历所有会话逐个哈希比对 —— 那样会话一多就慢，
    # 而且顺序还会影响结果）。refresh 是 320 位随机串，SHA-256 指纹足够。
    dig = refresh_digest(raw)
    sess = (TokenSession.objects.select_related("user")
            .filter(refresh_hash=dig, revoked_at__isnull=True).first())
    how = "current"
    if sess is None:
        sess = (TokenSession.objects.select_related("user")
                .filter(refresh_hash=dig, revoked_at__isnull=False).first())
        if sess is not None:
            # 认得出是哪个会话，但会话已经注销/撤销了
            log.warning("refresh 命中的是会话已注销的令牌 sid=%s ip=%s", sess.id, ip)
            return err("unauthorized", "这个会话已被注销，请重新登录", 401)
    if sess is None:
        # 也许是"刚被换掉的那个"（并发续期的宽限期），或者已经出窗的**重放**
        hit_prev = list(TokenSession.objects.select_related("user").filter(
            prev_refresh_hash=dig).order_by("-id")[:5])
        live = [s for s in hit_prev if s.revoked_at is None]
        if live:
            sess = live[0]
            how = "grace" if sess.check_prev_refresh(raw) else "replay"
        else:
            log.warning("refresh 未命中 ip=%s", ip)
            return err("unauthorized", "续期凭据无效，请重新登录", 401)

    if how == "replay":
        # 对应设计文档 §7：「重复使用 → 撤销整个会话」
        sess.revoke("reuse")
        log.warning("refresh 重放！已撤销整个会话 user_id=%s sid=%s ip=%s",
                    sess.user_id, sess.id, ip)
        return err("unauthorized", "续期凭据已被使用过，为安全起见本次登录已作废，请重新登录", 401)
    if not sess.alive:
        return err("unauthorized", "会话已过期，请重新登录", 401)
    if sess.jkt:
        proof = request.META.get("HTTP_DPOP", "") or ""
        if not proof:
            return err("unauthorized", "这个会话绑定了客户端密钥，续期也要带 DPoP 证明", 401)
        try:
            jkt = tokens.verify_dpop(proof, request.method, request.path)
        except tokens.TokenError as exc:
            log.warning("续期时 DPoP 校验失败 sid=%s ip=%s：%s", sess.id, ip, exc)
            return err("unauthorized", "DPoP 证明无效", 401)
        if jkt != sess.jkt:
            return err("unauthorized", "DPoP 公钥与会话绑定的不一致", 401)

    if how == "grace":
        # 宽限期内重复使用上一个 refresh：**并发续期很正常，不当作攻击**，
        # 但**不重发**那个新 refresh（它的明文只出现过一次，服务端也没有）。
        # 客户端拿到 `rotated:false` 且没有 refresh_token 字段时，应保持自己
        # 手里那串不变、隔一会儿再续一次 —— 那一串此时已经在上位了。
        access, claims = tokens.sign_access(
            sess.user_id, sess.id, device=sess.device, jkt=sess.jkt)
        log.info("续期（宽限期内重复） user_id=%s sid=%s ip=%s",
                 sess.user_id, sess.id, ip)
        return ok({
            "session_id": sess.id, "token_type": "Bearer",
            "access_token": access,
            "expires_in": int(claims["exp"]) - int(claims["iat"]),
            "expires_at": claims["exp"], "rotated": False,
            "refresh_expires_at": int(sess.expires_at.timestamp()),
        })

    new_refresh, grace_until = sess.rotate()
    access, claims = tokens.sign_access(
        sess.user_id, sess.id, device=sess.device, jkt=sess.jkt)
    TokenSession.objects.filter(id=sess.id).update(last_seen_at=timezone.now(),
                                                  last_ip=ip[:64])
    log.info("续期成功 user_id=%s sid=%s ip=%s", sess.user_id, sess.id, ip)
    return ok({
        "session_id": sess.id, "token_type": "Bearer",
        "access_token": access, "refresh_token": new_refresh,
        "expires_in": int(claims["exp"]) - int(claims["iat"]),
        "expires_at": claims["exp"], "rotated": True,
        "refresh_grace_until": int(grace_until.timestamp()),
        "refresh_expires_at": int(sess.expires_at.timestamp()),
    })


def _dek_proof_ok(data, kmat):
    """证明「客户端手里真有 DEK」。

    做法：客户端把服务端存的那份 `key_check` 信封解开，把里面的**随机明文**（hex）
    报回来比对。该明文只在注册接口被收下，**此后任何接口都不下发**；
    而 `key_check` 只有用 DEK 派生的密钥才解得开。
    所以"报一串公开常量"或"凭令牌偷看"都伪造不了 —— 这是真正的持有性证明。

    强度边界（诚实说明）：它防的是「令牌被偷但对 DEK 一无所知」；
    若攻击者能直接读数据库，他本来就能改密码哈希，这一层拦不住也不该由它拦。
    """
    if not kmat.key_check_plain:
        return False
    got = data.get("dek_proof")
    if not isinstance(got, str):
        return False
    return hmac.compare_digest(got.strip().lower(), kmat.key_check_plain.lower())


def _client_jkt(request, data):
    """客户端要求把自己的密钥绑到会话上（DPoP）时，验证并返回公钥指纹。

    客户端在登录/注册请求里带 `dpop_jkt`，并同时带一个 `DPoP` 证明 ——
    **必须能验证通过**，否则等于谁都能替别人绑一把钥匙。
    没要求绑定就返回 ""。
    """
    want = data.get("dpop_jkt")
    if not isinstance(want, str) or not want.strip():
        return "", None
    want = want.strip()
    proof = request.META.get("HTTP_DPOP", "") or ""
    if not proof:
        return "", "要求绑定客户端密钥（dpop_jkt）就必须同时带 DPoP 证明"
    try:
        got = tokens.verify_dpop(proof, request.method, request.path)
    except tokens.TokenError as exc:
        return "", f"DPoP 证明无效：{exc}"
    if got != want:
        return "", "DPoP 证明用的公钥与 dpop_jkt 不一致"
    return got, None


# ---------------- 注册 ----------------

@require_POST
def register(request):
    if limiter.hit(f"reg:{client_ip(request)}",
                   limit=getattr(settings, "PHIX_REGISTER_LIMIT", 10),
                   window_seconds=3600):
        return err("rate_limited", "注册太频繁了，请稍后再试", 429)
    data = json_body(request)
    if data is None:
        return err("bad_request", "请求格式错误（需要 JSON 对象）")

    username = data.get("username")
    credential, kind = _credential(data)
    if not isinstance(username, str) or credential is None:
        return err("bad_request", "账号和密码格式不正确")
    if kind == "auth_hash_bad":
        return err("bad_request", "auth_hash 必须是 64 位十六进制")
    username = username.strip()
    if not username or not credential:
        return err("bad_request", "账号和密码都要填")
    if len(username) > 150:
        return err("bad_request", "账号太长了（最多 150 个字符）")
    try:
        _username_validator(username)
    except ValidationError:
        return err("bad_request", "账号只能包含字母、数字、下划线、点、@、+、- 和中文")
    # v1 客户端发口令原文 → 仍然按口令规则校验；v2 发的是派生值，长度规则不适用
    if kind == "password":
        if len(credential) < 6:
            return err("bad_request", "密码至少 6 位")
        if len(credential) > 256:
            return err("bad_request", "密码太长了")
    if data.get("agree") is not True:
        return err("bad_request", "请先阅读并同意服务条款")

    kmat_err = _key_material_error(data)
    if kmat_err:
        return err("bad_request", kmat_err)

    User = get_user_model()
    if User.objects.filter(username=username).exists():
        return err("bad_request", "这个账号已经被注册了，换一个吧")

    try:
        with transaction.atomic():
            # **存的是凭证的哈希**：v2 账号下服务器从未见过用户的口令
            user = User.objects.create_user(username=username, password=credential)
            UserKeyMaterial.objects.create(
                user=user,
                kdf_algo=data.get("kdf_algo", KDF_ALGOS[0]),
                kdf_salt=data["kdf_salt"],
                auth_salt=data.get("auth_salt", ""),
                key_wrap=data["key_wrap"],
                key_check=data["key_check"],
                key_check_plain=data["key_check_plain"].strip().lower(),
                key_mode=data.get("key_mode", "password"),
                recovery_salt=data["recovery_salt"],
                recovery_wrap=data["recovery_wrap"],
            )
    except IntegrityError:
        return err("bad_request", "这个账号已经被注册了，换一个吧")

    log.info("注册成功 user_id=%s username=%s", user.id, user.username)
    jkt, jkt_err = _client_jkt(request, data)
    if jkt_err:
        return err("bad_request", jkt_err)
    out = _auth_payload(user)
    creds, _sess, _copy = _issue_session(user, data.get("device", ""), jkt=jkt)
    out.update(creds)
    return ok(out, status=201)

# ---------------- 登录 ----------------

@require_POST
def login(request):
    data = json_body(request)
    if data is None:
        return err("bad_request", "请求格式错误（需要 JSON 对象）")
    username = data.get("username")
    credential, kind = _credential(data)
    if not isinstance(username, str) or credential is None:
        return err("bad_request", "账号和密码格式不正确")
    if kind == "auth_hash_bad":
        return err("bad_request", "auth_hash 必须是 64 位十六进制")
    username = username.strip()

    rl_key = f"login:{client_ip(request)}:{username}"
    if limiter.hit(rl_key, limit=5, window_seconds=300):
        return err("rate_limited", "尝试太频繁了，过几分钟再试", 429)

    user = authenticate(request, username=username, password=credential)
    if user is None:
        log.warning("登录失败 username=%s ip=%s", username, client_ip(request))
        return err("bad_credentials", "账号或密码不对", 401)
    if not user.is_active:
        return err("forbidden", "这个账号已被停用", 403)

    limiter.clear(rl_key)
    log.info("登录成功 user_id=%s username=%s device=%s",
             user.id, user.username, data.get("device", ""))
    jkt, jkt_err = _client_jkt(request, data)
    if jkt_err:
        return err("bad_request", jkt_err)
    out = _auth_payload(user)
    creds, _sess, _copy = _issue_session(user, data.get("device", ""), jkt=jkt)
    out.update(creds)
    return ok(out)


# ---------------- 当前用户 ----------------

@require_GET
@require_token
def me(request):
    user = request.phix_user
    out = _auth_payload(user)
    out["created_at"] = iso(user.date_joined)
    agg = SyncObject.objects.filter(user=user).values_list("size", flat=True)
    used = sum(agg)
    out["quota"] = {
        "used_bytes": used,
        "limit_bytes": settings.PHIX_MAX_TOTAL_BYTES,
        "objects": SyncObject.objects.filter(user=user).count(),
        "limit_objects": settings.PHIX_MAX_OBJECTS,
    }
    out["device"] = _current_device(request)
    return ok(out)


def _current_device(request):
    """当前请求来自哪个设备 —— JWT 与老式令牌两种都支持。"""
    sess = getattr(request, "phix_session", None)
    if sess is not None:
        return {"id": sess.id, "name": sess.device, "session_id": sess.id,
                "jwt": True, "dpop_bound": bool(sess.jkt)}
    tok = getattr(request, "phix_token", None)
    if tok is not None:
        return {"id": tok.id, "name": tok.device, "session_id": None,
                "jwt": False, "dpop_bound": False}
    return {"id": None, "name": "", "session_id": None, "jwt": False,
            "dpop_bound": False}


@require_POST
@require_token
def logout(request):
    """注销**当前会话**：会话一注销，**访问令牌立刻失效**（不等它自然过期）。

    顺带把挂在这个会话下的老式长期令牌一起吊销（老客户端也是这么用的）。
    """
    sess = getattr(request, "phix_session", None)
    if sess is not None:
        sess.revoke("logout")
        n = _revoke_legacy_of_session(sess)
        return ok({"revoked": True, "session_id": sess.id, "legacy_revoked": n})
    tok = request.phix_token
    tok.revoked_at = timezone.now()
    tok.save(update_fields=["revoked_at"])
    return ok({"revoked": True, "session_id": None, "legacy_revoked": 1})


def _legacy_of_session(sess):
    """这个会话名下的老式长期令牌。

    它们没有外键指向会话，靠 (user, device, 时间) 匹配 —— 只在登出/注销设备时用，
    宁可多认一个（都是同一台设备同一账号的旧令牌），也不要漏掉。
    """
    if not sess.device:
        return DeviceToken.objects.none()
    return DeviceToken.objects.filter(
        user=sess.user, device=sess.device, revoked_at__isnull=True,
        created_at__lte=sess.created_at + timedelta(minutes=5),
    )


def _revoke_legacy_of_session(sess):
    """把这个会话名下的老式令牌一并吊销。"""
    return _legacy_of_session(sess).update(revoked_at=timezone.now())


# ---------------- 换密码 / 重新包裹 / 恢复 ----------------

@require_POST
@require_token
def change_password(request):
    """换登录密码 + 用新口令重新包裹 DEK。密文一个字节都不用动。"""
    data = json_body(request)
    if data is None:
        return err("bad_request", "请求格式错误")
    old, old_kind = _credential(data, "old_")
    new, new_kind = _credential(data, "new_")
    if old is None or new is None:
        return err("bad_request", "密码格式不正确")
    if old_kind == "auth_hash_bad" or new_kind == "auth_hash_bad":
        return err("bad_request", "auth_hash 必须是 64 位十六进制")
    if new_kind == "password" and len(new) < 6:
        return err("bad_request", "新密码至少 6 位")
    user = request.phix_user
    kmat = UserKeyMaterial.objects.get(user=user)
    # v2 账号 + 口令原文 = 客户端漏发 auth_hash → 拦下（否则会静默写坏凭证）
    if old_kind == "password":
        e = _credential_guard(user, old_kind, "old_auth_hash", can_migrate=True)[0]
        if e:
            return err(e[0], e[1])
    if new_kind == "password":
        e = _credential_guard(user, new_kind, "new_auth_hash",
                              can_migrate=True)[0]
        if e:
            return err(e[0], e[1])
    if not user.check_password(old):
        return err("unauthorized", "原密码不对", 401)
    # 只改登录密码时**可以不带** key_wrap：syncphrase 模式下 DEK 由独立同步口令包裹，
    # 与登录密码无关，不能顺手把它换成"用新登录密码包裹"。
    kmat_err = _key_material_error(data, require_recovery=False, require_wrap=False)
    if kmat_err:
        return err("bad_request", kmat_err)
    if not _dek_proof_ok(data, kmat):
        return err("bad_request", "DEK 校验失败（口令对不上，或客户端没解自检块）")

    with transaction.atomic():
        user.set_password(new)
        user.save(update_fields=["password"])
        _apply_key_material(kmat, data, bump_version=True)
    # 换了密码 → 其它设备的令牌保留（它们是独立的会话），但记录一条日志
    log.info("换密码 user_id=%s key_version=%s", user.id, kmat.key_version)
    return ok({
        "key_version": kmat.key_version,
        "kdf_salt": kmat.kdf_salt,
        "key_wrap": kmat.key_wrap,
        "key_check": kmat.key_check,
        "key_mode": kmat.key_mode,
        "kdf_algo": kmat.kdf_algo,
    })


@require_POST
@require_token
def rewrap(request):
    """只重新包裹 DEK（切 password/syncphrase 模式、或改同步口令）。"""
    data = json_body(request)
    if data is None:
        return err("bad_request", "请求格式错误")
    password, kind = _credential(data)
    if password is None:
        return err("bad_request", "需要当前登录密码")
    if kind == "auth_hash_bad":
        return err("bad_request", "auth_hash 必须是 64 位十六进制")
    user = request.phix_user
    if kind == "password":
        e = _credential_guard(user, kind, "auth_hash", can_migrate=True)[0]
        if e:
            return err(e[0], e[1])
    if not user.check_password(password):
        return err("unauthorized", "密码不对", 401)
    kmat_err = _key_material_error(data, require_recovery=False)
    if kmat_err:
        return err("bad_request", kmat_err)
    kmat = UserKeyMaterial.objects.get(user=user)
    if not _dek_proof_ok(data, kmat):
        return err("bad_request", "DEK 校验失败（口令对不上）")

    _apply_key_material(kmat, data, bump_version=True)
    log.info("重新包裹 DEK user_id=%s mode=%s key_version=%s",
             user.id, kmat.key_mode, kmat.key_version)
    return ok({k: v for k, v in kmat.as_public_dict().items()})


# ---------------- 忘记密码：取公开密钥材料 ----------------

def _fake_key_material(username, ):
    """给**不存在的账号**造一份形状一致的假材料，防止拿这个接口枚举账号。

    内容由服务端 SECRET_KEY 派生，对同一用户名稳定（不会一会一个样），
    但没有任何一份是真的。
    """
    import base64
    import hashlib

    from django.conf import settings as _s

    key = (_s.SECRET_KEY or "phix").encode()

    def blob(seed, n):
        out = b""
        i = 0
        while len(out) < n:
            out += hmac.new(key, f"{username}|{seed}|{i}".encode(),
                            hashlib.sha256).digest()
            i += 1
        return out[:n]

    def b64(raw):
        return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")

    return {
        "kdf_algo": KDF_ALGOS[0],
        "kdf_salt": blob("salt", 16).hex(),
        "auth_salt": blob("asalt", 16).hex(),
        "recovery_salt": blob("rsalt", 16).hex(),
        "key_wrap": f"{ENVELOPE_PREFIX}{b64(blob('wn', 12))}.{b64(blob('wc', 48))}",
        "recovery_wrap": f"{ENVELOPE_PREFIX}{b64(blob('rn', 12))}.{b64(blob('rc', 48))}",
        "key_check": f"{ENVELOPE_PREFIX}{b64(blob('kn', 12))}.{b64(blob('kc', 32))}",
        "key_mode": "password",
        "key_version": 1,
    }


@require_POST
def key_material(request):
    """取某个账号的**公开**密钥材料（只在"忘记密码、用恢复码重设"时用）。

    返回的全是密文或公开盐：没有口令/恢复码谁也解不开。
    账号不存在时返回**形状一致的假材料**，所以拿它枚举账号没有意义。
    """
    if limiter.hit(f"km:{client_ip(request)}",
                   limit=getattr(settings, "PHIX_KEYMATERIAL_LIMIT", 60),
                   window_seconds=3600):
        return err("rate_limited", "请求太频繁了，请稍后再试", 429)
    data = json_body(request)
    if data is None:
        return err("bad_request", "请求格式错误")
    username = data.get("username")
    if not isinstance(username, str) or not username.strip():
        return err("bad_request", "请填账号")
    username = username.strip()

    User = get_user_model()
    user = User.objects.filter(username=username).first()
    kmat = UserKeyMaterial.objects.filter(user=user).first() if user else None
    out = kmat.as_public_dict() if kmat is not None else _fake_key_material(username)
    out["username"] = username
    return ok(out)


@require_POST
def recover(request):
    """用恢复码重设密码。必须证明持有 DEK（否则等于任何人可重置别人的密码）。"""
    if limiter.hit(f"recover:{client_ip(request)}",
                   limit=getattr(settings, "PHIX_RECOVER_LIMIT", 8),
                   window_seconds=3600):
        return err("rate_limited", "尝试太频繁了，请稍后再试", 429)
    data = json_body(request)
    if data is None:
        return err("bad_request", "请求格式错误")
    username = data.get("username")
    new, new_kind = _credential(data, "new_")
    if not isinstance(username, str) or new is None:
        return err("bad_request", "账号和密码格式不正确")
    if new_kind == "auth_hash_bad":
        return err("bad_request", "auth_hash 必须是 64 位十六进制")
    if new_kind == "password" and len(new) < 6:
        return err("bad_request", "新密码至少 6 位")
    kmat_err = _key_material_error(data, require_recovery=False)
    if kmat_err:
        return err("bad_request", kmat_err)

    User = get_user_model()
    user = User.objects.filter(username=username.strip()).first()
    if user is None:
        # 不暴露账号是否存在
        return err("unauthorized", "恢复码不对（DEK 校验失败）", 401)
    kmat = UserKeyMaterial.objects.get(user=user)
    if not _dek_proof_ok(data, kmat):
        return err("unauthorized", "恢复码不对（DEK 校验失败）", 401)

    # v2 账号却收到口令原文：唯一需要拦的一次，因为它会把凭证写坏。
    # v2 账号的登录凭证是 AuthHash，而 AuthHash 由**登录口令**派生，
    # 服务端没有口令、也绝不接触口令 —— 所以服务端**无法**替用户重算。
    # 这里只能硬拒（让客户端的报错自己浮出来），放过去才是真事故。
    e = _credential_guard(user, new_kind, "new_auth_hash",
                          allow_plaintext=False)[0]
    if e:
        return err(e[0], e[1])

    with transaction.atomic():
        user.set_password(new)
        user.save(update_fields=["password"])
        kmat = UserKeyMaterial.objects.get(user=user)
        _apply_key_material(kmat, data, bump_version=True)
    log.warning("恢复码重置密码 user_id=%s username=%s", user.id, user.username)
    return ok({k: v for k, v in kmat.as_public_dict().items()})


# ---------------- 设备 / 会话管理 ----------------

@require_GET
@require_token
def devices(request):
    """列出本账号的**会话**（P3 之后的正式形态）与**老式令牌**（兼容期）。

    - `sessions`：一次登录 = 一个会话。注销某个会话 → 它的访问令牌**立刻**失效。
    - `devices`：老式长期令牌。P3 之后新登录基本不再产生，列出来只是为了
      让界面能显示并吊销历史设备。
    """
    cur_sid = getattr(getattr(request, "phix_session", None), "id", None)
    cur_tok = getattr(getattr(request, "phix_token", None), "id", None)
    legacy_by_device = {}
    for t in DeviceToken.objects.filter(user=request.phix_user):
        legacy_by_device.setdefault(t.device, []).append(t.id)
    sessions = [
        s.as_dict(current_sid=cur_sid,
                  legacy=legacy_by_device.get(s.device, [None])[0] if s.device else None)
        for s in TokenSession.objects.filter(user=request.phix_user)
    ]
    return ok({
        "sessions": sessions,
        "devices": [
            {
                "id": t.id,
                "name": t.device,
                "created_at": iso(t.created_at),
                "last_used_at": iso(t.last_used_at),
                "revoked": not t.alive,
                "current": t.id == cur_tok,
            }
            for t in DeviceToken.objects.filter(user=request.phix_user)
        ],
        "access_ttl": int(getattr(settings, "PHIX_JWT_ACCESS_TTL", 900)),
        "refresh_ttl": int(getattr(settings, "PHIX_REFRESH_TTL", 30 * 24 * 3600)),
    })


@require_POST
@require_token
def revoke_devices(request):
    """注销会话 / 老式令牌。

    参数（可组合）：
    - `session_id`            注销某一个会话
    - `all_except_current`    注销除当前会话以外的全部会话
    - `token_id`              注销某一个老式令牌
    - `all_tokens`            注销全部老式令牌
    """
    data = json_body(request)
    if data is None:
        return err("bad_request", "请求格式错误")
    user = request.phix_user
    cur_sid = getattr(getattr(request, "phix_session", None), "id", None)
    cur_tok = getattr(getattr(request, "phix_token", None), "id", None)

    s_qs = TokenSession.objects.filter(user=user, revoked_at__isnull=True)
    t_qs = DeviceToken.objects.filter(user=user, revoked_at__isnull=True)
    touched = False
    n_sess = n_tok = 0

    if data.get("all_except_current") is True:
        touched = True
        if cur_sid:
            s_qs = s_qs.exclude(id=cur_sid)
        # **当前会话名下的老式令牌也要排除**，否则老客户端（把长期 `token`
        # 当唯一凭据）点一下"注销其它设备"就把**自己**踢下线了。
        # 这种事真的被踩到过（PLL 接入 P3 时实测：返回 revoked:3/tokens:2，
        # 本机那串立刻 401）。JWT 认证时 `request.phix_token` 是 None，
        # 所以这里必须按会话自己去查它名下的老式令牌。
        keep_ids = set()
        if cur_tok:
            keep_ids.add(cur_tok)
        sess_for_legacy = getattr(request, "phix_session", None)
        if sess_for_legacy is not None:
            keep_ids |= {t.id for t in _legacy_of_session(sess_for_legacy)}
        if keep_ids:
            t_qs = t_qs.exclude(id__in=keep_ids)
        n_sess = s_qs.update(revoked_at=timezone.now(), revoked_reason="all")
        n_tok = t_qs.update(revoked_at=timezone.now())
    else:
        if data.get("session_id") is not None:
            touched = True
            n_sess = s_qs.filter(id=data["session_id"]).update(
                revoked_at=timezone.now(), revoked_reason="manual")
            if not n_sess:
                return err("not_found", "没有这个会话", 404)
        if data.get("token_id") is not None:
            touched = True
            n_tok = t_qs.filter(id=data["token_id"]).update(revoked_at=timezone.now())
            if not n_tok:
                return err("not_found", "没有这个设备令牌", 404)
        if data.get("all_tokens") is True:
            touched = True
            n_tok = t_qs.update(revoked_at=timezone.now())
    if not touched:
        return err("bad_request", "需要 session_id / token_id / all_except_current / all_tokens")
    log.info("注销设备 user_id=%s 会话=%s 老令牌=%s", user.id, n_sess, n_tok)
    return ok({"revoked": n_sess + n_tok, "sessions": n_sess, "tokens": n_tok})


# ---------------- 服务端到服务端：令牌公钥 / 自省 ----------------

@require_POST
def refresh(request):
    """`POST /auth/refresh`：用 refresh 令牌换新 access（并轮换 refresh）。**免认证**。

    请求：`{"refresh_token": "<40 字节 url-safe>"}`（也接受 `refresh` 字段名）
    响应：`{access_token, refresh_token, expires_in, expires_at, rotated, session_id}`

    规则（对应 `加密链路思路.md` §7）：
    - refresh 令牌**只能续期，不能调业务**（把它当 Bearer 发业务请求 → 401）。
    - **用一次换一次**：响应里的 `refresh_token` 必须被客户端保存下来。
    - 宽限期（默认 120 秒）内重复用上一个**不当作攻击**（并发续期很正常），
      但**不重发**新的那个 —— 响应里 `rotated:false` 且没有 `refresh_token`。
    - 超出宽限期再用旧的 = 真的重放 → **撤销整个会话**，必须重新登录。
    """
    return _rotate_access(request)


@require_GET
def jwks(request):
    """签名公钥（JWKS）。**免认证、免服务密钥** —— 公钥本来就是公开的。

    有了它，别的服务（第 1 台那类业务机、心履）可以**自己本地验签**，
    不必每次回连认证中心，也不必共享任何密钥（对应设计文档 §7.1 方式 A）。
    """
    return ok({"issuer": tokens.ISSUER, "audience": tokens.AUDIENCE,
               "alg": tokens.ALG, "kid": tokens.kid(), **tokens.jwks()})


@require_POST
def introspect(request):
    """令牌自省（RFC 7662 风格）：把令牌交回来问"它还有效吗、属于谁"。

    给**没有本地验签能力**的服务用（对应设计文档 §7.1 方式 B：内网问认证中心）。
    需要 `X-Phix-Service-Key`。
    """
    if not service_key_ok(request):
        return err("forbidden", "服务密钥无效", 403)
    if limiter.hit(f"introspect:{client_ip(request)}", limit=600, window_seconds=60):
        return err("rate_limited", "调用太频繁", 429)
    data = json_body(request)
    if data is None:
        return err("bad_request", "请求格式错误")
    raw = data.get("token") or ""
    if not isinstance(raw, str) or not raw:
        return err("bad_request", "缺少 token")

    # 老式长期令牌也算"有效"，否则兼容期里两个服务之间对不上
    legacy = DeviceToken.objects.select_related("user").filter(
        key=raw, revoked_at__isnull=True).first()
    if legacy is not None:
        return ok({
            "active": True, "kind": "legacy", "sub": str(legacy.user_id),
            "username": legacy.user.username, "sid": None,
            "device": legacy.device, "jkt": "", "exp": None,
        })

    from .utils import resolve_jwt

    # 令牌可以放在请求体里交回来（RFC 7662 的做法），也可以按老习惯放在
    # `Authorization` 头里。**优先用请求体那个** —— 自省的意义就是"把令牌亮出来问"，
    # 不该因为没带 Bearer 头就答"看不出这是什么"。
    raw_hdr = (request.META.get("HTTP_AUTHORIZATION") or "")
    request.META["HTTP_AUTHORIZATION"] = "Bearer " + raw
    sess, why = resolve_jwt(request)
    if sess is None:
        log.info("introspect 未通过：原因=%s", why)
        # 恢复原来的头，别让这次调用留下副作用
        request.META["HTTP_AUTHORIZATION"] = raw_hdr
    if sess is not None and why:
        return ok({
            "active": True, "kind": "jwt", "sub": why.get("sub"),
            "username": sess.user.username, "sid": sess.id,
            "device": sess.device, "jkt": sess.jkt,
            "exp": why.get("exp"), "jti": why.get("jti"),
            "revoked_reason": None,
        })
    return ok({"active": False, "reason": why if isinstance(why, str) else "unknown"})


# ---------------- 服务端到服务端：校验凭据 ----------------

@require_POST
def verify(request):
    """供心履等**服务端**校验 phix 账号密码。需要 X-Phix-Service-Key。

    只返回「对不对」和最基本身份，**绝不返回任何密钥材料**。
    """
    if not service_key_ok(request):
        return err("forbidden", "服务密钥无效", 403)
    if limiter.hit(f"verify:{client_ip(request)}", limit=120, window_seconds=60):
        return err("rate_limited", "调用太频繁", 429)
    data = json_body(request)
    if data is None:
        return err("bad_request", "请求格式错误")
    username = data.get("username")
    credential, kind = _credential(data)
    if not isinstance(username, str) or credential is None:
        return err("bad_request", "账号和密码格式不正确")
    if kind == "auth_hash_bad":
        return err("bad_request", "auth_hash 必须是 64 位十六进制")
    user = authenticate(request, username=username.strip(), password=credential)
    if user is None or not user.is_active:
        return err("bad_credentials", "账号或密码不对", 401)
    return ok({"user_id": user.id, "username": user.username,
               "is_active": True, "date_joined": iso(user.date_joined)})


# ---------------- 连通性 ----------------

@require_GET
def ping(request):
    from . import e2e

    enc = bool(getattr(settings, "PHIX_E2E_ENABLED", True))
    return ok({
        "version": 1,
        "server_time": timezone.now().isoformat(),
        "service": "phix",
        "kdf_algos": list(KDF_ALGOS),
        "key_modes": list(VALID_KEY_MODES),
        # 应用层加密（对应 加密链路思路.md §3）：
        # enc=1 表示支持 X-Phix-Enc 信封；pk 是服务器 X25519 公钥。
        # 客户端应当**首次信任后固定存下来**，以后对不上就拒绝连接 —— 防止公钥被替换。
        "enc": 1 if enc else 0,
        "pk": e2e.server_public_b64() if enc else "",
        "limits": {
            "max_payload_bytes": settings.PHIX_MAX_PAYLOAD_BYTES,
            "max_objects": settings.PHIX_MAX_OBJECTS,
            "max_total_bytes": settings.PHIX_MAX_TOTAL_BYTES,
            "max_batch": settings.PHIX_MAX_BATCH,
        },
        "service_verify_enabled": bool(getattr(settings, "PHIX_SERVICE_KEY", "")),
        # P3 令牌体系（对应 加密链路思路.md §7）：
        #   jwt=1          访问令牌是 Ed25519 签名的 JWT
        #   alg/kid       签名算法与密钥指纹（换钥匙时 kid 会变，客户端可据此察觉）
        #   access_ttl    访问令牌寿命（秒）
        #   refresh=1      支持 POST /auth/refresh 轮换续期
        #   jwks          取签名公钥的地址（别的服务可本地验签）
        #   dpop=1         支持 DPoP（令牌与客户端密钥绑定）
        #   legacy_tokens  还接受老式长期令牌（兼容期）
        "auth": {
            "jwt": 1,
            "alg": tokens.ALG,
            "kid": tokens.kid(),
            "access_ttl": int(getattr(settings, "PHIX_JWT_ACCESS_TTL", 900)),
            "refresh": 1,
            "refresh_ttl": int(getattr(settings, "PHIX_REFRESH_TTL", 30 * 24 * 3600)),
            "refresh_grace": int(getattr(settings, "PHIX_REFRESH_GRACE", 120)),
            "leeway": int(getattr(settings, "PHIX_JWT_LEEWAY", 60)),
            "iat_leeway": int(getattr(settings, "PHIX_JWT_IAT_LEEWAY", 300)),
            "jwks": "/api/v1/auth/jwks",
            "introspect": "/api/v1/auth/introspect",
            "dpop": 1,
            "legacy_tokens": 1 if legacy_tokens_enabled() else 0,
        },
    })


# ---------------- 管理端点（服务密钥保护） ----------------

@require_GET
def admin_users(request):
    """GET /api/v1/admin/users —— 列出所有用户（仅服务密钥）。"""
    if not service_key_ok(request):
        return err("forbidden", "服务密钥无效", 403)
    User = get_user_model()
    users = []
    for u in User.objects.order_by("id"):
        users.append({
            "id": u.id,
            "username": u.username,
            "is_staff": bool(u.is_staff),
            "is_superuser": bool(u.is_superuser),
            "is_active": bool(u.is_active),
            "date_joined": iso(u.date_joined),
        })
    return ok({"users": users})


@require_POST
def admin_user_flags(request, user_id):
    """POST /api/v1/admin/user/<id>/flags —— 设置 is_staff / is_superuser / is_active。

    body: {"is_staff": bool?, "is_superuser": bool?, "is_active": bool?}
    只允许改这三个字段；其它字段一律忽略。
    需要 X-Phix-Service-Key。
    """
    if not service_key_ok(request):
        return err("forbidden", "服务密钥无效", 403)
    data = json_body(request)
    if data is None:
        return err("bad_request", "请求格式错误")
    User = get_user_model()
    try:
        target = User.objects.get(id=int(user_id))
    except (User.DoesNotExist, ValueError, TypeError):
        return err("not_found", "用户不存在", 404)
    changed = []
    if "is_staff" in data:
        val = bool(data["is_staff"])
        if target.is_staff != val:
            target.is_staff = val
            changed.append(f"is_staff={val}")
    if "is_superuser" in data:
        val = bool(data["is_superuser"])
        if target.is_superuser != val:
            target.is_superuser = val
            changed.append(f"is_superuser={val}")
    if "is_active" in data:
        val = bool(data["is_active"])
        if target.is_active != val:
            target.is_active = val
            changed.append(f"is_active={val}")
    if changed:
        target.save(update_fields=["is_staff", "is_superuser", "is_active"])
        log.info("admin_flags user_id=%s %s", target.id, " ".join(changed))
    return ok({
        "user_id": target.id,
        "username": target.username,
        "is_staff": bool(target.is_staff),
        "is_superuser": bool(target.is_superuser),
        "is_active": bool(target.is_active),
    })
