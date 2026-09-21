"""Ed25519 签名的 JWT（对应 `加密链路思路.md` §7：Token 体系）。

## 为什么要换掉"长期不透明令牌"

原来发的是 40 位 hex 的长期令牌：**偷到就能一直用**，服务端只能靠查库才知道它还有效。
换成设计文档里的方案后：

| 性质 | 长期不透明令牌 | JWT（本文件） |
|---|---|---|
| 有效期 | 无限（除非手动吊销） | **15 分钟**（`exp` 在签名里，改不了） |
| 验证方式 | 每次都要查库 | **本地验签**即可（第 1 台那类服务不用回连认证中心） |
| 撤销 | 删记录 | 会话表 + `jti` 黑名单，**实时生效** |
| 续期 | 不需要 | refresh 令牌 **30 天**，**用一次换一次**，重放即撤销整个会话 |
| 被偷走 | 一直能用 | 15 分钟后自动作废；开了 DPoP 则**离了客户端私钥根本用不了** |

## 密钥

服务器启动时生成/加载 **Ed25519** 密钥对（`jwt_key.txt`，权限 600，**绝不入库、绝不下发私钥**）。
公钥通过 `GET /auth/jwks` 对外发布（JWKS 格式），这样"验签方"（心履、将来的其它服务）
**不需要共享密钥**，也不需要回连认证中心。

> 与 `e2e_key.txt` 是两个不同的钥匙：那把负责**保密**（X25519，网线上的密文），
> 这把负责**签名**（Ed25519，令牌的真伪）。一把泄露不牵连另一把。

## 令牌长什么样

```
header  = {"alg":"EdDSA","typ":"JWT","kid":"<公钥指纹前16位>", 可选 "jkt":"<DPoP公钥指纹>"}
payload = {"iss":"phix","aud":"phix","sub":"<user_id>","sid":"<会话id>",
           "iat":…, "exp":…, "jti":"<随机>", "typ":"access", "device":"…"}
签名     = Ed25519(header.payload)
```

- `sub` 用 **user_id**（不是用户名）：用户名能改，id 不能。
- `aud` 固定 `phix`，防止把令牌拿去别的服务用。
- 时钟：验签允许 ±`PHIX_JWT_LEEWAY` 秒（默认 60），给两台机器的时钟留余量。
"""
from __future__ import annotations

import base64
import hashlib
import json
import os
import secrets
import threading
import time
from pathlib import Path

import jwt as pyjwt
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey, Ed25519PublicKey)

ALG = "EdDSA"
ISSUER = "phix"
AUDIENCE = "phix"
ACCESS_TYP = "access"

_LOCK = threading.Lock()
_CACHE: dict = {}


# ---------------- 编解码 ----------------

def b64e(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def b64d(text: str) -> bytes:
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


# ---------------- 签名密钥 ----------------

def _key_path() -> Path:
    from django.conf import settings

    return Path(getattr(settings, "PHIX_JWT_KEY_FILE",
                        Path(settings.BASE_DIR) / "jwt_key.txt"))


def _load_or_create() -> tuple[Ed25519PrivateKey, Ed25519PublicKey]:
    """加载/生成签名密钥。私钥只在本机、权限 600。"""
    path = _key_path()
    if path.exists():
        raw = path.read_bytes()
        sk = Ed25519PrivateKey.from_private_bytes(raw)
        return sk, sk.public_key()
    sk = Ed25519PrivateKey.generate()
    raw = sk.private_bytes(encoding=serialization.Encoding.Raw,
                           format=serialization.PrivateFormat.Raw,
                           encryption_algorithm=serialization.NoEncryption())
    path.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(str(path), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    try:
        os.write(fd, raw)
    finally:
        os.close(fd)
    try:
        os.chmod(str(path), 0o600)      # Windows 上基本是空操作，不影响
    except OSError:
        pass
    return sk, sk.public_key()


def keys() -> tuple[Ed25519PrivateKey, Ed25519PublicKey]:
    """进程内缓存的一对签名密钥。"""
    with _LOCK:
        if "sk" not in _CACHE:
            _CACHE["sk"], _CACHE["pk"] = _load_or_create()
        return _CACHE["sk"], _CACHE["pk"]


def public_raw() -> bytes:
    return keys()[1].public_bytes(encoding=serialization.Encoding.Raw,
                                  format=serialization.PublicFormat.Raw)


def public_b64() -> str:
    return b64e(public_raw())


def kid() -> str:
    """密钥指纹（前 16 位 hex）：客户端据此判断"服务器换钥匙了没有"。"""
    return hashlib.sha256(public_raw()).hexdigest()[:16]


def jwks() -> dict:
    """JWKS：让别的服务**只拿公钥**就能验签，不用回连、也不用共享密钥。"""
    return {
        "keys": [{
            "kty": "OKP", "crv": "Ed25519", "alg": ALG, "use": "sig",
            "kid": kid(), "x": public_b64(),
        }]
    }


# ---------------- 签发 / 验签 ----------------

def _now() -> int:
    return int(time.time())


def _ttl_access() -> int:
    from django.conf import settings

    return int(getattr(settings, "PHIX_JWT_ACCESS_TTL", 900))


def _leeway() -> int:
    from django.conf import settings

    return int(getattr(settings, "PHIX_JWT_LEEWAY", 60))


def _iat_leeway() -> int:
    """`iat` 的**宽松**容差（默认 300 秒）。

    为什么比 `exp` 的 leeway 宽：`iat` 只用来挡"太老的令牌"（重放）。
    如果两台机器的时钟没对准，**任何** JWT 的 `iat` 都会跑到"未来"去，
    于是**所有令牌一律被拒** —— 线上就发生过：
    远端 `.41` 的时钟比本机慢近 2 分钟，导致 DPoP 证明全部回
    `The token is not yet valid (iat)`，而本地一切正常。
    真要防重放，靠的是短 `exp` + DPoP 的 `jti` 窗口，不是掐着 `iat` 不让过。
    """
    from django.conf import settings

    return int(getattr(settings, "PHIX_JWT_IAT_LEEWAY", 300))


def sign_access(user_id: int, sid: int, device: str = "", ttl: int | None = None,
                jkt: str = "") -> tuple[str, dict]:
    """签一个访问令牌。返回 (JWT, 载荷)。"""
    sk, _pk = keys()
    iat = _now()
    exp = iat + int(ttl if ttl is not None else _ttl_access())
    payload = {
        "iss": ISSUER, "aud": AUDIENCE, "sub": str(user_id), "sid": int(sid),
        "iat": iat, "exp": exp, "jti": secrets.token_urlsafe(16),
        "typ": ACCESS_TYP, "device": (device or "")[:100],
        "kid": kid(),
    }
    headers = {"kid": kid()}
    if jkt:
        # DPoP：令牌与客户端公钥绑定（偷了令牌没私钥也用不了）
        headers["jkt"] = jkt
    token = pyjwt.encode(payload, sk, algorithm=ALG, headers=headers)
    if isinstance(token, bytes):
        token = token.decode("ascii")
    return token, payload


def verify_access(token: str, verify_exp: bool = True) -> dict:
    """验签并返回载荷。**失败一律抛 `TokenError`**（子类见下）。"""
    _sk, pk = keys()
    try:
        return pyjwt.decode(
            token, pk, algorithms=[ALG], audience=AUDIENCE, issuer=ISSUER,
            leeway=_leeway(),
            options={"require": ["exp", "iat", "sub", "jti", "sid"],
                     # `iat` **不**交给 PyJWT 判"是不是未来"（它没有"未来容差"，
                     # 只有对称的 leeway）。我们自己按 `_iat_leeway()` 判，
                     # 免得两台机器时钟没对准就把所有令牌拒了。
                     "verify_exp": verify_exp, "verify_iat": False},
        )
    except pyjwt.ExpiredSignatureError as exc:
        raise TokenExpired("令牌已过期") from exc
    except pyjwt.InvalidTokenError as exc:
        raise TokenError(f"令牌无效：{exc}") from exc


def peek(token: str) -> dict:
    """**不验签**地读载荷（只用于判断代次、取 sid 这类无害用途）。"""
    try:
        return pyjwt.decode(token, options={"verify_signature": False})
    except Exception:  # noqa: BLE001
        return {}


def decode_unverified_header(token: str) -> dict:
    try:
        return pyjwt.get_unverified_header(token)
    except Exception:  # noqa: BLE001
        return {}


def looks_like_jwt(value: str) -> bool:
    """三段式且中间那段能 base64 解出 JSON。**只做形状判断，不验签。**"""
    if not isinstance(value, str) or value.count(".") != 2:
        return False
    head = value.split(".", 1)[0]
    try:
        obj = json.loads(b64d(head))
    except Exception:  # noqa: BLE001
        return False
    return isinstance(obj, dict) and obj.get("alg") == ALG


# ---------------- 客户端公钥指纹（DPoP） ----------------

def jwk_thumbprint(jwk: dict) -> str:
    """RFC 7638 JWK 指纹（这里只支持 OKP/Ed25519）。"""
    if not isinstance(jwk, dict) or jwk.get("kty") != "OKP":
        raise ValueError("只支持 OKP 公钥")
    if jwk.get("crv") != "Ed25519":
        raise ValueError("只支持 Ed25519")
    x = jwk.get("x") or ""
    b64d(x)                                   # 不合法就直接抛
    canon = json.dumps({"crv": "Ed25519", "kty": "OKP", "x": x},
                       separators=(",", ":"), sort_keys=True)
    return b64e(hashlib.sha256(canon.encode()).digest())


def verify_dpop(proof: str, method: str, path: str, access_token: str = "") -> str:
    """验证 DPoP 证明。**返回公钥指纹 jkt**；失败抛 `TokenError`。

    证明就是一个 JWT：`header={"alg":"EdDSA","typ":"dpop+jwk":{...}}`，
    载荷 `{htm, htu, iat, jti}`，用**客户端自己的私钥**签。

    校验点：typ 必须是 `dpop+jwk`；`htm`/`htu` 必须与本请求一致；
    `iat` 在允许窗口内；`jti` 不能重复（5 分钟 LRU）；
    若给了访问令牌，令牌头里的 `jkt` 必须与证明的公钥指纹一致。
    """
    try:
        header = pyjwt.get_unverified_header(proof)
    except Exception as exc:  # noqa: BLE001
        raise TokenError("DPoP 证明格式不对") from exc
    if header.get("typ") != "dpop+jwk" or header.get("alg") != ALG:
        raise TokenError("DPoP 证明的 typ/alg 不对")
    jwk = header.get("jwk")
    if not isinstance(jwk, dict):
        raise TokenError("DPoP 证明缺少 jwk")
    jkt = jwk_thumbprint(jwk)
    pk = Ed25519PublicKey.from_public_bytes(b64d(jwk["x"]))
    try:
        claims = pyjwt.decode(proof, pk, algorithms=[ALG],
                              options={"verify_aud": False, "verify_iss": False,
                                       # 见 `_iat_leeway()`：`iat` 的"未来"由我们
                                       # 自己按更宽的容差判，不用 PyJWT 的对称 leeway
                                       "verify_iat": False,
                                       "require": ["iat", "jti"]})
    except pyjwt.ExpiredSignatureError as exc:
        raise TokenExpired("DPoP 证明已过期") from exc
    except pyjwt.InvalidTokenError as exc:
        raise TokenError(f"DPoP 证明验签失败：{exc}") from exc

    if str(claims.get("htm", "")).upper() != method.upper():
        raise TokenError("DPoP 的 htm 与请求方法不一致")
    # htu 允许两种写法：完整 URL（RFC 9449 的写法）或纯路径。
    # 两种都只比路径部分 —— 客户端填的是它自己看到的那个 URL，别强求一致。
    want = "/" + str(path).lstrip("/").split("?", 1)[0].rstrip("/")
    got = str(claims.get("htu", "")).split("?", 1)[0].strip()
    if "://" in got:
        got = "/" + got.split("://", 1)[1].split("/", 1)[-1] if "/" in \
            got.split("://", 1)[1] else "/"
    got = "/" + got.lstrip("/").rstrip("/")
    if got != want:
        raise TokenError(f"DPoP 的 htu 与请求路径不一致（{got} ≠ {want}）")
    iat = int(claims.get("iat", 0))
    skew = _leeway()
    if abs(_now() - iat) > skew:
        raise TokenError("DPoP 的 iat 超出允许窗口")
    if _dpop_nonce_seen(jkt, str(claims.get("jti"))):
        raise TokenError("DPoP 的 jti 重复（重放）")
    if access_token:
        th = decode_unverified_header(access_token)
        if th.get("jkt") and th["jkt"] != jkt:
            raise TokenError("DPoP 证明与令牌绑定的不是同一把公钥")
    return jkt


_DPOP_SEEN: dict = {}
_DPOP_LOCK = threading.Lock()


def _dpop_nonce_seen(jkt: str, jti: str) -> bool:
    """DPoP 的 jti 5 分钟 LRU。重复返回 True。"""
    ttl = int(getattr(_settings(), "PHIX_DPOP_WINDOW", 300))
    now = _now()
    key = (jkt, jti)
    with _DPOP_LOCK:
        dead = [k for k, t in _DPOP_SEEN.items() if now - t > ttl]
        for k in dead:
            _DPOP_SEEN.pop(k, None)
        if key in _DPOP_SEEN:
            return True
        _DPOP_SEEN[key] = now
        return False


def _settings():
    from django.conf import settings

    return settings


class TokenError(Exception):
    """令牌类错误（验签失败 / 格式不对 / 重放）。"""


class TokenExpired(TokenError):
    """令牌过期（与"无效"分开，客户端据此决定"续期"还是"重新登录"）。"""
