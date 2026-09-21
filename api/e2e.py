"""应用层加密传输（对应 `加密链路思路.md` §3：**用应用层加密替代 HTTPS**）。

## 为什么要有这一层

没有 HTTPS 时，明文 HTTP 上的**登录口令是裸奔的**。这一层让客户端与服务器之间的
**每一个请求体和响应体都是密文**，网线上抓到的只有密文 —— 即使不接 TLS 也安全。

## 协议（与 `phix-协议规范.md` §10 一致）

```
密封盒 seal_box(msg, recipient_pk)：
    esk, epk = X25519 随机密钥对
    shared   = X25519(esk, recipient_pk)
    key      = HKDF-SHA256(ikm=shared, salt=epk||recipient_pk, info="phix/v1/seal", 32)
    nonce    = 12 字节随机
    ct       = AES-256-GCM(key, nonce, msg, aad=epk||recipient_pk)
    输出      = epk(32) || nonce(12) || ct

请求：头 X-Phix-Enc: 1，体 {"sealed_sk","iv","ct"}
      SK     = open_box(sealed_sk, 服务器私钥, 服务器公钥)   # 32 字节会话密钥
      明文    = {"m":方法,"p":路径,"q":查询串,"b":请求体,"ts":unix秒,"nonce":b64url}
      AAD    = "phix/v1/req|" + 方法 + "|" + 路径

响应：头 X-Phix-Enc: 1，体 {"iv","ct"}
      明文 = 原样 JSON 响应体，AAD 与请求相同
```

**抗重放**：`|now - ts| <= 300` 秒 + `nonce` 5 分钟 LRU（都在密文里，外面改不了）。

## 兼容

**没有 `X-Phix-Enc` 头就完全走原来的明文路径** —— 老客户端、curl 调试、心履的服务间调用
都不受影响。客户端可以从 `/ping` 拿到 `pk` 与 `enc` 字段判断服务器支不支持。
"""
from __future__ import annotations

import base64
import os
import secrets
import threading
import time
from pathlib import Path

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric.x25519 import (X25519PrivateKey,
                                                              X25519PublicKey)
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

SEAL_INFO = b"phix/v1/seal"
AAD_PREFIX = b"phix/v1/req|"
EPK_LEN = 32
NONCE_LEN = 12
SK_LEN = 32
TS_SKEW = 300          # 秒
NONCE_TTL = 300        # 秒
HEADER = "HTTP_X_PHIX_ENC"
CLIENT_HEADER = "X-Phix-Enc"


# ---------------- 编解码 ----------------

def b64e(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def b64d(text: str) -> bytes:
    if not isinstance(text, str):
        raise ValueError("需要 base64url 字符串")
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


# ---------------- 密封盒 ----------------

def seal_box(msg: bytes, recipient_pk: bytes) -> bytes:
    """把一段消息密封给某个 X25519 公钥的持有者。"""
    esk = X25519PrivateKey.generate()
    epk = esk.public_key().public_bytes(serialization.Encoding.Raw,
                                        serialization.PublicFormat.Raw)
    shared = esk.exchange(X25519PublicKey.from_public_bytes(recipient_pk))
    salt = epk + recipient_pk
    key = HKDF(algorithm=hashes.SHA256(), length=32, salt=salt,
               info=SEAL_INFO).derive(shared)
    nonce = os.urandom(NONCE_LEN)
    ct = AESGCM(key).encrypt(nonce, msg, salt)
    return epk + nonce + ct


def open_box(sealed: bytes, recipient_sk: X25519PrivateKey,
             recipient_pk: bytes) -> bytes:
    """打开给自己的密封盒。"""
    if len(sealed) < EPK_LEN + NONCE_LEN + 16:
        raise ValueError("密封盒长度不对")
    epk = sealed[:EPK_LEN]
    nonce = sealed[EPK_LEN:EPK_LEN + NONCE_LEN]
    ct = sealed[EPK_LEN + NONCE_LEN:]
    shared = recipient_sk.exchange(X25519PublicKey.from_public_bytes(epk))
    salt = epk + recipient_pk
    key = HKDF(algorithm=hashes.SHA256(), length=32, salt=salt,
               info=SEAL_INFO).derive(shared)
    return AESGCM(key).decrypt(nonce, ct, salt)


# ---------------- 服务器长期密钥 ----------------

_LOCK = threading.Lock()
_CACHE: dict = {}


def _key_path() -> Path:
    from django.conf import settings

    return Path(getattr(settings, "PHIX_E2E_KEY_FILE",
                        Path(settings.BASE_DIR) / "e2e_key.txt"))


def server_key():
    """加载/生成服务器 X25519 密钥对（进程内缓存）。

    **私钥只在本机**（文件权限 600），**绝不入库、绝不外发**。
    """
    with _LOCK:
        if _CACHE.get("sk") is not None:
            return _CACHE["sk"], _CACHE["pk"]
        path = _key_path()
        raw = None
        if path.exists():
            try:
                raw = bytes.fromhex(path.read_text(encoding="utf-8").strip())
            except (ValueError, OSError):
                raw = None
        if raw is None or len(raw) != 32:
            sk = X25519PrivateKey.generate()
            raw = sk.private_bytes(serialization.Encoding.Raw,
                                   serialization.PrivateFormat.Raw,
                                   serialization.NoEncryption())
            try:
                path.write_text(raw.hex() + "\n", encoding="utf-8")
                os.chmod(path, 0o600)
            except OSError:
                pass
        else:
            sk = X25519PrivateKey.from_private_bytes(raw)
        pk = sk.public_key().public_bytes(serialization.Encoding.Raw,
                                          serialization.PublicFormat.Raw)
        _CACHE["sk"], _CACHE["pk"] = sk, pk
        return sk, pk


def server_public_b64() -> str:
    return b64e(server_key()[1])


# ---------------- 抗重放 ----------------

_seen: dict[str, float] = {}
_seen_lock = threading.Lock()


def _gc(now: float) -> None:
    for k in [k for k, t in _seen.items() if now - t > NONCE_TTL]:
        _seen.pop(k, None)


def check_freshness(ts, nonce: str, now: float | None = None) -> str | None:
    """返回错误信息或 None。ts/nonce 都在密文里，外面篡改不了。"""
    now = now if now is not None else time.time()
    try:
        ts = float(ts)
    except (TypeError, ValueError):
        return "时间戳不合法"
    if abs(now - ts) > TS_SKEW:
        return f"请求过期（允许 ±{TS_SKEW} 秒，请检查本机时钟）"
    if not isinstance(nonce, str) or not (8 <= len(nonce) <= 64):
        return "nonce 不合法"
    with _seen_lock:
        _gc(now)
        if nonce in _seen:
            return "重复请求（nonce 已用过）"
        _seen[nonce] = now
    return None


def reset_replay_cache() -> None:
    """测试用：清空 nonce 缓存。"""
    with _seen_lock:
        _seen.clear()


# ---------------- 信封收发 ----------------

def aad_for(method: str, path: str) -> bytes:
    return AAD_PREFIX + method.encode("utf-8") + b"|" + path.encode("utf-8")


def open_request(method: str, path: str, envelope: dict):
    """解开请求信封。返回 (inner_dict, SK)；失败抛 ValueError。"""
    sk_obj, pk = server_key()
    try:
        sealed = b64d(envelope["sealed_sk"])
        iv = b64d(envelope["iv"])
        ct = b64d(envelope["ct"])
    except (KeyError, TypeError, ValueError) as exc:
        raise ValueError("信封字段缺失或格式不对") from exc
    try:
        sk = open_box(sealed, sk_obj, pk)
    except Exception as exc:  # noqa: BLE001  解不开 = 不是给我们的
        raise ValueError("信封打不开（服务器密钥不匹配）") from exc
    if len(sk) != SK_LEN:
        raise ValueError("会话密钥长度不对")
    try:
        inner = AESGCM(sk).decrypt(iv, ct, aad_for(method, path))
    except Exception as exc:  # noqa: BLE001
        raise ValueError("信封解密失败（内容被改过或路径不匹配）") from exc
    import json

    try:
        doc = json.loads(inner.decode("utf-8"))
    except (ValueError, UnicodeDecodeError) as exc:
        raise ValueError("信封里的内容不是 JSON") from exc
    if not isinstance(doc, dict):
        raise ValueError("信封里的内容必须是对象")
    return doc, sk


def seal_response(sk: bytes, method: str, path: str, body: bytes) -> dict:
    iv = os.urandom(NONCE_LEN)
    ct = AESGCM(sk).encrypt(iv, body, aad_for(method, path))
    return {"iv": b64e(iv), "ct": b64e(ct)}


def new_session_key() -> bytes:
    return secrets.token_bytes(SK_LEN)
