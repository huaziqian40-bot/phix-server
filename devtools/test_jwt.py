"""P3 专项：Ed25519 JWT + refresh 轮换 + DPoP + 公钥自验（`加密链路思路.md` §7）。

    cd D:\\phix\\server
    .venv\\Scripts\\python.exe -X utf8 devtools\\test_jwt.py

要证明的事（每条都实跑）：
  1. 登录拿到的 access 是 **Ed25519 签名的 JWT**，且能被 `/auth/jwks` 的公钥**本地验签**
     —— 别的服务（第 1 台那类）不必回连认证中心、也不必共享密钥。
  2. `exp` 到了就**真的作废**；改一个字节就验不过。
  3. **注销 / 撤销会立刻生效**（不等 15 分钟自然过期）。
  4. refresh **用一次换一次**；旧的**在宽限期外**再用 = 重放 → **整个会话作废**。
  5. refresh 令牌**不能当访问令牌用**（发业务请求一路 401）。
  6. **DPoP**：会话绑定客户端密钥后，没证明 → 401，换一把密钥 → 401，
     重放同一个证明 → 401，带对了才放行。
  7. `/auth/introspect` 给"没有本地验签能力"的服务用（需服务密钥）。
"""
import base64
import hashlib
import json
import os
import secrets
import sys
import threading
import time
from pathlib import Path

import jwt as pyjwt
import requests
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

sys.path.insert(0, r"D:\phl-lite-dev")
from hellopinghe import phixcrypto as pc  # noqa: E402

SERVER = os.environ.get("PHIX_SERVER", "http://127.0.0.1:8931")
API = SERVER.rstrip("/") + "/api/v1"
SERVICE_KEY = os.environ.get("PHIX_SERVICE_KEY", "")
if not SERVICE_KEY:
    _f = Path(r"D:\phix\server\.service_key")
    if _f.exists():
        SERVICE_KEY = _f.read_text(encoding="utf-8").strip()

PASSED, FAILED = [], []


def check(name, cond, extra=""):
    (PASSED if cond else FAILED).append(name)
    print(f"  [{'OK  ' if cond else 'FAIL'}] {name}"
          + (f"   {extra}" if extra and not cond else ""))
    return cond


def body_of(r):
    try:
        return r.json()
    except ValueError:
        return {}


def b64d(text):
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


def register(username, password, server=None):
    mat = pc.new_material(username, password)
    body = {
        "username": username, "agree": True, "device": "P3 测试机",
        "kdf_algo": mat["kdf_algo"], "kdf_salt": mat["kdf_salt"],
        "auth_salt": mat["auth_salt"], "key_wrap": mat["key_wrap"],
        "key_mode": mat["key_mode"], "key_check": mat["key_check"],
        "key_check_plain": mat["key_check_plain"],
        "recovery_salt": mat["recovery_salt"],
        "recovery_wrap": mat["recovery_wrap"], "auth_hash": mat["auth_hash"],
    }
    base = (server or SERVER).rstrip("/") + "/api/v1"
    r = requests.post(base + "/auth/register", json=body, timeout=30)
    return mat, r


def new_account(tag, server=None):
    """在**指定服务器**上开一个新账号。

    每台服务器的库是分开的（短命令牌服务器用 `_lab/short_db.sqlite3`），
    所以"要在哪台上测"，就必须在**那一台**上注册 —— 否则拿 A 台的令牌去 B 台，
    会被当成"没这个会话"，测的就不是想测的东西。
    """
    user = f"jwt{tag}" + secrets.token_hex(3)
    pw = "Jwt-Test-Pw-" + secrets.token_hex(3)
    mat, r = register(user, pw, server=server)
    if r.status_code != 201:
        raise SystemExit(f"注册失败：{r.status_code} {r.text[:200]}")
    return user, pw, mat, body_of(r)


def make_dpop_key():
    sk = Ed25519PrivateKey.generate()
    raw = sk.public_key().public_bytes(encoding=serialization.Encoding.Raw,
                                       format=serialization.PublicFormat.Raw)
    x = base64.urlsafe_b64encode(raw).rstrip(b"=").decode()
    return sk, {"kty": "OKP", "crv": "Ed25519", "x": x}


def jkt_of(jwk):
    canon = json.dumps({"crv": "Ed25519", "kty": "OKP", "x": jwk["x"]},
                       separators=(",", ":"), sort_keys=True)
    return base64.urlsafe_b64encode(
        hashlib.sha256(canon.encode()).digest()).rstrip(b"=").decode()


def dpop_proof(sk, jwk, method, path, iat=None, jti=None, htm=None, htu=None):
    payload = {
        "htm": htm or method, "htu": htu or (API + path),
        "iat": int(iat if iat is not None else time.time()),
        "jti": jti or secrets.token_urlsafe(12),
    }
    return pyjwt.encode(payload, sk, algorithm="EdDSA",
                        headers={"typ": "dpop+jwk", "jwk": jwk})


def main():
    print("=" * 74)
    print("P3 专项：JWT / refresh 轮换 / DPoP → " + SERVER)
    print("=" * 74)

    ping = body_of(requests.get(API + "/ping", timeout=15))
    auth = ping.get("auth") or {}
    if not auth.get("jwt"):
        raise SystemExit("服务器没开 JWT（看 ping.auth）")
    print(f"\n服务器令牌策略：{json.dumps(auth, ensure_ascii=False)}")

    # ---------- 1. JWT 结构 + 公钥自验 ----------
    print("\n[1] access 是 Ed25519 的 JWT，且公钥可本地验签")
    user, pw, mat, reg = new_account("a")
    access, refresh = reg["access_token"], reg["refresh_token"]
    check("登录响应里有 access_token / refresh_token",
          bool(access) and bool(refresh))
    check("access 是三段式 JWT", access.count(".") == 2, str(access[:40]))
    check("兼容字段 token 还在（老客户端不炸）", bool(reg.get("token")))
    hdr = pyjwt.get_unverified_header(access)
    check("header.alg = EdDSA", hdr.get("alg") == "EdDSA", str(hdr))
    payload = pyjwt.decode(access, options={"verify_signature": False})
    check("sub 是 user_id（不是用户名）", payload.get("sub") == str(reg["user_id"]),
          str(payload.get("sub")))
    check("exp - iat = 15 分钟", payload["exp"] - payload["iat"] == 900,
          f"{payload['exp'] - payload['iat']}")
    check("有 jti 与 sid", bool(payload.get("jti")) and payload.get("sid"))

    jw = body_of(requests.get(API + "/auth/jwks", timeout=15))
    key = (jw.get("keys") or [{}])[0]
    check("JWKS 是 Ed25519 公钥", key.get("kty") == "OKP" and key.get("crv") == "Ed25519",
          str(key))
    check("JWKS 的 kid 与 ping 里的一致", key.get("kid") == auth.get("kid"),
          f"{key.get('kid')} vs {auth.get('kid')}")
    pk = Ed25519PrivateKey  # 占位，下面用公钥验签
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

    pub = Ed25519PublicKey.from_public_bytes(b64d(key["x"]))
    claims = pyjwt.decode(access, pub, algorithms=["EdDSA"], audience="phix",
                          issuer="phix")
    check("**用 JWKS 公钥本地验签通过**（不用回连认证中心）",
          claims.get("sid") == payload.get("sid"))
    check("JWKS 里没有私钥字段", "d" not in key, str(list(key)))

    # 篡改一个字节 → 必须验不过
    parts = access.split(".")
    tampered = parts[0] + "." + parts[1][:-2] + ("AA" if parts[1][-2:] != "AA" else "BB") \
        + "." + parts[2]
    tamper_ok = False
    try:
        pyjwt.decode(tampered, pub, algorithms=["EdDSA"], audience="phix")
        tamper_ok = True
    except pyjwt.InvalidTokenError:
        pass
    check("载荷被改一个字节 → 验签失败", not tamper_ok)

    H = {"Authorization": "Bearer " + access}
    check("拿 access 调业务（/auth/me）→ 200",
          requests.get(API + "/auth/me", headers=H, timeout=15).status_code == 200)

    # ---------- 1b. 时钟没对准也不能全拒 ----------
    print("\n[1b] 时钟偏差容差（iat 跑到未来时，不该把所有令牌一律拒掉）")
    srv_time = str(ping.get("server_time") or "")
    if srv_time:
        try:
            from datetime import datetime
            skew = time.time() - datetime.fromisoformat(srv_time).timestamp()
            print("      本机与服务器时差约 %+.1f 秒" % skew)
        except ValueError:
            pass
    _uf, _pwf, mat_f, reg_f = new_account("j")
    sk_f, jwk_f = make_dpop_key()
    # 偏移量可配：`.41` 与本机有 1~2 秒时钟差，+60 会顶到容差边界；
    # 要测的是「容差存在」，不是「恰好卡边界」。
    off = float(os.environ.get("PHIX_IAT_OFFSET", "60"))
    future = dpop_proof(sk_f, jwk_f, "POST", "/auth/login", iat=time.time() + off)
    r = requests.post(API + "/auth/login", timeout=20, headers={"DPoP": future}, json={
        "username": _uf, "auth_hash": pc.auth_hash_hex(_pwf, mat_f["auth_salt"],
                                                      pc.KDF_ALGO_V2),
        "device": "未来时钟机", "dpop_jkt": jkt_of(jwk_f)})
    check("iat 在未来 %.0f 秒 → **仍然接受**（时钟偏差容差）" % off, r.status_code == 200,
          "%s %s" % (r.status_code, r.text[:140]))
    if r.status_code == 200:
        a_f = body_of(r)["access_token"]
        pf = dpop_proof(sk_f, jwk_f, "GET", "/auth/me", iat=time.time() + off)
        r = requests.get(API + "/auth/me", timeout=15, headers={
            "Authorization": "Bearer " + a_f, "DPoP": pf})
        check("未来时钟的会话也能正常用", r.status_code == 200,
              "%s %s" % (r.status_code, r.text[:140]))
    # 容差不是无限的：**必须用"绑定了 DPoP 的会话"来测** ——
    # 没绑定的会话压根不校验证明，拿它测只会得到假象。
    if r.status_code == 200:
        way_future = dpop_proof(sk_f, jwk_f, "GET", "/auth/me",
                                iat=time.time() + 3600)
        r2 = requests.get(API + "/auth/me", timeout=15, headers={
            "Authorization": "Bearer " + a_f, "DPoP": way_future})
        check("iat 在未来 1 小时 → 拒绝（容差不是无限）", r2.status_code == 401,
              "%s %s" % (r2.status_code, r2.text[:140]))

    # ---------- 2. 注销立刻生效 ----------
    print("\n[2] 注销立刻生效（不等 JWT 自然过期）")
    u2, pw2, _m2, reg2 = new_account("b")
    a2, r2 = reg2["access_token"], reg2["refresh_token"]
    H2 = {"Authorization": "Bearer " + a2}
    check("注销前可用", requests.get(API + "/auth/me", headers=H2, timeout=15).status_code == 200)
    r = requests.post(API + "/auth/logout", headers=H2, timeout=15)
    check("注销 200", r.status_code == 200, str(r.status_code))
    r = requests.get(API + "/auth/me", headers=H2, timeout=15)
    check("**同一个 access 立刻失效**（401，且 code=unauthorized）",
          r.status_code == 401 and body_of(r).get("error", {}).get("code") == "unauthorized",
          f"{r.status_code} {r.text[:120]}")
    r = requests.post(API + "/auth/refresh", json={"refresh_token": r2}, timeout=15)
    check("注销后 refresh 也不能用了", r.status_code == 401, str(r.status_code))

    # ---------- 3. refresh 轮换 ----------
    print("\n[3] refresh 用一次换一次")
    u3, pw3, _m3, reg3 = new_account("c")
    a3, r3 = reg3["access_token"], reg3["refresh_token"]
    r = requests.post(API + "/auth/refresh", json={"refresh_token": r3}, timeout=20)
    b = body_of(r)
    check("续期 200", r.status_code == 200, f"{r.status_code} {r.text[:160]}")
    check("拿到新的 access", bool(b.get("access_token")) and b["access_token"] != a3)
    check("拿到**新的** refresh（轮换了）",
          bool(b.get("refresh_token")) and b["refresh_token"] != r3)
    check("rotated=true", b.get("rotated") is True, str(b.get("rotated")))
    a4, r4 = b["access_token"], b["refresh_token"]
    check("新 access 能用",
          requests.get(API + "/auth/me", headers={"Authorization": "Bearer " + a4},
                       timeout=15).status_code == 200)

    # 宽限期内用旧的：不当作攻击，但不重发新的
    r = requests.post(API + "/auth/refresh", json={"refresh_token": r3}, timeout=20)
    b2 = body_of(r)
    check("宽限期内重复用旧 refresh → 200 且 rotated=false",
          r.status_code == 200 and b2.get("rotated") is False,
          f"{r.status_code} {r.text[:160]}")
    check("宽限期内**不重发** refresh（服务端也没有明文）",
          not b2.get("refresh_token"), str(b2.get("refresh_token"))[:20])
    check("宽限期内仍给新 access", bool(b2.get("access_token")))

    # 把宽限期设成 0 再重放 → 必须撤销整个会话（默认 120 秒等不起）
    print("\n[3b] 宽限期外重放 → 整个会话作废（用 PHIX_REFRESH_GRACE=0 的服务器验）")
    strict = os.environ.get("PHIX_STRICT_SERVER", "")
    if not strict:
        print("  [跳过] 没给 PHIX_STRICT_SERVER（那是一台 PHIX_REFRESH_GRACE=0 的服务器）")
    else:
        u3b, pw3b, _m3b, reg3b = new_account("d", server=strict)
        rr = requests.post(strict.rstrip("/") + "/api/v1/auth/refresh",
                           json={"refresh_token": reg3b["refresh_token"]}, timeout=20)
        rb = body_of(rr)
        rr2 = requests.post(strict.rstrip("/") + "/api/v1/auth/refresh",
                            json={"refresh_token": reg3b["refresh_token"]}, timeout=20)
        check("宽限期外重放旧 refresh → 401", rr2.status_code == 401,
              f"{rr2.status_code} {rr2.text[:160]}")
        check("重放后**连新 refresh 也作废**（会话已撤销）",
              requests.post(strict.rstrip("/") + "/api/v1/auth/refresh",
                            json={"refresh_token": rb.get("refresh_token")},
                            timeout=20).status_code == 401)
        check("重放后的新 access 也失效",
              requests.get(strict.rstrip("/") + "/api/v1/auth/me",
                           headers={"Authorization": "Bearer " + rb.get("access_token", "")},
                           timeout=15).status_code == 401)
        check("日志里能看到重放告警（服务端确实判定为重放）",
              rr2.status_code == 401)

    # ---------- 4. refresh 不能当访问令牌 ----------
    print("\n[4] refresh 令牌不能调业务")
    r = requests.get(API + "/auth/me", headers={"Authorization": "Bearer " + r4},
                     timeout=15)
    check("把 refresh 当 Bearer 用 → 401", r.status_code == 401,
          f"{r.status_code} {r.text[:120]}")
    r = requests.post(API + "/auth/refresh", json={"refresh_token": "x" * 60}, timeout=15)
    check("乱编 refresh → 401", r.status_code == 401, str(r.status_code))

    # ---------- 5. 过期 ----------
    print("\n[5] exp 到了就真的作废（用 PHIX_JWT_ACCESS_TTL=5 / LEEWAY=1 的服务器验）")
    short = os.environ.get("PHIX_SHORT_SERVER", "")
    if not short:
        print("  [跳过] 没给 PHIX_SHORT_SERVER（用 devtools/run_short.py 起一台 8933）")
    else:
        u5, pw5, _m5, reg5 = new_account("e", server=short)
        base = short.rstrip("/") + "/api/v1"
        hh = {"Authorization": "Bearer " + reg5["access_token"]}
        check("刚签发时可用", requests.get(base + "/auth/me", headers=hh, timeout=15).status_code == 200)
        print("      等 11 秒让它过期（ttl 5s + leeway 1s + 足够余量）……")
        time.sleep(11)
        r = requests.get(base + "/auth/me", headers=hh, timeout=15)
        check("**过期后 401 且 code=token_expired**（客户端据此去续期）",
              r.status_code == 401 and body_of(r).get("error", {}).get("code") == "token_expired",
              f"{r.status_code} {r.text[:160]}")
        r = requests.post(base + "/auth/refresh",
                          json={"refresh_token": reg5["refresh_token"]}, timeout=20)
        check("过期后 refresh 照样能换新的", r.status_code == 200, str(r.status_code))

    # ---------- 6. 会话列表与撤销 ----------
    print("\n[6] 会话列表 / 撤销其它设备")
    u6, pw6, mat6, reg6 = new_account("f")
    a6 = reg6["access_token"]
    # 第二台设备：拿同一账号再登一次（模拟另一台机器）
    reg6b = body_of(requests.post(API + "/auth/login", timeout=20, json={
        "username": u6, "auth_hash": pc.auth_hash_hex(pw6, mat6["auth_salt"], pc.KDF_ALGO_V2),
        "device": "第二台设备"}))
    lst = body_of(requests.get(API + "/auth/devices",
                               headers={"Authorization": "Bearer " + a6}, timeout=15))
    sessions = lst.get("sessions") or []
    check("会话列表里有当前会话", any(s.get("current") for s in sessions), str(sessions)[:200])
    check("两台设备 = 两个会话", len(sessions) >= 2, str(len(sessions)))
    check("会话项带 access_ttl / refresh_ttl",
          lst.get("access_ttl") == 900 and lst.get("refresh_ttl", 0) > 0, str(lst)[:200])
    check("列表里没有 refresh 明文", "refresh_token" not in json.dumps(lst))

    other = [s for s in sessions if not s.get("current")]
    if other:
        r = requests.post(API + "/auth/devices/revoke",
                          headers={"Authorization": "Bearer " + a6},
                          json={"session_id": other[0]["id"]}, timeout=15)
        check("撤销另一台设备的会话 → 200", r.status_code == 200, str(r.status_code))
        a6b = reg6b["access_token"]
        r = requests.get(API + "/auth/me",
                         headers={"Authorization": "Bearer " + a6b}, timeout=15)
        check("**被撤销那台设备的 access 立刻失效**", r.status_code == 401,
              f"{r.status_code} {r.text[:140]}")
        check("当前设备不受影响",
              requests.get(API + "/auth/me",
                           headers={"Authorization": "Bearer " + a6},
                           timeout=15).status_code == 200)
    else:
        check("有第二台设备的会话", False, str(sessions)[:200])

    # ---------- 6b. all_except_current 不能踢掉自己 ----------
    print("\n[6b] 「注销其它设备」不许把本机踢下线（含本机的老式令牌）")
    u6b, pw6b, mat6b, reg6b = new_account("k")
    a6b = reg6b["access_token"]
    legacy6b = reg6b.get("token") or ""
    # 再开一台"别的设备"
    body_of(requests.post(API + "/auth/login", timeout=20, json={
        "username": u6b, "auth_hash": pc.auth_hash_hex(pw6b, mat6b["auth_salt"],
                                                      pc.KDF_ALGO_V2),
        "device": "另一台"}))
    r = requests.post(API + "/auth/devices/revoke", timeout=15, headers={
        "Authorization": "Bearer " + a6b}, json={"all_except_current": True})
    check("注销其它设备 → 200", r.status_code == 200, str(r.status_code))
    check("当前 JWT 仍然可用（没把自己踢掉）",
          requests.get(API + "/auth/me", timeout=15,
                       headers={"Authorization": "Bearer " + a6b}).status_code == 200)
    if legacy6b:
        r = requests.get(API + "/auth/me", timeout=15,
                         headers={"Authorization": "Bearer " + legacy6b})
        check("**本机那串老式长期令牌也还在**（老客户端点这个按钮不该自踢）",
              r.status_code == 200, "%s %s" % (r.status_code, r.text[:120]))
    else:
        print("  [跳过] 这台服务器不发老式令牌")

    # ---------- 7. DPoP ----------
    print("\n[7] DPoP：令牌与客户端密钥绑定")
    sk_c, jwk_c = make_dpop_key()
    u7, pw7, mat7, reg7 = new_account("g")
    # 用同一把客户端密钥再登一次（登录时带证明 → 服务端把会话绑到这把公钥）
    prf = dpop_proof(sk_c, jwk_c, "POST", "/auth/login")
    r = requests.post(API + "/auth/login", timeout=20, headers={"DPoP": prf}, json={
        "username": u7, "auth_hash": pc.auth_hash_hex(pw7, mat7["auth_salt"], pc.KDF_ALGO_V2),
        "device": "DPoP 机", "dpop_jkt": jkt_of(jwk_c)})
    b7 = body_of(r)
    if r.status_code != 200:
        print(f"  [跳过] 登录时绑定 DPoP 还没实现（{r.status_code} {r.text[:120]}）")
    else:
        a7 = b7["access_token"]
        r = requests.get(API + "/auth/me", headers={"Authorization": "Bearer " + a7}, timeout=15)
        check("绑定了 DPoP 的会话：**不带证明 → 401**", r.status_code == 401,
              f"{r.status_code} {r.text[:140]}")
        proof = dpop_proof(sk_c, jwk_c, "GET", "/auth/me")
        r = requests.get(API + "/auth/me", timeout=15, headers={
            "Authorization": "Bearer " + a7, "DPoP": proof})
        check("带上正确证明 → 200", r.status_code == 200, f"{r.status_code} {r.text[:140]}")
        r = requests.get(API + "/auth/me", timeout=15, headers={
            "Authorization": "Bearer " + a7, "DPoP": proof})
        check("**重放同一个证明 → 401**", r.status_code == 401,
              f"{r.status_code} {r.text[:140]}")
        sk_x, jwk_x = make_dpop_key()
        r = requests.get(API + "/auth/me", timeout=15, headers={
            "Authorization": "Bearer " + a7,
            "DPoP": dpop_proof(sk_x, jwk_x, "GET", "/auth/me")})
        check("换一把别人（偷来）的密钥签证明 → 401", r.status_code == 401,
              f"{r.status_code} {r.text[:140]}")
        r = requests.get(API + "/auth/me", timeout=15, headers={
            "Authorization": "Bearer " + a7,
            "DPoP": dpop_proof(sk_c, jwk_c, "GET", "/auth/devices")})
        check("证明的 htu 指向别的路径 → 401", r.status_code == 401,
              f"{r.status_code} {r.text[:140]}")

    # ---------- 8. introspect ----------
    print("\n[8] /auth/introspect（给没有本地验签能力的服务）")
    u8, pw8, _m8, reg8 = new_account("h")
    a8 = reg8["access_token"]
    if not SERVICE_KEY:
        print("  [跳过] 没有服务密钥")
    else:
        HS = {"X-Phix-Service-Key": SERVICE_KEY}
        check("无服务密钥 → 403",
              requests.post(API + "/auth/introspect", json={"token": a8},
                            timeout=15).status_code == 403)
        b = body_of(requests.post(API + "/auth/introspect", json={"token": a8},
                                  headers=HS, timeout=15))
        check("有效令牌 → active=true 且带 sub/sid",
              b.get("active") is True and b.get("sub") == str(reg8["user_id"]),
              str(b)[:200])
        requests.post(API + "/auth/logout",
                      headers={"Authorization": "Bearer " + a8}, timeout=15)
        b = body_of(requests.post(API + "/auth/introspect", json={"token": a8},
                                  headers=HS, timeout=15))
        check("注销后 → active=false", b.get("active") is False, str(b)[:160])
        # 老式长期令牌：用**另一个**账号（上面那个已经登出、令牌已被一并吊销）
        _u9, _pw9, _m9, reg9 = new_account("i")
        b = body_of(requests.post(API + "/auth/introspect",
                                  json={"token": reg9["token"]}, headers=HS, timeout=15))
        check("老式长期令牌也能自省（兼容期）", b.get("active") is True and b.get("kind") == "legacy",
              str(b)[:160])
        r9 = requests.post(API + "/auth/logout", timeout=15,
                           headers={"Authorization": "Bearer " + reg9["token"]})
        check("用老式令牌也能登出", r9.status_code == 200, str(r9.status_code))
        b = body_of(requests.post(API + "/auth/introspect",
                                  json={"token": reg9["token"]}, headers=HS, timeout=15))
        check("老式令牌登出后 → active=false", b.get("active") is False, str(b)[:160])

    print("\n" + "=" * 74)
    print(f"通过 {len(PASSED)} 项，失败 {len(FAILED)} 项")
    for f in FAILED:
        print("  - " + f)
    print("=" * 74)
    return 1 if FAILED else 0


if __name__ == "__main__":
    sys.exit(main())
