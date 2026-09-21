"""应用层加密传输（P1）的专项测试。

对应 `加密链路思路.md` §3：**用应用层加密替代 HTTPS**。要证明的不只是"能跑通"，
而是**网线上抓到的只有密文**、以及重放/篡改/换公钥这些攻击都挡得住。

    cd D:\\phix\\server
    .venv\\Scripts\\python.exe -X utf8 devtools\\test_e2e_transport.py
"""
import json
import os
import secrets
import sys
import time
from pathlib import Path

import requests

sys.path.insert(0, r"D:\phl-lite-dev")
from hellopinghe import cloudsync as cs  # noqa: E402
from hellopinghe import phixcrypto as pc  # noqa: E402

SERVER = os.environ.get("PHIX_SERVER", "http://127.0.0.1:8931")
API = SERVER.rstrip("/") + "/api/v1"
PIN = Path(r"D:\phix\_lab\e2e_pin")

PASSED, FAILED = [], []


def check(name, cond, extra=""):
    (PASSED if cond else FAILED).append(name)
    print(f"  [{'OK  ' if cond else 'FAIL'}] {name}" + (f"   {extra}" if extra and not cond else ""))
    return cond


def main():
    print("=" * 74)
    print("应用层加密传输（P1）专项测试")
    print("=" * 74)
    print(f"服务器: {SERVER}")

    if PIN.exists():
        for p in PIN.glob("*.txt"):
            p.unlink()

    # ---------- 1. 服务器声明支持 ----------
    print("\n[1] 服务器声明支持加密传输")
    info = requests.get(API + "/ping", timeout=10).json()
    check("ping 返回 enc=1", int(info.get("enc") or 0) == 1, str(info.get("enc")))
    pk = pc.b64d(info["pk"])
    check("拿到 32 字节 X25519 公钥", len(pk) == 32, str(len(pk)))

    # ---------- 2. 加密往返 ----------
    print("\n[2] 加密往返：注册 / 读 / 写 / 删")
    client = cs.PhixClient(SERVER, e2e=True, pin_dir=PIN)
    check("客户端启用了加密", client.ensure_e2e() and client.encrypted)
    user = "e2etr" + secrets.token_hex(4)
    password = "Transport-Test-1"
    body, mat = client.register(user, password, device="加密传输测试")
    check("注册成功（走加密）", bool(body.get("token")), str(body)[:160])
    uid, token = body["user_id"], body["token"]

    c2 = cs.PhixClient(SERVER, token=token, e2e=True, pin_dir=PIN)
    check("manifest 可用（走加密）", c2.manifest().get("ok") is True)
    payload = json.dumps({"events": [{"id": 1, "title": "加密传输测试"}],
                          "lastId": 1}, ensure_ascii=False).encode()
    env = pc.seal_object(mat["dek"], uid, "schedule", payload)
    check("PUT 成功（走加密）", c2.put_object("schedule", 0, env, "测试").get("revision") == 1)
    got = c2.get_object("schedule")
    check("GET 解出内容正确",
          json.loads(pc.unseal_object(mat["dek"], uid, "schedule",
                                      got["payload"]))["events"][0]["title"] == "加密传输测试")
    check("DELETE 成功（query 在信封里）", c2.delete_object("schedule", 1).get("deleted") is True)

    # ---------- 3. 【核心】网线上真的是密文 ----------
    print("\n[3] 网线上抓到的只有密文（这是这一层存在的意义）")
    # v2 账号登录发的是 AuthHash（不是口令），所以这里也要用它
    km = requests.post(API + "/auth/keymaterial", json={"username": user},
                       timeout=10).json()
    ah = pc.auth_hash_hex(password, km["auth_salt"], km["kdf_algo"])
    check("账号是 v2（发 AuthHash）", pc.uses_auth_hash(km["kdf_algo"]), km["kdf_algo"])
    marker = "WireMarker-" + secrets.token_hex(4)
    envl, sk = pc.make_envelope(pk, "POST", "/api/v1/auth/login",
                                {"username": user, "auth_hash": ah,
                                 "device": marker})
    wire_body = json.dumps(envl, ensure_ascii=False)
    check("请求体里没有口令明文", password not in wire_body)
    check("请求体里没有 AuthHash 明文", ah not in wire_body)
    check("请求体里没有设备名明文（标记串）", marker not in wire_body)
    check("请求体里没有用户名明文", user not in wire_body)
    check("请求体里没有 password 字段名", "password" not in wire_body)
    check("请求体只有 sealed_sk / iv / ct 三个字段",
          set(envl.keys()) == {"sealed_sk", "iv", "ct"}, str(sorted(envl.keys())))

    resp = requests.post(API + "/auth/login", json=envl,
                         headers={"X-Phix-Enc": "1"}, timeout=15)
    check("服务器 200", resp.status_code == 200, f"{resp.status_code} {resp.text[:120]}")
    check("响应头标了 X-Phix-Enc", resp.headers.get("X-Phix-Enc") == "1")
    rj = resp.json()
    check("响应体也是信封（只有 iv/ct）", set(rj.keys()) == {"iv", "ct"}, str(sorted(rj.keys())))
    opened = json.loads(pc.open_envelope_response(sk, "POST", "/api/v1/auth/login", rj))
    check("解开响应信封拿到令牌", bool(opened.get("token")), str(opened)[:160])
    check("响应密文里没有令牌明文（抓到了也没用）",
          opened["token"] not in resp.text)
    check("响应密文里没有用户名明文", user not in resp.text)

    # ---------- 4. 抗重放 ----------
    print("\n[4] 抗重放：同一个信封不许用第二次")
    envl2, _ = pc.make_envelope(pk, "POST", "/api/v1/auth/login",
                                {"username": user, "auth_hash": ah, "device": "重放"})
    h = {"X-Phix-Enc": "1"}
    r1 = requests.post(API + "/auth/login", json=envl2, headers=h, timeout=15)
    r2 = requests.post(API + "/auth/login", json=envl2, headers=h, timeout=15)
    check("第一次成功", r1.status_code == 200, str(r1.status_code))
    check("重放同一条被拒（400）", r2.status_code == 400, str(r2.status_code))
    check("拒绝原因是重复请求", "重复" in r2.text, r2.text[:160])

    print("\n[4b] 过期的时间戳被拒")
    inner_old = {"m": "POST", "p": "/api/v1/auth/login", "q": "", "b": {"username": user},
                 "ts": int(time.time()) - 3600, "nonce": pc.b64e(os.urandom(16))}
    sk3 = pc.new_session_key()
    import base64 as _b64

    from cryptography.hazmat.primitives.ciphers.aead import AESGCM

    iv3 = os.urandom(12)
    ct3 = AESGCM(sk3).encrypt(iv3, json.dumps(inner_old).encode(),
                              pc.env_aad("POST", "/api/v1/auth/login"))
    sealed3 = pc.seal_box(sk3, pk)
    r3 = requests.post(API + "/auth/login",
                       json={"sealed_sk": pc.b64e(sealed3), "iv": pc.b64e(iv3),
                             "ct": pc.b64e(ct3)},
                       headers=h, timeout=15)
    check("过期请求被拒", r3.status_code == 400 and "过期" in r3.text, r3.text[:160])

    # ---------- 5. 篡改 ----------
    print("\n[5] 篡改挡得住")
    envl4, _ = pc.make_envelope(pk, "POST", "/api/v1/auth/login",
                                {"username": user, "auth_hash": ah})
    bad = dict(envl4)
    raw = bytearray(pc.b64d(bad["ct"]))
    raw[-1] ^= 0x01
    bad["ct"] = pc.b64e(bytes(raw))
    r4 = requests.post(API + "/auth/login", json=bad, headers=h, timeout=15)
    check("改了密文 → 400", r4.status_code == 400, str(r4.status_code))

    # 把给 /auth/login 的信封发到别的路径 → AAD 不匹配
    r5 = requests.post(API + "/auth/register", json=envl4, headers=h, timeout=15)
    check("换路径重放 → 400（AAD 绑了路径）", r5.status_code == 400, str(r5.status_code))

    bad2 = dict(envl4)
    bad2["sealed_sk"] = pc.b64e(os.urandom(80))
    r6 = requests.post(API + "/auth/login", json=bad2, headers=h, timeout=15)
    check("伪造 sealed_sk → 400", r6.status_code == 400, str(r6.status_code))

    # ---------- 6. 公钥固定 ----------
    print("\n[6] 公钥固定：服务器公钥变了要拒绝（防冒充）")
    host = SERVER.split("://", 1)[-1]
    pin_file = PIN / (host.replace(":", "_") + ".txt")
    check("首次连接把公钥存下来了", pin_file.exists(), str(pin_file))
    check("存的就是服务器公钥", pin_file.read_text().strip() == pk.hex())
    pin_file.write_text("ab" * 32 + "\n")      # 伪造一个不一样的
    c3 = cs.PhixClient(SERVER, e2e=True, pin_dir=PIN)
    try:
        c3.ensure_e2e()
        check("公钥对不上要报错", False, "居然通过了")
    except cs.PhixError as exc:
        check("公钥对不上要报错", exc.code == "server_key_changed", f"{exc.code}: {exc.message}")
    c3.trust_new_server_key()
    check("重新信任后能连上", c3.ensure_e2e() and c3.encrypted)

    # ---------- 7. 明文回退 ----------
    print("\n[7] 明文路径完全不受影响（老客户端 / curl / 心履服务间调用）")
    r7 = requests.post(API + "/auth/login",
                       json={"username": user, "auth_hash": ah}, timeout=15)
    check("不带 X-Phix-Enc 头 → 仍走明文且成功",
          r7.status_code == 200 and r7.json().get("ok") is True, str(r7.status_code))
    c4 = cs.PhixClient(SERVER, e2e=False)
    check("客户端可以显式关掉加密", bool(c4.login(user, password).get("token")))

    # ---------- 8. 大对象 ----------
    print("\n[8] 大对象也要能过（信封会让体积膨胀 ~1.33 倍）")
    big = secrets.token_bytes(900 * 1024)
    big_env = pc.seal_object(mat["dek"], uid, "agent:big", big)
    c5 = cs.PhixClient(SERVER, token=token, e2e=True, pin_dir=PIN)
    r8 = c5.put_object("agent:big", 0, big_env, "大对象测试")
    check("900KB 明文的信封装得下", r8.get("revision") == 1, str(r8)[:160])
    back = c5.get_object("agent:big")
    check("取回来逐字节一致",
          pc.unseal_object(mat["dek"], uid, "agent:big", back["payload"]) == big)

    print("\n" + "=" * 74)
    print(f"通过 {len(PASSED)} 项，失败 {len(FAILED)} 项")
    if FAILED:
        for f in FAILED:
            print("  - " + f)
    print("=" * 74)
    return 1 if FAILED else 0


if __name__ == "__main__":
    sys.exit(main())
