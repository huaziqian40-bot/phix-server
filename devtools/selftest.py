"""phix 服务端端到端自测（对着本地 127.0.0.1:8931 跑）。

覆盖：注册 / 登录 / 多设备 / 密钥自检 / 持有性证明 / 推送拉取 / 乐观锁冲突 /
批量 / 墓碑 / 换密码后老密文仍可解 / 恢复码重置 / 强模式 / 权限边界 / 服务端 verify。

    cd D:\\phix\\server
    .venv\\Scripts\\python.exe -X utf8 devtools\\selftest.py
"""
import json
import os
import secrets
import sys
import time

import requests

sys.path.insert(0, r"D:\phl-lite-dev")
from hellopinghe import phixcrypto as pc  # noqa: E402

BASE = os.environ.get("PHIX_BASE", "http://127.0.0.1:8931/api/v1")
DB_PATH = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                       "db.sqlite3")


def _service_key():
    """和 run_local.py 一样：环境变量没给就读 `.service_key`。

    以前这里只认环境变量 → 忘了 export 就会白掉 2 项（verify 那两节），
    看着像 bug 其实是没喂密钥。现在自给自足。
    """
    val = os.environ.get("PHIX_SERVICE_KEY", "").strip()
    if val:
        return val
    path = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                        ".service_key")
    try:
        with open(path, encoding="utf-8") as fh:
            val = fh.read().strip()
    except OSError:
        return ""
    if val:
        os.environ["PHIX_SERVICE_KEY"] = val   # 让子进程/后续调用也拿到
    return val


SERVICE_KEY = _service_key()

PASSED, FAILED = [], []


def check(name, cond, extra=""):
    (PASSED if cond else FAILED).append(name)
    print(f"  [{'OK  ' if cond else 'FAIL'}] {name}" +
          (f"   {extra}" if extra and not cond else ""))
    return cond


def req(method, path, token=None, **kw):
    headers = kw.pop("headers", {})
    if token:
        headers["Authorization"] = f"Bearer {token}"
    url = BASE + path
    try:
        r = requests.request(method, url, headers=headers, timeout=30, **kw)
    except requests.RequestException as exc:
        raise SystemExit(f"连不上 phix 服务 {url}：{exc}\n先跑 run_local.py") from exc
    try:
        body = r.json()
    except ValueError:
        body = {"_raw": r.text[:300]}
    return r.status_code, body


def jpost(path, payload, token=None, headers=None):
    return req("POST", path, json=payload, token=token, headers=headers or {})


def _cred(password, material=None, salt=None, algo=None, prefix=""):
    """构造"身份凭证"字段：v2 账号发 AuthHash，v1 老账号发口令原文。

    （这里以前一律发口令原文。服务端现在会拒绝"v2 账号却发口令原文"——
    因为那会把凭证静默写坏，所以自测也必须按真实客户端的规矩来。）

    ``material`` 给了就取里面的 ``auth_salt``/``kdf_algo``；
    没给则退回 ``salt``/``algo`` 参数。
    """
    mat = material or {}
    algo = mat.get("kdf_algo") or algo or pc.KDF_ALGO_V1
    if pc.uses_auth_hash(algo):
        asalt = mat.get("auth_salt") or salt
        if not asalt:
            return {}, algo          # 拿不到盐就什么都不加，让服务端报错更明显
        return {prefix + "auth_hash": pc.auth_hash_hex(password, asalt, algo)}, algo
    return {prefix + "password": password}, algo


def main():
    print("=" * 74)
    print("phix 服务端自测 → " + BASE)
    print("=" * 74)

    code, ping = req("GET", "/ping")
    if code != 200:
        raise SystemExit(f"/ping 失败：{code} {ping}")
    print(f"\n服务在线：{ping.get('service')} v{ping.get('version')}   "
          f"单对象上限 {ping['limits']['max_payload_bytes'] // 1024 // 1024} MiB")
    svc_verify = ping.get("service_verify_enabled")

    sfx = secrets.token_hex(4)
    username = f"selftest_{sfx}"
    password = "Test-Pass-123"
    device_a = "自测机-A"

    # ---------- 1. 注册 ----------
    print("\n[1] 注册")
    mat = pc.new_material(username, password)
    dek = mat["dek"]
    body_reg = {
        "username": username, "agree": True, "device": device_a,
        "kdf_algo": mat["kdf_algo"], "kdf_salt": mat["kdf_salt"],
        "auth_salt": mat["auth_salt"],
        "key_wrap": mat["key_wrap"], "recovery_salt": mat["recovery_salt"],
        "recovery_wrap": mat["recovery_wrap"], "key_check": mat["key_check"],
        "key_check_plain": mat["key_check_plain"], "key_mode": mat["key_mode"],
    }
    # v2 账号的凭证是 AuthHash（服务端永远见不到口令）
    body_reg.update(_cred(password, material=mat)[0])
    code, body = jpost("/auth/register", body_reg)
    check("注册 201", code == 201, f"{code} {body}")
    if code != 201:
        raise SystemExit("注册失败，后续无法继续")
    user_id, token_a = body["user_id"], body["token"]
    recovery_code = mat["recovery_code"]
    check("返回 user_id / 40 位令牌", bool(user_id) and len(token_a) == 40)
    check("服务端回显同一份 key_wrap", body["key_wrap"] == mat["key_wrap"])
    check("响应里不含 key_check_plain", "key_check_plain" not in body, str(list(body)))

    code, _ = jpost("/auth/register", body_reg)
    check("重复注册被拒", code == 400, str(code))

    # ---------- 2. 第二台设备登录 ----------
    print("\n[2] 第二台设备登录 + 本地解包 DEK")
    login_b = {"username": username, "device": "自测机-B"}
    login_b.update(_cred(password, material=mat)[0])
    code, body = jpost("/auth/login", login_b)
    check("登录 200", code == 200, f"{code} {body}")
    token_b = body.get("token")
    check("两台设备令牌不同", bool(token_b) and token_b != token_a)
    check("登录响应也不含 key_check_plain", "key_check_plain" not in body)

    t0 = time.time()
    dek_b = pc.unwrap_dek(body["key_wrap"], password, body["kdf_salt"], username)
    dt = (time.time() - t0) * 1000
    check(f"B 机用口令解出 DEK（{dt:.0f} ms）", dek_b == dek)
    check("B 机自检块通过", pc.check_dek(dek_b, username, body["key_check"]))
    check("错口令解不出 DEK",
          _try_unwrap(body["key_wrap"], "wrong-password", body["kdf_salt"], username) is None)
    check("错 DEK 自检失败", not pc.check_dek(os.urandom(32), username, body["key_check"]))
    proof = pc.prove_dek(dek_b, username, body["key_check"])
    check("能从存的自检块解出证明明文", proof == mat["key_check_plain"])

    wrong_login = {"username": username}
    wrong_login.update(_cred("nope-nope", material=mat)[0])
    code, _ = jpost("/auth/login", wrong_login)
    check("错误密码 401", code == 401, str(code))

    # ---------- 3. 推送 / 拉取 ----------
    print("\n[3] 同步：推送 / 拉取 / 服务端零明文")
    sched_plain = json.dumps({
        "version": 1, "kind": "pinghe-schedule", "app": "自测", "lastId": 3,
        "events": [{"id": 3, "day": "2026-09-20", "time": "15:30",
                    "title": "打球（自测）", "note": "带球拍",
                    "created": "2026-09-12T11:00:00+08:00"}],
    }, ensure_ascii=False).encode("utf-8")

    env = pc.seal_object(dek, user_id, "schedule", sched_plain)
    code, body = req("PUT", "/sync/objects/schedule", token=token_a,
                     json={"base_revision": 0, "payload": env, "device": device_a})
    check("首次推送 200 且 rev=1", code == 200 and body.get("revision") == 1, f"{code} {body}")

    code, body = req("GET", "/sync/manifest", token=token_b)
    check("清单含 schedule@1",
          code == 200 and any(o["name"] == "schedule" and o["revision"] == 1
                              for o in body.get("objects", [])), f"{code} {body}")

    code, body = req("GET", "/sync/objects/schedule", token=token_b)
    check("B 机取到密文", code == 200 and str(body.get("payload", "")).startswith("PHIX1."))
    got = pc.unseal_object(dek_b, user_id, "schedule", body["payload"]).decode("utf-8")
    check("B 机解出原文", got == sched_plain.decode("utf-8"))

    if os.path.exists(DB_PATH):
        raw = open(DB_PATH, "rb").read()
        check("服务端数据库里没有明文", "打球（自测）".encode("utf-8") not in raw)
        check("服务端数据库里没有 DEK 明文",
              bytes.fromhex(mat["key_check_plain"]) not in raw)

    # ---------- 4. 乐观锁 ----------
    print("\n[4] 乐观锁：并发写必须 409，绝不静默覆盖")
    env2 = pc.seal_object(dek, user_id, "schedule", b'{"events":[],"v":2}')
    code, body = req("PUT", "/sync/objects/schedule", token=token_b,
                     json={"base_revision": 0, "payload": env2, "device": "自测机-B"})
    check("基于旧版本推送 → 409",
          code == 409 and body.get("error", {}).get("code") == "revision_conflict",
          f"{code} {body}")
    check("409 里带 current.revision", body.get("current", {}).get("revision") == 1,
          str(body.get("current")))

    code, body = req("PUT", "/sync/objects/schedule", token=token_b,
                     json={"base_revision": 1, "payload": env2, "device": "自测机-B"})
    check("基于最新版本重推 → rev=2", code == 200 and body.get("revision") == 2, f"{code} {body}")

    # ---------- 5. 批量 ----------
    print("\n[5] 批量推送")
    items = [{"name": nm, "base_revision": 0, "device": device_a,
              "payload": pc.seal_object(dek, user_id, nm, f'{{"n":"{nm}"}}'.encode())}
             for nm in ("settings.lessons", "settings.accounts", "timetable")]
    code, body = req("POST", "/sync/objects/batch", token=token_a, json={"objects": items})
    check("批量 3 个全成功",
          code == 200 and sum(1 for r in body.get("results", []) if r.get("ok")) == 3,
          f"{code} {body}")

    code, body = req("POST", "/sync/objects/batch", token=token_a, json={"objects": [
        {"name": "timetable", "base_revision": 0, "device": device_a,
         "payload": pc.seal_object(dek, user_id, "timetable", b'{"x":1}')},
        {"name": "bad name!", "base_revision": 0, "payload": "PHIX1.a.b"},
    ]})
    res = {r.get("name"): r for r in body.get("results", [])}
    check("批量里冲突项报 revision_conflict",
          res.get("timetable", {}).get("code") == "revision_conflict", str(res))
    check("批量里非法对象名被拒", res.get("bad name!", {}).get("code") == "name_invalid")

    # ---------- 6. 墓碑 ----------
    print("\n[6] 墓碑删除（防同步复活）")
    code, body = req("DELETE", "/sync/objects/settings.accounts?base_revision=1",
                     token=token_a)
    check("删除后 revision 继续 +1 到 2",
          code == 200 and body.get("revision") == 2 and body.get("deleted") is True,
          f"{code} {body}")
    code, body = req("GET", "/sync/objects/settings.accounts", token=token_b)
    check("别的设备看到 deleted=true 且无 payload",
          body.get("deleted") is True and body.get("payload") is None, str(body))

    # ---------- 7. 换密码 ----------
    print("\n[7] 换密码 → 云端密文一个字节都不动")
    new_pw = "Test-Pass-456"
    rw = pc.rewrap(dek, username, new_pw, "password", recovery_code,
                   mat["key_check_plain"])
    # 注意：auth_salt 必须沿用**原来那个**（它永不改变），否则 AuthHash 会变。
    rw["auth_salt"] = mat["auth_salt"]
    chg = {
        "kdf_algo": rw["kdf_algo"], "kdf_salt": rw["kdf_salt"],
        "key_wrap": rw["key_wrap"], "key_check": rw["key_check"],
        "key_mode": rw["key_mode"], "dek_proof": proof,
    }
    chg.update(_cred(password, material=rw, prefix="old_")[0])
    chg.update(_cred(new_pw, material=rw, prefix="new_")[0])
    code, body = jpost("/auth/password", chg, token=token_a)
    check("换密码 200 且 key_version=2",
          code == 200 and body.get("key_version") == 2, f"{code} {body}")

    login_old = {"username": username}
    login_old.update(_cred(password, material=rw)[0])
    code, _ = jpost("/auth/login", login_old)
    check("旧密码登录失败", code == 401, str(code))
    login_new = {"username": username}
    login_new.update(_cred(new_pw, material=rw)[0])
    code, body = jpost("/auth/login", login_new)
    check("新密码登录成功", code == 200, str(code))
    token_c = body["token"]
    dek_c = pc.unwrap_dek(body["key_wrap"], new_pw, body["kdf_salt"], username)
    check("新口令解出的 DEK 与原来相同", dek_c == dek)
    code, body = req("GET", "/sync/objects/schedule", token=token_c)
    check("换密码后老密文照样解得开",
          pc.unseal_object(dek_c, user_id, "schedule", body["payload"]) == b'{"events":[],"v":2}')

    # 伪造证明：把公开常量当 dek_proof
    rw_bad = pc.rewrap(dek, username, "Sneaky-789", "password", recovery_code,
                       mat["key_check_plain"])
    rw_bad["auth_salt"] = mat["auth_salt"]
    for label, fake_proof in (("乱填字符串", "x" * 64),
                              ("公开常量 phix-keycheck-v1", "phix-keycheck-v1"),
                              ("别人的证明", "0" * 64)):
        bad = {
            "kdf_algo": rw_bad["kdf_algo"], "kdf_salt": rw_bad["kdf_salt"],
            "key_wrap": rw_bad["key_wrap"], "key_check": rw_bad["key_check"],
            "dek_proof": fake_proof,
        }
        bad.update(_cred(new_pw, material=rw_bad, prefix="old_")[0])
        bad.update(_cred("Sneaky-789", material=rw_bad, prefix="new_")[0])
        code, _ = jpost("/auth/password", bad, token=token_a)
        check(f"伪造证明（{label}）被拒", code == 400, str(code))
    nop = {
        "kdf_algo": rw_bad["kdf_algo"], "kdf_salt": rw_bad["kdf_salt"],
        "key_wrap": rw_bad["key_wrap"], "key_check": rw_bad["key_check"],
    }
    nop.update(_cred(new_pw, material=rw_bad, prefix="old_")[0])
    nop.update(_cred("Sneaky-789", material=rw_bad, prefix="new_")[0])
    code, _ = jpost("/auth/password", nop, token=token_a)
    check("完全不带宽 proof 被拒", code == 400, str(code))

    # ---------- 8. 恢复码 ----------
    print("\n[8] 恢复码重置密码")
    relogin = {"username": username}
    relogin.update(_cred(new_pw, material=rw)[0])
    code, lb = jpost("/auth/login", relogin)
    cur_dek = pc.unwrap_dek_with_recovery(rw["recovery_wrap"], recovery_code,
                                          rw["recovery_salt"], username)
    check("恢复码能解出 DEK", cur_dek == dek)
    cur_proof = pc.prove_dek(cur_dek, username, lb["key_check"])

    fake_dek = os.urandom(32)
    fake = pc.rewrap(fake_dek, username, "Recover-999", "password", recovery_code,
                     mat["key_check_plain"])
    fake["auth_salt"] = mat["auth_salt"]
    fake_body = {
        "username": username,
        "kdf_algo": fake["kdf_algo"], "kdf_salt": fake["kdf_salt"],
        "key_wrap": fake["key_wrap"], "key_check": fake["key_check"],
        "dek_proof": "phix-keycheck-v1",
    }
    fake_body.update(_cred("Recover-999", material=fake, prefix="new_")[0])
    code, _ = jpost("/auth/recover", fake_body)
    check("伪造 DEK 的恢复被拒（旧漏洞已封）", code == 401, str(code))

    # v2 账号却发口令原文 → 必须被拒（否则会把凭证静默写坏，真的踩过）。
    # 这里**故意用真的证明**：证明对了才轮得到凭证类型的检查，
    # 否则 401 会先把它挡掉，测不到护栏本身。
    # 被拒之后，真凭证照样能改成功
    rr = pc.rewrap(cur_dek, username, "Recover-999", "password", recovery_code,
                   mat["key_check_plain"], auth_salt=mat["auth_salt"],
                   auth_passphrase="Recover-999")
    plain_body = {
        "username": username, "new_password": "Recover-999",
        "kdf_algo": rr["kdf_algo"], "kdf_salt": rr["kdf_salt"],
        "key_wrap": rr["key_wrap"], "key_check": rr["key_check"],
        "dek_proof": cur_proof,
    }
    code, pb = jpost("/auth/recover", plain_body)
    check("v2 账号发口令原文被拒（静默降级已封）",
          code == 400 and "new_auth_hash" in json.dumps(pb, ensure_ascii=False),
          f"{code} {pb}")
    rec_body = {
        "username": username,
        "kdf_algo": rr["kdf_algo"], "kdf_salt": rr["kdf_salt"],
        "key_wrap": rr["key_wrap"], "key_check": rr["key_check"],
        "dek_proof": cur_proof,
    }
    rec_body.update(_cred("Recover-999", material=rr, prefix="new_")[0])
    code, body = jpost("/auth/recover", rec_body)
    check("真恢复码重置成功", code == 200, f"{code} {body}")
    login_rec = {"username": username}
    login_rec.update(_cred("Recover-999", material=rr)[0])
    code, body = jpost("/auth/login", login_rec)
    check("用新密码登录成功", code == 200, str(code))
    token_d = body["token"]
    dek_d = pc.unwrap_dek(body["key_wrap"], "Recover-999", body["kdf_salt"], username)
    check("恢复后 DEK 不变（数据没丢）", dek_d == dek)

    # ---------- 8b. 忘记密码：公开密钥材料 + 恢复码重置 ----------
    print("\n[8b] 忘记密码：取公开密钥材料 → 恢复码重置")
    code, km = jpost("/auth/keymaterial", {"username": username})
    check("取得到公开密钥材料", code == 200 and km.get("recovery_wrap"),
          f"{code} {km}")
    check("材料里带 recovery_salt / key_check",
          bool(km.get("recovery_salt")) and bool(km.get("key_check")))
    check("响应里不含 key_check_plain", "key_check_plain" not in km, str(list(km)))
    km_raw = json.dumps(km)
    check("响应里不含真实口令", "Recover-999" not in km_raw)
    check("响应里不含 DEK", dek.hex() not in km_raw and mat["key_check_plain"] not in km_raw)

    # 不存在的账号：形状一致、且不含任何真材料 → 防止拿它枚举账号
    code2, fake = jpost("/auth/keymaterial", {"username": f"nobody_{sfx}_xyz"})
    check("不存在的账号也返回 200", code2 == 200, str(code2))
    check("假材料形状与真材料一致",
          set(fake.keys()) - {"username"} == set(km.keys()) - {"username"},
          f"{sorted(fake)} vs {sorted(km)}")
    check("假材料确实不是真材料", fake["recovery_wrap"] != km["recovery_wrap"])
    code3, fake2 = jpost("/auth/keymaterial", {"username": f"nobody_{sfx}_xyz"})
    check("假材料对同一账号稳定（不会一会一个样）",
          fake2["recovery_wrap"] == fake["recovery_wrap"])
    code4, _ = jpost("/auth/keymaterial", {"username": ""})
    check("空账号被拒", code4 == 400, str(code4))

    # 真的用恢复码从头走一遍（模拟"忘了密码"的真实路径）
    fresh = f"forgot_{sfx}"
    mat2 = pc.new_material(fresh, "Original-Pass-1")
    reg2 = {
        "username": fresh, "agree": True,
        "kdf_algo": mat2["kdf_algo"], "kdf_salt": mat2["kdf_salt"],
        "key_wrap": mat2["key_wrap"], "key_mode": mat2["key_mode"],
        "auth_salt": mat2["auth_salt"],
        "key_check": mat2["key_check"], "key_check_plain": mat2["key_check_plain"],
        "recovery_salt": mat2["recovery_salt"], "recovery_wrap": mat2["recovery_wrap"],
    }
    reg2.update(_cred("Original-Pass-1", material=mat2)[0])
    code, body = jpost("/auth/register", reg2)
    fresh_uid = body["user_id"]
    env2 = pc.seal_object(mat2["dek"], fresh_uid, "schedule", b'{"i_forgot":"yes"}')
    req("PUT", "/sync/objects/schedule", token=body["token"],
        json={"base_revision": 0, "payload": env2, "device": "忘记密码测试"})

    # 客户端侧：完全按 phixsession.recover 的路径走
    info = cs_client_keymaterial(cfg=BASE, username=fresh)
    got_dek = pc.unwrap_dek_with_recovery(info["recovery_wrap"], mat2["recovery_code"],
                                          info["recovery_salt"], fresh)
    check("恢复码能解开", got_dek == mat2["dek"])
    proof2 = pc.prove_dek(got_dek, fresh, info["key_check"])
    # 按真实客户端（phixsession.recover）的路径：auth_salt 沿用原来的那一个，
    # 因为恢复码重置改的是登录口令 → AuthHash 要跟着换成新口令派生的那个。
    mat3 = pc.rewrap(got_dek, fresh, "Brand-New-Pass-9", "password",
                     key_check_plain=proof2, auth_salt=info["auth_salt"],
                     auth_passphrase="Brand-New-Pass-9")
    rec2 = {
        "username": fresh,
        "kdf_algo": mat3["kdf_algo"], "kdf_salt": mat3["kdf_salt"],
        "key_wrap": mat3["key_wrap"], "key_check": mat3["key_check"],
        "key_mode": "password", "dek_proof": proof2,
    }
    rec2.update(_cred("Brand-New-Pass-9", material=mat3, prefix="new_")[0])
    code, body = jpost("/auth/recover", rec2)
    check("重置成功", code == 200, f"{code} {body}")
    login_bn = {"username": fresh}
    login_bn.update(_cred("Brand-New-Pass-9", material=mat3)[0])
    code, body = jpost("/auth/login", login_bn)
    check("新密码能登录", code == 200, str(code))
    dek_new = pc.unwrap_dek(body["key_wrap"], "Brand-New-Pass-9",
                            body["kdf_salt"], fresh)
    code, obj = req("GET", "/sync/objects/schedule", token=body["token"])
    check("重置密码后老密文照样解得开（数据没丢）",
          pc.unseal_object(dek_new, fresh_uid, "schedule", obj["payload"])
          == b'{"i_forgot":"yes"}')

    # 错恢复码：应当在本地就失败，不该把请求打出去
    info_bad = cs_client_keymaterial(cfg=BASE, username=fresh)
    bad_ok = False
    try:
        pc.unwrap_dek_with_recovery(info_bad["recovery_wrap"], "AAAA-BBBB-CCCC-DDDD-EEEE-FFFF",
                                    info_bad["recovery_salt"], fresh)
        bad_ok = True
    except Exception:  # noqa: BLE001
        bad_ok = False
    check("错恢复码在本地就解不开", not bad_ok)

    # ---------- 9. 强模式：独立同步口令 ----------
    print("\n[9] 切到独立同步口令（真正端到端：服务端连实时都解不开）")
    sync_phrase = "another-secret-phrase"
    rw3 = pc.rewrap(dek, username, sync_phrase, "syncphrase", recovery_code,
                    mat["key_check_plain"], auth_salt=mat["auth_salt"],
                    auth_passphrase="Recover-999")
    rw3_body = {
        "kdf_algo": rw3["kdf_algo"], "kdf_salt": rw3["kdf_salt"],
        "key_wrap": rw3["key_wrap"], "key_check": rw3["key_check"],
        "key_mode": "syncphrase", "dek_proof": proof,
    }
    rw3_body.update(_cred("Recover-999", material=mat, salt=mat["auth_salt"])[0])
    code, body = jpost("/auth/rewrap", rw3_body, token=token_d)
    check("切模式 200 且 key_mode=syncphrase",
          code == 200 and body.get("key_mode") == "syncphrase", f"{code} {body}")
    dek_e = pc.unwrap_dek(body["key_wrap"], sync_phrase, body["kdf_salt"], username)
    check("同步口令解出同一把 DEK", dek_e == dek)
    check("同步口令 ≠ 登录密码（服务端拿不到它）", sync_phrase != "Recover-999")
    code, body2 = req("GET", "/sync/objects/schedule", token=token_d)
    check("强模式下老密文仍可解",
          pc.unseal_object(dek_e, user_id, "schedule", body2["payload"])
          == b'{"events":[],"v":2}')

    # ---------- 10. 权限边界 ----------
    print("\n[10] 权限边界")
    code, _ = req("GET", "/sync/manifest")
    check("无令牌 → 401", code == 401, str(code))
    code, _ = req("GET", "/sync/manifest", token="0" * 40)
    check("伪造令牌 → 401", code == 401, str(code))
    code, _ = req("GET", "/auth/me", token=token_d)
    check("有效令牌可读 /auth/me", code == 200, str(code))

    other = f"selftest_other_{sfx}"
    om = pc.new_material(other, "Other-Pass-1")
    reg_other = {
        "username": other, "agree": True,
        "kdf_algo": om["kdf_algo"], "kdf_salt": om["kdf_salt"],
        "key_wrap": om["key_wrap"], "recovery_salt": om["recovery_salt"],
        "auth_salt": om["auth_salt"],
        "recovery_wrap": om["recovery_wrap"], "key_check": om["key_check"],
        "key_check_plain": om["key_check_plain"],
    }
    reg_other.update(_cred("Other-Pass-1", material=om)[0])
    code, ob = jpost("/auth/register", reg_other)
    code, _ = req("GET", "/sync/objects/schedule", token=ob["token"])
    check("别的账号看不到本账号对象（404）", code == 404, str(code))
    code, _ = req("GET", "/auth/me", token=ob["token"])
    check("别人的令牌进不了我的账号", code == 200, str(code))

    code, _ = jpost("/auth/logout", {}, token=token_d)
    code2, _ = req("GET", "/auth/me", token=token_d)
    check("登出后令牌失效", code == 200 and code2 == 401, f"{code}/{code2}")

    # ---------- 11. verify（心履用） ----------
    print("\n[11] 服务端到服务端 /auth/verify")
    # 心履的 phix_verify() 对此账号会发 AuthHash（v2），所以这里也照做——
    # 发口令原文是 v1 老客户端的规矩，v2 账号发它会命中服务端护栏。
    vcred = _cred("Recover-999", material=rr)[0]
    vwrong = _cred("wrong", material=rr)[0]
    if not svc_verify:
        print("  [跳过] 未设置 PHIX_SERVICE_KEY（部署时必须设置）")
    else:
        v1 = {"username": username, **vcred}
        code, _ = jpost("/auth/verify", v1)
        check("无服务密钥 → 403", code == 403, str(code))
        code, vb = jpost("/auth/verify", v1, headers={"X-Phix-Service-Key": SERVICE_KEY})
        check("带服务密钥校验通过", code == 200 and vb.get("user_id") == user_id,
              f"{code} {vb}")
        code, _ = jpost("/auth/verify", {"username": username, **vwrong},
                        headers={"X-Phix-Service-Key": SERVICE_KEY})
        check("错密码 401", code == 401, str(code))
        check("verify 不泄露密钥材料",
              "key_wrap" not in json.dumps(vb) and "kdf_salt" not in json.dumps(vb))
        code, _ = jpost("/auth/verify", v1,
                        headers={"X-Phix-Service-Key": "wrong-key"})
        check("错服务密钥 403", code == 403, str(code))

    # ---------- 12. 输入校验 ----------
    print("\n[12] 输入校验")
    code, _ = jpost("/auth/register", {"username": "ab", "password": "123", "agree": True})
    check("短密码被拒", code == 400, str(code))
    code, _ = jpost("/auth/register", {"username": "a b c", "password": "123456",
                                       "agree": True})
    check("非法用户名被拒", code == 400, str(code))
    code, _ = jpost("/auth/register", {"username": "okname" + sfx, "password": "123456",
                                       "agree": False, "kdf_salt": "0" * 32,
                                       "key_wrap": "PHIX1.a.b", "recovery_salt": "0" * 32, "auth_salt": "0" * 32,
                                       "recovery_wrap": "PHIX1.a.b", "key_check": "PHIX1.a.b",
                                       "key_check_plain": "0" * 64})
    check("未同意条款被拒", code == 400, str(code))
    code, _ = req("PUT", "/sync/objects/schedule", token=token_a,
                  json={"base_revision": 0, "payload": "not-an-envelope"})
    check("非 PHIX1 信封被拒", code == 400, str(code))
    code, _ = req("PUT", "/sync/objects/ok", token=token_a,
                  json={"base_revision": 0,
                        "payload": "PHIX1." + "A" * (9 * 1024 * 1024)})
    check("超大 payload 被拒", code in (400, 413), str(code))

    # ---------- 13. 自测自身的规矩 ----------
    print("\n[13] 自测本身：请求体里有没有口令原文")
    check("注册请求体里没有口令明文", password not in json.dumps(body_reg,
                                                              ensure_ascii=False))
    check("注册请求体里带 auth_hash", "auth_hash" in body_reg)
    check("换密码请求体里没有口令明文",
          password not in json.dumps(chg, ensure_ascii=False)
          and new_pw not in json.dumps(chg, ensure_ascii=False))

    print("\n" + "=" * 74)
    print(f"通过 {len(PASSED)} 项，失败 {len(FAILED)} 项")
    if FAILED:
        print("失败清单：")
        for f in FAILED:
            print("  - " + f)
    print("=" * 74)
    return 1 if FAILED else 0


def _try_unwrap(envelope, pw, salt, username):
    try:
        return pc.unwrap_dek(envelope, pw, salt, username)
    except Exception:  # noqa: BLE001
        return None


def cs_client_keymaterial(cfg=None, username=""):
    """模拟客户端"忘记密码"第一步：取公开密钥材料。"""
    code, body = jpost("/auth/keymaterial", {"username": username})
    if code != 200:
        raise SystemExit(f"取密钥材料失败：{code} {body}")
    return body


if __name__ == "__main__":
    sys.exit(main())
