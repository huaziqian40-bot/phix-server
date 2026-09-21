"""专项：v2 账号收到「口令原文」凭据时的护栏（静默降级防护）。

**起因**：0 号客户端在"切同步口令"这条路上漏发了 `auth_hash`，只发了
`password` 原文。服务端 `_credential()` 不关心凭证是"哪一代"，于是照收，
`set_password(原文)` 把凭证写坏 —— 新旧密码 + 同步口令**全部失效，且不报任何错**。
这类静默降级最难查，所以加了 `_credential_guard()`：v2 账号 + 口令原文
= 要么记 warning 放行（`PHIX_V2_PLAINTEXT_OK=1`，兼容过渡期），
要么硬拒绝（`=0`，彻底杜绝）。**无论哪种，都不允许再写坏凭证。**

    cd D:\\phix\\server
    .venv\\Scripts\\python.exe -X utf8 devtools\\test_v2_guard.py

分两段：
  A. 纯函数单测（用 Django ORM 直接查库、不经过网络）——覆盖严格模式
  B. 线上接口实测（127.0.0.1:8931）——覆盖默认宽松模式下的拒绝与正常路径
"""
import json
import os
import secrets
import sqlite3
import sys
from pathlib import Path

import requests

sys.path.insert(0, r"D:\phl-lite-dev")
from hellopinghe import phixcrypto as pc  # noqa: E402

SERVER = os.environ.get("PHIX_SERVER", "http://127.0.0.1:8931")
API = SERVER.rstrip("/") + "/api/v1"
DB = Path(r"D:\phix\server\db.sqlite3")

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


def check_db(name, cond, extra=""):
    """库快照类断言：**读不到库时（对着远端跑）跳过，而不是判通过或失败。**"""
    if DB.exists() and ("127.0.0.1" in SERVER or "localhost" in SERVER):
        return check(name, cond, extra)
    print(f"  [跳过] {name}（读不到对方的库）")
    return True


def msg_of(r):
    return (body_of(r).get("error") or {}).get("message", "")


# ---------------- A. 纯函数单测（严格模式） ----------------

class _FakeKeys:
    def __init__(self, algo):
        self.kdf_algo = algo


class _FakeUser:
    def __init__(self, algo, uid=1):
        self.id = uid
        self.phix_keys = _FakeKeys(algo) if algo else None


def unit_tests():
    print("\n[A] _credential_guard 纯函数单测（含严格模式 PHIX_V2_PLAINTEXT_OK=0）")
    os.environ.setdefault("DJANGO_SETTINGS_MODULE", "phixsvc.settings")
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
    import django

    django.setup()
    from django.conf import settings
    from django.test import override_settings

    from api.views_auth import _credential_guard

    v2 = _FakeUser(pc.KDF_ALGO_V2)
    v1 = _FakeUser(pc.KDF_ALGO_V1)
    nowhere = _FakeUser(None)

    # 凭证本来就是 AuthHash → 一律放行，不管什么账号
    for u, tag in ((v2, "v2"), (v1, "v1")):
        e, _m = _credential_guard(u, "auth_hash", "auth_hash")
        check(f"{tag} 账号发 auth_hash：放行", e is None, str(e))

    # v1 账号发口令原文 → 老行为，放行
    e, mig = _credential_guard(v1, "password", "auth_hash", allow_plaintext=True)
    check("v1 账号发口令原文：放行（老行为）", e is None, str(e))
    check("v1 账号不触发迁移标记", mig is False, str(mig))

    # 没有密钥材料的账号（理论上不该有）→ 按非 v2 处理，不误伤
    e, _m = _credential_guard(nowhere, "password", "auth_hash", allow_plaintext=True)
    check("没有密钥材料的账号：不误伤", e is None, str(e))

    # v2 账号发口令原文（默认宽松）→ 放行，但调用方拿得到迁移标记
    with override_settings(PHIX_V2_PLAINTEXT_OK=True):
        e, mig = _credential_guard(v2, "password", "auth_hash",
                                   allow_plaintext=True, can_migrate=True)
        check("v2 账号发口令原文（宽松模式）：放行但标记可迁移", e is None and mig,
              f"{e} {mig}")
        e, _m = _credential_guard(v2, "password", "auth_hash", allow_plaintext=False)
        check("v2 账号发口令原文（不许原文）：拒绝", e is not None, str(e))
        if e:
            check("拒绝消息点名要 auth_hash 字段", "auth_hash" in e[1], e[1])

    # v2 账号发口令原文（严格模式）→ 硬拒绝，且文案点名该补哪个字段
    with override_settings(PHIX_V2_PLAINTEXT_OK=False):
        e, _m = _credential_guard(v2, "password", "old_auth_hash",
                                  allow_plaintext=True, can_migrate=True)
        check("严格模式：即便调用方允许原文也硬拒绝", e is not None, str(e))
        if e:
            check("严格模式文案点名 old_auth_hash", "old_auth_hash" in e[1], e[1])
            check("严格模式错误码是 bad_request", e[0] == "bad_request", e[0])

    # 换密码接口传的是带前缀的字段名，护栏不能串味
    e, _m = _credential_guard(v2, "password", "new_auth_hash", allow_plaintext=False)
    check("字段名按调用点区分（new_auth_hash）",
          e is not None and "new_auth_hash" in e[1], str(e))
    check("默认（settings 未覆盖）是宽松模式",
          getattr(settings, "PHIX_V2_PLAINTEXT_OK", None) is True,
          str(getattr(settings, "PHIX_V2_PLAINTEXT_OK", None)))


# ---------------- B. 线上接口实测 ----------------

def db_credential(username):
    """直接读库：看 Django 存的凭证哈希有没有被换掉。

    **只对本机服务器有意义**：远端（.41）的库在对方机器上，这里读不到，
    返回 None，调用方据此跳过这一节（而不是判失败）。
    """
    if not DB.exists():
        return None
    con = sqlite3.connect(str(DB))
    try:
        row = con.execute(
            "select u.password, k.kdf_algo from auth_user u "
            "join phix_user_key_material k on k.user_id=u.id "
            "where u.username=?", (username,)).fetchone()
    except sqlite3.Error:
        row = None
    finally:
        con.close()
    return row


def register(username, password):
    mat = pc.new_material(username, password)
    body = {
        "username": username, "agree": True, "device": "护栏测试",
        "kdf_algo": mat["kdf_algo"], "kdf_salt": mat["kdf_salt"],
        "auth_salt": mat["auth_salt"], "key_wrap": mat["key_wrap"],
        "key_mode": mat["key_mode"], "key_check": mat["key_check"],
        "key_check_plain": mat["key_check_plain"],
        "recovery_salt": mat["recovery_salt"],
        "recovery_wrap": mat["recovery_wrap"], "auth_hash": mat["auth_hash"],
    }
    r = requests.post(API + "/auth/register", json=body, timeout=30)
    return mat, r


def live_tests():
    print("\n[B] 线上接口实测：" + SERVER)
    ping = body_of(requests.get(API + "/ping", timeout=15))
    check("服务器支持 v2 kdf", pc.KDF_ALGO_V2 in ping.get("kdf_algos", []),
          str(ping.get("kdf_algos")))

    user = "v2guard" + secrets.token_hex(4)
    pw = "Guard-Old-Pw-" + secrets.token_hex(3)
    new_pw = "Guard-New-Pw-" + secrets.token_hex(3)
    mat, r = register(user, pw)
    check("v2 账号注册成功", r.status_code == 201,
          f"{r.status_code} {r.text[:160]}")
    if r.status_code != 201:
        return
    token = body_of(r)["token"]
    local = "127.0.0.1" in SERVER or "localhost" in SERVER
    before = db_credential(user) if local else None
    if before:
        check("库里凭证是 PBKDF2 哈希", before[0].startswith("pbkdf2_sha256$"),
              str(before)[:60])
    else:
        print("  [跳过] 直读数据库快照（对着远端服务器跑时读不到对方的库）")

    H = {"Authorization": "Bearer " + token}

    # [1] 换密码：只发口令原文（**没有** auth_hash）→ 必须被拒
    print("\n[1] 换密码漏发 auth_hash（就是踩过的那个坑）")
    proof = pc.prove_dek(mat["dek"], user, mat["key_check"])
    r = requests.post(API + "/auth/password", headers=H, timeout=30, json={
        "old_password": pw, "new_password": new_pw, "dek_proof": proof,
    })
    check("换密码（只发口令原文）被拒", r.status_code == 400,
          f"{r.status_code} {r.text[:200]}")
    check("拒绝原因点名 old_auth_hash", "old_auth_hash" in msg_of(r), msg_of(r))
    after = db_credential(user)
    check_db("**库里凭证一个字节都没变**（没被写坏）", after == before,
             f"{str(before)[:40]} -> {str(after)[:40]}")
    r = requests.post(API + "/auth/login", timeout=15,
                      json={"username": user, "auth_hash": mat["auth_hash"]})
    check("原密码照常能登（凭证没坏）", r.status_code == 200,
          f"{r.status_code} {r.text[:160]}")

    # [2] 换密码：正确发 auth_hash → 成功
    print("\n[2] 换密码正确姿势（发 old_/new_ 两个 AuthHash）")
    new_ah = pc.auth_hash_hex(new_pw, mat["auth_salt"], pc.KDF_ALGO_V2)
    r = requests.post(API + "/auth/password", headers=H, timeout=30, json={
        "old_auth_hash": mat["auth_hash"], "new_auth_hash": new_ah,
        "dek_proof": proof,
    })
    check("换密码成功", r.status_code == 200, f"{r.status_code} {r.text[:200]}")
    r = requests.post(API + "/auth/login", timeout=15,
                      json={"username": user, "auth_hash": new_ah})
    check("用新密码能登", r.status_code == 200, f"{r.status_code} {r.text[:160]}")
    r = requests.post(API + "/auth/login", timeout=15,
                      json={"username": user, "auth_hash": mat["auth_hash"]})
    check("旧密码失效", r.status_code == 401, str(r.status_code))

    # [3] 重新包裹：只发口令原文 → 必须被拒
    print("\n[3] 重新包裹（切同步口令）漏发 auth_hash")
    snapshot = db_credential(user)      # 步骤 [2] 刚换过密码，重新取基准
    r = requests.post(API + "/auth/rewrap", headers=H, timeout=30, json={
        "password": new_pw, "dek_proof": proof,
        "kdf_algo": pc.KDF_ALGO_V2, "kdf_salt": pc.new_salt(),
        "auth_salt": mat["auth_salt"], "key_mode": "syncphrase",
        "key_wrap": mat["key_wrap"],
    })
    check("重新包裹（只发口令原文）被拒", r.status_code == 400,
          f"{r.status_code} {r.text[:200]}")
    check("拒绝原因点名 auth_hash", "auth_hash" in msg_of(r), msg_of(r))
    check_db("库里凭证仍未被写坏", db_credential(user) == snapshot,
             str(db_credential(user))[:50])

    # [4] 忘记密码：v2 账号发口令原文 → 必须被拒（旧客户端会踩）
    print("\n[4] 忘记密码重置：v2 账号发口令原文")
    r = requests.post(API + "/auth/recover", timeout=30, json={
        "username": user, "new_password": new_pw, "dek_proof": proof,
        "kdf_algo": pc.KDF_ALGO_V2, "kdf_salt": mat["kdf_salt"],
        "auth_salt": mat["auth_salt"], "key_wrap": mat["key_wrap"],
    })
    check("恢复码重置（只发口令原文）被拒", r.status_code == 400,
          f"{r.status_code} {r.text[:200]}")
    check("拒绝原因点名 new_auth_hash", "new_auth_hash" in msg_of(r), msg_of(r))

    # [5] v1 账号：发口令原文是**正当**行为，不能被误伤
    print("\n[5] v1 老账号发口令原文（不许误伤）")
    v1user = "v2guardv1" + secrets.token_hex(4)
    v1pw = "Legacy-Pw-" + secrets.token_hex(3)
    m1 = pc.new_material(v1user, v1pw, kdf_algo=pc.KDF_ALGO_V1)
    b1 = {
        "username": v1user, "agree": True, "device": "v1 老客户端",
        "kdf_algo": m1["kdf_algo"], "kdf_salt": m1["kdf_salt"],
        "key_wrap": m1["key_wrap"], "key_mode": m1["key_mode"],
        "key_check": m1["key_check"], "key_check_plain": m1["key_check_plain"],
        "recovery_salt": m1["recovery_salt"],
        "recovery_wrap": m1["recovery_wrap"], "password": v1pw,
    }
    r = requests.post(API + "/auth/register", json=b1, timeout=30)
    check("v1 账号注册成功（发口令原文）", r.status_code == 201,
          f"{r.status_code} {r.text[:160]}")
    if r.status_code == 201:
        t1 = body_of(r)["token"]
        proof1 = pc.prove_dek(m1["dek"], v1user, m1["key_check"])
        new1 = "Legacy-New-" + secrets.token_hex(3)
        r = requests.post(API + "/auth/password",
                          headers={"Authorization": "Bearer " + t1}, timeout=30,
                          json={"old_password": v1pw, "new_password": new1,
                                "dek_proof": proof1})
        check("v1 账号换密码照旧可用（没被 v2 护栏误伤）", r.status_code == 200,
              f"{r.status_code} {r.text[:200]}")
        r = requests.post(API + "/auth/login", timeout=15,
                          json={"username": v1user, "password": new1})
        check("v1 账号用新口令能登", r.status_code == 200, str(r.status_code))

    # [6] 服务端日志里必须留下 warning（静默降级不再静默）
    print("\n[6] 服务端日志留下 warning 痕迹")
    logf = Path(r"D:\phix\server\logs\phix.log")
    if logf.exists() and "127.0.0.1" in SERVER:
        tail = logf.read_text(encoding="utf-8", errors="replace")[-20000:]
        hit = [ln for ln in tail.splitlines() if "v2 账号收到口令原文凭据" in ln]
        check("日志里出现了护栏 warning", bool(hit), "没找到")
        if hit:
            print("      " + hit[-1][:150])
    else:
        print("  [跳过] 只看本机日志（远端服务器/无日志文件）")


def main():
    print("=" * 74)
    print("v2 → 口令原文 静默降级护栏专项")
    print("=" * 74)
    unit_tests()
    try:
        live_tests()
    except requests.RequestException as e:
        check("线上接口实测", False, f"连不上 {SERVER}：{e}")
    print("\n" + "=" * 74)
    print(f"通过 {len(PASSED)} 项，失败 {len(FAILED)} 项")
    for f in FAILED:
        print("  - " + f)
    print("=" * 74)
    return 1 if FAILED else 0


if __name__ == "__main__":
    sys.exit(main())
