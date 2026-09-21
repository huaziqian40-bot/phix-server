"""P2 专项：证明「**服务器永远见不到用户的口令**」。

对应 `加密链路思路.md` §2.2 与 §11 的关键约束：「服务器永远不见 P、MK、KEK」。

    cd D:\\phix\\server
    .venv\\Scripts\\python.exe -X utf8 devtools\\test_authhash.py

要证明四件事：
  1. 网线上没有口令（连明文路径下也没有）
  2. 数据库里没有口令、也没有 AuthHash 明文
  3. **服务端手里的一切都推不出 KEK**（拿 AuthHash 算不出 KEK）
  4. 两个盐各司其职：切同步口令 / 换密码之后，登录照常（这是踩过的坑）
"""
import json
import os
import secrets
import sqlite3
import sys
import time
from pathlib import Path

import requests

sys.path.insert(0, r"D:\phl-lite-dev")
from hellopinghe import cloudsync as cs  # noqa: E402
from hellopinghe import phixcrypto as pc  # noqa: E402

SERVER = os.environ.get("PHIX_SERVER", "http://127.0.0.1:8931")
API = SERVER.rstrip("/") + "/api/v1"
DB = Path(r"D:\phix\server\db.sqlite3")
PIN = Path(r"D:\phix\_lab\authh_pin")

PASSED, FAILED = [], []


def check(name, cond, extra=""):
    (PASSED if cond else FAILED).append(name)
    print(f"  [{'OK  ' if cond else 'FAIL'}] {name}" + (f"   {extra}" if extra and not cond else ""))
    return cond


def db_row(username):
    if not DB.exists():
        return None
    con = sqlite3.connect(str(DB))
    try:
        row = con.execute(
            "select u.password, k.kdf_algo, k.kdf_salt, k.auth_salt, k.key_wrap "
            "from auth_user u join phix_user_key_material k on k.user_id=u.id "
            "where u.username=?", (username,)).fetchone()
    except sqlite3.Error:
        row = None
    finally:
        con.close()
    return row


def main():
    print("=" * 74)
    print("P2 专项：服务器永远见不到用户的口令")
    print("=" * 74)

    if PIN.exists():
        for p in PIN.glob("*.txt"):
            p.unlink()

    user = "ahprf" + secrets.token_hex(4)
    password = "Never-Seen-Pw-" + secrets.token_hex(3)
    client = cs.PhixClient(SERVER, e2e=True, pin_dir=PIN)

    # ---------- 1. 注册：网线上没有口令 ----------
    print("\n[1] 注册时网线上没有口令（**关掉信封的明文路径也一样**）")
    mat = pc.new_material(user, password)
    body = {
        "username": user, "agree": True, "device": "凭证测试",
        "kdf_algo": mat["kdf_algo"], "kdf_salt": mat["kdf_salt"],
        "auth_salt": mat["auth_salt"],
        "key_wrap": mat["key_wrap"], "key_mode": mat["key_mode"],
        "key_check": mat["key_check"], "key_check_plain": mat["key_check_plain"],
        "recovery_salt": mat["recovery_salt"], "recovery_wrap": mat["recovery_wrap"],
        "auth_hash": mat["auth_hash"],
    }
    raw = json.dumps(body, ensure_ascii=False)
    check("注册请求体里没有口令明文", password not in raw)
    check("注册请求体里有 auth_hash", "auth_hash" in body)
    check("auth_hash 是 64 位 hex", len(mat["auth_hash"]) == 64)
    r = requests.post(API + "/auth/register", json=body, timeout=30)
    check("注册成功（明文路径，故意不套信封）", r.status_code == 201,
          f"{r.status_code} {r.text[:160]}")
    uid = r.json()["user_id"]

    # ---------- 2. 数据库里没有口令、也没有 AuthHash ----------
    print("\n[2] 数据库里存的到底是什么")
    local = ("127.0.0.1" in SERVER or "localhost" in SERVER)
    row = db_row(user) if local else None
    if row is None:
        print("  [跳过] 这一节直接读本机 db.sqlite3；对着远端服务器跑时没意义")
    else:
        stored, algo, kdf_salt, auth_salt, key_wrap = row
        check("存的是 Django 的 PBKDF2 哈希", stored.startswith("pbkdf2_sha256$"),
              stored[:40])
        check("**库里没有口令明文**", password not in stored)
        check("**库里没有 AuthHash 明文**", mat["auth_hash"] not in stored)
        check("kdf_algo = v2", algo == pc.KDF_ALGO_V2, algo)
        check("auth_salt 与 kdf_salt 是两个不同的盐", kdf_salt != auth_salt,
              f"{kdf_salt} vs {auth_salt}")

    # ---------- 3. 服务端手里的一切都推不出 KEK ----------
    print("\n[3] 服务端手里的一切都推不出 KEK")
    ah = pc.derive_auth_hash(password, mat["auth_salt"], pc.KDF_ALGO_V2)
    kek = pc.derive_kek(password, mat["kdf_salt"], pc.KDF_ALGO_V2)
    check("AuthHash ≠ KEK", ah != kek)
    check("AuthHash 长度 32 字节", len(ah) == 32)
    # KEK 是从 MK 经 HKDF("enc") 来的；AuthHash 是 HKDF("auth")，两者不可互推
    mk = pc.derive_mk(password, mat["auth_salt"])
    check("HKDF 两条链互不相同",
          pc._hkdf_sha256(mk, bytes.fromhex(mat["auth_salt"]), pc.AUTH_INFO, 32)
          != pc._hkdf_sha256(mk, bytes.fromhex(mat["auth_salt"]), pc.ENC_INFO, 32))
    # 服务器能拿到的是 auth_salt + kdf_salt + key_wrap + PBKDF2(AuthHash)
    # 没有口令 / MK / KEK 中的任何一个，key_wrap 就打不开
    check("没有 KEK 打不开 key_wrap",
          _cannot_open(mat["key_wrap"], b"\x00" * 32, "phix/v1/identity|" + user))

    # ---------- 4. 登录：客户端自动发 AuthHash ----------
    print("\n[4] 登录：客户端自动发 AuthHash（口令不出本机）")
    c2 = cs.PhixClient(SERVER, e2e=True, pin_dir=PIN)
    info = c2.login(user, password, "第二台")
    check("登录成功", bool(info.get("token")))
    dek = pc.unwrap_dek(info["key_wrap"], password, info["kdf_salt"], user,
                        info["kdf_algo"])
    check("用口令本地解出 DEK", dek == mat["dek"])
    # 拿 AuthHash 当"口令"去登录必须失败 —— 说明服务器认的是派生值、不是口令
    r2 = requests.post(API + "/auth/login",
                       json={"username": user, "auth_hash": "ab" * 32}, timeout=15)
    check("随便编一个 auth_hash 登不进", r2.status_code == 401, str(r2.status_code))

    # ---------- 5. 两个盐各司其职（踩过的坑） ----------
    print("\n[5] 切同步口令 / 换密码之后，登录必须照常")
    from hellopinghe import phixsession as ps

    lab = Path(r"D:\phix\_lab\authh")
    if lab.exists():
        import shutil

        shutil.rmtree(lab)
    lab.mkdir(parents=True, exist_ok=True)
    os.environ["PHLL_DATA_DIR"] = str(lab)
    for m in [k for k in list(sys.modules) if k.startswith("hellopinghe")]:
        del sys.modules[m]
    from hellopinghe import phixsession as ps2

    u2 = "ahsalt" + secrets.token_hex(4)
    pw2 = "Two-Salt-Test-1"
    phrase = "my-sync-phrase-2"
    st = ps2.SESSION.register(SERVER, u2, pw2)
    check("注册成功", st["logged_in"] and st["unlocked"])
    before = db_row(u2) if local else None
    if before:
        check("注册时 auth_salt 与 kdf_salt 都写进去了",
              bool(before[3]) and bool(before[2]))
    else:
        print("  [跳过] 数据库快照（远端服务器）")

    ps2.SESSION.set_sync_passphrase(pw2, phrase)
    after = db_row(u2) if local else None
    if after and before:
        check("切同步口令后 **auth_salt 没变**", after[3] == before[3],
              f"{before[3]} -> {after[3]}")
        check("切同步口令后 kdf_salt 变了（KEK 换了）", after[2] != before[2])
    ps2.SESSION.logout()
    st = ps2.SESSION.login(SERVER, u2, pw2, sync_passphrase=phrase)
    check("**切完之后用登录密码还能登**（这就是两个盐分开的意义）",
          st["logged_in"] and st["unlocked"], str(st)[:200])

    # syncphrase 模式下改登录密码：DEK 不动，但 AuthHash 必须换
    ps2.SESSION.change_password(pw2, "Two-Salt-New-2")
    ps2.SESSION.logout()
    try:
        ps2.SESSION.login(SERVER, u2, pw2, sync_passphrase=phrase)
        check("旧密码失效", False, "旧密码还能登")
    except Exception:  # noqa: BLE001
        check("旧密码失效", True)
    st = ps2.SESSION.login(SERVER, u2, "Two-Salt-New-2", sync_passphrase=phrase)
    check("**换完密码用新密码能登**", st["logged_in"] and st["unlocked"],
          str(st)[:200])
    after2 = db_row(u2) if local else None
    if after2 and before:
        check("换密码后 auth_salt 仍然没变", after2[3] == before[3])

    print("\n" + "=" * 74)
    print(f"通过 {len(PASSED)} 项，失败 {len(FAILED)} 项")
    if FAILED:
        for f in FAILED:
            print("  - " + f)
    print("=" * 74)
    return 1 if FAILED else 0


def _cannot_open(envelope, key, aad_text) -> bool:
    """用一把错的钥匙去开信封：**打不开**返回 True（我们希望它打不开）。"""
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM

    try:
        rest = envelope[len("PHIX1."):]
        n, c = rest.split(".", 1)
        AESGCM(key).decrypt(pc.b64d(n), pc.b64d(c), aad_text.encode())
        return False           # 居然开了 → 调用方会报错
    except Exception:  # noqa: BLE001
        return True            # 打不开 = 正确


if __name__ == "__main__":
    sys.exit(main())
