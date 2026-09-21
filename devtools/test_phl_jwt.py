"""PHL（Node 客户端）· P3 JWT + refresh 自动续期 —— **对着真服务端**跑完整链路。

    cd D:\\phix\\server
    .venv\\Scripts\\python.exe -X utf8 devtools\\test_phl_jwt.py

两段：

  [A] 正式本地服务（8931，15 分钟 access / 120 秒宽限）
      登录 → access 调业务 → 落盘位置（三个键分开、DEK 不落盘）→ 会话列表 →
      注销另一台设备 → 登出后两串令牌都失效。

  [B] 短命令牌服务（8933，access_ttl=5s、grace=0；先 `devtools/run_short.py start`）
      等令牌过期 → **不做任何手工续期**，让 PHL 自己的客户端去撞 401 →
      自动续期 + 重试**恰好一次**成功 → 服务端那边的 refresh 哈希确实变了
      （=真的轮换过）→ 再等一轮仍能续（没被判重放）→ 登出后两串都失效。

为什么单独一个脚本：`test_jwt.py` 用 Python 手写的客户端动作，验的是**服务端**；
这里用 PHL 自己的 `electron/phix-session.cjs` / `cloudsync.cjs`（Node，由
`devtools/phl_jwt_driver.cjs` 驱动），验的是**客户端那一层真的接上了**：
落盘的键名、401 → 续期 → 重试只一次、续期只用一次、登出清两组令牌。

账号一律 `phljwt` 前缀（`clean_dev_db.py` 的 PREFIXES 里已加），跑完自己清。
本脚本**只在自己建的临时目录里写文件**，绝不碰任何真实 `data/`。
"""
import json
import os
import secrets
import shutil
import sqlite3
import subprocess
import sys
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
DRIVER = HERE / "phl_jwt_driver.cjs"
LAB_ROOT = Path(os.environ.get("PHIX_LAB_DIR", r"D:\phix\_lab"))
LAB = LAB_ROOT / "phljwt"
SERVER = os.environ.get("PHIX_SERVER", "http://127.0.0.1:8931")
SHORT = os.environ.get("PHIX_SHORT_SERVER", "http://127.0.0.1:8933")
SHORT_DB = LAB_ROOT / "short_db.sqlite3"

PASSED, FAILED = [], []


def check(name, cond, extra=""):
    (PASSED if cond else FAILED).append(name)
    print(f"  [{'OK  ' if cond else 'FAIL'}] {name}" + (f"   {extra}" if extra and not cond else ""))
    return cond


def node(command, *args, timeout=600):
    """跑一次 PHL 侧的驱动，取回它最后一行 JSON。**不打印令牌、口令任何内容**。"""
    env = dict(os.environ, PYTHONUTF8="1")
    proc = subprocess.run(["node", str(DRIVER), command, *[str(a) for a in args]],
                          capture_output=True, text=True, encoding="utf-8",
                          errors="replace", env=env, cwd=str(HERE), timeout=timeout)
    for line in reversed((proc.stdout or "").splitlines()):
        if line.startswith("__PHL_RESULT__"):
            return json.loads(line[len("__PHL_RESULT__"):])
    return {"ok": False, "error": "驱动没有输出结果",
            "stdout": (proc.stdout or "")[-400:], "stderr": (proc.stderr or "")[-400:]}


def workspace(name, server, username):
    """给 PHL 会话层一个**独立**的数据目录（临时、跑完删）。"""
    root = LAB / name
    if root.exists():
        shutil.rmtree(root)
    data = root / "data"
    (data / ".sync" / "pinned").mkdir(parents=True, exist_ok=True)
    (data / "settings.yaml").write_text(
        "version: 1\n"
        "phix:\n"
        f"  server: '{server}'\n"
        f"  username: '{username}'\n"
        "  e2e: false\n"
        "secrets_extra: {}\n",
        encoding="utf-8")
    return data


def secrets_of(data_dir):
    """读回 `secrets_extra` 段 —— **只在内存里比对/看长度，绝不打印值**。

    注意键名自己带冒号（`phix:token`），所以按**最后一个**冒号切，不能从头切。
    """
    text = (Path(data_dir) / "settings.yaml").read_text(encoding="utf-8")
    out, inside = {}, False
    for line in text.splitlines():
        if line.startswith("secrets_extra:"):
            inside = True
            continue
        if inside:
            if line and not line.startswith(" "):
                break
            if ":" in line:
                key, _, value = line.strip().rpartition(":")
                out[key.strip()] = value.strip().strip("'\"")
    return out


def refresh_hashes(db_path, username):
    """直接只读查库，看这个账号各会话当前的 refresh **哈希**。

    哈希不是凭据（也没法反推），但**能证明"轮换真的发生过"** —— 客户端是不是
    真把新那串存下来了，服务端这边说了算。返回值绝不打印。
    """
    if not Path(db_path).exists():
        return []
    con = sqlite3.connect(f"file:{Path(db_path).as_posix()}?mode=ro", uri=True)
    try:
        rows = con.execute(
            "SELECT s.refresh_hash FROM phix_token_session s "
            "JOIN auth_user u ON u.id = s.user_id WHERE u.username = ? "
            "ORDER BY s.id", (username,)).fetchall()
    finally:
        con.close()
    return [row[0] for row in rows]


def stored_fingerprints(data_dir):
    """从盘上两串令牌各算一个短指纹（sha256 前 8 位）—— 只用来比"是不是同一串"。"""
    import hashlib
    secrets_now = secrets_of(data_dir)
    out = {}
    for label, key in (("access", "phix:access_token"), ("refresh", "phix:refresh_token")):
        value = secrets_now.get(key) or ""
        out[label] = hashlib.sha256(value.encode("utf-8")).hexdigest()[:8] if value else ""
    return out


def new_account(tag):
    return f"phljwt{tag}{secrets.token_hex(3)}", "Phl-Jwt-Pw-" + secrets.token_hex(3)


def banner(text):
    print("\n" + "=" * 74)
    print(text)
    print("=" * 74)


def part_a():
    user, password = new_account("a")
    data = workspace("main", SERVER, user)
    print(f"\n[A] 正式服务 {SERVER}   账号 {user}")
    print(f"    临时数据目录：{data}")

    out = node("jwt-flow", SERVER, user, password, data)
    if not out.get("ok"):
        check("PHL 侧主流程跑完（登录/业务/会话/登出）", False,
              json.dumps(out, ensure_ascii=False)[:600])
        return

    login = out.get("login") or {}
    check("登录成功且已解锁（DEK 只在内存里）",
          bool(login.get("logged_in") and login.get("unlocked")),
          json.dumps(login, ensure_ascii=False)[:200])
    check("登录后三串令牌都有（老式 token + access + refresh）",
          bool(login.get("has_token") and login.get("has_access_token") and login.get("has_refresh_token")),
          json.dumps(login, ensure_ascii=False)[:200])

    check("拿 access 调业务（/auth/me）成功", bool((out.get("me") or {}).get("ok")),
          json.dumps(out.get("me"), ensure_ascii=False)[:200])
    # 驱动把服务端 `/auth/me` 的 `device`（jwt / session_id 在那儿）拍平成了
    # `me.jwt` + `me.session_id`：**JWT 会话**才会是 jwt=true 且 session_id 非空，
    # 老式长期令牌那条路 session_id 是 null。
    me = out.get("me") or {}
    check("/auth/me 认出这是 **JWT 会话**（jwt 为真、带 session_id）",
          me.get("jwt") is True and bool(me.get("session_id")),
          json.dumps(me, ensure_ascii=False)[:200])

    sessions = out.get("sessions") or []
    check("会话列表拿得到（sessions 形态）", bool(sessions),
          json.dumps(sessions, ensure_ascii=False)[:300])
    check("列表里有一台标成 current（本机）", (out.get("current_count") or 0) >= 1,
          f"current_count={out.get('current_count')}")
    check("两台设备 = 两条会话（第二台是再登一次的）", len(sessions) >= 2, str(len(sessions)))
    check("**列表里没有 refresh 明文**", "refresh_token" not in json.dumps(sessions, ensure_ascii=False))
    check("列表项带 device/created_at/last_seen_at/expires_at",
          all(key in sessions[0] for key in ("device", "created_at", "last_seen_at", "expires_at")),
          json.dumps(sessions[0], ensure_ascii=False)[:200])

    check("注销**另一台**设备成功", int((out.get("revoke") or {}).get("revoked") or 0) >= 1,
          json.dumps(out.get("revoke"), ensure_ascii=False)[:200])
    check("**被注销那台的 access 立刻失效**（401）", out.get("other_revoked") == 401,
          str(out.get("other_revoked")))
    check("本机不受影响（200）", out.get("mine_still_ok") == 200, str(out.get("mine_still_ok")))

    logout = out.get("logout") or {}
    check("登出后本地不再处于登录态", logout.get("logged_in") is False,
          json.dumps(logout, ensure_ascii=False)[:200])
    check("登出后本地两组令牌都清了（has_access/has_refresh 都是假）",
          logout.get("has_access_token") is False and logout.get("has_refresh_token") is False,
          json.dumps(logout, ensure_ascii=False)[:200])

    after = out.get("after_logout") or {}
    check("登出后拿旧 access 打业务 → 401", after.get("status") == 401, str(after.get("status")))
    check("登出后拿旧 refresh 续期 → 401（服务端把两串一起作废）",
          after.get("refresh_status") == 401, str(after.get("refresh_status")))

    secrets_now = secrets_of(data)
    check("三个键都从磁盘上清掉了",
          not any(key in secrets_now for key in
                  ("phix:token", "phix:access_token", "phix:refresh_token")),
          str(sorted(secrets_now)))


def part_b():
    user, password = new_account("b")
    data = workspace("short", SHORT, user)
    print(f"\n[B] 短命令牌服务 {SHORT}   账号 {user}")
    print(f"    临时数据目录：{data}")

    first = node("jwt-login", SHORT, user, password, data)
    if not first.get("ok"):
        print("    [注意] 短命令牌服务没起来：先 `python -X utf8 devtools/run_short.py start`")
        check("短命令牌服务可用（run_short.py start）", False,
              json.dumps(first, ensure_ascii=False)[:400])
        return

    secrets_first = secrets_of(data)
    hashes_before = refresh_hashes(SHORT_DB, user)
    check("在短命令牌服务器上注册成功（独立库）",
          bool((first.get("status") or {}).get("logged_in")), json.dumps(first.get("status"), ensure_ascii=False)[:200])
    check("刚登录时业务请求可用", bool((first.get("me") or {}).get("ok")))
    check("三串令牌**分开三个键**落盘（互不覆盖）",
          all(key in secrets_first for key in ("phix:token", "phix:access_token", "phix:refresh_token")),
          str(sorted(secrets_first)))
    check("access 是 JWT 形状（三段、两个点）",
          secrets_first.get("phix:access_token", "").count(".") == 2)
    check("refresh 是那串 40 字节 url-safe（不是 JWT、也不等于 access）",
          len(secrets_first.get("phix:refresh_token", "")) >= 40
          and secrets_first.get("phix:access_token") != secrets_first.get("phix:refresh_token"))
    settings_text = (Path(data) / "settings.yaml").read_text(encoding="utf-8")
    check("**DEK/密钥材料不落盘**（没有 key_wrap / kdf_salt / key_check / dek）",
          not any(word in settings_text for word in ("key_wrap", "kdf_salt", "key_check", "dek")))
    check("服务端侧能看到这条会话的 refresh 哈希（用来对照轮换）", bool(hashes_before),
          f"{len(hashes_before)} 条")

    print("    等 11 秒让 access 过期（ttl 5s + leeway 1s + 余量）……")
    time.sleep(11)

    # 过期之后**不手工续期**：让 PHL 自己的客户端去撞 401
    after = node("jwt-me", SHORT, user, password, data)
    check("过期后发业务请求仍然成功（客户端自动续期 + 重试）",
          bool(after.get("ok") and (after.get("data") or {}).get("user_id")),
          json.dumps(after, ensure_ascii=False)[:400])
    check("**业务请求只发了两次**（第一次 401 + 续期后重试一次，绝不循环）",
          after.get("attempts") == 2, str(after.get("attempts")))
    check("续期恰好调了一次 /auth/refresh", after.get("refreshCalls") == 1, str(after.get("refreshCalls")))
    check("续期请求是**免认证**的（没带 Bearer）", after.get("refreshAuthSent") is False,
          str(after.get("refreshAuthSent")))

    secrets_now = secrets_of(data)
    hashes_after = refresh_hashes(SHORT_DB, user)
    print(f"    [指纹] 登录时 {json.dumps(first.get('stored'))} → 本轮用了 "
          f"{json.dumps(after.get('used'))} → 续期后内存里 {json.dumps(after.get('now'))} "
          f"→ 盘上 {json.dumps(stored_fingerprints(data))}")
    check("续期后 access 落盘的是**新**那串（与登录时那串不同）",
          bool(secrets_now.get("phix:access_token"))
          and secrets_now.get("phix:access_token") != secrets_first.get("phix:access_token"))
    check("续期后**新 refresh 也落盘了**（响应里有就必须存）",
          bool(secrets_now.get("phix:refresh_token"))
          and secrets_now.get("phix:refresh_token") != secrets_first.get("phix:refresh_token"),
          str(stored_fingerprints(data)))
    check("**服务端侧的 refresh 哈希变了 = 真的轮换过**（客户端存下了新那串）",
          bool(hashes_after) and hashes_after != hashes_before,
          f"{len(hashes_before)} -> {len(hashes_after)}")
    check("续期**没有**把老式 `phix:token` 抹掉（语义不变）",
          secrets_now.get("phix:token") == secrets_first.get("phix:token"))

    # 再等一轮：新那串 refresh 必须还能用（证明没被判重放、客户端也没用旧的连点）
    print("    再等 11 秒，验证**新**那串还能继续续（没被判重放）……")
    time.sleep(11)
    again = node("jwt-me", SHORT, user, password, data)
    check("第二轮过期后照样自动续期成功（新 refresh 有效、没被判重放）",
          bool(again.get("ok") and (again.get("data") or {}).get("user_id")),
          json.dumps(again, ensure_ascii=False)[:400])
    check("第二轮同样只重试一次、只续期一次",
          again.get("attempts") == 2 and again.get("refreshCalls") == 1,
          f"attempts={again.get('attempts')} refreshCalls={again.get('refreshCalls')}")

    final = node("jwt-logout", SHORT, user, password, data)
    check("登出后本地不再登录且两组令牌都清掉",
          bool(final.get("ok")) and (final.get("logout") or {}).get("logged_in") is False
          and (final.get("logout") or {}).get("has_refresh_token") is False,
          json.dumps(final.get("logout"), ensure_ascii=False)[:200])
    after_logout = final.get("after_logout") or {}
    check("登出后旧 access 打业务 → 401", after_logout.get("status") == 401, str(after_logout.get("status")))
    check("登出后旧 refresh 续期 → 不是 200（服务端把这条会话整条作废了）",
          after_logout.get("refresh_status") not in (0, 200, None),
          json.dumps(after_logout, ensure_ascii=False)[:200])


def main():
    LAB.mkdir(parents=True, exist_ok=True)
    banner("PHL（Node）· P3 JWT + refresh 自动续期（真实服务端）")
    try:
        part_a()
        part_b()
    finally:
        # 只删**自己建的**临时目录（绝不动任何真实 data/）
        for name in ("main", "short"):
            shutil.rmtree(LAB / name, ignore_errors=True)
        try:
            LAB.rmdir()
        except OSError:
            pass

    banner("")
    print(f"通过 {len(PASSED)} 项，失败 {len(FAILED)} 项")
    for name in FAILED:
        print("  - " + name)
    print("=" * 74)
    if FAILED:
        print("\n有失败项：先看上面的 [FAIL] 行。")
    print("\n清理测试账号（本地库回到 0 账号 / 0 对象）：")
    print("  $env:PHIX_CLEAN_YES='1'; .venv\\Scripts\\python.exe -X utf8 devtools\\clean_dev_db.py")
    print(f"  $env:PHIX_DB='{SHORT_DB}'; ... 再跑一次（短命令牌服务那台是独立库）")
    return 1 if FAILED else 0


if __name__ == "__main__":
    sys.exit(main())
