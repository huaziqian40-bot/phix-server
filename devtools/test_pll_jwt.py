"""PLL 客户端接入 phix P3（Ed25519 JWT + refresh 轮换）—— 端到端测试。

    cd D:\\phix\\server
    .venv\\Scripts\\python.exe -X utf8 devtools\\test_pll_jwt.py

测的是 **PLL 客户端那侧**（`D:\\phl-lite-dev\\hellopinghe\\cloudsync.py` 与
`phixsession.py`）是否真的做到了 P3 接入说明 §2 要求的事。按**实跑顺序**编号：

  [1] 登录/注册拿到**两组**令牌：access（JWT）当 Bearer、refresh 单独落盘（secrets_extra）
  [2] 访问令牌过期（401 + `token_expired`）→ **自动续期一次 + 用新令牌重试原请求**
      （连"续期几次、重试几次"都数过：续期 1 次、业务请求 2 次，不多不少）
  [3] 续期成功后**新的 refresh 被持久化**（rotated:true 那一路）
  [4] refresh **不能当 Bearer** 用；这种失败不会触发续期
  [5] 登出：服务端会话立刻注销 + 本地 `phix:token` / `phix:access_token` /
      `phix:refresh_token`（以及旧键 `phix:refresh`）**全都清掉**
  [6] 宽限期内重复续期（`rotated:false`）→ **不覆盖本地 refresh、不报错**
  [7] 磁盘上那串 refresh 真的还能换出令牌（不是空写）
  [8] `/auth/devices` 列出会话；能注销**另一台设备**（那台立刻掉线，本机不受影响）；
      会话被注销时**不去**续期
  [9] 续期失败**不重试**：只发一次 `/auth/refresh`，给一句中文错误
  [10] 访问令牌**已过期**时点「退出登录」→ 先续期再注销（服务端不留下活会话）
  [11] 全程 **DEK 不落盘**（副本数据根里没有 DEK、没有密钥材料字段）

两台服务器，各测各的：
  · `8933` —— `python -X utf8 devtools/run_short.py start` 起的短命令牌服务器
    （access_ttl=5s / leeway=1s / **grace=0** / 独立库）。过期与"重放"边界靠它。
  · `8934` —— 本脚本**自己起自己停**的临时服务器（复用 `run_short.py` 的启动逻辑，
    只把写死的端口/库/pid 指到 `_lab/plljwt/` 下，**绝不碰 8933 那台的任何东西**）。
    **grace=120**：宽限期里重复用旧串回的是 `rotated:false` —— 这条正常路径在
    grace=0 的服务器上测不到（那边第二次用旧串会被判成重放、整个会话作废）。

数据全程用**副本数据根**（`PHLL_DATA_DIR` 指到 `_lab\\plljwt\\data\\...`），
绝不动真实 `data/`。测试账号统一 `plljwt` 前缀，跑完用
`devtools/clean_dev_db.py`（该前缀已进白名单）清掉。
"""
import json
import os
import shutil
import sys
import time
from pathlib import Path

import requests

sys.path.insert(0, r"D:\phl-lite-dev")

SHORT = os.environ.get("PHIX_SHORT_SERVER", "http://127.0.0.1:8933").rstrip("/")
GRACE = os.environ.get("PHIX_GRACE_SERVER", "http://127.0.0.1:8934").rstrip("/")
GRACE_PORT = int(GRACE.rsplit(":", 1)[-1])
LAB = Path(r"D:\phix\_lab\plljwt")
SHORT_DB = Path(r"D:\phix\_lab\short_db.sqlite3")
DEVTOOLS = Path(r"D:\phix\server\devtools")
PREFIX = "plljwt"

PASSED, FAILED = [], []
DEKS: set = set()


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


def api(base: str) -> str:
    return base.rstrip("/") + "/api/v1"


def err_code(r) -> str:
    return (body_of(r).get("error") or {}).get("code") or ""


def ping(base: str, timeout: float = 4):
    try:
        return body_of(requests.get(api(base) + "/ping", timeout=timeout))
    except requests.RequestException:
        return None


def wait_expired(base: str, access: str, limit: float = 25) -> bool:
    """等这串 access **真的**过期（以服务端回 `token_expired` 为准）。

    比"睡够 8 秒"靠谱：短命令牌服务器 5 秒一张，但中途客户端可能自己续过期，
    盲目 sleep 会让后面的断言时好时坏。
    """
    end = time.time() + limit
    while time.time() < end:
        r = requests.get(api(base) + "/auth/me",
                         headers={"Authorization": "Bearer " + access}, timeout=15)
        if err_code(r) == "token_expired":
            return True
        time.sleep(1)
    return False


def wrap_calls(client, log=None):
    """记下这个客户端**真正发出去**的请求路径。

    用它数"续期了几次、业务请求重试了几次" —— 比只看结果更硬：
    能抓住"循环续期""续期失败还在连点"这类问题。
    """
    log = [] if log is None else log
    plain, enc = client._plain, client._enc_req

    def _plain(method, path, *a, **k):
        log.append(path.split("?", 1)[0])
        return plain(method, path, *a, **k)

    def _enc(method, path, *a, **k):
        log.append(path.split("?", 1)[0])
        return enc(method, path, *a, **k)

    client._plain, client._enc_req = _plain, _enc
    return log


# ---------------------------------------------------------------- 服务器
def patch_run_short():
    """把官方 devtools/run_short.py 的写死路径指到 `_lab/plljwt/` 下。"""
    sys.path.insert(0, str(DEVTOOLS))
    import run_short

    run_short.PORT = GRACE_PORT
    run_short.DBFILE = LAB / "grace_db.sqlite3"
    run_short.PIDFILE = LAB / "grace_server.pid"
    run_short.LOGFILE = LAB / "grace_server.log"
    return run_short


def start_grace_server():
    run_short = patch_run_short()
    os.environ["PHIX_REFRESH_GRACE"] = "120"     # start() 会读这个环境变量
    # ⚠️ 这里**故意不复制 8933 的库**：
    # 以前为了省一次 migrate，把短命令牌服务器的库复制过来当"宽限期服务器"的库，
    # 结果两台服务器其实**共用同一批账号** —— 下面那句
    # "8933 的账号在 8934 上登不进来（两台服务器确实是两个库）" 就变成了假断言
    # （它一真跑就报"居然登进来了"）。
    # `run_short.ensure_db()` 本来就会给不存在的库跑一次 migrate，所以直接让它建新的空库。
    if run_short.DBFILE.exists():
        run_short.DBFILE.unlink()      # 保证是干净的空库（都在 _lab/ 下，不含真实数据）
    run_short.start()
    return run_short


def stop_grace_server(quiet=False):
    try:
        run_short = patch_run_short()
        if not quiet:
            print(f"\n[停] {GRACE} 那台临时服务器")
        run_short.stop()
    except Exception as exc:  # noqa: BLE001
        if not quiet:
            print(f"  停服务器时出了点问题（不影响结论）：{exc}")


def wait_up(base: str, seconds: float = 40) -> dict:
    end = time.time() + seconds
    while time.time() < end:
        info = ping(base)
        if info:
            return info
        time.sleep(0.5)
    raise SystemExit(f"服务器 {base} 起不来（看 {LAB}\\grace_server.log）")


def device(tag: str):
    """一份全新的副本数据根 + 重新加载过的 PLL 模块（数据根是启动时解析的）。"""
    root = LAB / f"dev{tag}" / "data"
    root.mkdir(parents=True, exist_ok=True)
    os.environ["PHLL_DATA_DIR"] = str(root)
    for mod in [m for m in list(sys.modules) if m.startswith("hellopinghe")]:
        del sys.modules[mod]
    from hellopinghe import cloudsync as cs
    from hellopinghe import filestore as fs
    from hellopinghe import phixsession as ps

    ps.save_config(auto_sync=False)      # 别让后台自动同步插进测试里
    return cs, fs, ps, root


def secrets_of(fs) -> dict:
    return (fs.load_settings() or {}).get("secrets_extra") or {}


# ---------------------------------------------------------------- 主流程
def main():
    try:
        print("=" * 74)
        print("PLL 客户端 × phix P3（JWT + refresh 自动续期）")
        print(f"  短命令牌服务器 {SHORT}    宽限期服务器 {GRACE}")
        print(f"  副本数据根 {LAB}")
        print("=" * 74)

        # ---------- 0. 两台服务器就位 ----------
        print("\n[0] 服务器就位")
        if LAB.exists():
            if (LAB / "grace_server.pid").exists():
                stop_grace_server(quiet=True)   # 上一轮跑挂了留下的 pid
            shutil.rmtree(LAB)
        LAB.mkdir(parents=True, exist_ok=True)

        info_s = ping(SHORT)
        if not info_s:
            raise SystemExit(
                f"{SHORT} 没起来 —— 先跑：python -X utf8 "
                r"D:\phix\server\devtools\run_short.py start")
        a_s = info_s.get("auth") or {}
        check("8933 开着 JWT（auth.jwt=1）", a_s.get("jwt") == 1, str(a_s))
        check("8933 访问令牌很短（≤30s，能在测试里等到过期）",
              0 < int(a_s.get("access_ttl") or 0) <= 30, str(a_s.get("access_ttl")))
        check("8933 宽限期 = 0（用它测重放边界）",
              int(a_s.get("refresh_grace") or 0) == 0, str(a_s.get("refresh_grace")))

        start_grace_server()
        info_g = wait_up(GRACE)
        a_g = info_g.get("auth") or {}
        check(f"{GRACE} 起来了（本脚本自己管的宽限期服务器）", bool(a_g.get("jwt")), str(a_g))
        check("8934 宽限期 = 120（用它测 rotated:false）",
              int(a_g.get("refresh_grace") or 0) == 120, str(a_g.get("refresh_grace")))

        sfx = str(int(time.time()))[-6:]

        # ============ 设备 A：8933（过期 / 续期 / 落盘 / 登出） ============
        print("\n[1] 注册登录：两组令牌 + refresh 落到 secrets_extra")
        cs, fs, ps, root_a = device("A")
        S = ps.SESSION
        user_a = f"{PREFIX}{sfx}a"
        pw_a = "Pll-Jwt-Aa1"
        st = S.register(SHORT, user_a, pw_a)
        check("注册后已登录且已解锁（DEK 在内存里）",
              st["logged_in"] and st["unlocked"], str(st)[:200])
        check("status 报出两串都在（has_token / has_refresh）",
              st.get("has_token") is True and st.get("has_refresh") is True, str(st)[:200])
        DEKS.add(S.dek.hex())

        c = S.client
        check("业务用的 token 是 JWT（三段式）", (c.token or "").count(".") == 2,
              str(c.token)[:40])
        check("refresh 是**另一串**（不是 access）",
              bool(c.refresh_token) and c.refresh_token != c.token)
        check("老式长期令牌也留着了（兼容期，只在内存里）", bool(c.legacy_token))

        se = secrets_of(fs)
        check("phix:refresh_token（新键）落在 secrets_extra 里", bool(se.get("phix:refresh_token")))
        check("phix:refresh_token 与内存里的一致", se.get("phix:refresh_token") == c.refresh_token)
        check("phix:access_token 存的就是访问令牌（JWT）",
              (se.get("phix:access_token") or "").count(".") == 2,
              str(se.get("phix:access_token"))[:30])
        cfg = fs.load_settings() or {}
        check("refresh 没混进 phix 段", "refresh" not in (cfg.get("phix") or {}),
              str(cfg.get("phix")))
        raw = (root_a / "settings.yaml").read_text(encoding="utf-8")
        check("settings.yaml 里没有 DEK（DEK 不落盘）", S.dek.hex() not in raw)
        check("settings.yaml 里没有密钥材料字段",
              "key_wrap" not in raw and "recovery_wrap" not in raw)

        # ---------- 2. 过期 → 自动续期 + 重试一次 ----------
        print("\n[2] 过期（token_expired）→ 自动续期一次 + 重试原请求")
        old_access, old_refresh = c.token, c.refresh_token
        print("      等访问令牌过期（ttl 5s + leeway 1s）……")
        expired = wait_expired(SHORT, old_access)
        check("旧令牌确实过期了（直连服务器：401 + code=token_expired）", expired)

        calls = wrap_calls(c)
        me = c.me()
        check("**客户端自动续期后原请求成功**（不需要用户重新登录）",
              me.get("username") == user_a, str(me)[:160])
        check("access 已经换成新的", c.token != old_access)
        check("refresh 也轮换了（rotated:true 那一路）", c.refresh_token != old_refresh)
        check("续期只发了 1 次 /auth/refresh", calls.count("/auth/refresh") == 1, str(calls))
        check("业务请求一共 2 次（失败 1 + 用新令牌重试 1，**没有循环**）",
              calls.count("/auth/me") == 2, str(calls))

        # ---------- 3. 新 refresh 被持久化 ----------
        print("\n[3] 轮换后的新 refresh 必须落盘（不落盘 15 分钟后就续不上了）")
        se = secrets_of(fs)
        check("settings.yaml 里的 phix:refresh_token 已经是**新**那串",
              se.get("phix:refresh_token") == c.refresh_token
              and se.get("phix:refresh_token") != old_refresh,
              "磁盘上还是旧串" if se.get("phix:refresh_token") == old_refresh else "")
        check("phix:access_token 也跟着更新成新 access",
              se.get("phix:access_token") == c.token)

        # ---------- 4. refresh 不能当 Bearer ----------
        print("\n[4] refresh 不能当访问令牌用（也不能被误当成「该续期」）")
        calls = wrap_calls(c)
        try:
            c.me(token=c.refresh_token)
            check("把 refresh 当 Bearer → 必须被拒", False, "居然成功了")
        except cs.PhixError as exc:
            check("把 refresh 当 Bearer → 401 被拒", exc.status == 401,
                  f"{exc.status} {exc.code} {exc.message}")
        check("这种拒绝**不会**触发续期（没去调 /auth/refresh）",
              "/auth/refresh" not in calls, str(calls))

        # ---------- 5. 登出：两串都清掉 ----------
        print("\n[5] 登出：服务端会话立刻注销 + 本地两串都清掉")
        S.client.me()                      # 先确保手上是**没过期**的 access
        live_access, live_refresh = S.client.token, S.client.refresh_token
        st = S.logout()
        check("登出后未登录、DEK 也清了",
              not st["logged_in"] and not st["unlocked"], str(st)[:200])
        se = secrets_of(fs)
        check("本机 phix:access_token / phix:token 都清掉了",
              not se.get("phix:access_token") and not se.get("phix:token"),
              str(sorted(se)))
        check("本机 phix:refresh_token / 旧键 phix:refresh 都清掉了",
              not se.get("phix:refresh_token") and not se.get("phix:refresh"),
              str(sorted(se)))
        check("status 里 has_token / has_refresh 都为 False",
              st.get("has_token") is False and st.get("has_refresh") is False)
        r = requests.get(api(SHORT) + "/auth/me",
                         headers={"Authorization": "Bearer " + live_access}, timeout=15)
        check("服务端那个访问令牌**立刻**失效（401，不等它自然过期）",
              r.status_code == 401 and err_code(r) == "unauthorized",
              f"{r.status_code} {r.text[:140]}")
        r = requests.post(api(SHORT) + "/auth/refresh",
                          json={"refresh_token": live_refresh}, timeout=15)
        check("登出后 refresh 也不能用了（401）", r.status_code == 401,
              f"{r.status_code} {r.text[:120]}")

        # ============ 设备 B：8934（宽限期 rotated:false） ============
        print("\n[6] 宽限期内重复续期（rotated:false）→ 不覆盖本地、不报错")
        cs2, fs2, ps2, _root_b = device("B")
        S2 = ps2.SESSION
        user_b = f"{PREFIX}{sfx}b"
        st2 = S2.register(GRACE, user_b, "Pll-Jwt-Bb1")
        check("在宽限期服务器上注册成功", st2["logged_in"] and st2["unlocked"])
        DEKS.add(S2.dek.hex())
        c2 = S2.client
        r0 = c2.refresh_token
        d1 = c2.refresh_access()                     # 第一次：正常轮换
        r1 = c2.refresh_token
        check("第一次续期 rotated=true", d1.get("rotated") is True, str(d1)[:160])
        check("轮换后 refresh 换了新串", bool(r1) and r1 != r0)
        check("轮换后新的 refresh 已落盘", secrets_of(fs2).get("phix:refresh_token") == r1)

        # 并发续期里"晚到的那个请求"：它手里还是**旧**那串
        c2.refresh_token = r0
        d2 = c2.refresh_access()
        check("宽限期内重复用旧串 → 200 且 rotated=false（这**不是**错误）",
              d2.get("rotated") is False, str(d2)[:200])
        check("这次响应里**没有** refresh_token（服务端不重发明文）",
              not d2.get("refresh_token"), str(d2.get("refresh_token"))[:20])
        check("rotated=false 时本地那串**没被清空、没被改写**",
              c2.refresh_token == r0 and bool(c2.refresh_token))

        # 真正要防的是"晚到的 rotated:false 把已经上位的那串冲掉"
        c2.refresh_token = r1
        c2._apply_refresh_response({"access_token": c2.token, "rotated": False})
        check("晚到的 rotated:false 响应**不会**覆盖本地已在位的那串 refresh",
              c2.refresh_token == r1)
        c2._apply_refresh_response({"access_token": c2.token, "rotated": True,
                                    "refresh_token": r1 + "Z"})
        check("rotated:true（带 refresh_token）才会覆盖", c2.refresh_token == r1 + "Z")

        # ---------- 7. 盘上那串真的还能续期 ----------
        print("\n[7] 磁盘上那串 refresh 确实能换出令牌（不是空写）")
        c2.refresh_token = r1
        S2._persist_tokens(c2)
        on_disk = secrets_of(fs2).get("phix:refresh_token")
        check("盘上的串就是上位那串", on_disk == r1)
        r = requests.post(api(GRACE) + "/auth/refresh",
                          json={"refresh_token": on_disk}, timeout=20)
        b = body_of(r)
        check("把盘上那串交给服务端 → 200 且轮换成功",
              r.status_code == 200 and b.get("rotated") is True,
              f"{r.status_code} {r.text[:160]}")

        # ============ 设备 C：8933（会话列表 / 注销 / 续期失败不重试） ============
        print("\n[8] 会话列表（/auth/devices）与注销另一台设备")
        cs3, fs3, ps3, _root_c = device("C")
        S3 = ps3.SESSION
        user_c = f"{PREFIX}{sfx}c"
        pw_c = "Pll-Jwt-Cc1"

        # 先确认"两台服务器是两个库"：8933 上注册的账号在 8934 上登不进来
        probe = cs3.PhixClient(GRACE, e2e=True, pin_dir=ps3._pin_dir())
        try:
            probe.login(user_a, pw_a, device="probe")
            check("8933 的账号在 8934 上登不进来（两台服务器确实是两个库）",
                  False, "居然登进来了")
        except cs3.PhixError as exc:
            check("8933 的账号在 8934 上登不进来（两台服务器确实是两个库）",
                  exc.code == "bad_credentials", f"{exc.code} {exc.message}")

        st3 = S3.register(SHORT, user_c, pw_c)
        check("设备 C 注册成功", st3["logged_in"] and st3["unlocked"])
        DEKS.add(S3.dek.hex())
        other = cs3.PhixClient(SHORT, e2e=True, pin_dir=ps3._pin_dir())
        other.login(user_c, pw_c, device=f"{PREFIX} 第二台")

        lst = S3.devices()
        sessions = lst.get("sessions") or []
        check("会话列表拿得到（至少两台设备 = 两个会话）", len(sessions) >= 2,
              str(len(sessions)))
        check("列表里有 current 标记（本机）", any(s.get("current") for s in sessions),
              str(sessions)[:200])
        check("带 access_ttl / refresh_ttl",
              int(lst.get("access_ttl") or 0) > 0 and int(lst.get("refresh_ttl") or 0) > 0,
              str(lst)[:160])
        check("列表里**没有** refresh 明文",
              "refresh_token" not in json.dumps(lst, ensure_ascii=False))

        others = [s for s in sessions if not s.get("current")]
        check("能看到另一台设备", bool(others), str(sessions)[:200])
        sid = others[0]["id"] if others else 0
        other.refresh_access()          # 保证那台手上是新鲜 access（5 秒就过期）
        other_access = other.token
        out = S3.revoke_device(session_id=sid)
        after = {s["id"]: s for s in (out.get("sessions") or [])}
        check("注销另一台设备 → 那个会话变 revoked",
              bool(after.get(sid, {}).get("revoked")), str(after.get(sid)))
        r = requests.get(api(SHORT) + "/auth/me",
                         headers={"Authorization": "Bearer " + other_access}, timeout=15)
        check("**被注销那台设备的访问令牌立刻失效**",
              r.status_code == 401 and err_code(r) == "unauthorized",
              f"{r.status_code} {r.text[:140]}")
        check("本机不受影响", S3.client.me().get("username") == user_c)

        calls = wrap_calls(other)
        try:
            other.me()
            check("被注销的会话再用 → 必须报错", False, "居然成功了")
        except cs3.PhixError as exc:
            check("被注销的会话 → 401 unauthorized（不是 token_expired）",
                  exc.status == 401 and exc.code == "unauthorized",
                  f"{exc.status} {exc.code} {exc.message}")
        check("会话被注销时**不去续期**（续期救不回来，还可能被判重放）",
              "/auth/refresh" not in calls, str(calls))

        third = cs3.PhixClient(SHORT, e2e=True, pin_dir=ps3._pin_dir())
        third.login(user_c, pw_c, device=f"{PREFIX} 第三台")
        out = S3.revoke_device(all_except_current=True)
        live = [s for s in (out.get("sessions") or []) if not s.get("revoked")]
        check("注销其它设备后：只剩本机一个活会话",
              len(live) == 1 and live[0].get("current"), str(out.get("sessions"))[:240])
        r = requests.get(api(SHORT) + "/auth/me",
                         headers={"Authorization": "Bearer " + third.token}, timeout=15)
        check("第三台也立刻掉线", r.status_code == 401, str(r.status_code))

        # ---------- 9. 续期失败不重试 ----------
        print("\n[9] 续期失败：不重试、不连点，给一句中文错误")
        c3 = S3.client
        stale = c3.token
        print("      等访问令牌过期，同时把本地 refresh 换成无效串……")
        c3.refresh_token = "plljwt-invalid-" + "x" * 50
        check("先把令牌等到真的过期", wait_expired(SHORT, stale))
        calls = wrap_calls(c3)
        try:
            c3.me()
            check("续期失败时必须报错", False, "居然成功了")
        except cs3.PhixError as exc:
            check("续期失败给出中文错误（提示重新登录）",
                  ("重新登录" in exc.message) or ("续期" in exc.message),
                  str(exc.message))
            check("错误码告诉上层「要重新登录」",
                  exc.code in ("relogin_required", "session_revoked"), str(exc.code))
        check("续期**只尝试了 1 次**（不重试、不拿旧串连点）",
              calls.count("/auth/refresh") == 1, str(calls))
        check("业务请求也只发了 1 次（失败就报错，不循环重试）",
              calls.count("/auth/me") == 1, str(calls))

        # ---------- 10. 过期状态下登出：服务端会话也要真的注销 ----------
        print("\n[10] 访问令牌过期时点「退出登录」：先续期再注销（别留下活着的会话）")
        cs4, fs4, ps4, _root_d = device("D")
        S4 = ps4.SESSION
        user_d = f"{PREFIX}{sfx}d"
        st4 = S4.register(SHORT, user_d, "Pll-Jwt-Dd1")
        check("设备 D 注册成功", st4["logged_in"] and st4["unlocked"])
        DEKS.add(S4.dek.hex())
        old_d = S4.client.token
        # 第二台设备：用它来查"第一台那个会话后来怎么样了"
        probe2 = cs4.PhixClient(SHORT, e2e=True, pin_dir=ps4._pin_dir())
        probe2.login(user_d, "Pll-Jwt-Dd1", device=f"{PREFIX} D2")
        check("先把 D1 的访问令牌等到真的过期", wait_expired(SHORT, old_d))
        S4.logout()
        check("D1 登出后本地令牌都清了",
              not secrets_of(fs4).get("phix:access_token")
              and not secrets_of(fs4).get("phix:refresh_token"))
        sessions_d = probe2.devices().get("sessions") or []
        d1 = [s for s in sessions_d if not s.get("current")]
        check("服务端那条会话**真的被注销了**（不是等它自己过期）",
              bool(d1) and all(s.get("revoked") for s in d1), str(sessions_d)[:240])
        check("D2 自己不受影响", probe2.me().get("username") == user_d)

        # ---------- 11. DEK 不落盘（全流程复查） ----------
        print("\n[11] 整个流程跑完，客户端数据根里仍然没有 DEK / 密钥材料")
        leaks, dek_hits = [], []
        # **只看客户端的数据根**（dev*/data）：服务端那个 sqlite 库本来就该存
        # key_wrap（那是 E2E 设计的一部分），不算客户端泄露。
        for p in sorted(LAB.glob("dev*/**/*")):
            if not p.is_file():
                continue
            try:
                text = p.read_text(encoding="utf-8", errors="ignore")
            except OSError:
                continue
            if "key_wrap" in text or "recovery_wrap" in text:
                leaks.append(str(p.relative_to(LAB)))
            if any(d in text for d in DEKS):
                dek_hits.append(str(p.relative_to(LAB)))
        check("客户端数据根里没有任何文件含 key_wrap / recovery_wrap", not leaks, str(leaks))
        check("客户端数据根里没有任何文件含 DEK 的十六进制", not dek_hits, str(dek_hits))
        # 注意：fs.load_settings() 用的是**当前**数据根（环境变量是动态读的），
        # 所以这里按**显式路径**读设备 C 那份，别被后面切的设备 D 带跑。
        sec_c = (fs.load_settings_at(_root_c / "settings.yaml") or {}).get("secrets_extra") or {}
        check("（对照）设备 C 的 settings.yaml 里确实写着两串令牌，但没有密钥材料",
              bool(sec_c.get("phix:access_token")) and bool(sec_c.get("phix:refresh_token")))

    finally:
        stop_grace_server()

    print("\n" + "=" * 74)
    print(f"通过 {len(PASSED)} 项，失败 {len(FAILED)} 项")
    for f in FAILED:
        print("  - " + f)
    print(f"副本数据根（可整删）：{LAB}")
    print("清测试账号：PHIX_CLEAN_YES=1 跑 devtools\\clean_dev_db.py"
          "（8933 与 8934 的库另带 PHIX_DB）")
    print("=" * 74)
    return 1 if FAILED else 0


if __name__ == "__main__":
    sys.exit(main())
