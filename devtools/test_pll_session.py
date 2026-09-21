"""PLL 会话层（hellopinghe/phixsession.py）端到端测试。

覆盖 bridge 那一层真正会用到的东西：注册 / 登录 / 令牌落盘 / 配置落盘 /
同步 / 登出 / 重登 / 第二台设备 / 切独立同步口令 / 换密码。

    cd D:\\phix\\server
    .venv\\Scripts\\python.exe -X utf8 devtools\\test_pll_session.py

**数据全程用副本**（D:\\phix\\_lab\\session\\），绝不碰真实 data/。
"""
import json
import os
import shutil
import sys
import time
from pathlib import Path

sys.path.insert(0, r"D:\phl-lite-dev")

SERVER = os.environ.get("PHIX_SERVER", "http://127.0.0.1:8931")
SOURCE = Path(r"D:\HPHL\testenv\data")
LAB = Path(r"D:\phix\_lab\session")

PASSED, FAILED = [], []


def check(name, cond, extra=""):
    (PASSED if cond else FAILED).append(name)
    print(f"  [{'OK  ' if cond else 'FAIL'}] {name}" + (f"   {extra}" if extra and not cond else ""))
    return cond


def fresh_device(tag: str) -> Path:
    dst = LAB / f"dev{tag}" / "data"
    if dst.exists():
        shutil.rmtree(dst)
    dst.parent.mkdir(parents=True, exist_ok=True)
    shutil.copytree(SOURCE, dst)
    return dst


def load_session_modules(root: Path):
    """在指定数据根下重新加载 PLL 的模块（数据根是启动时解析的，必须重载）。"""
    os.environ["PHLL_DATA_DIR"] = str(root)
    for mod in [m for m in list(sys.modules) if m.startswith("hellopinghe")]:
        del sys.modules[mod]
    from hellopinghe import cloudsync as cs
    from hellopinghe import filestore as fs
    from hellopinghe import phixsession as ps
    return cs, fs, ps


def main():
    if not SOURCE.exists():
        raise SystemExit(f"找不到真实数据目录 {SOURCE}")
    LAB.mkdir(parents=True, exist_ok=True)

    print("=" * 74)
    print("PLL phix 会话层 · 端到端（数据用副本）")
    print("=" * 74)

    root_a = fresh_device("A")
    print(f"\n设备 A 数据根: {root_a}")
    cs, fs, ps = load_session_modules(root_a)
    S = ps.SESSION

    sfx = str(int(time.time()))[-6:]
    username = f"pllsess_{sfx}"
    password = "Session-Test-1"

    # ---------- 1. 注册 ----------
    print("\n[1] 注册 + 密钥材料就位")
    st = S.register(SERVER, username, password)
    check("注册后已登录", st["logged_in"])
    check("已解锁（DEK 在内存里）", st["unlocked"])
    check("拿到恢复码", len(st.get("recovery_code") or "") >= 24,
          str(st.get("recovery_code"))[:30])
    check("设备名非空", bool(st["device"]), st["device"])

    settings = fs.load_settings()
    check("settings.yaml 写了 phix 段", isinstance(settings.get("phix"), dict),
          str(settings.get("phix")))
    check("phix 段里有服务器与用户名",
          settings["phix"].get("server") == SERVER
          and settings["phix"].get("username") == username)
    check("令牌落在 secrets_extra 里",
          bool((settings.get("secrets_extra") or {}).get("phix:access_token")))
    check("令牌没写进 phix 段（不混）", "token" not in settings["phix"])

    raw = (root_a / "settings.yaml").read_text(encoding="utf-8")
    check("settings.yaml 里没有 DEK（DEK 不落盘）",
          ps.SESSION.dek.hex() not in raw)

    # ---------- 2. 同步 ----------
    print("\n[2] 首次同步")
    rep = S.sync()
    check("同步成功", rep["ok"], json.dumps(rep.get("errors"), ensure_ascii=False))
    check("推了 schedule/选课/账号",
          {"schedule", "settings.lessons", "settings.accounts"} <= set(rep["pushed"]),
          str(rep["pushed"]))
    check("配置里记了 last_sync_at", bool(ps.load_config().get("last_sync_at")))
    # 状态与快照**按账号隔离**：data/.sync/accounts/<账号>/
    acct_dir = root_a / cs.SYNC_DIR / "accounts" / username
    state = fs.load_json(acct_dir / cs.STATE_NAME, {}) or {}
    check("状态文件记录了每个对象的 revision",
          len(state.get("objects") or {}) >= 5, str(list((state.get("objects") or {}))))
    check("状态文件在按账号隔离的目录里", state.get("username") == username,
          str(state.get("username")))
    check("快照也在该账号目录下",
          (acct_dir / "last").is_dir() and
          len(list((acct_dir / "last").glob("*.json"))) >= 5,
          str(list((acct_dir / "last").glob("*.json"))[:6]))

    # ---------- 3. 登出 / 重登 ----------
    print("\n[3] 登出 → 令牌清掉 → 重登恢复")
    S.logout()
    st = S.status()
    check("登出后未登录", not st["logged_in"])
    check("登出后 DEK 已清", not st["unlocked"])
    settings = fs.load_settings()
    check("登出后本机令牌已删",
          not any((settings.get("secrets_extra") or {}).get(k) for k in
                  ("phix:token", "phix:access_token", "phix:refresh_token", "phix:refresh")))

    st = S.login(SERVER, username, password)
    check("重登成功", st["logged_in"] and st["unlocked"])
    check("重登后 key_mode=password", st["key_mode"] == "password", st["key_mode"])

    # ---------- 4. 第二台设备 ----------
    print("\n[4] 第二台设备：登录 → 拉到同一份数据")
    root_b = fresh_device("B")
    # 让 B 的日程少一条，验证拉取真的把远端内容带过来了
    sched_b = fs.load_json(root_b / "Schedule", {}) or {}
    removed = None
    if sched_b.get("events"):
        removed = sched_b["events"].pop()
        fs.save_json(root_b / "Schedule", sched_b)

    cs2, fs2, ps2 = load_session_modules(root_b)
    st2 = ps2.SESSION.login(SERVER, username, password)
    check("B 登录成功", st2["logged_in"] and st2["unlocked"])
    check("B 的 settings.yaml 也被写上 phix 段",
          isinstance((fs2.load_settings() or {}).get("phix"), dict))
    rep2 = ps2.SESSION.sync()
    check("B 同步成功", rep2["ok"], json.dumps(rep2.get("errors"), ensure_ascii=False))
    if removed is not None:
        titles_b = {e.get("title") for e in (fs2.load_json(root_b / "Schedule", {}) or {}).get("events", [])}
        check("B 本地删掉的那条从云端拉回来了", removed.get("title") in titles_b,
              str(titles_b))
    check("两端的选课一致",
          json.dumps(ps2.SESSION.status() and
                     (fs2.load_settings() or {}).get("lessons"), sort_keys=True,
                     ensure_ascii=False)
          == json.dumps((fs.load_settings() or {}).get("lessons"), sort_keys=True,
                        ensure_ascii=False))

    # ---------- 5. 切独立同步口令 ----------
    print("\n[5] 切「独立同步口令」→ 服务端从此解不开")
    phrase = "my-own-sync-phrase"
    st = ps2.SESSION.set_sync_passphrase(password, phrase)
    check("key_mode 变成 syncphrase", st["key_mode"] == "syncphrase", st["key_mode"])
    check("配置里也记下了", ps2.load_config().get("key_mode") == "syncphrase")
    rep3 = ps2.SESSION.sync()
    check("切完还能同步", rep3["ok"], json.dumps(rep3.get("errors"), ensure_ascii=False))

    ps2.SESSION.logout()
    st = ps2.SESSION.login(SERVER, username, password)      # 只给登录密码
    check("只给登录密码时：登录成功但数据锁着",
          st["logged_in"] and not st["unlocked"], str(st))
    try:
        ps2.SESSION.sync()
        check("未解锁时同步应被拒绝", False, "居然同步成功了")
    except Exception as exc:  # noqa: BLE001
        check("未解锁时同步被拒绝", "锁" in str(exc) or "locked" in str(exc).lower(),
              str(exc))
    st = ps2.SESSION.unlock(phrase)
    check("给对同步口令后解锁", st["unlocked"])
    try:
        ps2.SESSION.unlock("wrong-phrase")
        check("错口令解不开", False, "居然解开了")
    except Exception:  # noqa: BLE001
        check("错口令解不开", True)
    check("解锁后能同步", ps2.SESSION.sync()["ok"])

    # ---------- 6. 换登录密码 ----------
    print("\n[6] 换登录密码 → 云端密文不动，另一台设备照常")
    # A 的账号此刻是 syncphrase 模式，登录需要带上独立同步口令
    S.login(SERVER, username, password, sync_passphrase=phrase)
    new_pw = "Session-Test-2"
    st = S.change_password(password, new_pw)
    check("A 换密码成功", st["logged_in"], str(st))
    check("换密码没有把 syncphrase 模式改掉", st["key_mode"] == "syncphrase",
          st["key_mode"])
    S.logout()
    try:
        S.login(SERVER, username, password)
        check("旧密码已失效", False, "旧密码还能登")
    except Exception:  # noqa: BLE001
        check("旧密码已失效", True)
    st = S.login(SERVER, username, new_pw, sync_passphrase=phrase)
    check("新密码 + 同步口令能登且解锁（包裹没被换掉）",
          st["logged_in"] and st["unlocked"], str(st))
    rep = S.sync()
    check("换密码后同步照样成功", rep["ok"], json.dumps(rep.get("errors"), ensure_ascii=False))
    check("没有因为换密码而重推全部对象（密文没作废）",
          len(rep.get("pushed") or []) <= 2, str(rep.get("pushed")))

    # 切回简单模式
    print("\n[6b] 切回「用登录密码包裹」")
    st = S.use_login_password(new_pw)
    check("key_mode 回到 password", st["key_mode"] == "password", st["key_mode"])
    S.logout()
    st = S.login(SERVER, username, new_pw)
    check("之后只给登录密码就能解锁", st["logged_in"] and st["unlocked"], str(st))
    check("切回后同步正常", S.sync()["ok"])

    # ---------- 7. 状态接口给界面的东西 ----------
    print("\n[7] 忘记密码：恢复码重设（走 phixsession.recover）")
    root_c = fresh_device("C")
    cs3, fs3, ps3 = load_session_modules(root_c)
    u3 = f"forgot{sfx}"
    st3 = ps3.SESSION.register(SERVER, u3, "Forgot-Me-1")
    code3 = st3["recovery_code"]
    check("新账号拿到恢复码", len(code3 or "") >= 24)
    ps3.SESSION.sync()
    # 记下一条云端数据，重置密码后要能解开
    before_obj = ps3.SESSION.client.get_object("schedule")
    ps3.SESSION.logout()

    try:
        ps3.recover(SERVER, u3, "AAAA-BBBB-CCCC-DDDD-EEEE-FFFF", "Nope-Pass-1")
        check("错恢复码被拒", False, "居然成功了")
    except Exception as exc:  # noqa: BLE001
        check("错恢复码被拒", "恢复码" in str(exc), str(exc))

    out = ps3.recover(SERVER, u3, code3, "Forgot-Me-2")
    check("用真恢复码重设成功", out.get("ok") is True, str(out))
    st3 = ps3.SESSION.login(SERVER, u3, "Forgot-Me-2")
    check("新密码能登录", st3["logged_in"] and st3["unlocked"], str(st3))
    after_obj = ps3.SESSION.client.get_object("schedule")
    check("重置后 revision 没变（云端密文没动）",
          before_obj["revision"] == after_obj["revision"],
          f"{before_obj['revision']} -> {after_obj['revision']}")
    check("重置后旧密文照样解得开（数据没丢）",
          ps3.SESSION.dek is not None and after_obj["payload"] == before_obj["payload"])
    rep3 = ps3.SESSION.sync()
    check("重置后同步正常", rep3["ok"], json.dumps(rep3.get("errors"), ensure_ascii=False))

    # ---------- 8. 状态接口给界面的东西 ----------
    print("\n[8] 界面需要的状态字段齐全")
    st = S.status()
    for field in ("configured", "server", "username", "logged_in", "unlocked",
                  "key_mode", "auto_sync", "sync_interval_minutes", "last_sync_at",
                  "device", "objects", "state"):
        check(f"status 有 {field}", field in st)
    check("objects 含 8 个默认对象（含 profile/mood）", len(st["objects"]) == 8,
          str(st["objects"]))

    print("\n" + "=" * 74)
    print(f"通过 {len(PASSED)} 项，失败 {len(FAILED)} 项")
    if FAILED:
        print("失败清单：")
        for f in FAILED:
            print("  - " + f)
    print(f"实验目录（可整删）：{LAB}")
    print("=" * 74)
    return 1 if FAILED else 0


if __name__ == "__main__":
    sys.exit(main())
