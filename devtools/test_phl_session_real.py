"""PHL 会话层 · 改密码 / 切独立同步口令 / 切回 —— **对着真实服务端**跑一遍。

PHL 的界面里用户点得到这三个功能，但之前只验证过"参数构造 + IPC 接线"，
没走过真服务端。这个脚本补上（用 PHL 自己的 `phix-session.cjs`，不是另写一套）。

    cd D:\\phix\\server
    .venv\\Scripts\\python.exe -X utf8 devtools\\test_phl_session_real.py
"""
import json
import os
import shutil
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(r"D:\phix\server")
SERVER = os.environ.get("PHIX_SERVER", "http://127.0.0.1:8931")
SOURCE = Path(r"D:\HPHL\testenv\data")
LAB = Path(r"D:\phix\_lab\phlsess")
DRIVER = ROOT / "devtools" / "phl_driver.cjs"

PASSED, FAILED = [], []


def check(name, cond, extra=""):
    (PASSED if cond else FAILED).append(name)
    print(f"  [{'OK  ' if cond else 'FAIL'}] {name}" + (f"   {extra}" if extra and not cond else ""))
    return cond


def node(args, timeout=300):
    env = dict(os.environ, PYTHONUTF8="1")
    r = subprocess.run(["node", str(DRIVER)] + [str(a) for a in args],
                       capture_output=True, text=True, encoding="utf-8",
                       errors="replace", env=env, cwd=str(ROOT), timeout=timeout)
    for line in reversed((r.stdout or "").splitlines()):
        if line.startswith("__PHL_RESULT__"):
            return json.loads(line[len("__PHL_RESULT__"):])
    return {"ok": False, "error": "驱动没有输出结果",
            "stdout": (r.stdout or "")[-500:], "stderr": (r.stderr or "")[-500:]}


def main():
    if LAB.exists():
        shutil.rmtree(LAB)
    LAB.mkdir(parents=True, exist_ok=True)
    shutil.copytree(SOURCE, LAB / "data", dirs_exist_ok=True)
    data_dir = LAB / "data"
    for marker in (".pll-running", ".phl-running"):
        p = data_dir / marker
        if p.exists():
            p.unlink()

    print("=" * 74)
    print("PHL 会话层 · 改密码 / 切同步口令 / 切回（真实服务端）")
    print("=" * 74)
    print(f"服务器: {SERVER}\n数据目录: {data_dir}")

    user = f"phlsess{int(time.time()) % 1000000}"
    password = "Phl-Real-1"
    print(f"\n测试账号: {user}")

    out = node(["session-test", SERVER, user, password, str(data_dir)])
    if not out.get("ok"):
        check("PHL 会话层流程跑完", False, json.dumps(out, ensure_ascii=False)[:600])
        print(f"\n通过 {len(PASSED)} 项，失败 {len(FAILED)} 项")
        return 1

    print("\n[1] 注册 + 首推")
    check("注册后已登录且已解锁", out["register"]["logged_in"] and out["register"]["unlocked"])
    check("拿到恢复码", out["register"]["has_recovery"])
    check("首次同步成功", out["first_sync_ok"], str(out.get("first_sync_ok")))

    print("\n[2] 换登录密码")
    check("换完仍处于登录态", out["after_change"]["logged_in"])
    check("旧密码登录失败", out["old_password_rejected"])
    check("新密码能登录且解锁", out["new_password_ok"])
    check("**云端密文没作废**（schedule 的 revision 没变）", out["revision_unchanged"],
          str(out.get("rev")))
    check("换密码后同步正常", out["sync_after_change"])

    print("\n[3] 切独立同步口令")
    check("key_mode 变成 syncphrase", out["after_set_phrase"]["key_mode"] == "syncphrase",
          str(out.get("after_set_phrase")))
    check("只给登录密码时：登录成功但锁着", out["locked_without_phrase"])
    check("锁着的时候同步被拒", out["sync_blocked_when_locked"])
    check("给对独立口令能解锁", out["unlock_with_phrase"])
    check("解锁后能同步", out["sync_with_phrase"])

    print("\n[4] 切回「用登录密码包裹」")
    check("key_mode 回到 password", out["after_back"]["key_mode"] == "password",
          str(out.get("after_back")))
    check("之后只给登录密码就能解锁", out["plain_login_after_back"])

    print("\n" + "=" * 74)
    print(f"通过 {len(PASSED)} 项，失败 {len(FAILED)} 项")
    if FAILED:
        for f in FAILED:
            print("  - " + f)
    print("=" * 74)
    return 1 if FAILED else 0


if __name__ == "__main__":
    sys.exit(main())
