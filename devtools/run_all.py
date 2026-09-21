"""回归总跑：按顺序把 phix 服务端全部 Python 测试跑一遍，汇总通过/失败数。

    cd D:\\phix\\server
    .venv\\Scripts\\python.exe -X utf8 devtools\\run_all.py            # 全部（→ 710/710；需要 8933 时自动起停）
    .venv\\Scripts\\python.exe -X utf8 devtools\\run_all.py selftest jwt

**先起服务器**：`python -X utf8 devtools\\run_dev_server.py`（带放大限流的那台）。
用 `run_local.py` 直接起的话，一轮回归会撞上生产默认限流（恢复码 8 次/小时），
结果是「通过 0 项、退出码 1」这种**看起来像代码坏了**的假失败。

为什么要有它：以前一个个手敲，容易漏跑、也容易看串输出。
本脚本**不改任何东西**，只跑测试并把每一节的 `通过 N 项，失败 M 项` 抓出来。
"""
import os
import re
import subprocess
import sys
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
PY = str(HERE.parent / ".venv" / "Scripts" / "python.exe")
# 少数套件要用**另一个解释器**：real_bridge 会 import 真实 bridge，
# 而那棵树依赖 bs4 —— 服务端 venv 里没有（也不该有），系统 python 里有。
PY_OVERRIDE = {"real_bridge": os.environ.get("PHIX_PY_SYS", "python")}

# (名字, 文件)：顺序有意义——selftest 先跑（最快确认服务活着）
SUITES = [
    ("selftest", "selftest.py"),
    ("v2_guard", "test_v2_guard.py"),
    ("jwt", "test_jwt.py"),
    ("authhash", "test_authhash.py"),
    ("sync_e2e", "test_sync_e2e.py"),
    ("pll_session", "test_pll_session.py"),
    ("phl_session_real", "test_phl_session_real.py"),
    ("e2e_transport", "test_e2e_transport.py"),
    ("crypto_interop", "test_crypto_interop.py"),
    ("cross_app", "test_cross_app.py"),
    ("real_bridge", "test_real_bridge.py"),
    ("token_keys", "test_token_keys.py"),
]

# **跑在最后**的套件。`test_pll_jwt.py` 自己会起停两台服务器、还会在
# `_lab/` 下建/删自己的副本目录 —— 排在中间时会和别的套件抢 `_lab`（实测：
# 紧接着的两个套件会「通过 0 项、退出码 1」，单独重跑又全绿）。
# 放到最后，谁也不影响谁。
TAIL_SUITES = [
    ("pll_jwt", "test_pll_jwt.py"),
]

TALLY = re.compile(r"通过\s*(\d+)\s*项[，,]\s*失败\s*(\d+)\s*项")
# 有的测试用 "PASS/FAIL" 或 "N/M" 记账，兜底也认一下
TALLY2 = re.compile(r"(?:PASS|通过)[^\d]{0,3}(\d+)")

# 边界服务器（可选）：`devtools/run_short.py` 起的那台。在跑，就顺手把它的地址
# 交给 test_jwt —— 那样"令牌过期"和"refresh 重放"两节也会真跑，而不是跳过。
BOUNDARY_PORTS = (8933,)


def boundary_servers(env: dict) -> list[str]:
    import socket

    found = []
    for port in BOUNDARY_PORTS:
        with socket.socket() as s:
            s.settimeout(0.4)
            if s.connect_ex(("127.0.0.1", port)) == 0:
                found.append(f"http://127.0.0.1:{port}")
    if found:
        env.setdefault("PHIX_STRICT_SERVER", found[0])
        env.setdefault("PHIX_SHORT_SERVER", found[0])
    return found


def ensure_boundary_server():
    """需要的时候**自己**把 8933 那台起起来，跑完收工时再关掉。

    它服务两个套件：`jwt`（令牌过期 / refresh 重放的边界两节）与 `pll_jwt`
    （整轮都要它）。**必须自动起** —— 以前靠人手 `run_short.py start`，
    结果要么忘了起、要么被别的会话 `stop` 掉，出现「通过 0 项、退出码 1」
    这种看着像代码坏了的假失败（真发生过两次）。
    库是 `_lab/short_db.sqlite3`（专门给它的空库，与正式库分开）。
    """
    started = False
    if not boundary_servers({}):
        print("边界服务器没起 —— 自动拉起 8933（跑完会关掉）", flush=True)
        subprocess.run([PY, "-X", "utf8", str(HERE / "run_short.py"), "start"],
                       cwd=str(HERE.parent), stdout=subprocess.DEVNULL,
                       stderr=subprocess.DEVNULL, check=False)
        time.sleep(4)
        started = True
    return started


def stop_boundary_server():
    subprocess.run([PY, "-X", "utf8", str(HERE / "run_short.py"), "stop"],
                   cwd=str(HERE.parent), stdout=subprocess.DEVNULL,
                   stderr=subprocess.DEVNULL, check=False)


def main():
    wanted = sys.argv[1:]
    rows = []
    started = ensure_boundary_server()
    try:
        return _run(wanted, rows)
    finally:
        if started:
            print("\n关掉自动拉起的边界服务器", flush=True)
            stop_boundary_server()


def _run(wanted, rows):
    probe = dict(os.environ)
    found = boundary_servers(probe)
    print(f"边界服务器：{found if found else '（没起，test_jwt 的过期/重放两节会跳过）'}",
          flush=True)
    for name, fname in SUITES + TAIL_SUITES:
        if wanted and name not in wanted:
            continue
        path = HERE / fname
        if not path.exists():
            print(f"[跳过] {fname} 不存在")
            continue
        print(f"\n{'=' * 74}\n>>> {name}  ({fname})\n{'=' * 74}", flush=True)
        t0 = time.time()
        env = dict(probe)
        env["PYTHONIOENCODING"] = "utf-8"
        proc = subprocess.run([PY_OVERRIDE.get(name, PY), "-X", "utf8", str(path)],
                              cwd=str(HERE.parent),
                              env=env, stdout=subprocess.PIPE,
                              stderr=subprocess.STDOUT)
        out = proc.stdout.decode("utf-8", "replace")
        print(out, flush=True)
        hit = TALLY.search(out)
        if hit:
            passed, failed = int(hit.group(1)), int(hit.group(2))
        else:
            nums = [int(x) for x in TALLY2.findall(out)]
            passed, failed = (max(nums), 0) if nums else (0, 0)
        rows.append((name, passed, failed, proc.returncode, time.time() - t0))

    print("\n" + "=" * 74)
    print("回归汇总")
    print("=" * 74)
    tp = tf = 0
    for name, passed, failed, rc, secs in rows:
        tp += passed
        tf += failed
        flag = "OK  " if (failed == 0 and rc == 0) else "FAIL"
        print(f"  [{flag}] {name:<18} 通过 {passed:>4}  失败 {failed:>3}  "
              f"退出码 {rc}  {secs:.1f}s")
    print(f"\n  合计：通过 {tp} 项，失败 {tf} 项")
    print("=" * 74)
    return 1 if tf else 0


if __name__ == "__main__":
    sys.exit(main())
