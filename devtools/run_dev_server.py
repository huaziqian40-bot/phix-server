"""起一台**开发用**的 phix 本地服务器：自动带上放大后的限流阈值。

    python -X utf8 D:\\phix\\server\\devtools\\run_dev_server.py [端口，默认 8931]

为什么要有它：`run_local.py` 用的是**生产默认限流**（注册 10/小时、恢复 8/小时、
取密钥材料 60/小时）。而 `devtools/` 里的回归套件一轮要注册几十个账号、
跑十几次恢复码重置 —— 撞上限流就会**大面积假失败**（"通过 0 项 退出码 1"，
看起来像代码坏了，其实是被限流了）。这个脚本只是把阈值调大，别的一模一样。

生产（systemd）不受影响：那边是 `~/.config/phix/env` 说了算。
"""
import os
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
PORT = sys.argv[1] if len(sys.argv) > 1 else "8931"

DEV_LIMITS = {
    "PHIX_REGISTER_LIMIT": "900",
    "PHIX_RECOVER_LIMIT": "900",
    "PHIX_KEYMATERIAL_LIMIT": "9000",
    "PHIX_REFRESH_LIMIT": "90000",
}

if __name__ == "__main__":
    env = dict(os.environ)
    env.update(DEV_LIMITS)
    env.setdefault("PYTHONIOENCODING", "utf-8")
    print("[dev] 放大后的限流：" + ", ".join(f"{k}={v}" for k, v in DEV_LIMITS.items()),
          flush=True)
    raise SystemExit(subprocess.call(
        [str(ROOT / ".venv" / "Scripts" / "python.exe"), "-X", "utf8",
         str(ROOT / "run_local.py"), "127.0.0.1", PORT],
        cwd=str(ROOT), env=env))
