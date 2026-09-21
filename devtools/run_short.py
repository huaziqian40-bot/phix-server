"""跑一台"短命令牌 / 零宽限"的 phix 服务器，用来验证 P3 的边界行为。

    python -X utf8 D:\\phix\\server\\devtools\\run_short.py start|stop

- `PHIX_JWT_ACCESS_TTL=5` + `PHIX_JWT_LEEWAY=3`：访问令牌 5 秒就过期 → 用来证明
  "过期真的作废，且客户端能靠 refresh 续上"（`test_jwt.py` 第 5 节）。
  **必须把 leeway 调小**：默认 60 秒的时钟余量会把 2 秒的令牌一直判成"还没过期"，
  那样测的其实是 leeway 而不是 exp。
- `PHIX_REFRESH_GRACE=0`：refresh 轮换宽限期设为 0 → 用来证明
  "旧的 refresh 再用一次 = 重放 → 撤销整个会话"（`test_jwt.py` 第 3b 节）。

监听 `127.0.0.1:8933`，与正式本地服务（8931）分开，互不打扰。
"""
import os
import signal
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
PORT = int(os.environ.get("PHIX_SHORT_PORT", 8933))
PIDFILE = Path(r"D:\phix\_lab\short_server.pid")
LOGFILE = Path(r"D:\phix\_lab\short_server.log")
DBFILE = Path(r"D:\phix\_lab\short_db.sqlite3")


def ensure_db():
    """短命令牌服务器用**自己的库**。

    否则它会和 8931 那个正式服务共用 `server/db.sqlite3` —— 那样"令牌过期"这类
    边界测试就失真了（在 8931 上用 15 分钟令牌注册、拿到 8933 上照样有效，
    因为 8933 查的是同一个库）。这个库在 `_lab/` 下，随便建、随便删。
    """
    import os as _os
    env = dict(_os.environ)
    env["DJANGO_SETTINGS_MODULE"] = "phixsvc.settings"
    env["PHIX_DB"] = str(DBFILE)
    env["PYTHONIOENCODING"] = "utf-8"
    if DBFILE.exists():
        return
    subprocess.run([str(ROOT / ".venv" / "Scripts" / "python.exe"), "-X", "utf8",
                    "manage.py", "migrate", "--noinput"],
                   cwd=str(ROOT), env=env, check=True,
                   stdout=subprocess.DEVNULL, stderr=subprocess.STDOUT)
    print(f"已为短命令牌服务器建库：{DBFILE}")


def start():
    ensure_db()
    env = dict(os.environ)
    env["PHIX_DB"] = str(DBFILE)          # 自己的库，不碰正式数据
    env["PHIX_JWT_ACCESS_TTL"] = os.environ.get("PHIX_JWT_ACCESS_TTL", "5")
    env["PHIX_JWT_LEEWAY"] = os.environ.get("PHIX_JWT_LEEWAY", "1")
    env["PHIX_REFRESH_GRACE"] = os.environ.get("PHIX_REFRESH_GRACE", "0")
    env["PHIX_REGISTER_LIMIT"] = "900"
    env["PHIX_REFRESH_LIMIT"] = "9000"
    env["PYTHONIOENCODING"] = "utf-8"
    log = open(LOGFILE, "ab")
    proc = subprocess.Popen(
        [str(ROOT / ".venv" / "Scripts" / "python.exe"), "-X", "utf8",
         str(ROOT / "run_local.py"), "127.0.0.1", str(PORT)],
        cwd=str(ROOT), env=env, stdout=log, stderr=log,
        creationflags=getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0),
    )
    PIDFILE.write_text(str(proc.pid), encoding="ascii")
    print(f"已在 {PORT} 起短命令牌服务器 pid={proc.pid}"
          f"（access_ttl={env['PHIX_JWT_ACCESS_TTL']}s，grace={env['PHIX_REFRESH_GRACE']}s）")
    print(f"日志：{LOGFILE}")


def stop():
    if not PIDFILE.exists():
        print("没有记录到 pid，跳过")
        return
    pid = int(PIDFILE.read_text(encoding="ascii").strip() or 0)
    for kill in (False, True):
        try:
            os.kill(pid, signal.SIGTERM if not kill else signal.SIGTERM)
            time.sleep(0.5)
        except OSError:
            break
    try:
        os.kill(pid, signal.SIGTERM)
    except OSError:
        pass
    PIDFILE.unlink(missing_ok=True)
    print(f"已请求停止 pid={pid}")


if __name__ == "__main__":
    cmd = (sys.argv[1] if len(sys.argv) > 1 else "start").lower()
    if cmd == "stop":
        stop()
    else:
        start()
