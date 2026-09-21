"""用**真实 bridge**（不是 MockApi）验证 phix 接口接线。

    python -X utf8 D:\\phix\\server\\devtools\\test_real_bridge.py

数据根指向一份副本（PHLL_DATA_DIR），绝不碰真实 data/。
"""
import json
import os
import shutil
import sys
import time
from pathlib import Path

ROOT = Path(r"D:\phix\_lab\realbridge\data")
SOURCE = Path(r"D:\HPHL\testenv\data")
SERVER = os.environ.get("PHIX_SERVER", "http://127.0.0.1:8931")

if ROOT.exists():
    shutil.rmtree(ROOT)
ROOT.parent.mkdir(parents=True, exist_ok=True)
shutil.copytree(SOURCE, ROOT)
os.environ["PHLL_DATA_DIR"] = str(ROOT)
sys.path.insert(0, r"D:\phl-lite-dev")

from hellopinghe.app.bridge import Api  # noqa: E402

PASSED, FAILED = [], []


def check(name, cond, extra=""):
    (PASSED if cond else FAILED).append(name)
    print(f"  [{'OK  ' if cond else 'FAIL'}] {name}" + (f"   {extra}" if extra and not cond else ""))
    return cond


def main():
    print("=" * 74)
    print("真实 bridge × phix 接口接线验证")
    print("=" * 74)
    print("数据根:", ROOT)

    api = Api()
    names = [m for m in dir(api) if m.startswith("phix_")]
    print("\n[1] 接口齐备")
    for want in ("phix_status", "phix_ping", "phix_login", "phix_register", "phix_unlock",
                 "phix_logout", "phix_sync", "phix_sync_preview", "phix_conflicts",
                 "phix_settings_save", "phix_devices", "phix_set_passphrase",
                 "phix_change_password", "phix_open_data_dir"):
        check(f"有 {want}", want in names)
    print(f"  （共 {len(names)} 个 phix_ 方法）")

    print("\n[2] 未登录时的状态")
    r = api.phix_status()
    check("返回 ok=True", r.get("ok") is True, str(r)[:200])
    st = r.get("data") or {}
    check("logged_in=False", st.get("logged_in") is False, str(st)[:200])
    check("带 insecure_transport 字段", "insecure_transport" in st)
    check("本机地址不算不安全", st.get("insecure_transport") is False, str(st.get("server")))

    print("\n[3] 连通性探测")
    r = api.phix_ping(SERVER)
    check("ping 成功", r.get("ok") is True, str(r)[:200])
    check("拿到版本号", (r.get("data") or {}).get("version") == 1, str(r)[:200])
    r = api.phix_ping("http://127.0.0.1:9")
    check("连不上时返回 ok=False 而不是抛异常", r.get("ok") is False, str(r)[:160])

    print("\n[4] 参数不全时给中文提示（不是栈）")
    r = api.phix_login("", "", "")
    check("空参数被拒", r.get("ok") is False)
    check("错误是中文人话", "填" in str(r.get("error")), str(r.get("error")))

    print("\n[5] 注册 → 状态 → 同步（真实服务）")
    user = f"bridge_{int(time.time())}"
    r = api.phix_register(SERVER, user, "Bridge-Test-1")
    check("注册成功", r.get("ok") is True, str(r)[:250])
    st = r.get("data") or {}
    check("返回恢复码", len(st.get("recovery_code") or "") >= 24)
    check("已登录且已解锁",
          st.get("logged_in") is True and st.get("unlocked") is True, str(st)[:200])

    r = api.phix_sync()
    check("同步成功", r.get("ok") is True, str(r)[:250])
    summ = (r.get("data") or {}).get("summary") or {}
    check("有同步摘要", bool(summ), str(summ))
    check("推上去东西了", bool(summ.get("pushed")), str(summ))

    r = api.phix_sync()
    check("再同步一次应当无事可做",
          not ((r.get("data") or {}).get("summary") or {}).get("pushed"),
          str((r.get("data") or {}).get("summary")))

    r = api.phix_status()
    st = r.get("data") or {}
    check("状态里记了 last_sync_at", bool(st.get("last_sync_at")), str(st)[:200])
    check("状态里能看到对象的 revision",
          bool((st.get("state") or {}).get("objects")),
          str(st.get("state"))[:200])

    print("\n[6] 预览（不写入）")
    before = (ROOT / "Schedule").read_bytes()
    r = api.phix_sync_preview()
    check("预览成功", r.get("ok") is True, str(r)[:200])
    check("预览没有改动本地文件", (ROOT / "Schedule").read_bytes() == before)

    print("\n[7] 设备列表 / 设置保存 / 退出登录")
    r = api.phix_devices()
    check("列出设备", r.get("ok") is True and len((r.get("data") or {}).get("devices") or []) >= 1,
          str(r)[:200])
    r = api.phix_settings_save(json.dumps(
        {"auto_sync": False, "sync_interval_minutes": 30,
         "objects": ["schedule", "settings.lessons"]}))
    check("保存设置成功", r.get("ok") is True, str(r)[:200])
    st = r.get("data") or {}
    check("auto_sync 已关", st.get("auto_sync") is False)
    check("间隔已改 30", st.get("sync_interval_minutes") == 30, str(st.get("sync_interval_minutes")))
    check("对象清单已改", st.get("objects") == ["schedule", "settings.lessons"],
          str(st.get("objects")))

    r = api.phix_logout()
    check("退出登录成功", r.get("ok") is True, str(r)[:200])
    r = api.phix_status()
    check("退出后 logged_in=False", (r.get("data") or {}).get("logged_in") is False)

    print("\n" + "=" * 74)
    print(f"通过 {len(PASSED)} 项，失败 {len(FAILED)} 项")
    if FAILED:
        print("失败清单：")
        for f in FAILED:
            print("  - " + f)
    print("=" * 74)
    return 1 if FAILED else 0


if __name__ == "__main__":
    sys.exit(main())
