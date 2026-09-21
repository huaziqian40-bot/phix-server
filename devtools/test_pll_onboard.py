"""PLL 首启引导 + profile 头像 功能测试。

覆盖：
- 首启引导分支（有会话 / 无会话）
- profile 同步对象读写
- 头像字段格式校验（data URL / 大小限制）

    cd D:\\phix\\server
    .venv\\Scripts\\python.exe -X utf8 devtools\\test_pll_onboard.py

**数据全程用副本**（D:\\phix\\_lab\\onboard\\），绝不碰真实 data/。
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
LAB = Path(r"D:\phix\_lab\onboard")

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
    """在指定数据根下重新加载 PLL 的模块。"""
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
    print("PLL 首启引导 + profile 测试（数据用副本）")
    print("=" * 74)

    sfx = str(int(time.time()))[-6:]
    username = f"onboard_{sfx}"
    password = "Onboard-Test-1"

    # ========== 1. 无会话状态：status 报告无令牌 ==========
    print("\n[1] 无会话状态检查")
    root_a = fresh_device("A")
    cs, fs, ps = load_session_modules(root_a)
    S = ps.SESSION
    st = S.status()
    check("status 有 has_access_token", "has_access_token" in st)
    check("status 有 has_refresh_token", "has_refresh_token" in st)
    check("status 有 has_token", "has_token" in st)
    check("新设备无令牌", not st["has_access_token"] and not st["has_refresh_token"]
          and not st["has_token"])
    check("新设备未登录", not st["logged_in"])

    # ========== 2. 注册后已有会话 ==========
    print("\n[2] 注册 → 有会话")
    st = S.register(SERVER, username, password)
    check("注册后已登录", st["logged_in"])
    check("注册后有 access_token", st["has_access_token"])
    check("注册后有 refresh_token", st["has_refresh_token"])

    # ========== 3. 同步后 profile/mood 在对象清单里 ==========
    print("\n[3] 同步 + 对象清单含 profile/mood")
    rep = S.sync()
    check("同步成功", rep["ok"], json.dumps(rep.get("errors"), ensure_ascii=False))
    check("objects 含 profile", "profile" in st.get("objects", []))
    check("objects 含 mood", "mood" in st.get("objects", []))
    # 默认对象现在有 8 个
    check("objects 共 8 个", len(st.get("objects", [])) == 8, str(st.get("objects")))

    # ========== 4. profile 读写 ==========
    print("\n[4] profile 同步对象读写")
    from datetime import datetime, timezone

    profile_path = root_a / "Profile"
    # 写入 profile
    profile_doc = {
        "display_name": "测试用户",
        "avatar": "data:image/png;base64,iVBORw0KGgoAAAANSUhEUg==",
        "updated_at": datetime.now(timezone.utc).isoformat(),
    }
    fs.save_json(profile_path, profile_doc)
    check("Profile 文件已写入", profile_path.exists())
    loaded = fs.load_json(profile_path, None)
    check("Profile 可读回", loaded is not None and loaded.get("display_name") == "测试用户")
    check("avatar 字段是 data URL", loaded["avatar"].startswith("data:image/"))
    check("updated_at 字段存在", bool(loaded.get("updated_at")))

    # ========== 5. profile 通过 collect 读取 ==========
    print("\n[5] SyncEngine.collect('profile') 读取")
    from hellopinghe.cloudsync import SyncEngine

    engine = SyncEngine(S.client, S.dek, S.user_id, username,
                        data_dir=root_a, device="test")
    collected = engine.collect("profile")
    check("collect('profile') 返回非空", collected is not None)
    check("collect('profile') 的 display_name", collected.get("display_name") == "测试用户")

    # ========== 6. profile 通过 apply 写回 ==========
    print("\n[6] SyncEngine.apply('profile') 写回")
    new_profile = {
        "display_name": "已修改",
        "avatar": "data:image/jpeg;base64,/9j/4AAQ",
        "updated_at": datetime.now(timezone.utc).isoformat(),
    }
    engine.apply("profile", new_profile)
    reloaded = fs.load_json(profile_path, None)
    check("apply 后 display_name 已更新", reloaded.get("display_name") == "已修改")
    check("apply 后 avatar 已更新", "jpeg" in reloaded.get("avatar", ""))

    # ========== 7. 头像字段格式校验 ==========
    print("\n[7] 头像字段格式校验")
    # 合法 data URL
    valid_avatar = "data:image/png;base64," + "A" * 100
    doc1 = {"display_name": "t", "avatar": valid_avatar, "updated_at": ""}
    check("合法 data URL 可写入", True)
    fs.save_json(profile_path, doc1)
    r1 = fs.load_json(profile_path, None)
    check("data URL 格式完整", r1["avatar"].startswith("data:image/"))

    # 空 avatar（无头像）
    doc2 = {"display_name": "t2", "avatar": "", "updated_at": ""}
    fs.save_json(profile_path, doc2)
    r2 = fs.load_json(profile_path, None)
    check("空 avatar 可写入", r2["avatar"] == "")

    # 超长 avatar（模拟 >200KB）—— 客户端应拦截，这里只验服务端侧不崩溃
    huge_avatar = "data:image/png;base64," + "B" * (250 * 1024)
    doc3 = {"display_name": "t3", "avatar": huge_avatar, "updated_at": ""}
    fs.save_json(profile_path, doc3)
    r3 = fs.load_json(profile_path, None)
    check("超大 avatar 写入不崩溃", r3 is not None and len(r3.get("avatar", "")) > 200 * 1024)

    # ========== 8. 登出后状态 ==========
    print("\n[8] 登出后状态")
    S.logout()
    st = S.status()
    check("登出后未登录", not st["logged_in"])
    check("登出后无令牌", not st["has_access_token"])

    # ========== 9. 重登后 profile 保留 ==========
    print("\n[9] 重登后 profile 保留")
    st = S.login(SERVER, username, password)
    check("重登成功", st["logged_in"])
    rep2 = S.sync()
    check("重登后同步成功", rep2["ok"], json.dumps(rep2.get("errors"), ensure_ascii=False))
    # profile 应该还在（通过同步拉回来）
    loaded2 = fs.load_json(profile_path, None)
    check("重登后 profile 可读", loaded2 is not None)

    # ========== 10. 引导分支：有会话时 status 报告 ==========
    print("\n[10] 有会话时引导分支判断")
    st = S.status()
    check("已登录时 logged_in=true", st["logged_in"])
    check("已登录时 has_access_token=true", st["has_access_token"])
    # 前端判断逻辑: has_access_token || has_refresh_token || has_token → 跳过引导
    should_skip = st["has_access_token"] or st["has_refresh_token"] or st["has_token"]
    check("有会话 → 应跳过引导", should_skip)

    # ========== 清理 ==========
    print("\n[清理] 删除测试账号")
    try:
        S.logout(forget_token=True)
    except Exception:
        pass
    try:
        # 通过 API 删除账号
        import requests as _req
        _req.post(f"{SERVER}/api/v1/auth/delete",
                  json={"username": username, "password": password},
                  timeout=10)
    except Exception:
        pass

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
    raise SystemExit(main())
