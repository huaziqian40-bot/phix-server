"""跨程序互通：**PLL(Python) 与 PHL(Node) 对着同一个 `data/` 轮流同步**。

这是"统筹"的核心场景：两个程序共用同一个数据文件夹、同一份 `.sync/` 状态，
必须能互相看懂对方的写入，且不会互相打架。

    cd D:\\phix\\server
    .venv\\Scripts\\python.exe -X utf8 devtools\\test_cross_app.py

数据全程用副本（D:\\phix\\_lab\\cross\\），绝不碰真实 data/。
"""
import json
import os
import shutil
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(r"D:\phix\server")
sys.path.insert(0, r"D:\phl-lite-dev")

SERVER = os.environ.get("PHIX_SERVER", "http://127.0.0.1:8931")
SOURCE = Path(r"D:\HPHL\testenv\data")
LAB = Path(r"D:\phix\_lab\cross")
DRIVER = ROOT / "devtools" / "phl_driver.cjs"

PASSED, FAILED = [], []


def check(name, cond, extra=""):
    (PASSED if cond else FAILED).append(name)
    print(f"  [{'OK  ' if cond else 'FAIL'}] {name}" + (f"   {extra}" if extra and not cond else ""))
    return cond


def node(args, timeout=180):
    """跑 Node 驱动，取最后一行 __PHL_RESULT__。"""
    env = dict(os.environ, PYTHONUTF8="1")
    r = subprocess.run(["node", str(DRIVER)] + [str(a) for a in args],
                       capture_output=True, text=True, encoding="utf-8",
                       errors="replace", env=env, cwd=str(ROOT), timeout=timeout)
    for line in reversed((r.stdout or "").splitlines()):
        if line.startswith("__PHL_RESULT__"):
            return json.loads(line[len("__PHL_RESULT__"):])
    return {"ok": False, "error": "驱动没有输出结果",
            "stdout": (r.stdout or "")[-400:], "stderr": (r.stderr or "")[-400:]}


def load_pll(data_root: Path):
    """在指定数据根下加载 PLL 的模块（数据根在导入时解析，必须重载）。"""
    os.environ["PHLL_DATA_DIR"] = str(data_root)
    for m in [k for k in list(sys.modules) if k.startswith("hellopinghe")]:
        del sys.modules[m]
    from hellopinghe import cloudsync as cs
    from hellopinghe import filestore as fs
    return cs, fs


def events(root: Path) -> dict:
    doc = json.loads((root / "Schedule").read_text(encoding="utf-8"))
    return {e["id"]: e for e in doc.get("events", [])}


def main():
    if not SOURCE.exists():
        raise SystemExit(f"找不到 {SOURCE}")
    if LAB.exists():
        shutil.rmtree(LAB)
    (LAB / "data").mkdir(parents=True, exist_ok=True)
    shutil.copytree(SOURCE, LAB / "data", dirs_exist_ok=True)
    data_dir = LAB / "data"
    # 副本是从真实 testenv 抄的，里面带着**正在运行的 PLL 的运行标记**。
    # 不同步删掉的话，PHL 会按纪律跳过整轮同步（那是正确行为，但测不了互通）。
    for marker in (".pll-running", ".phl-running"):
        p = data_dir / marker
        if p.exists():
            p.unlink()
    print("=" * 74)
    print("跨程序互通：PLL(Python) ↔ PHL(Node) 同一个 data/")
    print("=" * 74)
    print(f"数据目录: {data_dir}")

    cs, fs = load_pll(data_dir)
    user = f"cross{int(time.time()) % 1000000}"
    password = "Cross-App-1"

    print("\n[1] PLL 注册并首推")
    from hellopinghe import phixsession as ps

    st = ps.SESSION.register(SERVER, user, password)
    check("注册成功", st.get("logged_in") and st.get("unlocked"), str(st)[:200])
    rep = ps.SESSION.sync()
    check("PLL 首推成功", rep["ok"], json.dumps(rep.get("errors"), ensure_ascii=False))
    check("推了日程/选课/账号",
          {"schedule", "settings.lessons", "settings.accounts"} <= set(rep["pushed"]),
          str(rep["pushed"]))
    n0 = len(events(data_dir))
    print(f"      起始日程 {n0} 条")

    print("\n[2] 账号目录名两端必须一致（否则各记各的状态，三方合并会退化）")
    py_acct = cs.account_dir_name(user)
    nx = node(["account", user])
    check("Node 的账号目录名与 Python 一致",
          nx.get("accountName") == py_acct, f"node={nx.get('accountName')} py={py_acct}")

    print("\n[3] PHL 对着**同一个目录**同步 —— 应当无事可做（共用状态）")
    r = node(["sync", SERVER, user, password, str(data_dir), "PHL-测试机"])
    check("PHL 同步成功", r.get("ok"), json.dumps(r, ensure_ascii=False)[:300])
    check("PHL 用的账号目录与 PLL 一致",
          r.get("accountName") == py_acct, f"{r.get('accountName')} vs {py_acct}")
    check("PHL 认得出已经是同步好的（没有来回推）",
          len(r.get("pushed") or []) == 0, str(r.get("pushed")))
    check("PHL 的状态文件路径就在同一个目录下",
          str(data_dir) in str(r.get("statePath") or ""), str(r.get("statePath")))

    print("\n[4] PHL 加一条日程并同步 → PLL 应当能拿到")
    ev_title = f"PHL加的-{user}"
    r = node(["add", str(data_dir), ev_title, "2026-11-11"])
    check("PHL 本地加成功", r.get("ok"), json.dumps(r, ensure_ascii=False)[:200])
    r = node(["sync", SERVER, user, password, str(data_dir), "PHL-测试机"])
    check("PHL 推上去了", "schedule" in (r.get("pushed") or []), str(r.get("pushed")))

    rep2 = ps.SESSION.sync()
    check("PLL 同步成功", rep2["ok"], json.dumps(rep2.get("errors"), ensure_ascii=False))
    titles = {e["title"] for e in events(data_dir).values()}
    check("PLL 看到了 PHL 加的那条", ev_title in titles, str(sorted(titles)))
    check("条数增加了 1", len(events(data_dir)) == n0 + 1,
          f"{len(events(data_dir))} vs {n0 + 1}")

    print("\n[5] PLL 加一条日程并同步 → PHL 应当能拿到")
    ev2 = f"PLL加的-{user}"
    sched = json.loads((data_dir / "Schedule").read_text(encoding="utf-8"))
    nid = max([e["id"] for e in sched["events"]] + [sched.get("lastId") or 0]) + 1
    sched["events"].append({"id": nid, "day": "2026-11-12", "time": "10:00",
                            "title": ev2, "note": "PLL 加的",
                            "created": fs.now_iso()})
    sched["lastId"] = nid
    fs.save_json(data_dir / "Schedule", sched)
    rep3 = ps.SESSION.sync()
    check("PLL 推上去了", "schedule" in (rep3["pushed"] or []), str(rep3["pushed"]))

    r = node(["sync", SERVER, user, password, str(data_dir), "PHL-测试机"])
    check("PHL 同步成功", r.get("ok"), json.dumps(r, ensure_ascii=False)[:250])
    titles = {e["title"] for e in events(data_dir).values()}
    check("PHL 侧（同一份文件）有两条新日程",
          ev_title in titles and ev2 in titles, str(sorted(titles)))
    check("两端条数一致（同一份文件，本就该一致）",
          len(events(data_dir)) == n0 + 2, str(len(events(data_dir))))

    print("\n[6] 稳定态：两边都不该再有动作")
    r = node(["sync", SERVER, user, password, str(data_dir), "PHL-测试机"])
    moved = {k: v for k, v in (r.get("actions") or {}).items()
             if v not in ("noop", "skip")}
    check("PHL 已收敛", not moved and r.get("ok"), str(moved))
    rep4 = ps.SESSION.sync()
    moved2 = {k: v.get("action") for k, v in rep4["objects"].items()
              if v.get("action") not in ("noop", "skip")}
    check("PLL 已收敛", not moved2, str(moved2))

    print("\n[7] 并发护栏：对方程序在跑时，PHL 必须整轮跳过")
    marker = data_dir / ".pll-running"
    marker.write_text(json.dumps({"kind": "pll", "pid": os.getpid(),
                                  "started_at": fs.now_iso(),
                                  "updated_at": fs.now_iso()},
                                 ensure_ascii=False), encoding="utf-8")
    r = node(["sync", SERVER, user, password, str(data_dir), "PHL-测试机"])
    check("PHL 识别出 PLL 在跑并跳过", bool(r.get("skipped")),
          json.dumps(r, ensure_ascii=False)[:250])
    check("跳过时不动任何对象", not (r.get("actions") or {}), str(r.get("actions")))
    marker.unlink()

    print("\n[8] 两端对同一个对象的密文理解一致")
    from hellopinghe import phixcrypto as pc

    obj = ps.SESSION.client.get_object("schedule")
    plain = pc.unseal_object(ps.SESSION.dek, ps.SESSION.user_id, "schedule",
                             obj["payload"]).decode("utf-8")
    remote_ids = {e["id"] for e in json.loads(plain).get("events", [])}
    check("PLL 解得开的云端日程 = 本地日程",
          remote_ids == set(events(data_dir)), f"{sorted(remote_ids)}")

    print("\n" + "=" * 74)
    print(f"通过 {len(PASSED)} 项，失败 {len(FAILED)} 项")
    if FAILED:
        for f in FAILED:
            print("  - " + f)
    print(f"实验目录（可整删）：{LAB}")
    print("=" * 74)
    return 1 if FAILED else 0


if __name__ == "__main__":
    sys.exit(main())
