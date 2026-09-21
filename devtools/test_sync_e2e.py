"""phix 云同步 · 端到端双设备验证（PLL 侧引擎）。

**全程在副本上跑，绝不碰真实 data/。**

    cd D:\\phix\\server
    .venv\\Scripts\\python.exe -X utf8 devtools\\test_sync_e2e.py

场景：
  1. 两端的本地数据都从真实 testenv 的**副本**起步
  2. A 注册并首推 → B 登录拉取，应拿到同一份选课/账号/日程/课表/学校
  3. 两边各加一条日程 → 双方都合并到两条
  4. A 删一条 → B 同步后也跟着删（靠三方合并的快照，不是「看不见就当没删」）
  5. 两边改同一条 → 报告冲突且不静默丢数据
  6. 远端空的一周不许清掉本地课表
  7. 学校数据 managebac/edupage 并集
  8. phll/ 等私有目录绝不出现为对象
"""
import json
import os
import shutil
import sys
import time
from pathlib import Path

sys.path.insert(0, r"D:\phl-lite-dev")

from hellopinghe import cloudsync as cs  # noqa: E402
from hellopinghe import filestore as fs  # noqa: E402
from hellopinghe import phixcrypto as pc  # noqa: E402

BASE = os.environ.get("PHIX_SERVER", "http://127.0.0.1:8931")
SOURCE = Path(r"D:\HPHL\testenv\data")
LAB = Path(r"D:\phix\_lab")

PASSED, FAILED = [], []


def check(name, cond, extra=""):
    (PASSED if cond else FAILED).append(name)
    print(f"  [{'OK  ' if cond else 'FAIL'}] {name}" +
          (f"   {extra}" if extra and not cond else ""))
    return cond


def make_device(tag: str) -> Path:
    """从真实数据的**副本**造一台"设备"的 data 目录。"""
    dst = LAB / f"dev{tag}" / "data"
    if dst.exists():
        shutil.rmtree(dst)
    dst.parent.mkdir(parents=True, exist_ok=True)
    shutil.copytree(SOURCE, dst)
    return dst


def read_schedule(root: Path) -> dict:
    return fs.load_json(root / "Schedule", {}) or {}


def events_of(root: Path) -> dict:
    return {e["id"]: e for e in read_schedule(root).get("events", [])}


def main():
    if not SOURCE.exists():
        raise SystemExit(f"找不到真实数据目录 {SOURCE}")
    LAB.mkdir(parents=True, exist_ok=True)

    print("=" * 74)
    print("phix 云同步 · 双设备端到端（数据全程用副本）")
    print("=" * 74)

    root_a = make_device("A")
    root_b = make_device("B")
    print(f"\n设备 A: {root_a}")
    print(f"设备 B: {root_b}")
    print(f"起始日程条数: A={len(events_of(root_a))} B={len(events_of(root_b))}")

    sfx = f"{int(time.time())}"
    username = f"e2e_{sfx}"
    password = "Sync-Test-123"

    client = cs.PhixClient(BASE)
    code, body = None, None
    try:
        body, mat = client.register(username, password, device="设备A")
    except cs.PhixError as exc:
        raise SystemExit(f"注册失败：{exc}") from exc
    user_id, token_a = body["user_id"], body["token"]
    dek = mat["dek"]
    recovery_code = mat["recovery_code"]
    print(f"注册成功 user_id={user_id} username={username}")

    # ---------- 1. A 首推 ----------
    print("\n[1] A 首次同步（把本地全部推上云）")
    ca = cs.PhixClient(BASE, token_a)
    ea = cs.SyncEngine(ca, dek, user_id, username, data_dir=root_a, device="设备A")
    rep = ea.sync()
    pushed = [k for k, v in rep["objects"].items() if v.get("action") == "push"]
    check("A 首推成功", rep["ok"], json.dumps(rep.get("errors"), ensure_ascii=False))
    check("推了 schedule", "schedule" in pushed, str(pushed))
    check("推了 settings.lessons", "settings.lessons" in pushed, str(pushed))
    check("推了 settings.accounts", "settings.accounts" in pushed, str(pushed))
    check("推了 timetable", "timetable" in pushed, str(pushed))
    check("推了 school", "school" in pushed, str(pushed))
    check("推了 AI 会话对象",
          any(n.startswith("agent:") for n in pushed), str(pushed))

    man = ca.manifest()
    names = {o["name"] for o in man["objects"]}
    check("云端没有 phll/ 私有对象",
          not any(n.startswith(("phll", "phl", "logs", "_backups", ".sync")) for n in names),
          str(sorted(names)))
    check("云端没有 .gh_token", ".gh_token" not in names)

    # ---------- 2. B 登录并拉取 ----------
    print("\n[2] B 登录 + 拉取，应与 A 完全一致")
    lr = cs.PhixClient(BASE).login(username, password, device="设备B")
    token_b = lr["token"]
    dek_b = pc.unwrap_dek(lr["key_wrap"], password, lr["kdf_salt"], username)
    check("B 解出同一把 DEK", dek_b == dek)

    cb = cs.PhixClient(BASE, token_b)
    eb = cs.SyncEngine(cb, dek_b, user_id, username, data_dir=root_b, device="设备B")
    # 先把 B 的本地数据改成"没有"这些内容不现实；直接用 A 之前的版本作对照：
    # B 的本地与 A 相同（同一份副本），所以这里应当 mostly noop；真正验证见第 3 步。
    rep_b = eb.sync()
    check("B 同步成功", rep_b["ok"], json.dumps(rep_b.get("errors"), ensure_ascii=False))
    check("B 的选课与 A 一致",
          ea.collect("settings.lessons") == eb.collect("settings.lessons"))
    check("B 的账号段与 A 一致",
          ea.collect("settings.accounts") == eb.collect("settings.accounts"))
    check("B 的日程与 A 一致",
          ea.collect("schedule") == eb.collect("schedule"))

    # ---------- 3. 两边各加一条日程 ----------
    print("\n[3] 两边各加一条日程 → 双向合并（含 id 撞车）")
    ea.sync()          # 先让两端版本号收敛，再各自新增
    sched_a = read_schedule(root_a)
    next_id = max([e["id"] for e in sched_a.get("events", [])] + [0]) + 1
    sched_a.setdefault("events", []).append(
        {"id": next_id, "day": "2026-09-25", "time": "16:00",
         "title": "A加的（e2e）", "note": "", "created": fs.now_iso()})
    sched_a["lastId"] = next_id
    fs.save_json(root_a / "Schedule", sched_a)

    sched_b = read_schedule(root_b)
    nb = max([e["id"] for e in sched_b.get("events", [])] + [0]) + 1
    sched_b.setdefault("events", []).append(
        {"id": nb, "day": "2026-09-26", "time": "17:00",
         "title": "B加的（e2e）", "note": "", "created": fs.now_iso()})
    sched_b["lastId"] = nb
    fs.save_json(root_b / "Schedule", sched_b)

    rep_a = ea.sync()
    check("A 推送自己那条", rep_a["objects"]["schedule"]["action"] == "push",
          str(rep_a["objects"]["schedule"]))
    rep_b2 = eb.sync()
    check("B 合并了 A 的那条（action=merge）",
          rep_b2["objects"]["schedule"]["action"] == "merge",
          str(rep_b2["objects"]["schedule"]))

    a_events = events_of(root_a)
    b_events = events_of(root_b)
    rep_a2 = ea.sync()
    a_events = events_of(root_a)
    titles_a = {e["title"] for e in a_events.values()}
    titles_b = {e["title"] for e in b_events.values()}
    check("A 侧含两条新日程",
          "A加的（e2e）" in titles_a and "B加的（e2e）" in titles_a, str(titles_a))
    check("B 侧含两条新日程",
          "A加的（e2e）" in titles_b and "B加的（e2e）" in titles_b, str(titles_b))
    check("两端日程条数一致", len(a_events) == len(b_events),
          f"A={len(a_events)} B={len(b_events)}")
    check("跨设备 id 撞车时两份都留下了（远端那条被改号）",
          any(c.get("note", "").startswith("两台设备各自新增") for c in rep_b2["conflicts"]),
          json.dumps(rep_b2["conflicts"], ensure_ascii=False)[:300])
    check("两条新日程的 id 不相同",
          len({e["id"] for e in a_events.values()
               if e["title"] in ("A加的（e2e）", "B加的（e2e）")}) == 2,
          str({e["title"]: e["id"] for e in a_events.values()}))
    check("lastId 取了两边的最大值",
          read_schedule(root_a).get("lastId") >= max(nb, next_id),
          str(read_schedule(root_a).get("lastId")))

    # ---------- 4. 删除传播 ----------
    print("\n[4] A 删一条 → B 同步后也应删掉（三方合并，不是「看不见就当没删」）")
    before = len(events_of(root_a))
    sched_a = read_schedule(root_a)
    sched_a["events"] = [e for e in sched_a["events"] if e["title"] != "A加的（e2e）"]
    fs.save_json(root_a / "Schedule", sched_a)
    ea.sync()
    eb.sync()
    titles_b = {e["title"] for e in events_of(root_b).values()}
    check("B 侧那条已消失", "A加的（e2e）" not in titles_b, str(titles_b))
    check("B 侧还留着 B 自己加的那条", "B加的（e2e）" in titles_b)
    check("条数减少 1", len(events_of(root_b)) == before - 1,
          f"{len(events_of(root_b))} vs {before - 1}")

    # ---------- 5. 冲突：两边改同一条 ----------
    print("\n[5] 两边改同一条日程 → 报冲突但不静默丢数据")
    tid = [e["id"] for e in read_schedule(root_a)["events"]
           if e["title"] == "B加的（e2e）"][0]
    for root, tag in ((root_a, "A改的"), (root_b, "B改的")):
        d = read_schedule(root)
        for e in d["events"]:
            if e["id"] == tid:
                e["note"] = tag
                e["updated_at"] = fs.now_iso()
        fs.save_json(root / "Schedule", d)
    ea.sync()
    rep_b3 = eb.sync()
    conf = [c for c in rep_b3["conflicts"] if c.get("path", "").startswith("events")]
    check("报告了同一条的冲突", bool(conf), json.dumps(rep_b3["conflicts"],
                                                  ensure_ascii=False)[:300])
    merged_note = [e["note"] for e in events_of(root_b).values() if e["id"] == tid]
    check("合并后本地内容仍在（没被清空）", merged_note and merged_note[0], str(merged_note))
    ea.sync()          # A 拉回 B 合并后的结果，两端才应完全一致
    check("两端最终一致",
          events_of(root_a) == events_of(root_b),
          f"A={sorted(events_of(root_a))} B={sorted(events_of(root_b))}")

    # ---------- 6. 空的一周不清课表 ----------
    print("\n[6] 远端「空的一周」绝不许清掉本地课表")
    tt_b = fs.load_json(root_b / "Timetable", {}) or {}
    days_b = tt_b.get("days") or {}
    nonempty = [d for d, v in days_b.items() if v]
    if not nonempty:
        check("B 有课表可测", False, "Timetable 里没有非空的一天")
    else:
        day = nonempty[0]
        before_cards = len(days_b[day])
        # 制造"只有 A 那边这一天变空"的远端版本
        tt_a = fs.load_json(root_a / "Timetable", {}) or {}
        tt_a.setdefault("days", {})[day] = []
        fs.save_json(root_a / "Timetable", tt_a)
        ea.sync()
        eb.sync()
        after = (fs.load_json(root_b / "Timetable", {}) or {}).get("days", {}).get(day, [])
        check(f"B 的 {day} 课卡没被清空", len(after) == before_cards,
              f"before={before_cards} after={len(after)}")

    # ---------- 7. 学校数据并集 ----------
    print("\n[7] School 的 managebac / edupage 取并集")
    sch_b = fs.load_json(root_b / "School", {}) or {}
    mb_tasks = ((sch_b.get("managebac") or {}).get("tasks") or [])
    check("B 有 managebac 数据可测", bool(mb_tasks), f"{len(mb_tasks)} 条")
    # 让 A 侧写一条 B 没有的作业，B 侧保留自己的
    sch_a = fs.load_json(root_a / "School", {}) or {}
    fake = {"id": "e2e-task-1", "course_id": "0", "course": "E2E",
            "title": "E2E 造出来的作业", "due_at": "2026-10-01 23:59",
            "due_text": "", "status": "Pending", "score": ""}
    sch_a.setdefault("managebac", {}).setdefault("tasks", []).append(fake)
    fs.save_json(root_a / "School", sch_a)
    ea.sync()
    eb.sync()
    tasks_b = ((fs.load_json(root_b / "School", {}) or {}).get("managebac") or {}).get("tasks") or []
    ids_b = {str(t.get("id")) for t in tasks_b}
    check("B 收到了 A 新增的作业（并集）", "e2e-task-1" in ids_b, str(sorted(ids_b))[:200])
    check("B 原有的作业没被抹掉", len(tasks_b) >= len(mb_tasks),
          f"{len(tasks_b)} vs {len(mb_tasks)}")

    # ---------- 8. 二次同步应无事可做 ----------
    print("\n[8] 稳定态：再同步一次应当没有变化")
    r1 = ea.sync()
    r2 = eb.sync()
    changed_a = [k for k, v in r1["objects"].items()
                 if v.get("action") not in ("noop", "skip", "remote-deleted")]
    changed_b = [k for k, v in r2["objects"].items()
                 if v.get("action") not in ("noop", "skip", "remote-deleted")]
    check("A 已收敛", not changed_a, str(changed_a))
    check("B 已收敛", not changed_b, str(changed_b))

    # ---------- 9. 禁止上云名单 ----------
    print("\n[9] 禁止上云名单")
    for bad in ("phll/managebac/session_x.json", "phl/profile/x", "logs/app.log",
                "_backups/data-1.zip", ".gh_token", ".sync/state.json"):
        check(f"{bad} 被判为禁止", cs.SyncEngine._is_forbidden(bad), bad)
    for good in ("schedule", "settings.lessons", "agent:20260910-213045", "school"):
        check(f"{good} 允许同步", not cs.SyncEngine._is_forbidden(good), good)

    # ---------- 10. 服务端真的看不懂 ----------
    print("\n[10] 服务端拿到的只有密文")
    obj = ca.get_object("settings.lessons")
    check("payload 是 PHIX1 信封", str(obj["payload"]).startswith("PHIX1."))
    plain = json.dumps(ea.collect("settings.lessons"), ensure_ascii=False)
    marker = plain[10:30] if len(plain) > 30 else plain
    check("密文里不含选课明文", marker not in str(obj["payload"]), marker)

    # ---------- 11. 首次同步不能把云端配置抹掉（PHL 移植时报的 bug） ----------
    print("\n[11] 首次同步（没有基版）：空的那边必须让步，且绝不能崩")
    objs_ai = list(cs.DEFAULT_OBJECTS) + ["settings.ai"]
    # A 配一个 AI 服务商。
    # **2026-09-13 起 settings.ai 的同步载荷是规范形态**（三端统一，见
    # `hellopinghe/aiconfig.py` 与 `phix-协议规范.md`）：
    #   {"providers":[{"name","protocol","base_url","model","api_key"}], "default_index"}
    # 服务商列表是**跨端同步**的；`active_model`（本机选哪个模型）只是本机指针，
    # 不上云 —— 以前这条用例靠 `active_model` 单字段做载体，现在换成规范形态里的
    # `model`。断言的东西没变：**空的那边不许把云端配置抹掉、两边要收敛**。
    ai = fs.load_settings_at(root_a / "settings.yaml").get("ai") or {}
    ai["providers"] = [{
        "id": "p-e2e",
        "name": "同步测试服务商",
        "protocol": "openai",
        "base_url": "https://example.invalid/v1",
        "api_key": "sk-fake-e2e",
        "models": ["model-from-A"],
        "notes": "",
    }]
    ai["active_provider_id"] = "p-e2e"
    ai["active_model"] = "model-from-A"
    fs.update_settings_at(root_a / "settings.yaml", lambda d: d.__setitem__("ai", ai))
    ea_ai = cs.SyncEngine(ca, dek, user_id, username, data_dir=root_a,
                          device="设备A", objects=objs_ai)
    rep_ai_a = ea_ai.sync()
    check("A 把 settings.ai 推上去了",
          rep_ai_a["objects"].get("settings.ai", {}).get("action") in ("push", "merge"),
          str(rep_ai_a["objects"].get("settings.ai")))
    check("A 这轮没有报错（哨兵没泄漏）", rep_ai_a["ok"],
          json.dumps(rep_ai_a.get("errors"), ensure_ascii=False))

    # B：把服务商列表清空，模拟"一台还没配过 AI 的新设备"首拉
    ai_b = (fs.load_settings_at(root_b / "settings.yaml").get("ai") or {})
    ai_b["providers"] = []
    ai_b["active_provider_id"] = ""
    ai_b["active_model"] = ""
    fs.update_settings_at(root_b / "settings.yaml", lambda d: d.__setitem__("ai", ai_b))
    eb_ai = cs.SyncEngine(cb, dek_b, user_id, username, data_dir=root_b,
                          device="设备B", objects=objs_ai)
    rep_ai_b = eb_ai.sync()
    check("B 首拉没有崩", rep_ai_b["ok"],
          json.dumps(rep_ai_b.get("errors"), ensure_ascii=False))
    b_providers = ((fs.load_settings_at(root_b / "settings.yaml").get("ai") or {})
                   .get("providers") or [])
    # 本地 provider 的模型是个**列表**（`models`），规范形态里是单值 `model`；
    # 收下来的时候那个单值会前插到列表最前（见 aiconfig.to_local_provider）。
    b_models = (b_providers[0].get("models") or []) if b_providers else []
    check("B 拿到了云端的服务商与 Key（空的本地列表没有把云端配置抹掉）",
          len(b_providers) == 1 and b_models[:1] == ["model-from-A"]
          and b_providers[0].get("api_key") == "sk-fake-e2e",
          repr(b_providers))
    b_ai = (fs.load_settings_at(root_b / "settings.yaml").get("ai") or {})
    check("B 的 active_provider_id 指到了收下来的那条",
          bool(b_providers)
          and b_ai.get("active_provider_id") == b_providers[0].get("id"),
          repr(b_ai.get("active_provider_id")))
    rep_ai_a2 = ea_ai.sync()
    a_providers = ((fs.load_settings_at(root_a / "settings.yaml").get("ai") or {})
                   .get("providers") or [])
    check("A 的配置没被 B 的空列表覆盖",
          len(a_providers) == 1 and a_providers[0].get("api_key") == "sk-fake-e2e",
          repr(a_providers))
    check("两边都收敛", not any(v.get("action") not in ("noop", "skip")
                                for v in rep_ai_a2["objects"].values()),
          str({k: v.get("action") for k, v in rep_ai_a2["objects"].items()}))
    # 状态文件必须能落盘（哨兵一旦泄漏，这里就会 TypeError）
    st_ai = fs.load_json(root_a / cs.SYNC_DIR / "accounts" / username
                         / cs.STATE_NAME, {}) or {}
    check("状态文件写成功了", bool(st_ai.get("objects")), str(list(st_ai))[:120])

    # ---------- 12. 云端删除 → 本地也要落地 ----------
    print("\n[12] 云端删掉一个对象 → 本地真的会跟着处理")
    # (a) AI 会话：可以安全删除 → 本地文件应当消失
    aid = ea._agent_ids()[0]
    obj_name = f"agent:{aid}"
    ea_ai.sync()
    eb_ai.sync()
    check("B 本地有那个会话文件",
          (root_b / "agent" / f"{aid}.json").is_file())
    rev = ca.get_object(obj_name)["revision"]
    ca.delete_object(obj_name, rev)
    rep_del = eb_ai.sync()
    check("B 这轮没报错", rep_del["ok"],
          json.dumps(rep_del.get("errors"), ensure_ascii=False))
    check("B 本地的会话文件被删了（删除真的传播了）",
          not (root_b / "agent" / f"{aid}.json").exists(),
          str(rep_del["objects"].get(obj_name)))
    rep_del2 = eb_ai.sync()
    ent2 = rep_del2["objects"].get(obj_name)
    # 对象已经不在了 → 它连清单都不会进（这正是我们要的收敛结果）
    check("再同步一次不再反复报同一条",
          ent2 is None or ent2.get("action") in ("noop", "remote-deleted"),
          str(ent2))

    # (b) 共用大文件（Schedule）：**不自动删**，但保留本地并报一次，然后收敛
    sched = read_schedule(root_a)
    rev_s = ca.get_object("schedule")["revision"]
    ca.delete_object("schedule", rev_s)
    rep_del3 = eb_ai.sync()
    check("B 报出「云端删了共用大文件、本地保留」",
          any("共用的大文件" in c.get("note", "") for c in rep_del3["conflicts"]),
          json.dumps(rep_del3["conflicts"], ensure_ascii=False)[:300])
    check("B 的 Schedule 还在（没被误删）",
          (root_b / "schedule").is_file() or (root_b / "Schedule").is_file())
    check("B 的日程条数没变", len(events_of(root_b)) == len(sched.get("events", [])),
          f"{len(events_of(root_b))} vs {len(sched.get('events', []))}")
    rep_del4 = eb_ai.sync()
    check("第二轮不再重复报这条（已收敛）",
          not any("共用的大文件" in c.get("note", "") for c in rep_del4["conflicts"]),
          json.dumps(rep_del4["conflicts"], ensure_ascii=False)[:200])

    # (c) 云端删了、但本地改过 → 保留本地并推回云端（否决这次删除）
    sched_a = read_schedule(root_a)
    sched_a.setdefault("events", []).append(
        {"id": (sched_a.get("lastId") or 0) + 1, "day": "2026-12-01", "time": "10:00",
         "title": "删除后又改的（e2e）", "note": "", "created": fs.now_iso()})
    sched_a["lastId"] = sched_a["events"][-1]["id"]
    fs.save_json(root_a / "Schedule", sched_a)
    ea_ai.sync()          # 推回云端（顺便把墓碑覆盖掉）
    rep_back = eb_ai.sync()
    check("B 从云端又拿到了这份日程（删除被否决）",
          any(e["title"] == "删除后又改的（e2e）"
              for e in events_of(root_b).values()),
          str(sorted(e["title"] for e in events_of(root_b).values())))
    check("两端一致", events_of(root_a) == events_of(root_b),
          f"{len(events_of(root_a))} vs {len(events_of(root_b))}")

    # ---------- 13. 本地只剩一部分时，绝不能把云端的数据当"被删了" ----------
    print("\n[13] 本地不是完整副本时，绝不许静默删掉云端数据")
    # 此时 schedule 上两边都有若干条。把 B 的本地截成只剩 1 条，
    # 同时让 B 的快照"不可信"（sha256 清空，模拟老布局迁移/被别的程序改写）。
    full_a = events_of(root_a)
    sched_b = read_schedule(root_b)
    keep = (sched_b.get("events") or [])[:1]
    sched_b["events"] = keep
    fs.save_json(root_b / "Schedule", sched_b)
    st_file = root_b / cs.SYNC_DIR / "accounts" / username / cs.STATE_NAME
    st = fs.load_json(st_file, {}) or {}
    (st.setdefault("objects", {}).setdefault("schedule", {}))["sha256"] = ""
    fs.save_json(st_file, st)
    check("B 现在只剩 1 条日程", len(events_of(root_b)) == 1, str(len(events_of(root_b))))
    check("云端还有多条", len(full_a) > 1, str(len(full_a)))

    rep_part = eb_ai.sync()
    n_after = len(events_of(root_b))
    check("B 没有把云端日程当『删掉』（并集回来了）",
          n_after >= len(full_a) - 1,
          f"B={n_after} 云端={len(full_a)} obj={rep_part['objects'].get('schedule')}")
    check("A 的日程也没被删", len(events_of(root_a)) >= len(full_a),
          f"A={len(events_of(root_a))}")
    # 收敛：第二轮之后两端一致
    ea_ai.sync()
    eb_ai.sync()
    ea_ai.sync()
    check("最终两端一致", events_of(root_a) == events_of(root_b),
          f"A={len(events_of(root_a))} B={len(events_of(root_b))}")

    # ---------- 14. 账号名安全化边界 ----------
    print("\n[14] 账号目录名安全化（`.` / `..` 不许逃出目录）")
    for bad_name in (".", "..", "...", "", "a/b", "中文名", "x" * 100):
        eng = cs.SyncEngine(ca, dek, user_id, bad_name, data_dir=root_a)
        d = eng._account_dir()
        rel = d.relative_to(root_a / cs.SYNC_DIR / "accounts")
        check(f"账号 {bad_name!r} 的目录名安全 → {rel}",
              len(rel.parts) == 1 and ".." not in rel.parts and rel.name != ".",
              str(d))
        check(f"账号 {bad_name!r} 长度受控", len(rel.name) <= 60, str(rel))

    print("\n" + "=" * 74)
    print(f"通过 {len(PASSED)} 项，失败 {len(FAILED)} 项")
    if FAILED:
        print("失败清单：")
        for f in FAILED:
            print("  - " + f)
    print(f"\n实验目录（可整删，与真实数据无关）：{LAB}")
    print("=" * 74)
    return 1 if FAILED else 0


if __name__ == "__main__":
    sys.exit(main())
