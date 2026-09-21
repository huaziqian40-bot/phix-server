"""并发压力：验证 SQLite 并发写不再间歇性 500。

之前 `database is locked` 会在并发时随机冒出来（整批 500）。
修法是 WAL + `transaction_mode=IMMEDIATE`。这个脚本用**多个进程同时打**
来复现当时的条件。

    cd D:\\phix\\server
    .venv\\Scripts\\python.exe -X utf8 devtools\\stress_parallel.py
"""
import concurrent.futures as cf
import json
import os
import secrets
import sys
import time

import requests

sys.path.insert(0, r"D:\phl-lite-dev")
from hellopinghe import phixcrypto as pc  # noqa: E402

SERVER = os.environ.get("PHIX_SERVER", "http://127.0.0.1:8931")
API = SERVER.rstrip("/") + "/api/v1"
WORKERS = int(os.environ.get("PHIX_STRESS_WORKERS", 8))
ROUNDS = int(os.environ.get("PHIX_STRESS_ROUNDS", 12))


def register(tag):
    user = f"stress{tag}"
    mat = pc.new_material(user, "Stress-Pass-1")
    body = {
        "username": user, "password": "Stress-Pass-1", "agree": True,
        "device": f"压力机{tag}", "kdf_algo": mat["kdf_algo"],
        "kdf_salt": mat["kdf_salt"], "key_wrap": mat["key_wrap"],
        "key_mode": "password", "key_check": mat["key_check"],
        "key_check_plain": mat["key_check_plain"],
        "recovery_salt": mat["recovery_salt"], "recovery_wrap": mat["recovery_wrap"],
    }
    r = requests.post(API + "/auth/register", json=body, timeout=30)
    if r.status_code != 201:
        return None, f"register {r.status_code}: {r.text[:160]}"
    j = r.json()
    return {"user": user, "token": j["token"], "uid": j["user_id"], "dek": mat["dek"]}, None


def worker(idx, errors):
    tag = f"{int(time.time()) % 1000000}{idx}"
    acc, err = register(tag)
    if err:
        errors.append(err)
        return 0
    tok, uid, dek = acc["token"], acc["uid"], acc["dek"]
    h = {"Authorization": f"Bearer {tok}"}
    ok = 0
    for i in range(ROUNDS):
        name = f"obj{i:02d}"
        payload = pc.seal_object(dek, uid, name,
                                 json.dumps({"i": i, "big": "x" * 2000}).encode())
        r = requests.put(f"{API}/sync/objects/{name}", headers=h, timeout=30,
                         json={"base_revision": 0, "payload": payload,
                               "device": f"压力机{idx}"})
        if r.status_code == 200:
            ok += 1
        else:
            errors.append(f"put {r.status_code}: {r.text[:160]}")
        # 混着读，制造读写交错
        requests.get(API + "/sync/manifest", headers=h, timeout=30)
        requests.get(API + "/auth/me", headers=h, timeout=30)
    return ok


def main():
    print("=" * 70)
    print(f"并发压力：{WORKERS} 个进程 × 每人 {ROUNDS} 轮写 + 读")
    print("=" * 70)
    errors = []
    t0 = time.time()
    with cf.ThreadPoolExecutor(max_workers=WORKERS) as ex:
        futs = [ex.submit(worker, i, errors) for i in range(WORKERS)]
        written = sum(f.result() for f in futs)
    dt = time.time() - t0
    print(f"成功写入 {written} 个对象，耗时 {dt:.1f}s")
    print(f"错误 {len(errors)} 条")
    for e in errors[:10]:
        print("  - " + e)
    print("\n" + "=" * 70)
    print("结论：", "✅ 没有并发写失败" if not errors else f"❌ 有 {len(errors)} 条失败")
    print("=" * 70)
    return 1 if errors else 0


if __name__ == "__main__":
    sys.exit(main())
