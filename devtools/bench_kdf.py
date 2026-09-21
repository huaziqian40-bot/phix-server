"""P5 决策用的实测：scrypt 参数把登录/注册拖慢多少。

    cd D:\\phl-lite-dev
    python -X utf8 D:\\phix\\server\\devtools\\bench_kdf.py

对**真实客户端代码**（`hellopinghe/phixcrypto.py`）跑三种参数：
- 现状 N=2^15（r=8,p=1）：现在所有账号用的
- N=2^16：强度翻倍，代价是每次派生慢一倍（**可选升级**）
- N=2^17：再翻一倍

以及 Argon2id 的对照（本机没装 argon2-cffi 就跳过）。
结论只用来给 P5 拍板提供数字，**不改任何配置**。
"""
import os
import statistics
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, r"D:\phl-lite-dev")

from hellopinghe import phixcrypto as pc  # noqa: E402

SALT = "00112233445566778899aabbccddeeff"
PW = "Bench-Passphrase-1"


def timeit(fn, rounds=5):
    xs = []
    for _ in range(rounds):
        t0 = time.perf_counter()
        fn()
        xs.append((time.perf_counter() - t0) * 1000)
    return min(xs), statistics.median(xs)


def bench_scrypt(n, r=8, p=1):
    import hashlib

    def one():
        hashlib.scrypt(pc.normalize_passphrase(PW),
                       salt=bytes.fromhex(SALT), n=n, r=r, p=p,
                       dklen=32, maxmem=256 * 1024 * 1024)

    return timeit(one)


def bench_argon2():
    try:
        from argon2.low_level import Type, hash_secret_raw
    except ImportError:
        return None

    def one():
        hash_secret_raw(secret=pc.normalize_passphrase(PW),
                        salt=bytes.fromhex(SALT), time_cost=3, memory_cost=65536,
                        parallelism=1, hash_len=32, type=Type.ID)

    return timeit(one)


def main():
    print("=" * 70)
    print("scrypt / Argon2id 实测（本机 CPU，取多轮最小值与中位数，单位 ms）")
    print("=" * 70)
    rows = []
    for n in (1 << 15, 1 << 16, 1 << 17):
        try:
            lo, med = bench_scrypt(n)
            mem = 128 * n * 8 / (1024 * 1024)
            rows.append((f"scrypt N=2^{n.bit_length() - 1} (r=8,p=1)", lo, med,
                         f"内存约 {mem:.0f} MiB"))
        except Exception as exc:  # noqa: BLE001
            rows.append((f"scrypt N=2^{n.bit_length() - 1}", float("nan"),
                         float("nan"), f"跑不了：{exc}"))
    a = bench_argon2()
    if a:
        rows.append(("Argon2id m=64MiB,t=3,p=1", a[0], a[1], "内存 64 MiB"))
    else:
        rows.append(("Argon2id", float("nan"), float("nan"), "未安装 argon2-cffi，跳过"))

    print(f"{'方案':<34}{'最快':>10}{'中位':>10}   说明")
    for name, lo, med, note in rows:
        print(f"{name:<34}{lo:>10.0f}{med:>10.0f}   {note}")

    print("\n登录一次要跑几次派生的实测（用当前客户端代码，N=2^15）：")
    mat = pc.new_material("benchuser", PW)
    t0 = time.perf_counter()
    pc.unwrap_dek(mat["key_wrap"], PW, mat["kdf_salt"], "benchuser")
    t1 = time.perf_counter()
    pc.auth_hash_hex(PW, mat["auth_salt"])
    t2 = time.perf_counter()
    print(f"  解 DEK 一次：{(t1 - t0) * 1000:.0f} ms")
    print(f"  算 AuthHash 一次：{(t2 - t1) * 1000:.0f} ms")
    print("  注：**解 DEK 与算 AuthHash 现在各跑一次 scrypt**（MK 没缓存），"
          "登录合计约上面那两个之和。")
    return 0


if __name__ == "__main__":
    sys.exit(main())
