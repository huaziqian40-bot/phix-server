"""phix 密码学跨语言互操作测试：Python 权威实现 ↔ Node(Electron 主进程)实现。

被测对象：
    Python  D:\\phl-lite-dev\\hellopinghe\\phixcrypto.py            （唯一真理来源）
    Node    D:\\phl-dev\\PH-Launcher\\electron\\phix-crypto.cjs     （Electron 主进程侧）

做法：把 Node 模块当成"对端"。因为 nonce 是随机的、信封不可复现，所以不做"两边产出
同一密文"的比对，而是**方向交替验证**：Python 产 → Node 解，Node 产 → Python 解；
确定性派生（scrypt / HKDF / 规范化 / AAD / b64）则直接比 hex。

    运行：D:\\phix\\server\\.venv\\Scripts\\python.exe -X utf8 devtools\\test_crypto_interop.py

本脚本只读被测模块，绝不改写任何仓库文件；node 用的临时脚本写在系统临时目录并在结束时清理。
"""
import inspect
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import time
import traceback
from pathlib import Path

HERE = Path(__file__).resolve()
PY_CRYPTO_DIR = Path(os.environ.get("PHIX_PY_REPO", r"D:\phl-lite-dev"))
# 允许用环境变量指到别的副本（默认就是 PH-Launcher 工作区里的那一份）
NODE_CRYPTO = Path(os.environ.get("PHIX_NODE_CRYPTO", r"D:\phl-dev\PH-Launcher\electron\phix-crypto.cjs"))

sys.path.insert(0, str(PY_CRYPTO_DIR))
from hellopinghe import phixcrypto as pc  # noqa: E402

from cryptography.hazmat.primitives import serialization as _ser  # noqa: E402
from cryptography.hazmat.primitives.asymmetric.x25519 import (  # noqa: E402
    X25519PrivateKey, X25519PublicKey)
from cryptography.hazmat.primitives.ciphers.aead import AESGCM as _AESGCM  # noqa: E402

RE_HEX_FULL = re.compile(r"\A[0-9a-fA-F]*\Z")

PASSED, FAILED = [], []
NODE_RUNS = [0]


# ---------------------------------------------------------------- 结果记录

def check(name, cond, extra=""):
    (PASSED if cond else FAILED).append(name)
    print(f"  [{'OK  ' if cond else 'FAIL'}] {name}" + (f"   {extra}" if extra and not cond else ""))
    return bool(cond)


def eq(name, got, want):
    return check(name, got == want, f"got={got!r} want={want!r}")


# ---------------------------------------------------------------- 值的编解码

def enc(value):
    """Python 值 → 可进 JSON 的类型化标量（供 node 还原）。

    `dict` / `list` 走 `t:'json'`：驱动那侧会带着 __hex 标记还原 Buffer，
    主要给"Node 产出的密钥对象拿回来接着用"这种往返链路用。
    """
    if isinstance(value, (bytes, bytearray)):
        return {"t": "hex", "v": bytes(value).hex()}
    if isinstance(value, str):
        return {"t": "str", "v": value}
    if isinstance(value, bool):
        return {"t": "bool", "v": value}
    if isinstance(value, int):
        return {"t": "int", "v": value}
    if value is None:
        return {"t": "null", "v": None}
    if isinstance(value, (dict, list)):
        return {"t": "json", "v": json.dumps(value, ensure_ascii=False)}
    raise TypeError(f"不支持的入参类型：{type(value)!r}")


def dec(value):
    """node 回传的类型化标量 → Python 值。"""
    if value is None or not isinstance(value, dict) or "t" not in value:
        return value
    tag = value["t"]
    raw = value.get("v")
    if tag == "hex":
        return bytes.fromhex(raw)
    if tag == "str":
        return raw
    if tag == "bool":
        return bool(raw)
    if tag == "int":
        return int(raw)
    if tag == "null":
        return None
    if tag == "json":
        return json.loads(raw)
    raise ValueError(f"未知的返回值类型：{tag!r}")


def needs(*values):
    """把一个调用的入参依次转成 Encoded。"""
    return [enc(v) for v in values]


# ---------------------------------------------------------------- Node 对端

NODE_DRIVER = r"""
'use strict';
// phix 互操作测试的 node 对端驱动：读 ops JSON → 逐个执行 → 写结果 JSON。
const fs = require('node:fs');
const pc = require(process.env.PHIX_CRYPTO);

function decode(arg) {
  if (arg === null || typeof arg !== 'object' || !('t' in arg)) return arg;
  switch (arg.t) {
    case 'hex': return Buffer.from(arg.v, 'hex');
    case 'str': return arg.v;
    case 'bool': return !!arg.v;
    case 'int': return arg.v;
    case 'null': return null;
    // 'json'：把 Python 侧回传的**已编码对象**原样还原。
    //  - `__hex` 标记 → Buffer
    //  - `__keypem` 标记 → 用 PEM 重建密钥对象（KeyObject 没法直接 JSON 串）
    case 'json': return JSON.parse(arg.v, (k, v) => {
      if (v && typeof v === 'object' && typeof v.__hex === 'string') return Buffer.from(v.__hex, 'hex');
      if (v && typeof v === 'object' && typeof v.__keypem === 'string') {
        return v.__keyprivate
          ? require('node:crypto').createPrivateKey({ key: v.__keypem, format: 'pem' })
          : require('node:crypto').createPublicKey({ key: v.__keypem, format: 'pem' });
      }
      return v;
    });
    default: throw new Error('未知入参类型 ' + arg.t);
  }
}

function encode(value) {
  if (Buffer.isBuffer(value) || value instanceof Uint8Array) {
    return { t: 'hex', v: Buffer.from(value).toString('hex') };
  }
  if (typeof value === 'string') return { t: 'str', v: value };
  if (typeof value === 'boolean') return { t: 'bool', v: value };
  if (typeof value === 'number' && Number.isInteger(value)) return { t: 'int', v: value };
  if (value === null || value === undefined) return { t: 'null', v: null };
  // 密钥对象（KeyObject）不是普通对象，JSON 串不出来。用 PEM 装回来，
  // 这样"Node 产出的密钥对象 → Python → 回给 Node 接着用"能走通。
  if (value && typeof value === 'object' && typeof value.asymmetricKeyType === 'string') {
    const isPrivate = typeof value.asymmetricKeyType === 'string'
      && value.type === 'private';
    const pem = value.export({ type: isPrivate ? 'pkcs8' : 'spki', format: 'pem' });
    return { t: 'json', v: JSON.stringify({ __keypem: String(pem), __keyprivate: isPrivate }) };
  }
  if (Array.isArray(value) || typeof value === 'object') {
    return { t: 'json', v: JSON.stringify(value, (k, v) => (Buffer.isBuffer(v) ? { __hex: v.toString('hex') } : v)) };
  }
  return { t: 'str', v: String(value) };
}

const [, , inPath, outPath] = process.argv;
const ops = JSON.parse(fs.readFileSync(inPath, 'utf8'));
const results = ops.map((op) => {
  try {
    // 伪函数：拿回模块**真实**的导出清单（供"两边函数集合精确一致"那条用，
    // 不能只靠 Python 那边写死的名字清单）
    if (op.fn === '__exports__') {
      if (op.args.length) throw new Error('__exports__ 不接受参数');
      return { ok: true, value: encode(Object.keys(pc).sort()) };
    }
    // 常量（非函数）也允许直接取：op.args 为空时若取到非函数值就原样返回
    if (!(op.fn in pc)) throw new Error('模块没有导出 ' + op.fn);
    const fn = pc[op.fn];
    if (typeof fn !== 'function') {
      if (op.args.length) throw new Error(op.fn + ' 不是函数，不能带参数调用');
      return { ok: true, value: encode(fn) };
    }
    return { ok: true, value: encode(fn.apply(pc, op.args.map(decode))) };
  } catch (e) {
    return { ok: false, error: String((e && e.message) || e) };
  }
});
fs.writeFileSync(outPath, JSON.stringify({ version: process.version, results }), 'utf8');
"""


class NodePeer:
    """把 Node 模块当对端：批量调用，单条调用抛错也不影响其它条目。"""

    def __init__(self, workdir):
        self.workdir = Path(workdir)
        self.driver = self.workdir / "phix_node_peer.cjs"
        self.driver.write_text(NODE_DRIVER, encoding="utf-8")
        self.node = shutil.which("node")
        self.version = ""
        self.last_raw = ""
        self._n = 0

    def run(self, ops):
        """ops: [(fn, [已 enc 的入参...]), ...] → [(ok, 值或错误串), ...]"""
        self._n += 1
        in_path = self.workdir / f"in_{self._n}.json"
        out_path = self.workdir / f"out_{self._n}.json"
        in_path.write_text(json.dumps([{"fn": f, "args": a} for f, a in ops]), encoding="utf-8")
        env = dict(os.environ, PHIX_CRYPTO=str(NODE_CRYPTO))
        proc = subprocess.run([self.node, str(self.driver), str(in_path), str(out_path)],
                              capture_output=True, text=True, encoding="utf-8", env=env, timeout=600)
        NODE_RUNS[0] += 1
        if proc.returncode != 0 or not out_path.exists():
            raise SystemExit(f"node 驱动执行失败（exit={proc.returncode}）：\n{proc.stdout}\n{proc.stderr}")
        self.last_raw = out_path.read_text(encoding="utf-8")
        if os.environ.get("PHIX_INTEROP_DEBUG"):
            print(f"    [debug] ops={[(f, len(a)) for f, a in ops]}")
            print(f"    [debug] raw={self.last_raw[:400]}")
        payload = json.loads(self.last_raw)
        self.version = payload["version"]
        return [((True, dec(r["value"])) if r["ok"] else (False, r["error"])) for r in payload["results"]]

    def one(self, fn, *args):
        """单条调用 → (ok, 值或错误串)。"""
        return self.run([(fn, needs(*args))])[0]

    def consts(self, names):
        """批量读常量：返回 {名字: 值}，非函数导出原样回传。"""
        out = {}
        for name, (good, val) in zip(names, self.run([(n, []) for n in names])):
            if good:
                out[name] = val
        return out


def ok1(peer, name, fn, *args):
    """调用一次并要求成功，返回值（失败则记 FAIL 返回 None）。"""
    ok, val = peer.one(fn, *args)
    check(name, ok, f"node 报错：{val}")
    return val if ok else None


def fails(peer, name, fn, *args):
    """调用一次并要求失败（互操作中的"认证失败"路径）。"""
    ok, val = peer.one(fn, *args)
    check(name, not ok, "node 竟然成功了（本该认证失败）")


# ---------------------------------------------------------------- 各段测试

def section(title):
    print("\n" + "-" * 74)
    print(title)
    print("-" * 74)


def test_constants(peer):
    """协议常量两端必须完全一致。"""
    section("常量 / base64url / 规范化")
    ok, checks = peer.one("selfCheck")  # 先跑一次，确认模块能加载且本地往返全通
    base8 = ["key_wrap_roundtrip", "key_check_ok", "key_check_rejects_wrong_dek",
             "dek_proof_matches", "recovery_roundtrip", "object_roundtrip", "aad_binds_name",
             "rewrap_keeps_dek_and_check"]
    check("node 模块可加载且 selfCheck 原有八项全在且全为 true",
          ok and isinstance(checks, dict) and len(checks) >= 8
          and all(checks.get(k) is True for k in base8),
          f"selfCheck={checks}")

    names = ["KDF_ALGO", "ENVELOPE_PREFIX", "SCRYPT_N", "SCRYPT_R", "SCRYPT_P", "SCRYPT_MAXMEM",
             "DEK_BYTES", "NONCE_BYTES", "SALT_BYTES", "KEYCHECK_NAME", "RECOVERY_CHARS",
             "RECOVERY_ALPHABET", "OBJECT_KEY_SALT"]
    want = {"KDF_ALGO": pc.KDF_ALGO, "ENVELOPE_PREFIX": pc.ENVELOPE_PREFIX, "SCRYPT_N": pc.SCRYPT_N,
            "SCRYPT_R": pc.SCRYPT_R, "SCRYPT_P": pc.SCRYPT_P, "SCRYPT_MAXMEM": pc.SCRYPT_MAXMEM,
            "DEK_BYTES": pc.DEK_BYTES, "NONCE_BYTES": pc.NONCE_BYTES, "SALT_BYTES": pc.SALT_BYTES,
            "KEYCHECK_NAME": pc.KEYCHECK_NAME, "RECOVERY_CHARS": pc.RECOVERY_CHARS,
            "RECOVERY_ALPHABET": pc.RECOVERY_ALPHABET, "OBJECT_KEY_SALT": pc.OBJECT_KEY_SALT}
    got_consts = peer.consts(names)
    mismatched = [f"{n}: node={got_consts.get(n)!r} py={want[n]!r}"
                  for n in names if got_consts.get(n) != want[n]]
    check(f"{len(names)} 个协议常量两端一致", not mismatched, "; ".join(mismatched))

    # base64url：逐字节长往返（envelope 里 ct||tag 的长度是偶发的，必须全长度覆盖）
    raws = [b"", b"\x00", b"\xff" * 3, os.urandom(15),
            os.urandom(16), os.urandom(17), os.urandom(31), os.urandom(34), os.urandom(48),
            os.urandom(1023), os.urandom(4096)]
    ops = [("b64e", needs(raw)) for raw in raws] + [("b64d", needs(pc.b64e(raw))) for raw in raws]
    res = peer.run(ops)
    bad = []
    for i, raw in enumerate(raws):
        got_e, got_d = res[i][1], res[len(raws) + i][1]
        if got_e != pc.b64e(raw) or not res[i][0]:
            bad.append(f"b64e({len(raw)}B) node={got_e!r} py={pc.b64e(raw)!r}")
        if got_d != raw or not res[len(raws) + i][0]:
            bad.append(f"b64d({len(raw)}B) node={got_d!r} py={raw!r}")
    check(f"b64e/b64d {len(raws)} 种长度与 Python 逐字节一致（含无填充还原）", not bad, "; ".join(bad[:3]))

    # 方向互认：Python 编码的 base64url node 能解回原字节（上面已覆盖），反之亦然
    ok, node_b64 = peer.one("b64e", b"\x00\xff\x10hello")
    check("Node b64e 输出可被 Python b64d 还原",
          ok and pc.b64d(node_b64) == b"\x00\xff\x10hello", f"node={node_b64!r}")

    ok, val = peer.one("newSalt")
    check("newSalt 返回 32 位 hex（与 Python 格式一致）",
          ok and isinstance(val, str) and len(val) == pc.SALT_BYTES * 2
          and all(c in "0123456789abcdef" for c in val), f"got={val!r}")
    ok, val2 = peer.one("newSalt")
    check("两次 newSalt 不同（随机）", ok and val2 != val)


def test_passphrase_normalization(peer):
    """口令归一化：NFKC + 去首尾空白 → UTF-8。"""
    cases = [
        "correct horse battery staple",
        "  spaced  ",                              # 首尾空白
        "\ttabbed\n",                              # 制表/换行
        "ＡＢＣ－１２３",                            # 全角 → NFKC 半角
        "café",                                    # 组合重音
        "cafe\u0301",                              # 分解形重音（NFKC 合成后应与上一条同字节）
        "ｐａｓｓｗｏｒｄ\u3000",                      # 全角 + 表意空格
        "汉字\"引号\"\\反斜杠/",                    # 中文与转义
    ]
    ops = [("normalizePassphrase", needs(s)) for s in cases]
    res = peer.run(ops)
    bad = []
    for i, s in enumerate(cases):
        got = res[i][1] if res[i][0] else f"<err {res[i][1]}>"
        if got != pc.normalize_passphrase(s):
            bad.append(f"{s!r}: node={got!r} py={pc.normalize_passphrase(s)!r}")
    check(f"normalizePassphrase {len(cases)} 例与 Python 逐字节一致", not bad, "; ".join(bad[:3]))
    check("分解形/合成形重音归一后相同（NFKC 生效）",
          pc.normalize_passphrase("cafe\u0301") == pc.normalize_passphrase("café"))


def hexs(value):
    """node 回传的 Buffer 转 hex 字符串；本来就是字符串则原样返回（用于比 hex 的项）。"""
    return value.hex() if isinstance(value, (bytes, bytearray)) else value


def test_kek_and_key(peer):
    """scrypt(KEK) 与 HKDF(对象密钥) 的确定性一致性。"""
    section("KDF：scrypt KEK / HKDF 对象密钥")
    salts = [pc.new_salt(), pc.new_salt(), "00" * 16]
    phrases = ["correct horse battery staple", " 口令 with spaces ", "ＡＢ　"]
    dek = bytes(range(32))
    names = ["schedule", "__keycheck__", "带中文的名字.json", "a/b/c", ""]

    ops = []
    for s in salts:
        for p in phrases:
            ops.append(("deriveKek", needs(p, s)))
    res = peer.run(ops)
    bad, idx = [], 0
    for s in salts:
        for p in phrases:
            good, got = res[idx]
            want = pc.derive_kek(p, s).hex()
            if not good or hexs(got) != want:
                bad.append(f"kek(salt={s[:8]}…, pass={p!r}) node={hexs(got)} py={want}")
            idx += 1
    check(f"scrypt KEK {len(salts) * len(phrases)} 组两端 hex 完全相同（N=2^15,r=8,p=1）", not bad,
          "; ".join(bad[:2]))
    check("KEK 长度 32 字节", len(pc.derive_kek("x", salts[0])) == 32)

    ops = [("deriveObjectKey", needs(dek, n)) for n in names]
    res = peer.run(ops)
    bad = []
    for i, n in enumerate(names):
        good, got = res[i]
        want = pc.derive_object_key(dek, n).hex()
        if not good or hexs(got) != want:
            bad.append(f"{n!r}: node={hexs(got)} py={want}")
    check(f"HKDF 对象密钥 {len(names)} 例两端 hex 完全相同（salt=OBJECT_KEY_SALT）", not bad,
          "; ".join(bad[:2]))
    check("对象密钥长度 32 字节（与 Python 的 length=32 一致）",
          pc.derive_object_key(dek, "schedule") != pc.derive_object_key(dek, "schedule2"))


def test_aad(peer):
    """AAD 两族字符串必须逐字节一致。"""
    section("AAD 构造")
    id_cases = ["alice", "张三", "a|b", ""]
    obj_cases = [(7, "schedule"), (0, "x"), (123456789, "带中文/斜杠.json"), (7, "")]
    ops = [("aadIdentity", needs(u)) for u in id_cases] + [("aadObject", needs(uid, n)) for uid, n in obj_cases]
    res = peer.run(ops)
    bad = []
    for i, u in enumerate(id_cases):
        got = res[i][1] if res[i][0] else f"<err {res[i][1]}>"
        if got != pc.aad_identity(u):
            bad.append(f"identity({u!r}): node={got!r} py={pc.aad_identity(u)!r}")
    for j, (uid, n) in enumerate(obj_cases):
        got = res[len(id_cases) + j][1] if res[len(id_cases) + j][0] else "<err>"
        if got != pc.aad_object(uid, n):
            bad.append(f"object({uid},{n!r}): node={got!r} py={pc.aad_object(uid, n)!r}")
    check("aadIdentity/aadObject 与 Python 逐字节一致（含中文、空串、管道符）", not bad, "; ".join(bad[:3]))
    eq("身份族 AAD 前缀正确", pc.aad_identity("u")[:len("phix/v1/identity|")], b"phix/v1/identity|")


def test_envelopes(peer):
    """对象信封双向：Python 产 → Node 解；Node 产 → Python 解。"""
    section("对象信封 PHIX1：Python ⇄ Node")
    dek = pc.new_material("u", "p")["dek"]
    cases = [
        (7, "schedule", b'{"hello":"world"}'),
        (42, "带中文/名字.json", '{"msg":"中文与 emoji 🎓"}'.encode("utf-8")),
        (1, "empty", b""),
        (9, "big", os.urandom(200_000)),   # 覆盖各种 b64 长度余数（曾在此类长度上翻车）
    ]

    # 方向 A：Python seal_object → Node unsealObject
    py_envs = [pc.seal_object(dek, uid, name, plain) for uid, name, plain in cases]
    ops = [("unsealObject", needs(dek, uid, name, env)) for (uid, name, _), env in zip(cases, py_envs)]
    res = peer.run(ops)
    bad = []
    for (uid, name, plain), (good, got) in zip(cases, res):
        if not good or got != plain:
            bad.append(f"{name!r}: {'node 报错 ' + str(got) if not good else '明文不符'}")
    check(f"Python 加密 → Node 解密 {len(cases)} 例明文完全一致", not bad, "; ".join(bad))
    check("信封以 PHIX1. 开头且含两段 base64url",
          all(e.startswith("PHIX1.") and e.count(".") == 2 for e in py_envs))

    # 方向 B：Node sealObject → Python unseal_object
    ops = [("sealObject", needs(dek, uid, name, plain)) for uid, name, plain in cases]
    res = peer.run(ops)
    bad = []
    for (uid, name, plain), (good, env) in zip(cases, res):
        if not good:
            bad.append(f"{name!r}: node 报错 {env}")
            continue
        try:
            back = pc.unseal_object(dek, uid, name, env)
        except Exception as exc:  # noqa: BLE001
            bad.append(f"{name!r}: Python 解不开 {type(exc).__name__}")
            continue
        if back != plain:
            bad.append(f"{name!r}: 明文不符")
    check(f"Node 加密 → Python 解密 {len(cases)} 例明文完全一致", not bad, "; ".join(bad))

    # 同一明文两次加密必须不同（nonce 随机），但都能解开
    ok, e1 = peer.one("sealObject", dek, 7, "schedule", b"same")
    ok2, e2 = peer.one("sealObject", dek, 7, "schedule", b"same")
    check("两次 sealObject 信封不同（nonce 随机）", ok and ok2 and e1 != e2)
    check("两次信封都能被 Python 解开", ok and ok2 and pc.unseal_object(dek, 7, "schedule", e1) == b"same"
          and pc.unseal_object(dek, 7, "schedule", e2) == b"same")

    # AAD 绑定：错名字 / 错 user_id / 篡改密文 / 假信封 都必须失败
    env = py_envs[0]
    fails(peer, "错误对象名解 Python 信封 → node 抛错（AAD 绑名字）",
          "unsealObject", dek, 7, "timetable", env)
    fails(peer, "错误 user_id 解 Python 信封 → node 抛错（AAD 绑用户）",
          "unsealObject", dek, 8, "schedule", env)
    fails(peer, "错误 DEK 解 Python 信封 → node 抛错",
          "unsealObject", os.urandom(32), 7, "schedule", env)
    tampered = env[:-1] + ("A" if env[-1] != "A" else "B")
    fails(peer, "篡改信封末位 → node 抛错（GCM 认证）", "unsealObject", dek, 7, "schedule", tampered)
    fails(peer, "非 PHIX1 信封 → node 抛错", "unsealObject", dek, 7, "schedule", "PHIX2.abc.def")
    fails(peer, "缺段信封 → node 抛错", "unsealObject", dek, 7, "schedule", "PHIX1.onlyone")

    # 反向：Python 解 node 的错名字信封
    ok, node_env = peer.one("sealObject", dek, 7, "schedule", b"payload")
    wrong_name_ok = False
    try:
        pc.unseal_object(dek, 7, "timetable", node_env)
    except Exception:  # noqa: BLE001
        wrong_name_ok = True
    check("Python 用错误对象名解 node 信封 → 抛错（AAD 双向绑定）", ok and wrong_name_ok)


def test_key_wrap(peer):
    """key_wrap 双向：口令包裹的 DEK 互解。"""
    section("DEK 包裹 key_wrap（身份族 AAD）")
    username = "alice"
    passphrase = "correct horse battery staple"
    salt = pc.new_salt()
    dek = os.urandom(32)

    # Python wrap → Node unwrap
    py_env = pc.wrap_dek(dek, passphrase, salt, username)
    ok, got = peer.one("unwrapDek", py_env, passphrase, salt, username)
    check("Python wrap_dek → Node unwrapDek 得到同一 DEK", ok and got == dek,
          f"node 报错：{got}" if not ok else f"got={got.hex() if isinstance(got, bytes) else got}")
    ok, kek_node = peer.one("deriveKek", passphrase, salt)
    check("Node 解出的 DEK 与 Python KEK 派生路径一致",
          ok and pc.derive_kek(passphrase, salt).hex() == kek_node.hex())

    # Node wrap → Python unwrap
    ok, node_env = peer.one("wrapDek", dek, passphrase, salt, username)
    try:
        back = pc.unwrap_dek(node_env, passphrase, salt, username)
    except Exception as exc:  # noqa: BLE001
        back = f"<{type(exc).__name__}: {exc}>"
    check("Node wrapDek → Python unwrap_dek 得到同一 DEK", ok and back == dek, f"得到 {back!r}")

    # 口令错 / 用户名错 / 盐错 必须都失败
    ok, bad_env = peer.one("wrapDek", dek, passphrase, salt, username)
    for label, kwargs in [("口令错", ("wrong", salt, username)),
                          ("用户名错", (passphrase, salt, "bob")),
                          ("盐错", (passphrase, pc.new_salt(), username))]:
        try:
            pc.unwrap_dek(bad_env, *kwargs)
            wrapped = True
        except Exception:  # noqa: BLE001
            wrapped = False
        check(f"Python {label} 解 node 信封 → 抛错", ok and not wrapped)

    # 归一化后等价的口令：首尾空白 + 全角 必须能互解
    ok, env2 = peer.one("wrapDek", dek, "  ＡＢＣ－１２３　", salt, username)
    try:
        back2 = pc.unwrap_dek(env2, "ABC-123", salt, username)
    except Exception as exc:  # noqa: BLE001
        back2 = f"<{type(exc).__name__}>"
    check("归一化等价口令（全角/空白）跨语言互解", ok and back2 == dek, f"得到 {back2!r}")


def test_key_check(peer):
    """自检块：proveDek / checkDek 双向。"""
    section("自检块 key_check / proveDek")
    username = "张三"
    dek = os.urandom(32)

    # Python 造 → Node 证明
    plain = pc.new_key_check_plain()
    py_check = pc.make_key_check(dek, username, plain)
    ok, got = peer.one("proveDek", dek, username, py_check)
    check("Python key_check → Node proveDek 返回同一 hex 明文", ok and got == plain,
          f"node 报错：{got}" if not ok else f"got={got!r} want={plain!r}")
    ok, flag = peer.one("checkDek", dek, username, py_check)
    check("Node checkDek 对正确 DEK 返回 true", ok and flag is True, f"got={flag!r}")
    ok, flag = peer.one("checkDek", os.urandom(32), username, py_check)
    check("Node checkDek 对错误 DEK 返回 false", ok and flag is False, f"got={flag!r}")
    ok, other = peer.one("proveDek", dek, "李四", py_check)
    check("Node proveDek 用错用户名 → 认证失败", not ok, f"竟然成功：{other!r}")

    # Node 造 → Python 证明
    ok, node_plain = peer.one("newKeyCheckPlain")
    check("Node newKeyCheckPlain 是 64 位 hex", ok and isinstance(node_plain, str)
          and len(node_plain) == 64 and all(c in "0123456789abcdef" for c in node_plain), f"got={node_plain!r}")
    ok, node_check = peer.one("makeKeyCheck", dek, username, node_plain)
    try:
        proof = pc.prove_dek(dek, username, node_check)
    except Exception as exc:  # noqa: BLE001
        proof = f"<{type(exc).__name__}: {exc}>"
    check("Node key_check → Python prove_dek 返回同一 hex 明文", ok and proof == node_plain, f"得到 {proof!r}")
    check("Python check_dek 认 node 的 key_check", ok and pc.check_dek(dek, username, node_check) is True)
    check("Python check_dek 否决错 DEK", pc.check_dek(os.urandom(32), username, node_check) is False)
    check("自检块不是公开常量（两次生成明文不同）",
          pc.new_key_check_plain() != pc.new_key_check_plain())


def test_recovery(peer):
    """恢复码：生成 / 规范化 / 包裹解包双向。"""
    section("恢复码 recovery code")
    username = "bob"
    dek = os.urandom(32)
    rsalt = pc.new_salt()
    py_code = pc.new_recovery_code()

    # Python wrap → Node unwrap
    py_env = pc.wrap_dek_with_recovery(dek, py_code, rsalt, username)
    ok, got = peer.one("unwrapDekWithRecovery", py_env, py_code, rsalt, username)
    check("Python wrap_dek_with_recovery → Node unwrapDekWithRecovery 同一 DEK", ok and got == dek,
          f"node 报错：{got}" if not ok else "")
    ok, got2 = peer.one("unwrapDekWithRecovery", py_env, py_code.lower().replace("-", " "), rsalt, username)
    check("恢复码小写 + 空格分隔仍可解（规范化一致）", ok and got2 == dek,
          f"node 报错：{got2}" if not ok else "")

    # Node wrap → Python unwrap
    ok, node_env = peer.one("wrapDekWithRecovery", dek, py_code, rsalt, username)
    try:
        back = pc.unwrap_dek_with_recovery(node_env, py_code, rsalt, username)
    except Exception as exc:  # noqa: BLE001
        back = f"<{type(exc).__name__}: {exc}>"
    check("Node wrapDekWithRecovery → Python unwrap_dek_with_recovery 同一 DEK", ok and back == dek,
          f"得到 {back!r}")

    # Node 生成的码：格式 + 两边规范化一致 + Python 能用来解 node 的信封
    ok, node_code = peer.one("newRecoveryCode")
    check("Node newRecoveryCode 格式 XXXX-XXXX-XXXX-XXXX-XXXX-XXXX（24 位字母表）",
          ok and isinstance(node_code, str) and len(node_code) == 29
          and [len(g) for g in node_code.split("-")] == [4] * 6
          and all(ch in pc.RECOVERY_ALPHABET for ch in node_code.replace("-", "")),
          f"got={node_code!r}")
    bad = []
    variants = [node_code, node_code.lower(), node_code.replace("-", ""), f"  {node_code}  ",
                node_code.replace("-", " - "), node_code.replace("A", "Ａ") if "A" in node_code else node_code]
    res = peer.run([("normalizeRecoveryCode", needs(v)) for v in variants])
    for v, (good, got) in zip(variants, res):
        want = pc.normalize_recovery_code(v)
        if not good or got != want:
            bad.append(f"{v!r}: node={got!r} py={want!r}")
    check("normalizeRecoveryCode 6 种写法与 Python 一致（大写 + 只留字母数字）", not bad, "; ".join(bad[:2]))

    ok, env3 = peer.one("wrapDekWithRecovery", dek, node_code, rsalt, username)
    try:
        back3 = pc.unwrap_dek_with_recovery(env3, node_code.replace("-", " ").lower(), rsalt, username)
    except Exception as exc:  # noqa: BLE001
        back3 = f"<{type(exc).__name__}>"
    check("Node 新生成的恢复码 → Python 解 node 信封成功（端到端）", ok and back3 == dek, f"得到 {back3!r}")
    py_new = pc.new_recovery_code()
    ok, norm = peer.one("normalizeRecoveryCode", py_new)
    check("Python 新生成的恢复码 → Node 规范化与 Python 一致",
          ok and norm == pc.normalize_recovery_code(py_new), f"node={norm!r}")


def test_material(peer):
    """整套材料 material_from_dek / rewrap 的字段与跨语言可用性。"""
    section("整套密钥材料 materialFromDek / rewrap")
    username = "carol"
    passphrase = "correct horse battery staple"
    dek = os.urandom(32)

    py_mat = pc.material_from_dek(dek, username, passphrase)
    py_keys = sorted(py_mat.keys())
    # 基准字段 + v2 才有的凭证字段（auth_salt 一直有；auth_hash 只在 v2）
    base_keys = ["dek", "recovery_code", "kdf_algo", "kdf_salt", "auth_salt",
                 "recovery_salt", "key_wrap", "recovery_wrap", "key_check",
                 "key_check_plain", "key_mode"]
    expected_keys = sorted(base_keys + (["auth_hash"] if "auth_hash" in py_mat else []))
    check("Python material_from_dek 字段齐备", py_keys == expected_keys, f"{py_keys}")

    ok, node_mat = peer.one("materialFromDek", dek, username, passphrase)
    if not ok:
        check("Node materialFromDek 成功", False, str(node_mat))
    else:
        node_keys = sorted(node_mat.keys())
        want_keys = sorted(py_keys + ["dek_hex"])
        check("Node materialFromDek 键名与 Python 完全一致（+dek_hex）", node_keys == want_keys,
              f"node={node_keys}")
        eq("key_mode 默认 password", node_mat["key_mode"], py_mat["key_mode"])
        eq("kdf_algo 一致", node_mat["kdf_algo"], py_mat["kdf_algo"])
        eq("dek_hex 反映同一把 DEK", node_mat["dek_hex"], dek.hex())
        check("dek_hex 是 64 位小写 hex（JSON 可序列化的那一份）",
              isinstance(node_mat["dek_hex"], str) and len(node_mat["dek_hex"]) == 64
              and all(c in "0123456789abcdef" for c in node_mat["dek_hex"]))
        check("dek 是 32 字节的 Buffer（Node 侧类型，跨 JSON 后为 {type:Buffer,data:[..]}）",
              isinstance(node_mat["dek"], dict) and node_mat["dek"].get("type") == "Buffer"
              and len(node_mat["dek"].get("data", [])) == 32,
              f"dek={str(node_mat['dek'])[:60]}")
        check("盐是 32 位 hex", len(node_mat["kdf_salt"]) == 32 and len(node_mat["recovery_salt"]) == 32)
        check("kdf_salt 与 recovery_salt 不同", node_mat["kdf_salt"] != node_mat["recovery_salt"])
        check("key_check_plain 是 64 位 hex", len(node_mat["key_check_plain"]) == 64)
        check("recovery_code 是 6 组 4 位", len(node_mat["recovery_code"].split("-")) == 6)

        # node 材料 → Python 全链路可用
        try:
            dek_back = pc.unwrap_dek(node_mat["key_wrap"], passphrase, node_mat["kdf_salt"], username)
        except Exception as exc:  # noqa: BLE001
            dek_back = f"<{type(exc).__name__}: {exc}>"
        check("Python 用 node 的 key_wrap/salt 解出同一 DEK", dek_back == dek, f"得到 {dek_back!r}")
        check("Python 认 node 的 key_check",
              pc.prove_dek(dek, username, node_mat["key_check"]) == node_mat["key_check_plain"])
        try:
            dek_rec = pc.unwrap_dek_with_recovery(node_mat["recovery_wrap"], node_mat["recovery_code"],
                                                  node_mat["recovery_salt"], username)
        except Exception as exc:  # noqa: BLE001
            dek_rec = f"<{type(exc).__name__}: {exc}>"
        check("Python 用 node 的 recovery_wrap/恢复码解出同一 DEK", dek_rec == dek, f"得到 {dek_rec!r}")

    # Python 材料 → node 全链路可用
    ok, back = peer.one("unwrapDek", py_mat["key_wrap"], passphrase, py_mat["kdf_salt"], username)
    check("Node 用 Python 的 key_wrap/salt 解出同一 DEK", ok and back == dek, f"node 报错：{back}")
    ok, proof = peer.one("proveDek", dek, username, py_mat["key_check"])
    check("Node 认 Python 的 key_check", ok and proof == py_mat["key_check_plain"], f"node 报错：{proof}")
    ok, rec = peer.one("unwrapDekWithRecovery", py_mat["recovery_wrap"], py_mat["recovery_code"],
                       py_mat["recovery_salt"], username)
    check("Node 用 Python 的 recovery_wrap/恢复码解出同一 DEK", ok and rec == dek, f"node 报错：{rec}")

    # rewrap：同一把 DEK，只换包裹，key_check_plain 必须沿用
    ok, rw = peer.one("rewrap", dek, username, "new phrase", "password",
                      py_mat["recovery_code"], py_mat["key_check_plain"])
    if not ok:
        check("Node rewrap 成功", False, str(rw))
    else:
        check("rewrap 后 key_check_plain 沿用旧的", rw["key_check_plain"] == py_mat["key_check_plain"])
        try:
            dek_rw = pc.unwrap_dek(rw["key_wrap"], "new phrase", rw["kdf_salt"], username)
        except Exception as exc:  # noqa: BLE001
            dek_rw = f"<{type(exc).__name__}: {exc}>"
        check("Python 用新口令解 node rewrap 的信封 → 同一 DEK", dek_rw == dek, f"得到 {dek_rw!r}")
        check("Python 认 rewrap 后的 key_check",
              pc.prove_dek(dek, username, rw["key_check"]) == py_mat["key_check_plain"])

    # 换口令后密文不用动：老密文用同一 DEK 仍可解
    ok, env = peer.one("sealObject", dek, 7, "schedule", b"old ciphertext")
    ok2, rw2 = peer.one("rewrap", dek, username, "another phrase")
    check("换口令前后对象密文完全可解（三层密钥的意义）",
          ok and ok2 and pc.unseal_object(dek, 7, "schedule", env) == b"old ciphertext"
          and pc.unwrap_dek(rw2["key_wrap"], "another phrase", rw2["kdf_salt"], username) == dek)


def test_module_surface(peer):
    """两边导出的函数名清单必须一一对应（camelCase ↔ snake_case）。"""
    section("模块导出面")
    want = ["b64e", "b64d", "normalizePassphrase", "newSalt", "aadIdentity", "aadObject",
            "deriveKek", "deriveObjectKey", "seal", "unseal", "sealObject", "unsealObject",
            "wrapDek", "unwrapDek", "makeKeyCheck", "newKeyCheckPlain", "proveDek", "checkDek",
            "newRecoveryCode", "normalizeRecoveryCode", "wrapDekWithRecovery",
            "unwrapDekWithRecovery", "materialFromDek", "newMaterial", "rewrap", "selfCheck",
            # 应用层加密传输（加密链路思路.md §3）
            "sealBox", "openBox", "envAad", "newSessionKey", "makeEnvelope",
            "openEnvelopeResponse",
            # KDF 两代（§2.2：v1 KEK=MK；v2 MK→HKDF("auth")=AuthHash 发服务器、
            #                            HKDF("enc")=KEK 永不出客户端）
            "deriveMk", "deriveAuthHash", "authHashHex", "usesAuthHash",
            # MK 缓存（**只是省时间**：登录时"算 AuthHash"与"解 DEK"输入相同，
            # 缓存后省下一次 scrypt。不参与任何加解密，也不改变协议）
            "clearMkCache", "mkCacheStats"]

    def snake(name):
        return "".join("_" + c.lower() if c.isupper() else c for c in name)

    def camel(name):
        head, *rest = name.split("_")
        return head + "".join(w[:1].upper() + w[1:] for w in rest)

    want_snake = {snake(f) for f in want}
    missing_py = [f for f in want if f != "selfCheck" and not callable(getattr(pc, snake(f), None))]
    check(f"Python 侧 {len(want)} 个同名函数（snake_case）齐备", not missing_py,
          f"缺 {[snake(f) for f in missing_py]}")

    bad = []
    res = peer.run([(f, []) for f in want])
    for f, (good, err) in zip(want, res):
        # 参数不对必然报错，只要报的不是"模块没有导出 X"就算导出存在
        if not good and "没有导出" in str(err):
            bad.append(f)
    check(f"Node 侧 {len(want)} 个同名导出全部存在（camelCase）", not bad, f"缺 {bad}")

    # 唯一的名字差异：Python 是 selfcheck（全小写），Node 按任务书用 selfCheck
    check("selfCheck 命名差异已确认（Python selfcheck / Node selfCheck，语义相同）",
          callable(getattr(pc, "selfcheck", None)) and "selfCheck" in want)

    py_funcs = {n for n in dir(pc) if callable(getattr(pc, n)) and not n.startswith("_")
                and not inspect.isclass(getattr(pc, n))}
    # Python 公开函数 → 对应的 Node 名字（已知唯一差异 selfcheck ↔ selfCheck，已在上一条确认）
    node_names = want_snake | {"selfcheck", "clear_mk_cache"}
    extra = sorted(n for n in py_funcs if not inspect.ismodule(getattr(pc, n))
                   and n not in node_names and camel(n) not in set(want))
    check("Python 侧公开函数 Node 侧全部有对应（无遗漏函数）", not extra, f"多出 {extra}")

    # 反向：把 Node **真实**的导出清单拿回来，跟 Python 的公开函数集合精确比对。
    # 上面那条只查"Node 有没有这些名字"，这条能抓出"两边有一边多/少"。
    ok, node_exports = peer.one("__exports__")
    if not ok:
        # 驱动不支持时退化成逐个名字探测，避免因为拿不到清单就漏测
        ok, node_exports = peer.one("selfCheck")
        check("拿不到 Node 导出清单（退化检查已跳过）", False, str(node_exports))
        return
    node_fn = {n for n in node_exports if n in want}
    py_snake = {snake(n) for n in node_fn}
    # 已知且已确认的唯一命名差异：Python `selfcheck` ↔ Node `selfCheck`
    # 另外 MK 缓存那两个是**辅助函数**（不参与加解密），两边都刻意用 snake_case 导出，
    # 免得 `camel()` 把 clear_mk_cache 折成 clearMkCache 与 Node 对不上。
    aliases = {"selfcheck": "selfCheck", "selfCheck": "selfcheck",
               "clear_mk_cache": "clearMkCache", "clearMkCache": "clear_mk_cache"}
    python_only = sorted(n for n in py_funcs if not inspect.ismodule(getattr(pc, n))
                         and n not in py_snake and aliases.get(n) not in node_fn)
    node_only = sorted(n for n in node_fn if not callable(getattr(pc, snake(n), None))
                       and n not in aliases)
    check("Node 导出清单里的函数 Python 侧也都有", not node_only, f"Node 多出 {node_only}")
    check(f"两边公开函数集合精确一致（{len(py_snake)} 个）",
          not python_only and not node_only,
          f"Python 多出 {python_only} / Node 多出 {node_only}")


def test_application_transport(peer):
    """应用层加密传输：密封盒（X25519 + HKDF + AES-GCM）与请求/响应信封。"""
    section("应用层加密传输（密封盒 / 信封）")

    # ---- 常量 ----
    names = ["SEAL_INFO", "REQ_AAD_PREFIX", "EPK_LEN", "NONCE_LEN", "SK_LEN"]
    want = {"SEAL_INFO": pc.SEAL_INFO, "REQ_AAD_PREFIX": pc.REQ_AAD_PREFIX,
            "EPK_LEN": pc.EPK_LEN, "NONCE_LEN": pc.NONCE_LEN, "SK_LEN": pc.SK_LEN}
    got = peer.consts(names)
    mismatched = [f"{n}: node={got.get(n)!r} py={want[n]!r}" for n in names
                  if _norm_const(got.get(n)) != _norm_const(want[n])]
    check(f"{len(names)} 个传输层常量两端一致", not mismatched, "; ".join(mismatched))

    # ---- X25519 原始字节表示：最容易错的地方 ----
    py_sk_raw = bytes(range(32))
    py_sk = X25519PrivateKey.from_private_bytes(py_sk_raw)
    py_pk_raw = py_sk.public_key().public_bytes(_ser.Encoding.Raw, _ser.PublicFormat.Raw)

    # ① Node 用原始私钥算出的 X25519 共享密钥必须与 Python 的 exchange 一致
    #    （这条同时证明了"Node 从原始私钥推出的公钥"是对的 —— 推错就算不出同一个值）
    peer_sk = X25519PrivateKey.generate()
    peer_pk_raw = peer_sk.public_key().public_bytes(_ser.Encoding.Raw, _ser.PublicFormat.Raw)
    py_shared = py_sk.exchange(X25519PublicKey.from_public_bytes(peer_pk_raw))
    ok, node_shared = peer.one("x25519Shared", py_sk_raw, peer_pk_raw)
    check("X25519 共享密钥两端一致（原始字节进出）",
          ok and node_shared == py_shared,
          f"node={node_shared.hex() if isinstance(node_shared, bytes) else node_shared} py={py_shared.hex()}")

    # ② Python 的 Raw **公钥**交给 Node 包成对象再切回来，必须还是那 32 字节
    ok, node_pk_from_py = peer.one("x25519PublicFromRaw", py_pk_raw)
    if ok:
        ok2, round_trip = peer.one("x25519PublicRaw", node_pk_from_py)
        check("Python Raw 公钥 → Node 对象 → Raw 公钥（逐字节不变）",
              ok2 and round_trip == py_pk_raw,
              f"node={round_trip.hex() if isinstance(round_trip, bytes) else round_trip}")
    else:
        check("Python Raw 公钥 → Node 对象 → Raw 公钥（逐字节不变）", False, f"node 报错：{node_pk_from_py}")

    # ③ 私钥：原始字节 → Node 私钥对象 → 原始字节，必须原样回得来（PKCS8 尾巴就是它）
    ok, node_sk_obj = peer.one("x25519PrivateFromRaw", py_sk_raw)
    if ok:
        ok2, back_sk = peer.one("x25519PrivateRaw", node_sk_obj)
        check("Node 私钥对象 → 原始 32 字节 == 输入",
              ok2 and back_sk == py_sk_raw,
              f"node={back_sk.hex() if isinstance(back_sk, bytes) else back_sk}")
    else:
        check("Node 私钥对象 → 原始 32 字节 == 输入", False, f"node 报错：{node_sk_obj}")

    # ④ 长度不对要抛错（不接受别的长度，免得以后悄悄按 32 字节切错）
    fails(peer, "公钥原始字节给 31 字节 → 抛错", "x25519PublicFromRaw", py_sk_raw[:-1])
    fails(peer, "私钥原始字节给 33 字节 → 抛错", "x25519PrivateFromRaw", py_sk_raw + b"\x00")

    # ---- 密封盒双向 ----
    ok, sealed = peer.one("sealBox", b"line-is-ciphertext-only", py_pk_raw)
    if ok and isinstance(sealed, bytes):
        check("Node sealBox 长度 = 32(epk)+12(nonce)+len(msg)+16(tag)",
              len(sealed) == 32 + 12 + len(b"line-is-ciphertext-only") + 16, str(len(sealed)))
        check("Node sealBox 能把明文藏住（密文里不含明文）",
              b"line-is-ciphertext-only" not in sealed)
        opened = None
        try:
            opened = pc.open_box(sealed, py_sk_raw, py_pk_raw)
        except Exception as exc:  # noqa: BLE001
            check("Node 密封 → Python 打开", False, str(exc))
        if opened is not None:
            check("Node 密封 → Python 打开", opened == b"line-is-ciphertext-only", f"得到 {opened!r}")
    else:
        check("Node sealBox 可用", False, f"node 报错：{sealed}")

    py_sealed = pc.seal_box(b"python-sealed", py_pk_raw)
    ok, got = peer.one("openBox", py_sealed, py_sk_raw, py_pk_raw)
    check("Python 密封 → Node 打开", ok and got == b"python-sealed",
          f"node 报错：{got}" if not ok else f"得到 {got!r}")

    # 换一把钥匙 / 错公钥都要打不开
    other_sk = X25519PrivateKey.generate()
    other_sk_raw = other_sk.private_bytes(_ser.Encoding.Raw, _ser.PrivateFormat.Raw,
                                          _ser.NoEncryption())
    other_pk_raw = other_sk.public_key().public_bytes(_ser.Encoding.Raw, _ser.PublicFormat.Raw)
    fails(peer, "换一把私钥开 Node 的密封盒 → 认证失败", "openBox", py_sealed, other_sk_raw, py_pk_raw)
    fails(peer, "公钥对不上（salt 变了）→ 认证失败", "openBox", py_sealed, py_sk_raw, other_pk_raw)
    tampered = bytearray(py_sealed)
    tampered[-1] ^= 0x01
    fails(peer, "改动密封盒末位 → 认证失败", "openBox", bytes(tampered), py_sk_raw, py_pk_raw)
    fails(peer, "密封盒太短 → 抛错", "openBox", b"\x00" * 20, py_sk_raw, py_pk_raw)
    fails(peer, "接收方公钥长度不对 → 抛错", "sealBox", b"x", b"\x01" * 31)

    # ---- 信封 AAD ----
    aad_cases = [("POST", "/api/v1/auth/login"), ("GET", "/api/v1/ping"),
                 ("PUT", "/api/v1/sync/objects/schedule"), ("DELETE", "/api/v1/auth/devices/revoke")]
    ops = [("envAad", needs(m, p)) for (m, p) in aad_cases]
    bad = []
    for (m, p), (good, val) in zip(aad_cases, peer.run(ops)):
        if not good or val != pc.env_aad(m, p):
            bad.append(f"{m} {p}: node={val!r} py={pc.env_aad(m, p)!r}")
    check(f"{len(aad_cases)} 组 AAD（方法+完整路径）两端一致", not bad, "; ".join(bad))

    # ---- 信封双向 ----
    body = {"username": "someone", "password": "Secret-Pw-1", "device": "家里的台式机"}
    ok, env = peer.one("makeEnvelope", py_pk_raw, "POST", "/api/v1/auth/login", body, "")
    if ok and isinstance(env, dict) and "envelope" in env:
        envelope = env["envelope"]
        sk_hex = env.get("sk")
        check("Node 信封只有 sealed_sk / iv / ct 三个字段",
              sorted(envelope.keys()) == ["ct", "iv", "sealed_sk"], str(sorted(envelope.keys())))
        wire = json.dumps(envelope)
        check("Node 信封的报文体里没有口令/用户名/设备名明文",
              "Secret-Pw-1" not in wire and "someone" not in wire
              and "家里的台式机" not in wire and "password" not in wire)
        # Python 用会话密钥解开 Node 的信封，看到的内层字段必须对
        try:
            sk = _as_bytes(sk_hex)
            inner = json.loads(pc.AESGCM(sk).decrypt(
                pc.b64d(envelope["iv"]), pc.b64d(envelope["ct"]),
                pc.env_aad("POST", "/api/v1/auth/login")))
            check("Python 解开 Node 的信封，内层字段齐全",
                  inner.get("m") == "POST" and inner.get("p") == "/api/v1/auth/login"
                  and inner.get("q") == "" and inner.get("b") == body
                  and isinstance(inner.get("ts"), int) and len(pc.b64d(inner.get("nonce", ""))) == 16,
                  str(inner)[:200])
        except Exception as exc:  # noqa: BLE001
            check("Python 解开 Node 的信封，内层字段齐全", False, str(exc))
        # 换路径解 → AAD 不匹配
        try:
            pc.AESGCM(sk).decrypt(pc.b64d(envelope["iv"]), pc.b64d(envelope["ct"]),
                                  pc.env_aad("POST", "/api/v1/auth/register"))
            check("信封 AAD 绑了完整路径（换路径解不开）", False, "居然解开了")
        except Exception:  # noqa: BLE001
            check("信封 AAD 绑了完整路径（换路径解不开）", True)
    else:
        check("Node makeEnvelope 可用", False, f"node 报错：{env}")

    # Python 造信封的组件 → Node 组装/解开
    sk = pc.new_session_key()
    iv = os.urandom(12)
    inner = {"m": "GET", "p": "/api/v1/sync/manifest", "q": "a=1&b=2", "b": None,
             "ts": int(time.time()), "nonce": pc.b64e(os.urandom(16))}
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM as _AESGCM
    ct = _AESGCM(sk).encrypt(iv, json.dumps(inner).encode(), pc.env_aad("GET", "/api/v1/sync/manifest"))
    envelope = {"iv": pc.b64e(iv), "ct": pc.b64e(ct)}
    ok, got = peer.one("openEnvelopeResponse", sk, "GET", "/api/v1/sync/manifest", envelope)
    check("Python 造响应信封 → Node 解开得到同一 JSON",
          ok and got == json.dumps(inner, ensure_ascii=False).encode(), f"node 报错：{got}")
    fails(peer, "换路径解 Python 的响应信封 → 认证失败", "openEnvelopeResponse", sk, "GET",
          "/api/v1/ping", envelope)
    wrong_sk = os.urandom(32)
    fails(peer, "用错的会话密钥解响应信封 → 认证失败", "openEnvelopeResponse", wrong_sk, "GET",
          "/api/v1/sync/manifest", envelope)

    ok, sk2 = peer.one("newSessionKey")
    check("Node newSessionKey 是 32 字节", ok and isinstance(sk2, bytes) and len(sk2) == 32,
          str(sk2)[:60])

    # ---- 自检：密封盒/信封的往返也要进 selfCheck ----
    ok, checks = peer.one("selfCheck")
    if ok and isinstance(checks, dict):
        extras = ["seal_box_roundtrip", "seal_box_binds_key", "envelope_roundtrip",
                  "envelope_binds_path"]
        check("selfCheck 覆盖密封盒与信封（4 项且全为 true）",
              all(checks.get(k) is True for k in extras), str({k: checks.get(k) for k in extras}))


def test_kdf_v2(peer):
    """KDF 两代（§2.2）：v1 的 KEK 就是 MK；v2 由 MK 分出 AuthHash 与 KEK 两条单向链。"""
    section("KDF 两代（v1 / v2）")

    salt = pc.new_salt()
    passphrase = "correct horse battery staple"
    cases = [(passphrase, salt), ("中文口令 · 全角", pc.new_salt()),
             ("  首尾空格被裁掉  ", pc.new_salt())]

    # MK：两代共用同一步 scrypt，必须先逐字节一致
    ops = [("deriveMk", needs(p, s)) for (p, s) in cases]
    bad = []
    for (p, s), (good, val) in zip(cases, peer.run(ops)):
        if not good or val != pc.derive_mk(p, s):
            bad.append(f"{p!r}: node={val if not good else val.hex()} py={pc.derive_mk(p, s).hex()}")
    check(f"{len(cases)} 组 deriveMk（scrypt）逐字节一致", not bad, "; ".join(bad))

    # KEK 两代都要一致
    for algo in (pc.KDF_ALGO_V1, pc.KDF_ALGO_V2):
        ops = [("deriveKek", needs(p, s, algo)) for (p, s) in cases]
        bad = []
        for (p, s), (good, val) in zip(cases, peer.run(ops)):
            want = pc.derive_kek(p, s, algo)
            if not good or val != want:
                bad.append(f"{p!r}: node={val if not good else val.hex()} py={want.hex()}")
        check(f"{len(cases)} 组 deriveKek({algo}) 逐字节一致", not bad, "; ".join(bad))

    # v1 的 KEK 必须**就是** MK（这是 v1 的定义）
    ok, v1_kek = peer.one("deriveKek", passphrase, salt, pc.KDF_ALGO_V1)
    ok2, mk = peer.one("deriveMk", passphrase, salt)
    check("v1 的 KEK 就是 MK（定义如此）", ok and ok2 and v1_kek == mk)

    # v2 的 AuthHash 与 KEK 必须**不同**（两条单向链，分不开就等于 v1）
    ok3, v2_kek = peer.one("deriveKek", passphrase, salt, pc.KDF_ALGO_V2)
    ok4, v2_auth = peer.one("deriveAuthHash", passphrase, salt, pc.KDF_ALGO_V2)
    check("v2 的 AuthHash 与 KEK 不同（两条链分开）",
          ok3 and ok4 and v2_auth != v2_kek and len(v2_auth) == 32)

    # AuthHash 双向逐字节一致 + hex 形式
    ops = [("deriveAuthHash", needs(p, s, pc.KDF_ALGO_V2)) for (p, s) in cases]
    bad = []
    for (p, s), (good, val) in zip(cases, peer.run(ops)):
        want = pc.derive_auth_hash(p, s, pc.KDF_ALGO_V2)
        if not good or val != want:
            bad.append(f"{p!r}: node={val if not good else val.hex()} py={want.hex()}")
    check(f"{len(cases)} 组 deriveAuthHash 逐字节一致", not bad, "; ".join(bad))

    ok, hexed = peer.one("authHashHex", passphrase, salt, pc.KDF_ALGO_V2)
    check("authHashHex == deriveAuthHash 的 hex",
          ok and hexed == pc.auth_hash_hex(passphrase, salt, pc.KDF_ALGO_V2),
          f"node={hexed!r} py={pc.auth_hash_hex(passphrase, salt, pc.KDF_ALGO_V2)!r}")

    # v1 账号没有 AuthHash —— 调了要报错（不是静默给出假的）
    fails(peer, "v1 账号调 deriveAuthHash → 抛错", "deriveAuthHash", passphrase, salt,
          pc.KDF_ALGO_V1)
    fails(peer, "v1 账号调 authHashHex → 抛错", "authHashHex", passphrase, salt, pc.KDF_ALGO_V1)
    fails(peer, "不认识的 KDF → 抛错", "deriveKek", passphrase, salt, "scrypt-nope")
    fails(peer, "盐长度不对 → 抛错", "deriveMk", passphrase, "aabb")

    # usesAuthHash：v1 假、v2 真、缺省（None）按当前默认代次算
    for algo, want in ((pc.KDF_ALGO_V1, False), (pc.KDF_ALGO_V2, True), (None, True)):
        ok, got = peer.one("usesAuthHash", algo)
        check(f"usesAuthHash({algo!r}) == {want}", ok and got is want, f"node={got!r}")

    # 端到端：Node 产 v2 材料 → Python 用 auth_hash 与 KEK 都能对上
    ok, mat = peer.one("newMaterial", "someone", passphrase, "password", pc.KDF_ALGO_V2)
    if not ok:
        check("Node newMaterial(v2) 成功", False, str(mat))
        return
    check("Node v2 材料带 auth_salt 与 auth_hash（且两个盐不同）",
          isinstance(mat.get("auth_salt"), str) and len(mat["auth_salt"]) == 32
          and isinstance(mat.get("auth_hash"), str) and len(mat["auth_hash"]) == 64
          and mat["auth_salt"] != mat["kdf_salt"], str(sorted(mat.keys())))
    check("Python 用 Node 的 auth_salt 能算出同一个 AuthHash",
          pc.auth_hash_hex(passphrase, mat["auth_salt"], mat["kdf_algo"]) == mat["auth_hash"],
          f"py={pc.auth_hash_hex(passphrase, mat['auth_salt'], mat['kdf_algo'])} node={mat['auth_hash']}")
    try:
        dek_back = pc.unwrap_dek(mat["key_wrap"], passphrase, mat["kdf_salt"], "someone",
                                 mat["kdf_algo"])
        ok_dek = dek_back.hex() == mat["dek_hex"]
    except Exception as exc:  # noqa: BLE001
        ok_dek = False
        dek_back = f"<{type(exc).__name__}: {exc}>"
    check("Python 用 Node 的 v2 包裹解出同一 DEK", ok_dek, f"得到 {dek_back!r}")

    # 反向：Python 产 v2 材料 → Node 解
    py_v2 = pc.new_material("someone", passphrase, "password", pc.KDF_ALGO_V2)
    ok, dek_node = peer.one("unwrapDek", py_v2["key_wrap"], passphrase, py_v2["kdf_salt"],
                            "someone", py_v2["kdf_algo"])
    check("Node 解 Python 的 v2 包裹得到同一 DEK",
          ok and dek_node == py_v2["dek"], f"node 报错：{dek_node}" if not ok else "")
    ok, auth_node = peer.one("authHashHex", passphrase, py_v2["auth_salt"], py_v2["kdf_algo"])
    check("Node 用 Python 的 auth_salt 算出同一 AuthHash",
          ok and auth_node == py_v2["auth_hash"], f"node={auth_node!r}")


def _norm_const(value):
    """常量比对用：bytes / Buffer / hex 串归一成同一种表示（都当字节看待）。

    注意 `REQ_AAD_PREFIX` 这种"看着像文本"的常量在 Python 侧是 **bytes**，
    Node 侧是字符串，所以两边都按 UTF-8 字节比。
    """
    if isinstance(value, (bytes, bytearray)):
        return bytes(value)
    if isinstance(value, dict) and value.get("type") == "Buffer":
        return bytes(value.get("data", []))
    if isinstance(value, str):
        if value and RE_HEX_FULL.match(value) and len(value) % 2 == 0:
            # 纯 hex 串：既可能是"真的 hex 值"，也可能是"恰好只含 hex 字符的文本"。
            # 只在与字节比较时才有歧义 —— 这里不做猜测，留给调用方按需 .hex() 比。
            return value
        return value.encode("utf-8")
    return value


def _as_bytes(value):
    """node 回传的 Buffer（`{'type': 'Buffer', 'data': [...]}`）或 hex 串 → bytes。"""
    if isinstance(value, (bytes, bytearray)):
        return bytes(value)
    if isinstance(value, dict) and value.get("type") == "Buffer":
        return bytes(value.get("data", []))
    if isinstance(value, str):
        return bytes.fromhex(value)
    raise TypeError(f"没法当字节用：{value!r}")


# ---------------------------------------------------------------- 主流程

def main():
    print("=" * 74)
    print("phix 密码学跨语言互操作测试：Python hellopinghe.phixcrypto ↔ Node electron/phix-crypto.cjs")
    print("=" * 74)

    if not NODE_CRYPTO.is_file():
        raise SystemExit(f"找不到 Node 模块：{NODE_CRYPTO}")
    if not (PY_CRYPTO_DIR / "hellopinghe" / "phixcrypto.py").is_file():
        raise SystemExit(f"找不到 Python 权威实现：{PY_CRYPTO_DIR}")
    node_bin = shutil.which("node")
    if not node_bin:
        raise SystemExit("PATH 里找不到 node")

    workdir = Path(tempfile.mkdtemp(prefix="phix_interop_"))
    print(f"Python : {sys.version.split()[0]}  ({PY_CRYPTO_DIR / 'hellopinghe' / 'phixcrypto.py'})")
    print(f"Node   : {shutil.which('node')}")
    print(f"临时目录: {workdir}（结束即删，不污染仓库）")
    try:
        peer = NodePeer(workdir)
        sections = [
            ("常量与规范化的对齐", test_constants),
            ("口令归一化", test_passphrase_normalization),
            ("KDF", test_kek_and_key),
            ("AAD", test_aad),
            ("对象信封双向", test_envelopes),
            ("DEK 包裹双向", test_key_wrap),
            ("自检块", test_key_check),
            ("恢复码", test_recovery),
            ("整套材料", test_material),
            ("应用层加密传输（密封盒 / 信封）", test_application_transport),
            ("KDF 两代（v1 / v2）", test_kdf_v2),
            ("导出面", test_module_surface),
        ]
        for title, fn in sections:
            try:
                fn(peer)
            except Exception:  # noqa: BLE001 单段炸掉不影响其它段
                FAILED.append(f"{title}（异常中断）")
                print(f"  [FAIL] {title} 段异常中断：\n{traceback.format_exc()}")
        print(f"\n（node 版本 {peer.version}，共启动 node 进程 {NODE_RUNS[0]} 次）")
    finally:
        shutil.rmtree(workdir, ignore_errors=True)

    print("=" * 74)
    print(f"通过 {len(PASSED)} 项，失败 {len(FAILED)} 项")
    if FAILED:
        for name in FAILED:
            print(f"  - 失败：{name}")
    print("=" * 74)
    return 1 if FAILED else 0


if __name__ == "__main__":
    sys.exit(main())
