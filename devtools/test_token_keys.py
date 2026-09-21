"""两个客户端**令牌落盘键名对齐**（三键制）—— 端到端测试。

    cd D:\\phix\\server
    .venv\\Scripts\\python.exe -X utf8 devtools\\test_token_keys.py

背景：PLL（Python）与 PHL（Electron/Node）**共用同一份** ``data/settings.yaml``
（``secrets_extra`` 段）。P3 之后两边各自接了自动续期，但落盘键名不一样：PLL 把
15 分钟的 JWT 写进 ``phix:token``、续期串写进 ``phix:refresh``；PHL 用的是
``phix:access_token`` / ``phix:refresh_token``。后果是**两个程序互相覆盖、互相看不见**
对方的令牌（PHL 会把 PLL 存的 JWT 当成"老式长期令牌"用）。

本脚本测的就是修好之后的三键制契约（两边文件头都写着同一张表）：

  ``phix:token``          老式长期令牌（兼容期；不再是业务 Bearer 首选）
  ``phix:access_token``   15 分钟的 JWT → 业务请求的 Bearer
  ``phix:refresh_token``  续期凭据 → **只**喂给 /auth/refresh

  读兼容：新键缺失 → 回落到 ``phix:token`` 里**像 JWT 的那串**与旧键 ``phix:refresh``，
          读到就**补写新键**（迁移，只补写、不删旧键）。
  写新键：登录/注册/续期都写新键；**除登出外不删任何键**。
  登出：四个 phix 令牌键（三键 + 旧 ``phix:refresh``）一起清，别的东西一个都不动。

按实跑顺序编号：

  [1] **同一个 data 目录**：PLL 注册 → 三个键都写对（``phix:token`` 里**不再**是 JWT）；
      再用 PHL 的真实模块读同一份 ``settings.yaml`` → **读到的访问令牌与 refresh
      与 PLL 写的一模一样**（这正是本次要防的 bug）。
  [2] PHL 拿着 PLL 写的令牌 `restore()` + 真发一次业务请求（证明真的能用，不只是读到）。
  [3] 反向：PHL 登录写盘 → PLL 读到同样的两串，并且**能用那串 refresh 真的续期**。
  [4] PLL 旧格式（``phix:token`` = JWT、``phix:refresh`` = 续期串）→ 新 PLL
      自动迁到新键、旧的照旧保留、并且**照常续期**（续期后新串落盘）。
  [5] PHL 旧格式（只有旧键）→ 新 PHL 能认：``phix:refresh`` 当续期串、
      ``phix:token`` 里像 JWT 的当访问令牌。**不像 JWT 的老式令牌绝不当访问令牌用**。
  [6] 登出（两边各一次）→ 三个键（连旧 ``phix:refresh``）都空；无关的键一个都没动。

数据全程用**副本目录**（``D:\\phix\\_lab\\keyalign\\``，每个场景一个新建的空目录），
绝不碰任何真实 ``data/``。测试账号统一 ``keyalign`` 前缀（``clean_dev_db.py`` 的
PREFIXES 里已加），跑完**自己清**（脚本末尾调 clean_dev_db.py 收尾）。

**绝不打印任何令牌/口令**：跨程序比较一律用 sha256 前 8 位的**短指纹**。
"""
import hashlib
import json
import os
import secrets as _secrets
import shutil
import subprocess
import sys
import time
from pathlib import Path

import requests

sys.path.insert(0, r"D:\phl-lite-dev")

SERVER = os.environ.get("PHIX_SERVER", "http://127.0.0.1:8931").rstrip("/")
HERE = Path(__file__).resolve().parent
SERVER_ROOT = HERE.parent
LAB = Path(r"D:\phix\_lab\keyalign")
ELECTRON = os.environ.get("PHL_ELECTRON_DIR", r"D:\phl-dev\PH-Launcher\electron")
DRIVER = LAB / "keyalign_driver.cjs"
PREFIX = "keyalign"

#: 磁盘上那四个 phix 令牌键（三键 + 旧键）—— 登出后这四个都该是空的
TOKEN_KEYS = ("phix:token", "phix:access_token", "phix:refresh_token", "phix:refresh")
#: 与令牌无关的键：全程一个字节都不许被动过（用来证明"不删别人的东西"）
MARKER_KEY = "keyalign:marker"
MARKER_VALUE = "keep-me"

PASSED, FAILED = [], []

#: 写进 `_lab/keyalign/keyalign_driver.cjs` 的 PHL 侧驱动（**不是 PHL 的一部分**，
#: 只是把 PHL 的 `phix-session.cjs` 当库来调，好让 Python 这头能对着真服务端
#: 验证"PHL 读同一份 settings.yaml 读到的是什么"）。输出只有短指纹，没有令牌。
DRIVER_SOURCE = r"""
'use strict';
const path = require('node:path');
const crypto = require('node:crypto');
const ELECTRON = process.env.PHL_ELECTRON_DIR || 'D:\\phl-dev\\PH-Launcher\\electron';
const session = require(path.join(ELECTRON, 'phix-session.cjs'));

const fp = (v) => (v ? crypto.createHash('sha256').update(String(v)).digest('hex').slice(0, 8) : '');
const emit = (p) => { process.stdout.write('\n__PHL_RESULT__' + JSON.stringify(p) + '\n'); };

function makeApi(dataDir) {
  session.configure({ dataDir });
  session.saveConfig({ e2e: false, auto_sync: false });   // 别让后台自动同步插进测试
  return new session.PhixSession({ log: () => {} });
}
const flags = (t) => ({
  has_token: Boolean(t.legacy), has_access_token: Boolean(t.access), has_refresh_token: Boolean(t.refresh),
});
function storedFp(dataDir) {
  session.configure({ dataDir });
  const t = session.storedTokens();      // 读兼容 + 顺手迁移都在这里
  return { access: fp(t.access), refresh: fp(t.refresh), legacy: fp(t.legacy), flags: flags(t) };
}
async function ensureAccount(api, server, user, pw) {
  try { return { status: await api.login(server, user, pw), created: false }; }
  catch (error) {
    if (!error || error.code !== 'bad_credentials') throw error;
    return { status: await api.register(server, user, pw), created: true };
  }
}

async function main() {
  const [cmd, ...a] = process.argv.slice(2);
  if (cmd === 'read') {
    const [dataDir, server] = a;
    const out = { ok: true, stored: storedFp(dataDir), status: null, bearer: '', refresh_in_memory: '' };
    const api = makeApi(dataDir);
    const st = api.status();
    out.status = {
      logged_in: st.logged_in, has_token: st.has_token,
      has_access_token: st.has_access_token, has_refresh_token: st.has_refresh_token,
    };
    if (server) {
      const client = session.makeClient(server, null, undefined, { withTokens: true });
      out.bearer = fp(client.authToken());
      out.refresh_in_memory = fp(client.refreshToken);
    }
    return out;
  }
  if (cmd === 'login') {
    const [server, user, pw, dataDir] = a;
    const api = makeApi(dataDir);
    const { status, created } = await ensureAccount(api, server, user, pw);
    const t = storedFp(dataDir);
    return {
      ok: true, created,
      status: {
        logged_in: status.logged_in, unlocked: status.unlocked,
        has_token: status.has_token, has_access_token: status.has_access_token,
        has_refresh_token: status.has_refresh_token,
      },
      memory: {
        access: fp(api.client.accessToken), refresh: fp(api.client.refreshToken),
        legacy: fp(api.client.legacyToken),
      },
      stored: t,
    };
  }
  if (cmd === 'restore') {
    const [server, dataDir] = a;
    const api = makeApi(dataDir);
    const restored = await api.restore(server);
    if (!restored) return { ok: false, error: 'restore 返回 null（盘上没有可用令牌）' };
    const before = { bearer: fp(api.client.authToken()), refresh: fp(api.client.refreshToken) };
    let me = null, error = '';
    try { me = await api.client.me(); } catch (e) { error = String((e && e.message) || e); }
    return {
      ok: Boolean(me), error, logged_in: restored.logged_in,
      before, after: { bearer: fp(api.client.authToken()), refresh: fp(api.client.refreshToken) },
      me: { user_id: (me && me.user_id) || 0, username: (me && me.username) || '' },
    };
  }
  if (cmd === 'logout') {
    const [server, dataDir] = a;
    const api = makeApi(dataDir);
    const restored = await api.restore(server);
    const status = await api.logout();
    return {
      ok: true, restored: Boolean(restored),
      status: {
        logged_in: status.logged_in, has_token: status.has_token,
        has_access_token: status.has_access_token, has_refresh_token: status.has_refresh_token,
      },
      stored: storedFp(dataDir),
    };
  }
  return { ok: false, error: 'unknown command: ' + cmd };
}

main().then(emit).catch((error) => emit({ ok: false, error: String((error && error.message) || error), code: (error && error.code) || null }));
"""


# ---------------------------------------------------------------- 小工具
def check(name, cond, extra=""):
    (PASSED if cond else FAILED).append(name)
    print(f"  [{'OK  ' if cond else 'FAIL'}] {name}"
          + (f"   {extra}" if extra and not cond else ""))
    return cond


def fp(value: str) -> str:
    """令牌的**短指纹**（sha256 前 8 位）—— 跨程序比较用，绝不落令牌本身。"""
    return hashlib.sha256((value or "").encode("utf-8")).hexdigest()[:8] if value else ""


def looks_like_jwt(value: str) -> bool:
    parts = (value or "").split(".")
    return len(parts) == 3 and all(parts)


def node(command, *args, timeout=600) -> dict:
    """跑一次 PHL 侧驱动，取回最后一行 JSON（**不回传也不打印任何令牌**）。"""
    env = dict(os.environ, PYTHONIOENCODING="utf-8", PHL_ELECTRON_DIR=ELECTRON)
    proc = subprocess.run(["node", str(DRIVER), command, *[str(a) for a in args]],
                          capture_output=True, text=True, encoding="utf-8",
                          errors="replace", env=env, cwd=str(LAB), timeout=timeout)
    for line in reversed((proc.stdout or "").splitlines()):
        if line.startswith("__PHL_RESULT__"):
            return json.loads(line[len("__PHL_RESULT__"):])
    return {"ok": False, "error": "驱动没有输出结果",
            "stdout": (proc.stdout or "")[-300:], "stderr": (proc.stderr or "")[-300:]}


def api(path: str) -> str:
    return SERVER + "/api/v1" + path


def ping() -> dict:
    try:
        return requests.get(api("/ping"), timeout=6).json()
    except (requests.RequestException, ValueError):
        return {}


def fresh_root(tag: str) -> Path:
    """一份**全新空目录**当数据根（在 `_lab/keyalign/` 下，绝不碰真实 data/）。"""
    root = LAB / tag / "data"
    if root.exists():
        shutil.rmtree(root)          # 只删本项目自己在 _lab 下建的目录
    (root / ".sync" / "pinned").mkdir(parents=True, exist_ok=True)
    return root


def shared_root() -> Path:
    """两个程序共用的那一份数据根：``_lab\\keyalign\\data``（`PHLL_DATA_DIR` 指这儿）。"""
    root = LAB / "data"
    if root.exists():
        shutil.rmtree(root)
    (root / ".sync" / "pinned").mkdir(parents=True, exist_ok=True)
    return root


def load_pll(root: Path):
    """在指定数据根下重新加载 PLL 的真实模块（数据根是启动时解析的，必须重载）。"""
    os.environ["PHLL_DATA_DIR"] = str(root)
    for mod in [m for m in list(sys.modules) if m.startswith("hellopinghe")]:
        del sys.modules[mod]
    from hellopinghe import cloudsync as cs
    from hellopinghe import filestore as fs
    from hellopinghe import phixsession as ps
    from hellopinghe import secrets as sec

    ps.save_config(auto_sync=False, e2e=False)      # 别让后台自动同步插进测试里
    return cs, fs, ps, sec


def secrets_of(fs, root: Path) -> dict:
    """直接从盘上读 `secrets_extra` 段（用 PLL 自己的解析器 → 与真实读写同一口径）。"""
    return (fs.load_settings_at(root / "settings.yaml") or {}).get("secrets_extra") or {}


def account(tag: str) -> tuple[str, str]:
    sfx = _secrets.token_hex(3)
    return f"{PREFIX}{tag}{sfx}", "Keyalign-Pw-" + _secrets.token_hex(3)


def banner(text: str) -> None:
    print("\n" + "=" * 74)
    print(text)
    print("=" * 74)


# ---------------------------------------------------------------- 各场景
def scene_shared() -> None:
    """[1][2][6-a] PLL 写 → PHL 读（同一个 data 目录），PHL 还能真发业务请求。"""
    banner("[1][2] 同一个 data 目录：PLL 写 → PHL 读（访问令牌与 refresh 必须一致）")
    root = shared_root()
    cs, fs, ps, sec = load_pll(root)
    user, pw = account("s")
    print(f"    共用数据根 {root}（PHLL_DATA_DIR 指这儿）   账号 {user}")

    st = ps.SESSION.register(SERVER, user, pw)
    check("PLL 注册成功且已解锁（DEK 只在内存里）",
          bool(st["logged_in"] and st["unlocked"]), json.dumps(st, ensure_ascii=False)[:200])
    c = ps.SESSION.client
    access, refresh, legacy = c.token or "", c.refresh_token or "", c.legacy_token or ""

    se = secrets_of(fs, root)
    check("三个键都写了：phix:token + phix:access_token + phix:refresh_token",
          all(se.get(k) for k in ("phix:token", "phix:access_token", "phix:refresh_token")),
          str(sorted(se)))
    check("phix:access_token 里是那个 JWT（三段式）",
          looks_like_jwt(se.get("phix:access_token") or "")
          and se.get("phix:access_token") == access)
    check("phix:refresh_token 里是续期串（与 access 不同一串）",
          bool(se.get("phix:refresh_token")) and se.get("phix:refresh_token") == refresh
          and refresh != access)
    check("**phix:token 里不再塞 JWT**（本次要修的 bug：老实现把访问令牌写这儿）",
          se.get("phix:token") != access
          and not looks_like_jwt(se.get("phix:token") or ""))
    check("phix:token 里是服务端给的老式长期令牌（响应里有就一致）",
          (se.get("phix:token") == legacy) if legacy else True,
          f"legacy present={bool(legacy)}")
    sec.set(MARKER_KEY, MARKER_VALUE)        # 无关的键：全程不许被动
    check("盘上有密钥材料时也照样写（DEK 不落盘）",
          ps.SESSION.dek.hex() not in (root / "settings.yaml").read_text(encoding="utf-8"))

    out = node("read", root, SERVER)
    check("PHL 能读同一份 settings.yaml（驱动跑通）", bool(out.get("ok")),
          json.dumps(out, ensure_ascii=False)[:300])
    stored = out.get("stored") or {}
    check("**PHL 读到的访问令牌与 PLL 写的完全一致**（同一个 JWT 指纹）",
          stored.get("access") == fp(access), f"PHL={stored.get('access')} PLL={fp(access)}")
    check("**PHL 读到的 refresh 与 PLL 写的完全一致**",
          stored.get("refresh") == fp(refresh), f"PHL={stored.get('refresh')} PLL={fp(refresh)}")
    check("PHL 读到的老式令牌就是 phix:token 里那串",
          stored.get("legacy") == fp(se.get("phix:token")))
    check("PHL 的 status 认出三串都在（has_token/has_access/has_refresh）",
          all((out.get("status") or {}).get(k) for k in
              ("has_token", "has_access_token", "has_refresh_token")),
          json.dumps(out.get("status"), ensure_ascii=False))
    check("PHL 拿到的 Bearer 就是 PLL 写的那串 access",
          out.get("bearer") == fp(access))
    check("PHL 手里的 refresh 也是同一串", out.get("refresh_in_memory") == fp(refresh))

    banner("[2] PHL 用 PLL 写的令牌真的能干活（restore + 业务请求）")
    res = node("restore", SERVER, root)
    check("PHL restore 成功（盘上的令牌能装进客户端）", bool(res.get("ok")),
          json.dumps(res, ensure_ascii=False)[:300])
    check("restore 后发业务请求成功，认的就是同一个账号",
          (res.get("me") or {}).get("username") == user,
          json.dumps(res.get("me"), ensure_ascii=False))
    check("这次没触发续期（access 还新鲜）→ refresh 一个字节没动",
          (res.get("before") or {}).get("refresh") == (res.get("after") or {}).get("refresh"))
    check("PLL 侧看到的 refresh 指纹仍与 PHL 手里的一致",
          (res.get("after") or {}).get("refresh") == fp(refresh))

    banner("[6-a] PHL 登出：三个键（连旧 phix:refresh）都空")
    out = node("logout", SERVER, root)
    check("PHL 登出后不再处于登录态",
          (out.get("status") or {}).get("logged_in") is False,
          json.dumps(out.get("status"), ensure_ascii=False))
    se = secrets_of(fs, root)
    check("登出后四个 phix 令牌键都空了",
          not any(se.get(k) for k in TOKEN_KEYS), str(sorted(se)))
    check("登出**没有**动无关的键（别的程序/别的东西原样保留）",
          se.get(MARKER_KEY) == MARKER_VALUE, str(sorted(se)))
    st2 = ps.SESSION.status()
    check("PLL 这边看也是三个「没有」（has_token/has_access/has_refresh 全假）",
          st2.get("has_token") is False and st2.get("has_access_token") is False
          and st2.get("has_refresh_token") is False, str(st2)[:200])


def scene_reverse() -> None:
    """[3][6-b] PHL 写 → PLL 读，而且 PLL 能用那串 refresh 真的续期。"""
    banner("[3] 反向：PHL 登录写盘 → PLL 读到同样的令牌，并能用那串 refresh 续期")
    root = fresh_root("reverse")
    cs, fs, ps, sec = load_pll(root)
    user, pw = account("r")
    print(f"    副本数据根 {root}   账号 {user}")

    out = node("login", SERVER, user, pw, root)
    check("PHL 登录成功（账号不存在就注册）", bool(out.get("ok")),
          json.dumps(out, ensure_ascii=False)[:300])
    mem = out.get("memory") or {}
    stored = out.get("stored") or {}
    check("PHL 登录后三个键都落盘了",
          all((stored.get("flags") or {}).get(k) for k in
              ("has_token", "has_access_token", "has_refresh_token")),
          json.dumps(stored, ensure_ascii=False))
    check("PHL 落盘的 access 是 JWT，且与 phix:token 不是同一串",
          stored.get("access") != stored.get("legacy") and bool(stored.get("access")))

    # PLL 这头（**同一个数据根**）读同一份文件
    t = ps.stored_tokens()
    check("**PLL 读到的访问令牌与 PHL 写的完全一致**",
          fp(t["access"]) == stored.get("access"), f"PLL={fp(t['access'])} PHL={stored.get('access')}")
    check("**PLL 读到的 refresh 与 PHL 写的完全一致**",
          fp(t["refresh"]) == stored.get("refresh"), f"PLL={fp(t['refresh'])} PHL={stored.get('refresh')}")
    check("PLL 读到的老式令牌就是 phix:token 那串",
          fp(t["legacy"]) == stored.get("legacy"))
    check("盘上没有旧键 phix:refresh 也能正常工作（新键优先）",
          not secrets_of(fs, root).get("phix:refresh"))

    # 真续期：拿 PHL 写下的 refresh 换新 access（服务端说了算，不是空写）
    client = cs.PhixClient(SERVER, t["access"], e2e=False, pin_dir=ps._pin_dir(),
                           refresh_token=t["refresh"])
    data = client.refresh_access()
    check("PLL 用 PHL 写的 refresh 真的换到了新令牌（rotated）",
          bool(data.get("rotated")), json.dumps(data, ensure_ascii=False)[:200])
    check("续期后访问令牌换了新串（与 PHL 写的那串不同）",
          fp(client.token) != stored.get("access"))
    check("续期后 refresh 也轮换了（旋转过）",
          bool(client.refresh_token) and fp(client.refresh_token) != stored.get("refresh"))

    banner("[6-b] PLL 登录 + 登出：三个键都空，无关的键不动")
    st = ps.SESSION.login(SERVER, user, pw)
    check("PLL 后面登录同一账号成功", bool(st["logged_in"]))
    sec.set(MARKER_KEY, MARKER_VALUE)
    ps.SESSION.logout()
    se = secrets_of(fs, root)
    check("PLL 登出后四个 phix 令牌键都空了",
          not any(se.get(k) for k in TOKEN_KEYS), str(sorted(se)))
    check("PLL 登出没动无关的键", se.get(MARKER_KEY) == MARKER_VALUE)


def scene_legacy() -> None:
    """[4][5] 旧格式兼容：PLL 旧（JWT 在 phix:token）与 PHL 旧（只有 phix:refresh）。"""
    banner("[4][5] 旧格式兼容：老实现写下的键必须还能用，并且自动迁到新键")
    root = fresh_root("legacy")
    cs, fs, ps, sec = load_pll(root)
    user, pw = account("l")
    print(f"    副本数据根 {root}   账号 {user}")

    ps.SESSION.register(SERVER, user, pw)
    c = ps.SESSION.client
    access, refresh = c.token or "", c.refresh_token or ""

    def write_old_pll_format() -> None:
        """把盘改回**旧 PLL 的写法**：JWT 在 phix:token、续期串在 phix:refresh。"""
        sec.delete("phix:access_token")
        sec.delete("phix:refresh_token")
        sec.set("phix:token", access)
        sec.set("phix:refresh", refresh)
        sec.set(MARKER_KEY, MARKER_VALUE)

    def write_old_phl_format() -> None:
        """旧 PHL 的写法：只有 phix:refresh（续期），phix:token 是老式长期令牌。"""
        sec.delete("phix:access_token")
        sec.delete("phix:refresh_token")
        sec.delete("phix:token")
        sec.set("phix:refresh", refresh)
        sec.set(MARKER_KEY, MARKER_VALUE)

    # ---------- [4-a] 旧 PLL 格式 → 新 PLL ----------
    print("\n[4-a] PLL 旧格式（phix:token=JWT、phix:refresh=续期串）→ 新 PLL 读")
    write_old_pll_format()
    se = secrets_of(fs, root)
    check("先把盘摆成旧格式（新键确实不存在）",
          not se.get("phix:access_token") and not se.get("phix:refresh_token")
          and looks_like_jwt(se.get("phix:token") or "") and bool(se.get("phix:refresh")),
          str(sorted(se)))
    t = ps.stored_tokens()
    check("新 PLL 回落读出访问令牌（phix:token 里那串像 JWT 的）",
          fp(t["access"]) == fp(access))
    check("新 PLL 回落读出续期串（旧键 phix:refresh）", fp(t["refresh"]) == fp(refresh))
    se = secrets_of(fs, root)
    check("读到就**补写**了新键 phix:access_token", se.get("phix:access_token") == access)
    check("读到就**补写**了新键 phix:refresh_token", se.get("phix:refresh_token") == refresh)
    check("迁移**不删**旧键（phix:token / phix:refresh 都还在）",
          se.get("phix:token") == access and se.get("phix:refresh") == refresh)
    check("迁移没动无关的键", se.get(MARKER_KEY) == MARKER_VALUE)
    st = ps.SESSION.status()
    check("status 报出三串都在（含新名字 has_access_token / has_refresh_token）",
          st.get("has_access_token") is True and st.get("has_refresh_token") is True,
          str(st)[:200])

    # 照常续期：用回落出来的 refresh 换新令牌，并把新串写回新键
    print("      用回落出来的 refresh 真的续一次期……")
    runner = cs.PhixClient(SERVER, access, e2e=False, pin_dir=ps._pin_dir(),
                           refresh_token=refresh)
    data = runner.refresh_access()
    check("旧格式落盘的 refresh 仍然能续期（服务端判定有效、旋转成功）",
          bool(data.get("rotated")), json.dumps(data, ensure_ascii=False)[:200])
    ps.SESSION.client = runner
    ps.SESSION._persist_tokens(runner)
    se = secrets_of(fs, root)
    check("续期后 phix:access_token 是新那串",
          se.get("phix:access_token") == runner.token and fp(runner.token) != fp(access))
    check("续期后 phix:refresh_token 是新轮换的那串（旧键留着不动）",
          se.get("phix:refresh_token") == runner.refresh_token
          and fp(runner.refresh_token) != fp(refresh))
    check("续期写盘没碰老键 phix:token", se.get("phix:token") == access)

    # ---------- [5] 旧 PHL 格式 → 新 PHL ----------
    print("\n[5-a] 旧 PHL 格式（只有旧键 phix:refresh）→ 新 PHL 读")
    write_old_pll_format()                    # phix:token 仍是 JWT 形态（老 PLL 存的访问令牌）
    out = node("read", root, SERVER)
    stored = out.get("stored") or {}
    check("PHL 驱动跑通", bool(out.get("ok")), json.dumps(out, ensure_ascii=False)[:300])
    check("新 PHL 认旧键 phix:refresh 当续期串",
          stored.get("refresh") == fp(refresh), f"PHL={stored.get('refresh')}")
    check("新 PHL 认得 phix:token 里那串像 JWT 的 → 当访问令牌",
          stored.get("access") == fp(access))
    se = secrets_of(fs, root)
    check("PHL 读到旧键也顺手补写新键（迁移，不删旧键）",
          se.get("phix:access_token") == access and se.get("phix:refresh_token") == refresh
          and bool(se.get("phix:refresh")) and bool(se.get("phix:token")))
    check("PHL 的迁移也没动无关的键", se.get(MARKER_KEY) == MARKER_VALUE)

    res = node("restore", SERVER, root)
    check("PHL 用旧键里的令牌 restore + 业务请求成功（真的能用，不只是读到）",
          bool(res.get("ok")) and (res.get("me") or {}).get("username") == user,
          json.dumps(res, ensure_ascii=False)[:300])

    # ---------- [5-b] phix:token 不是 JWT（老式长期令牌）→ 绝不当访问令牌用 ----------
    print("\n[5-b] phix:token 里是**老式长期令牌**（不像 JWT）→ 绝不当访问令牌用")
    plain_root = fresh_root("legacyplain")
    cs2, fs2, ps2, sec2 = load_pll(plain_root)
    sec2.set("phix:token", "legacy-long-token-not-a-jwt")
    sec2.set(MARKER_KEY, MARKER_VALUE)
    out = node("read", plain_root, SERVER)
    stored = out.get("stored") or {}
    check("PHL：不像 JWT 的 phix:token **不**当作访问令牌（access 为空）",
          stored.get("access") == "", f"PHL access={stored.get('access')!r}")
    check("PHL：它仍然作为老式长期令牌被认出来（legacy 非空）",
          stored.get("legacy") == fp("legacy-long-token-not-a-jwt"))
    check("PHL：没有 access 时 Bearer 退回老式令牌（老客户端行为不变）",
          out.get("bearer") == fp("legacy-long-token-not-a-jwt"),
          str(out.get("bearer")))
    check("PHL：status 里 has_token 真、has_access_token 假",
          (out.get("status") or {}).get("has_token") is True
          and (out.get("status") or {}).get("has_access_token") is False,
          json.dumps(out.get("status"), ensure_ascii=False))
    t = ps2.stored_tokens()
    check("PLL：同样不把不像 JWT 的 phix:token 当访问令牌",
          t["access"] == "" and t["legacy"] == "legacy-long-token-not-a-jwt")
    se = secrets_of(fs2, plain_root)
    check("PLL：没有可迁移的东西时**不写**新键、旧键原样",
          not se.get("phix:access_token") and not se.get("phix:refresh_token")
          and se.get("phix:token") == "legacy-long-token-not-a-jwt"
          and se.get(MARKER_KEY) == MARKER_VALUE, str(sorted(se)))

    # ---------- [5-c] 只有旧键 phix:refresh（连 phix:token 都没有） ----------
    print("\n[5-c] 盘上**只有**旧键 phix:refresh → 两边的读都认得它")
    only_root = fresh_root("onlyrefresh")
    cs3, fs3, ps3, sec3 = load_pll(only_root)

    def only_old_refresh() -> None:
        sec3.delete("phix:access_token")
        sec3.delete("phix:refresh_token")
        sec3.delete("phix:token")
        sec3.set("phix:refresh", refresh)
        sec3.set(MARKER_KEY, MARKER_VALUE)

    only_old_refresh()
    t = ps3.stored_tokens()
    check("PLL：认得旧键 phix:refresh（refresh 非空且就是那串）",
          fp(t["refresh"]) == fp(refresh) and t["access"] == "")
    check("PLL：顺手把它迁到新键 phix:refresh_token（旧键留着）",
          secrets_of(fs3, only_root).get("phix:refresh_token") == refresh
          and bool(secrets_of(fs3, only_root).get("phix:refresh")))
    only_old_refresh()                        # 再把盘摆回"只有旧键"，让 PHL 也走一遍回落
    out = node("read", only_root)
    stored = out.get("stored") or {}
    check("PHL：只有旧键 phix:refresh 也认得（refresh 就是那串）",
          stored.get("refresh") == fp(refresh), f"PHL={stored.get('refresh')}")
    check("PHL：access / legacy 都是空（盘上确实没有别的令牌）",
          stored.get("access") == "" and stored.get("legacy") == "")
    check("PHL：也顺手迁到新键 phix:refresh_token（旧键留着）",
          secrets_of(fs3, only_root).get("phix:refresh_token") == refresh
          and bool(secrets_of(fs3, only_root).get("phix:refresh")))
    # 已知行为（不是缺陷）：只有 refresh、没有 access/老式令牌时，PHL 的 restore() 仍
    # 返回 null —— 一条会话得有能当 Bearer 的令牌才算"登着"，光有续期凭据不够。
    res = node("restore", SERVER, only_root)
    check("只有 refresh 时 PHL restore() 仍然返回 null（既有语义：没 Bearer 不算登录态）",
          res.get("ok") is False, json.dumps(res, ensure_ascii=False)[:200])


def self_clean() -> None:
    """跑完自己清测试账号（只删本项目测试前缀；本地库交回 0 账号 / 0 对象）。"""
    banner("收尾：清掉本项目的测试账号（clean_dev_db.py，只认测试前缀）")
    env = dict(os.environ, PHIX_CLEAN_YES="1", PYTHONIOENCODING="utf-8")
    proc = subprocess.run([sys.executable, "-X", "utf8", str(HERE / "clean_dev_db.py")],
                          cwd=str(SERVER_ROOT), env=env, capture_output=True,
                          text=True, encoding="utf-8", errors="replace")
    tail = [line for line in (proc.stdout or "").splitlines() if line.strip()][-3:]
    for line in tail:
        print("    " + line)


def main() -> int:
    if not (LAB.parent.name == "_lab" and LAB.name == "keyalign"):
        raise SystemExit(f"副本目录不像测试目录，拒绝动它：{LAB}")
    if LAB.exists():
        shutil.rmtree(LAB)                    # 只删 _lab/keyalign 这个副本目录
    LAB.mkdir(parents=True, exist_ok=True)
    DRIVER.write_text(DRIVER_SOURCE, encoding="utf-8")

    info = ping()
    if not info:
        raise SystemExit(f"{SERVER} 没起来：先跑 python -X utf8 devtools/run_dev_server.py")
    auth = info.get("auth") or {}
    banner("两个客户端的令牌落盘键名对齐（三键制）")
    print(f"  服务端 {SERVER}   JWT={auth.get('jwt')} "
          f"access_ttl={auth.get('access_ttl')}s grace={auth.get('refresh_grace')}s")
    print(f"  副本目录 {LAB}    账号前缀 {PREFIX}")
    check("服务端开着 JWT（auth.jwt=1）", auth.get("jwt") == 1, str(auth))
    check("服务端还开着老式长期令牌（兼容期：phix:token 仍会下发）",
          auth.get("legacy_tokens") == 1, str(auth.get("legacy_tokens")))

    t0 = time.time()
    scene_shared()
    scene_reverse()
    scene_legacy()
    self_clean()

    print("\n" + "=" * 74)
    print(f"通过 {len(PASSED)} 项，失败 {len(FAILED)} 项   用时 {time.time() - t0:.1f}s")
    for name in FAILED:
        print("  - " + name)
    print(f"副本目录（可整删）：{LAB}")
    print("=" * 74)
    return 1 if FAILED else 0


if __name__ == "__main__":
    sys.exit(main())
