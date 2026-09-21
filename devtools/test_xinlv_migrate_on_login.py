"""心履老用户登录自动迁移 phix 账号 —— 端到端测试（≥15 项）。

验证 `D:\\moodsite\\web\\core\\phix_auth.py` 的迁移三段式：
① 先问 phix → ② 明确拒绝回落本地 → ③ 本地口令通过（老用户）就现场建 phix 账号。

**数据安全**：起一台**专用** phix 服务器（独立端口 8941 + 独立副本库 `_lab/xlmig_db.sqlite3`），
moodsite 侧用**全新测试库** `_lab/xlmig_moodsite.sqlite3`（跑全部迁移生成，绝不碰原库）。
所有账号用 `xlmig` 前缀，跑完删除两个测试库（它们只是本测试的产物，可安全删）。

运行（用 moodsite 的 venv，因为它有 dotenv；phix 子进程用 phix 自己的 venv）：

    cd D:\\moodsite\\web
    venv\\Scripts\\python.exe -X utf8 D:\\phix\\server\\devtools\\test_xinlv_migrate_on_login.py
"""
import json
import os
import sqlite3
import subprocess
import sys
import time
from pathlib import Path

import requests

PHIX_ROOT = Path(r"D:\phix\server")
PHIX_VENV = PHIX_ROOT / ".venv" / "Scripts" / "python.exe"
MOODSITE_ROOT = Path(r"D:\moodsite\web")
LAB = Path(r"D:\phix\_lab")
LAB.mkdir(exist_ok=True)

PORT = 8941
SERVER = f"http://127.0.0.1:{PORT}"
API = SERVER + "/api/v1"
SERVICE_KEY = "xlmig-test-service-key-123456789"
PHIX_DB = LAB / "xlmig_db.sqlite3"
MOODSITE_COPY = LAB / "xlmig_moodsite.sqlite3"
DEAD_SERVER = "http://127.0.0.1:8999"   # 空端口，模拟"phix 不可达"

PASSED, FAILED = [], []


def check(name, cond, extra=""):
    (PASSED if cond else FAILED).append(name)
    print(f"  [{'OK  ' if cond else 'FAIL'}] {name}"
          + (f"   {extra}" if extra and not cond else ""))
    return cond


# ---------------- phix 专用服务器（副本数据根） ----------------

def _py(cmd, cwd, env, check_rc=True, **kw):
    r = subprocess.run([str(PHIX_VENV), "-X", "utf8"] + cmd,
                       cwd=str(cwd), env=env,
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, **kw)
    if check_rc and r.returncode != 0:
        raise RuntimeError(f"命令失败({r.returncode}): {' '.join(cmd)}")
    return r


def start_phix():
    if PHIX_DB.exists():
        PHIX_DB.unlink()
    base = dict(os.environ)
    base["DJANGO_SETTINGS_MODULE"] = "phixsvc.settings"
    base["PHIX_DB"] = str(PHIX_DB)
    base["PYTHONIOENCODING"] = "utf-8"
    _py(["manage.py", "migrate", "--noinput"], PHIX_ROOT, base)

    env = dict(os.environ)
    env["PHIX_DB"] = str(PHIX_DB)
    env["PHIX_SERVICE_KEY"] = SERVICE_KEY
    env["PHIX_DEBUG"] = "1"
    env["PHIX_REGISTER_LIMIT"] = "9000"
    env["PHIX_KEYMATERIAL_LIMIT"] = "90000"
    env["PHIX_RECOVER_LIMIT"] = "9000"
    env["PHIX_REFRESH_LIMIT"] = "90000"
    env["PYTHONIOENCODING"] = "utf-8"
    logf = open(LAB / "xlmig_server.log", "ab")
    proc = subprocess.Popen(
        [str(PHIX_VENV), "-X", "utf8", str(PHIX_ROOT / "run_local.py"),
         "127.0.0.1", str(PORT)],
        cwd=str(PHIX_ROOT), env=env, stdout=logf, stderr=logf,
        creationflags=getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0),
    )
    for _ in range(60):
        try:
            if requests.get(API + "/ping", timeout=2).ok:
                return proc
        except requests.RequestException:
            pass
        time.sleep(0.2)
    proc.terminate()
    raise RuntimeError("phix 测试服务器没能起来")


def stop_phix(proc):
    try:
        proc.terminate()
        proc.wait(timeout=10)
    except Exception:
        try:
            proc.kill()
        except Exception:
            pass


def phix_count(username):
    con = sqlite3.connect(str(PHIX_DB))
    try:
        return con.execute("select count(*) from auth_user where username=?",
                           (username,)).fetchone()[0]
    finally:
        con.close()


def phix_kdf(username):
    con = sqlite3.connect(str(PHIX_DB))
    try:
        row = con.execute(
            "select k.kdf_algo from auth_user u "
            "join phix_user_key_material k on k.user_id=u.id where u.username=?",
            (username,)).fetchone()
        return row[0] if row else None
    finally:
        con.close()


def keymaterial(username):
    r = requests.post(API + "/auth/keymaterial", json={"username": username}, timeout=15)
    return r.json()


# ---------------- moodsite（副本库，绝不动原库） ----------------

def boot_moodsite():
    """在**全新测试库**里跑 moodsite（跑全部迁移，得到一个干净、结构正确的副本库）。

    不复制真实库：真实库可能停留在较旧的迁移版本（本次实测就在 0012，缺
    ``phix_user_id``），直接复制会缺列。全新 migrate 最稳，且绝不碰原库。
    """
    if MOODSITE_COPY.exists():
        MOODSITE_COPY.unlink()

    os.environ["DJANGO_SETTINGS_MODULE"] = "moodsite.settings"
    os.environ["DJANGO_DEBUG"] = "1"
    os.environ["PHIX_AUTH_ENABLED"] = "1"
    os.environ["PHIX_SERVER"] = SERVER
    os.environ["PHIX_SERVICE_KEY"] = SERVICE_KEY
    sys.path.insert(0, str(MOODSITE_ROOT))
    sys.path.insert(0, r"D:\phl-lite-dev")

    import django
    django.setup()

    from django.test import override_settings
    from django.test import RequestFactory
    from django.contrib.sessions.backends.db import SessionStore
    from django.contrib.auth import get_user_model
    from django.core.management import call_command
    from hellopinghe import phixcrypto as pc
    from core import phix_auth
    from core.models import UserProfile

    COPY_DB = {"default": {"ENGINE": "django.db.backends.sqlite3",
                           "NAME": str(MOODSITE_COPY), "OPTIONS": {"timeout": 20}}}
    with override_settings(DATABASES=COPY_DB):
        call_command("migrate", interactive=False, verbosity=0)

    ON = dict(PHIX_AUTH_ENABLED=True, PHIX_SERVER=SERVER,
              PHIX_SERVICE_KEY=SERVICE_KEY, ALLOWED_HOSTS=["testserver"],
              AUTHENTICATION_BACKENDS=[
                  "core.phix_auth.PhixAuthBackend",
                  "django.contrib.auth.backends.ModelBackend"])
    return dict(override_settings=override_settings, RequestFactory=RequestFactory,
                SessionStore=SessionStore, User=get_user_model(), pc=pc,
                phix_auth=phix_auth, UserProfile=UserProfile,
                COPY_DB=COPY_DB, ON=ON)


def register_phix_account(username, password, pc):
    """直接（明文 HTTP）注册一个 phix 账号，模拟"已有 phix 账号"的场景。"""
    mat = pc.new_material(username, password)
    body = {
        "username": username, "agree": True, "device": "迁移测试-预注册",
        "kdf_algo": mat["kdf_algo"], "kdf_salt": mat["kdf_salt"],
        "auth_salt": mat["auth_salt"], "key_wrap": mat["key_wrap"],
        "key_mode": mat["key_mode"], "key_check": mat["key_check"],
        "key_check_plain": mat["key_check_plain"],
        "recovery_salt": mat["recovery_salt"],
        "recovery_wrap": mat["recovery_wrap"], "auth_hash": mat["auth_hash"],
    }
    r = requests.post(API + "/auth/register", json=body, timeout=30)
    return mat, r


# ---------------- 主流程 ----------------

def main():
    print("=" * 74)
    print("心履老用户登录自动迁移 phix 账号 · 端到端测试")
    print("=" * 74)

    proc = start_phix()
    try:
        env = boot_moodsite()
        with env["override_settings"](DATABASES=env["COPY_DB"], **env["ON"]):
            run_tests(env)
    finally:
        stop_phix(proc)

    print("\n" + "=" * 74)
    print(f"通过 {len(PASSED)} 项，失败 {len(FAILED)} 项")
    for f in FAILED:
        print("  - " + f)
    print("=" * 74)

    # 自清：删掉本测试的两个副本库（副本库是本测试的产物，可安全删；绝不动原库）
    for f in (PHIX_DB, MOODSITE_COPY, LAB / "xlmig_db.sqlite3-wal",
              LAB / "xlmig_db.sqlite3-shm"):
        try:
            f.unlink(missing_ok=True)
        except OSError:
            pass
    return 1 if FAILED else 0


def run_tests(env):
    override_settings = env["override_settings"]
    RequestFactory = env["RequestFactory"]
    SessionStore = env["SessionStore"]
    User = env["User"]
    pc = env["pc"]
    phix_auth = env["phix_auth"]
    UserProfile = env["UserProfile"]
    backend = phix_auth.PhixAuthBackend()

    ping = requests.get(API + "/ping", timeout=15).json()
    check("phix 测试服务器已启动且支持应用层加密", ping.get("enc") == 1,
          str(ping.get("enc")))

    # ============ [1] 老用户迁移主流程 ============
    print("\n[1] 老用户用原密码登录 → 自动迁移")
    u1 = "xlmig_legacy_" + os.urandom(4).hex()
    pw1 = "Old-Local-Pass-9"
    User.objects.create_user(username=u1, password=pw1)
    rf = RequestFactory()
    req = rf.post("/login/")
    req.session = SessionStore()
    got = backend.authenticate(req, u1, pw1)

    check("老用户用原密码登录成功（返回该用户）", got is not None and got.username == u1,
          str(got))
    phix_id = phix_auth.phix_user_id_of(got) if got else None
    check("登录后本地账号已关联 phix user_id", phix_id is not None, str(phix_id))
    check("登录后本地口令已作废", got is not None and not got.has_usable_password(),
          "has_usable_password=" + str(got.has_usable_password() if got else "?"))
    check("phix 侧出现了同名账号", phix_count(u1) == 1, str(phix_count(u1)))
    check("迁移建的是 v2 账号（scrypt-hkdf-v2）", phix_kdf(u1) == "scrypt-hkdf-v2",
          str(phix_kdf(u1)))

    code = req.session.get(phix_auth.RECOVERY_SESSION_KEY)
    check("恢复码写进了 session（登录后展示一次）", isinstance(code, str) and len(code) > 10,
          str(code))
    km = keymaterial(u1)
    ok_rec = False
    if code and km.get("recovery_wrap"):
        try:
            dek_rec = pc.unwrap_dek_with_recovery(
                km["recovery_wrap"], code, km["recovery_salt"], u1, km["kdf_algo"])
            dek_pw = pc.unwrap_dek(
                km["key_wrap"], pw1, km["kdf_salt"], u1, km["kdf_algo"])
            ok_rec = dek_rec == dek_pw
        except Exception as exc:  # noqa: BLE001
            print("      恢复码校验异常:", exc)
    check("恢复码能解开 phix 侧的 recovery_wrap（与原口令解出的 DEK 一致）", ok_rec)

    # ============ [2] 第二次登录走 phix，不重复建号 ============
    print("\n[2] 同一用户第二次登录")
    got2 = backend.authenticate(None, u1, pw1)
    check("第二次登录成功（走 phix 路径）", got2 is not None and got2.pk == got.pk)
    check("phix 侧账号仍是 1 个（不重复建号）", phix_count(u1) == 1, str(phix_count(u1)))

    # ============ [3] 口令错误 ============
    print("\n[3] 口令错误")
    u3 = "xlmig_wrong_" + os.urandom(4).hex()
    User.objects.create_user(username=u3, password="Right-Local-Pass-9")
    got3 = backend.authenticate(None, u3, "totally-wrong-pass")
    check("口令错误登录失败（返回 None）", got3 is None)
    check("口令错误后 phix 没有建出任何账号", phix_count(u3) == 0, str(phix_count(u3)))

    # ============ [4] 已有 phix 账号（不触发迁移） ============
    print("\n[4] 已有 phix 账号的用户")
    u4 = "xlmig_existing_" + os.urandom(4).hex()
    pw4 = "Already-Phix-Pass-9"
    _mat, r4 = register_phix_account(u4, pw4, pc)
    check("预注册 phix 账号成功", r4.status_code == 201, f"{r4.status_code} {r4.text[:120]}")
    got4 = backend.authenticate(None, u4, pw4)
    check("moodsite 无本地账号 → 自动建影子账号并登录成功",
          got4 is not None and got4.username == u4)
    check("影子账号已关联 phix user_id", phix_auth.phix_user_id_of(got4) is not None)
    check("phix 侧账号仍是 1 个（没重复注册）", phix_count(u4) == 1, str(phix_count(u4)))

    # ============ [5] phix 不可达（兜底） ============
    print("\n[5] phix 不可达（指向空端口）")
    u5 = "xlmig_unreach_" + os.urandom(4).hex()
    pw5 = "Reach-Local-Pass-9"
    User.objects.create_user(username=u5, password=pw5)
    with override_settings(PHIX_SERVER=DEAD_SERVER):
        got5 = backend.authenticate(None, u5, pw5)
        check("未关联老用户仍可用本地口令登录", got5 is not None and got5.username == u5)
        check("phix 不可达时**没有**建号", phix_count(u5) == 0, str(phix_count(u5)))
        check("该用户仍处于待迁移（phix_user_id 为空）",
              phix_auth.phix_user_id_of(got5) is None)

        u6 = "xlmig_linked_" + os.urandom(4).hex()
        lk = User.objects.create_user(username=u6, password="localpass1")
        UserProfile.objects.update_or_create(user=lk, defaults={"phix_user_id": 5})
        lk.set_unusable_password()
        lk.save()
        got6 = backend.authenticate(None, u6, "localpass1")
        check("已关联账号在 phix 不可达时 fail closed（拒绝登录）", got6 is None)

    # ============ [6] 通告条渲染 ============
    print("\n[6] 通告条渲染断言")
    from django.test import Client
    from core.models import SiteSettings
    c = Client()
    html = c.get("/").content.decode("utf-8")
    check("首页 HTML 出现账号迁移通告文案",
          "我们正在把账号迁移到统一的 phix 账号" in html)
    s = SiteSettings.load()
    s.show_migration_notice = False
    s.save()
    html2 = c.get("/").content.decode("utf-8")
    check("关闭开关后首页不再出现该通告",
          "我们正在把账号迁移到统一的 phix 账号" not in html2)
    s.show_migration_notice = True
    s.save()


if __name__ == "__main__":
    sys.exit(main())
