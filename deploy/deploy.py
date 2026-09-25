#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""phix 服务端 · 幂等部署脚本（在 Windows 侧运行，通过 SSH/SFTP 推到 Ubuntu）。

用法（本机全局 Python 3.14，已装 paramiko）：

    python -X utf8 D:\\phix\\server\\deploy\\deploy.py            # 完整部署 / 升级
    python -X utf8 D:\\phix\\server\\deploy\\deploy.py --check    # 只体检，不改远端任何东西
    python -X utf8 D:\\phix\\server\\deploy\\deploy.py --dry-run  # 演练：只打印将要做什么

设计要点（务必读懂再改）：
1. **幂等**：重复运行只会「按需」做事。远端已有的 db.sqlite3 绝不删除、绝不覆盖；
   远端已有的 ~/.config/phix/env（里面有 PHIX_SECRET_KEY / PHIX_SERVICE_KEY）绝不覆盖，
   否则会踢掉已登录令牌、导致旧密文解不开。只做「覆盖式上传」，从不「先清空再上传」。
2. **自包含**：所有东西都在 /home/phix/phix-server 和 /home/phix/.config/phix/ 里，
   不动系统其它任何位置；唯一的例外是为了建 venv 而安装 python3-venv / python3-pip
   这两个 apt 包（缺了才装）。
3. **不硬编码密码**：一律从 D:\\phix\\server\\.deploy_secret 读（KEY=VALUE）。
   密码只经 stdin 交给 sudo -S，不落进任何命令行（否则会出现在远端进程列表里）。
4. **不碰 192.168.5.35**：那是心履生产机，与本任务无关。本脚本只连接 .deploy_secret
   里写的 PHIX_DEPLOY_HOST，并且显式拒绝连接 192.168.5.35。
5. 上传范围**白名单**，只同步这四个：phixsvc/、api/、manage.py、requirements.txt。
   部署工具目录 deploy/ 本身不上传（远端只要运行期需要的东西）。
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import io
import os
import posixpath
import re
import secrets
import socket
import stat as statmod
import sys
import time
from pathlib import Path

# ---------------------------------------------------------------------------
# 常量
# ---------------------------------------------------------------------------

HERE = Path(__file__).resolve().parent          # D:\phix\server\deploy
SERVER_DIR = HERE.parent                        # D:\phix\server
SECRET_FILE = SERVER_DIR / ".deploy_secret"
LOCAL_SERVICE_KEY = SERVER_DIR / ".service_key"
UNIT_SRC = HERE / "phix.service"

REMOTE_ROOT = "/home/phix/phix-server"
REMOTE_ENV_DIR = "/home/phix/.config/phix"
REMOTE_ENV = REMOTE_ENV_DIR + "/env"
REMOTE_VENV = REMOTE_ROOT + "/.venv"
REMOTE_PY = REMOTE_VENV + "/bin/python"
REMOTE_DB = REMOTE_ROOT + "/db.sqlite3"
UNIT_PATH = "/etc/systemd/system/phix.service"
DROPIN_DIR = "/etc/systemd/system/phix.service.d"
DROPIN_PATH = DROPIN_DIR + "/10-listen.conf"
SERVICE_NAME = "phix.service"

PORT = 8931
LISTEN_HOST = "127.0.0.1"        # phix.service 单元文件里的绑定地址（安全默认：只本机）
# 局域网直连用的绑定地址。默认 0.0.0.0，因为 phix 是内网学习助手：
# 客户端（Windows/手机）要能直接连 8931。用 systemd drop-in 覆盖，不动主单元文件，
# 想收回本机就 --bind-host 127.0.0.1 再跑一次。将来上域名/Cloudflare Tunnel 后，
# 建议收回 127.0.0.1（走隧道即可，不需要对内网裸露端口）。
LAN_BIND_HOST = "0.0.0.0"

# 上传白名单：文件 -> 远端相对路径（相对 REMOTE_ROOT）
# 说明：这里刻意用**白名单**而不是同步整个目录 ——
#   · 远端只要运行期需要的东西；deploy/（部署工具）、devtools/（自测）、.venv、db.sqlite3
#     都不该上传，尤其 db.sqlite3（远端那台是账号数据的唯一副本）
#   · **自动扫描**：以前这里是写死的清单，2026-09-12 新增 api/middleware.py 时漏补了一行，
#     settings.py 引用了它 → 远端直接崩溃重启循环。改成"扫目录"就不会再犯。
#   · 仍然保留一份"必须存在"的清单（EXPLICIT_REQUIRED）做最低保障。
#   · 新增迁移文件会被自动带上。
UPLOAD_EXCLUDE_DIRS = {
    ".venv", "__pycache__", ".git", "logs", "_backups", "devtools",
    "deploy", ".vscode", ".idea",
}
UPLOAD_EXCLUDE_FILES = {
    "db.sqlite3", "secret_key.txt", ".service_key", ".deploy_secret",
    "e2e_key.txt",          # 应用层加密的服务器私钥：**绝不能上传**，远端自己生成
    "jwt_key.txt",          # 令牌签名的服务器私钥：**绝不能上传**，远端自己生成
    ".env", ".gitignore",
}
# 远端会自己生成、绝不能被本地版本覆盖的东西（保险丝，双保险）
UPLOAD_NEVER_OVERWRITE = {"db.sqlite3", "e2e_key.txt", "jwt_key.txt"}

EXPLICIT_REQUIRED = [
    "manage.py",
    "requirements.txt",
    "phixsvc/settings.py",
    "phixsvc/urls.py",
    "phixsvc/wsgi.py",
    "api/models.py",
    "api/urls.py",
    "api/utils.py",
    "api/views_auth.py",
    "api/views_sync.py",
    "api/tokens.py",
    "api/sso.py",           # 跨站免密登录（一次性码）；漏传会让 /auth/sso/* 直接 404
]


def scan_upload_files() -> list[str]:
    """扫描工程目录，得到要上传的相对路径清单（排序、稳定）。"""
    out: list[str] = []
    for dirpath, dirnames, filenames in os.walk(SERVER_DIR):
        dirnames[:] = sorted(d for d in dirnames if d not in UPLOAD_EXCLUDE_DIRS)
        for fn in sorted(filenames):
            if fn in UPLOAD_EXCLUDE_FILES or fn.endswith((".pyc", ".pyo", ".log")):
                continue
            full = Path(dirpath) / fn
            rel = full.relative_to(SERVER_DIR).as_posix()
            if any(part in UPLOAD_EXCLUDE_DIRS for part in Path(rel).parts[:-1]):
                continue
            out.append(rel)
    for must in EXPLICIT_REQUIRED:
        if must not in out:
            out.append(must)
    return sorted(set(out))


UPLOAD_FILES = scan_upload_files()

# 绝对不许触碰的机器（心履生产机）
FORBIDDEN_HOSTS = {"192.168.5.35"}

# 远端绝不允许被本脚本删除的路径（保险丝：任何删除动作前都会再查一次）
PROTECTED_REMOTE = {REMOTE_DB, REMOTE_ENV}

# ---------------------------------------------------------------------------
# 输出小工具（中文、带步骤号、UTF-8 安全）
# ---------------------------------------------------------------------------


class Log:
    def __init__(self, quiet: bool = False):
        self.quiet = quiet
        self.step_no = 0
        self.warnings: list[str] = []

    def _emit(self, text: str) -> None:
        # Windows 控制台可能是 GBK，容错输出，绝不因为编码把脚本弄崩
        try:
            print(text, flush=True)
        except UnicodeEncodeError:
            sys.stdout.buffer.write((text + "\n").encode("utf-8", "replace"))
            sys.stdout.flush()

    def head(self) -> None:
        self._emit("")
        self._emit("=" * 72)
        self._emit("  phix 服务端部署 · 192.168.5.41（幂等；不碰 192.168.5.35）")
        self._emit("=" * 72)

    def step(self, title: str) -> None:
        self.step_no += 1
        self._emit("")
        self._emit(f"[{self.step_no}] {title}")

    def ok(self, text: str) -> None:
        self._emit(f"    \u2713 {text}")

    def info(self, text: str) -> None:
        self._emit(f"    · {text}")

    def warn(self, text: str) -> None:
        self.warnings.append(text)
        self._emit(f"    ! {text}")

    def err(self, text: str) -> None:
        self._emit(f"    \u00d7 {text}")

    def detail(self, text: str, indent: int = 6) -> None:
        for line in (text or "").rstrip().splitlines():
            self._emit(" " * indent + line)


LOG = Log()


def die(msg: str, code: int = 1):
    LOG.err(msg)
    LOG._emit("")
    LOG._emit("部署中止。")
    sys.exit(code)


# ---------------------------------------------------------------------------
# 凭据文件
# ---------------------------------------------------------------------------


def read_deploy_secret(path: Path) -> dict:
    """读 KEY=VALUE 格式的部署凭据。支持 # 注释、空行、值带引号。"""
    if not path.exists():
        die(f"找不到部署凭据文件：{path}\n      格式：PHIX_DEPLOY_HOST=... / PHIX_DEPLOY_USER=... / PHIX_DEPLOY_PASSWORD=...")
    conf: dict[str, str] = {}
    for lineno, raw in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        k, v = line.split("=", 1)
        k = k.strip()
        v = v.strip()
        if len(v) >= 2 and v[0] == v[-1] and v[0] in "\"'":
            v = v[1:-1]
        if k:
            conf[k] = v
    # 兼容小写写法
    for key in ("HOST", "USER", "PASSWORD"):
        conf.setdefault(f"PHIX_DEPLOY_{key}", conf.get(f"PHIX_DEPLOY_{key.lower()}", ""))
    missing = [k for k in ("PHIX_DEPLOY_HOST", "PHIX_DEPLOY_USER", "PHIX_DEPLOY_PASSWORD") if not conf.get(k)]
    if missing:
        die(f"部署凭据缺少字段：{', '.join(missing)}（文件：{path}）")
    host = conf["PHIX_DEPLOY_HOST"]
    if host in FORBIDDEN_HOSTS:
        die(f"拒绝连接 {host}：那是心履生产机，本任务绝对不许碰。")
    return conf


def mask(text: str) -> str:
    """把密码从任何将要打印的文本里抹掉。"""
    pw = CONFIG.get("PHIX_DEPLOY_PASSWORD") if CONFIG else None
    if pw and text:
        return text.replace(pw, "******")
    return text or ""


# ---------------------------------------------------------------------------
# SSH / SFTP 封装
# ---------------------------------------------------------------------------


class Remote:
    def __init__(self, host: str, user: str, password: str, dry_run: bool = False):
        self.host = host
        self.user = user
        self.password = password
        self.dry_run = dry_run
        self.client = None
        self._sftp = None

    # -- 连接 -------------------------------------------------------------
    def preflight(self) -> None:
        """连接前先探测：ICMP ping 一次（不通用则退回 TCP 探测），不通就友好报错。"""
        alive = False
        try:
            import subprocess

            r = subprocess.run(
                ["ping", "-n", "1", "-w", "2000", self.host],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
            alive = r.returncode == 0
            LOG.info(f"ICMP ping {self.host}：{'通' if alive else '不通'}")
        except Exception as exc:  # pragma: no cover
            LOG.info(f"ICMP ping 不可用（{exc}），改用 TCP 探测")
        if not alive:
            LOG.warn("ICMP 不通（对方可能禁 ping），继续用 TCP:22 探测")
        try:
            with socket.create_connection((self.host, 22), timeout=6):
                LOG.ok("TCP 22 可达，继续连接")
                return
        except OSError as exc:
            die(
                f"连不上 {self.host}:22 —— {exc}\n"
                f"      请确认服务器已开机、网线/网络通、SSH 服务在跑（在服务器上：systemctl status ssh）。"
            )

    def connect(self) -> None:
        import paramiko

        try:
            c = paramiko.SSHClient()
            c.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            c.connect(
                self.host,
                port=22,
                username=self.user,
                password=self.password,
                timeout=20,
                banner_timeout=20,
                auth_timeout=20,
                look_for_keys=False,
                allow_agent=False,
            )
            self.client = c
        except Exception as exc:
            die(f"SSH 登录失败（{self.user}@{self.host}）：{exc}\n      请核对 .deploy_secret 里的用户名/密码。")
        LOG.ok(f"SSH 已登录：{self.user}@{self.host}")

    def close(self) -> None:
        try:
            if self._sftp is not None:
                self._sftp.close()
        except Exception:
            pass
        try:
            if self.client is not None:
                self.client.close()
        except Exception:
            pass

    # -- 执行 -------------------------------------------------------------
    def run(self, cmd: str, timeout: int = 120, check: bool = True, quiet: bool = False,
            stdin_data: str | None = None):
        """执行远端命令，返回 (rc, stdout, stderr)。"""
        assert self.client is not None
        chan = self.client.get_transport().open_session(timeout=timeout)
        chan.settimeout(timeout)
        chan.exec_command(cmd)
        if stdin_data is not None:
            chan.sendall((stdin_data + "\n").encode("utf-8"))
        chan.shutdown_write()
        out, err = b"", b""
        while True:
            if chan.recv_ready():
                out += chan.recv(65536)
                continue
            if chan.recv_stderr_ready():
                err += chan.recv_stderr(65536)
                continue
            if chan.exit_status_ready() and not chan.recv_ready() and not chan.recv_stderr_ready():
                break
            time.sleep(0.05)
        while chan.recv_ready():
            out += chan.recv(65536)
        while chan.recv_stderr_ready():
            err += chan.recv_stderr(65536)
        rc = chan.recv_exit_status()
        chan.close()
        so = mask(out.decode("utf-8", "replace"))
        se = mask(err.decode("utf-8", "replace"))
        if not quiet:
            pass
        if check and rc != 0:
            die(f"远端命令失败（rc={rc}）：{cmd}\n{so}\n{se}")
        return rc, so, se

    def out(self, cmd: str, timeout: int = 120) -> str:
        """只取 stdout（宽松：非 0 退出码不算错误，例如 systemctl is-active 返回 3=inactive）。"""
        return self.run(cmd, timeout=timeout, check=False, quiet=True)[1].strip()

    def sudo(self, cmd: str, timeout: int = 600, check: bool = True):
        """用 sudo -S 执行，密码只经 stdin（不进命令行、不进远端进程列表）。"""
        wrapped = f"sudo -S -p '' bash -lc {shq(cmd)}"
        return self.run(wrapped, timeout=timeout, check=check, stdin_data=self.password)

    def sudo_out(self, cmd: str, timeout: int = 300) -> str:
        return self.sudo(cmd, timeout=timeout)[1].strip()

    # -- SFTP -------------------------------------------------------------
    @property
    def sftp(self):
        if self._sftp is None:
            self._sftp = self.client.open_sftp()
        return self._sftp

    def file_exists(self, path: str) -> bool:
        try:
            self.sftp.stat(path)
            return True
        except IOError:
            return False

    def file_size(self, path: str) -> int | None:
        try:
            return self.sftp.stat(path).st_size
        except IOError:
            return None


    def sha256(self, path: str) -> str:
        """远端文件的 sha256（拿不到返回空串）。

        用途：只比文件大小会漏传 —— 实测两个 APK 恰好同为 5,602,420 字节但内容不同，
        按大小判定"未变"会让生产机一直服役旧包，客户端 SHA256 校验失败。
        """
        out = self.out(f"sha256sum {shq(path)} 2>/dev/null | cut -d' ' -f1")
        got = out.strip().split("\n")[-1].strip() if out.strip() else ""
        return got if re.fullmatch(r"[0-9a-f]{64}", got) else ""

    def put_text(self, remote_path: str, text: str, mode: int = 0o600) -> None:
        data = text.encode("utf-8")
        self.sftp.putfo(io.BytesIO(data), remote_path)
        try:
            self.sftp.chmod(remote_path, mode)
        except IOError:
            pass

    def put_file(self, local: Path, remote_path: str, mode: int = 0o644) -> None:
        self.sftp.put(str(local), remote_path)
        try:
            self.sftp.chmod(remote_path, mode)
        except IOError:
            pass

    def makedirs(self, remote_dir: str) -> None:
        parts = remote_dir.strip("/").split("/")
        cur = ""
        for p in parts:
            cur = cur + "/" + p
            try:
                self.sftp.stat(cur)
            except IOError:
                try:
                    self.sftp.mkdir(cur)
                except IOError:
                    pass


def shq(s: str) -> str:
    """POSIX 单引号转义。"""
    return "'" + s.replace("'", "'\"'\"'") + "'"


def sha256_of_file(path) -> str:
    """本地文件 sha256（分块读，安装包 171 MB 也不吃内存）。"""
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def md5_of(data: bytes) -> str:
    return hashlib.md5(data).hexdigest()


# ---------------------------------------------------------------------------
# 各步骤
# ---------------------------------------------------------------------------

CONFIG: dict = {}


def step_connect(remote: Remote, args) -> None:
    LOG.step("检查目标机连通性并登录")
    # 注意：--dry-run 也真的连一次（只读）。否则「演练」只是自欺欺人，
    # 看不出远端到底缺什么；连接本身不改变远端任何状态。
    remote.preflight()
    remote.connect()


def remote_need_pkgs(remote: Remote) -> list[str]:
    """返回需要安装的 apt 包列表（只在确实缺失时才装）。

    只看 dpkg 不够可靠：Ubuntu 把 venv/ensurepip 拆到了 python3-venv 包里，
    而缺失时 `python3 -m venv --help` 居然也返回 0（argparse 先接管了），
    所以这里**真的建一个临时 venv 再删掉**来判定，最准确。
    """
    need: list[str] = []
    ensurepip_rc = remote.run("python3 -c 'import ensurepip' >/dev/null 2>&1", check=False)[0]
    probe_out = remote.out(
        "rm -rf /tmp/.phix_venv_probe && python3 -m venv /tmp/.phix_venv_probe >/dev/null 2>&1; "
        "echo rc=$?; rm -rf /tmp/.phix_venv_probe"
    )
    venv_ok = "rc=0" in probe_out
    pip_rc = remote.run("python3 -m pip --version >/dev/null 2>&1", check=False)[0]
    if not venv_ok:
        need.append("python3-venv")
    if pip_rc != 0:
        need.append("python3-pip")
    LOG.info(f"远端 python3 版本：{remote.out('python3 -V')}")
    LOG.info(
        f"ensurepip {'可用' if ensurepip_rc == 0 else '缺失'}；"
        f"venv {'可用' if venv_ok else '缺失'}；系统 pip {'可用' if pip_rc == 0 else '缺失'}"
    )
    return need


def step_apt(remote: Remote, args) -> None:
    LOG.step("远端基础依赖：python3-venv / python3-pip（缺了才装）")
    if args.dry_run:
        need = remote_need_pkgs(remote)
        LOG.info(f"[dry-run] 需要安装：{need or '无'}")
        return
    need = remote_need_pkgs(remote)
    if not need:
        LOG.ok("两者都已就绪，跳过 apt（幂等）")
        return
    LOG.info(f"缺失：{', '.join(need)}，开始安装（sudo）")
    pkgs = " ".join(need)
    rc, so, se = remote.sudo(
        f"export DEBIAN_FRONTEND=noninteractive; apt-get update -qq && apt-get install -y {pkgs}",
        timeout=900,
        check=False,
    )
    LOG.detail(so[-2000:] if so else "")
    if se:
        LOG.detail(se[-2000:])
    if rc != 0:
        die(f"apt-get 安装失败（rc={rc}）。请检查远端是否能访问 cn.archive.ubuntu.com。")
    LOG.ok(f"已安装：{pkgs}")


def step_sync(remote: Remote, args) -> int:
    """覆盖式上传（绝不删除远端任何文件）。返回实际改动文件数。"""
    LOG.step("同步工程到 " + REMOTE_ROOT + "（覆盖式上传，不删除任何远端文件）")
    missing_local = [f for f in UPLOAD_FILES if not (SERVER_DIR / f.replace("/", os.sep)).exists()]
    if missing_local:
        die("本地缺少待上传文件：" + ", ".join(missing_local))

    if args.dry_run:
        remote.makedirs(REMOTE_ROOT)
        for rel in UPLOAD_FILES:
            local = SERVER_DIR / rel.replace("/", os.sep)
            rp = posixpath.join(REMOTE_ROOT, rel)
            same = remote.file_exists(rp) and remote.file_size(rp) == local.stat().st_size
            LOG.info(f"[dry-run] {'跳过(大小一致)' if same else '上传'} {rel}")
        LOG.info(f"[dry-run] 远端 db.sqlite3 存在: {remote.file_exists(REMOTE_DB)}（存在则原样保留）")
        return 0

    remote.makedirs(REMOTE_ROOT)
    remote.makedirs(REMOTE_ROOT + "/phixsvc")
    remote.makedirs(REMOTE_ROOT + "/api/migrations")
    remote.makedirs(REMOTE_ROOT + "/logs")
    db_exists_before = remote.file_exists(REMOTE_DB)
    changed = 0
    for rel in UPLOAD_FILES:
        local = SERVER_DIR / rel.replace("/", os.sep)
        rp = posixpath.join(REMOTE_ROOT, rel)
        lsize = local.stat().st_size
        rsize = remote.file_size(rp)
        # 大小相同**不等于**内容相同：实测 xinlv-android.apk 与 xinlv-windows-setup.exe
        # 新旧版本恰好同字节数，只比大小会漏传 → 生产机继续服役旧包，客户端 SHA256 校验失败。
        # 所以大小相同时再用 sha256 确认一次（空文件直接认为相同）。
        same = rsize == lsize and (lsize == 0 or sha256_of_file(local) == remote.sha256(rp))
        if same and not args.force:
            LOG.info(f"未变，跳过  {rel}（{lsize} 字节，哈希一致）")
            continue
        # 上传前确保远端父目录存在（新文件所在的新目录不会被初次遍历建出来）
        parent = posixpath.dirname(rp)
        if parent and parent != REMOTE_ROOT:
            remote.makedirs(parent)
        remote.put_file(local, rp, mode=0o644)
        changed += 1
        LOG.ok(f"已上传  {rel}（{lsize} 字节{'' if rsize is None else f'，原 {rsize} 字节'}）")
    # 保险丝：确认上传过程没有动到数据库
    db_exists_after = remote.file_exists(REMOTE_DB)
    if db_exists_before and not db_exists_after:
        die("严重：远端 db.sqlite3 在上传过程中消失了，请立即人工检查（本脚本不做任何删除操作）")
    if db_exists_after:
        LOG.ok("远端 db.sqlite3 仍在原位，未被动过（账号数据安全）")
    else:
        LOG.info("远端暂无 db.sqlite3，将由 migrate 新建（这是首次部署的正常情况）")
    LOG.ok(f"同步完成：{changed} 个文件有变化 / 共 {len(UPLOAD_FILES)} 个")
    return changed


def step_venv(remote: Remote, args) -> int:
    LOG.step("远端虚拟环境 .venv 与依赖安装")
    if args.dry_run:
        LOG.info("[dry-run] python3 -m venv .venv；pip install -r requirements.txt（requirements.txt 未变则跳过）")
        return 0
    has_venv = remote.file_exists(REMOTE_PY)
    if has_venv:
        LOG.ok("venv 已存在，复用：" + remote.out(f"{REMOTE_PY} -V"))
    else:
        rc, so, se = remote.run(f"cd {REMOTE_ROOT} && python3 -m venv .venv", timeout=300, check=False)
        if rc != 0:
            die(f"创建 venv 失败（rc={rc}）：\n{so}\n{se}")
        LOG.ok("已创建 venv：" + remote.out(f"{REMOTE_PY} -V"))
    # requirements.txt 内容与已安装记录比对，决定是否真的装
    req_hash = remote.out(f"md5sum {REMOTE_ROOT}/requirements.txt | cut -d' ' -f1")
    stamp = REMOTE_VENV + "/.phix-requirements.md5"
    old_hash = remote.out(f"cat {stamp} 2>/dev/null") if remote.file_exists(stamp) else ""
    if req_hash and req_hash == old_hash:
        LOG.ok(f"依赖未变（requirements.txt md5={req_hash[:8]}…），跳过 pip install（幂等）")
        return 0
    LOG.info("开始 pip install -r requirements.txt（首次或依赖有变）")
    rc, so, se = remote.run(
        f"cd {REMOTE_ROOT} && {REMOTE_PY} -m pip install --upgrade pip -q && "
        f"{REMOTE_PY} -m pip install -r requirements.txt",
        timeout=900,
        check=False,
    )
    LOG.detail((so or "")[-3000:])
    if se:
        LOG.detail(se[-1500:])
    if rc != 0:
        die(f"pip install 失败（rc={rc}）。若是网络慢，可重跑本脚本（幂等）。")
    remote.run(f"echo {shq(req_hash)} > {stamp}", check=False)
    LOG.ok("依赖安装完成")
    return 1


def step_env(remote: Remote, args) -> int:
    """生成或复用 ~/.config/phix/env。返回 1 表示有改动（需要重启）。"""
    LOG.step("服务密钥 " + REMOTE_ENV + "（已存在则原样复用，绝不覆盖）")
    if args.dry_run:
        LOG.info(f"[dry-run] 远端 env 存在: {remote.file_exists(REMOTE_ENV)}（存在则复用，不存在才生成）")
        return 0
    exists = remote.file_exists(REMOTE_ENV)
    if exists and not args.force_env:
        body = remote.out(f"cat {REMOTE_ENV}")
        keys = [ln.split("=", 1)[0].strip() for ln in body.splitlines() if "=" in ln and not ln.strip().startswith("#")]
        LOG.ok("env 已存在，原样复用（不覆盖）：" + ", ".join(keys))
        LOG.info("  —— 这样做是为了不踢掉已有登录令牌、不让旧密文解不开")
        # 权限保险
        remote.run(f"chmod 600 {REMOTE_ENV}", check=False)
        return 0

    # 生成：优先沿用远端已有值，其次用本地 .service_key，最后随机
    secret_key = ""
    service_key = ""
    if exists:
        body = remote.out(f"cat {REMOTE_ENV}")
        for ln in body.splitlines():
            if "=" in ln and not ln.strip().startswith("#"):
                k, v = ln.split("=", 1)
                if k.strip() == "PHIX_SECRET_KEY":
                    secret_key = v.strip()
                elif k.strip() == "PHIX_SERVICE_KEY":
                    service_key = v.strip()
    if not secret_key:
        secret_key = secrets.token_urlsafe(64)
    if not service_key:
        if LOCAL_SERVICE_KEY.exists():
            service_key = LOCAL_SERVICE_KEY.read_text(encoding="utf-8").strip()
            LOG.info("PHIX_SERVICE_KEY 沿用本地 .service_key（与本地/心履联调一致）")
        else:
            service_key = secrets.token_urlsafe(48)
            LOG.info("PHIX_SERVICE_KEY 已随机生成")

    # 默认要把**公网域名（含带 www 的）**一起写进去：只写 127.0.0.1/localhost/部署机 IP 的话，
    # 一旦这份 env 被重建（首次生成、换机器、误删），Django 就会对 phix.ing / www.phix.ing
    # 直接 400 DisallowedHost —— 而 Cloudflare 回源时带的正是域名 Host。
    # 现有生产 env 已含这两个域名，这里是让默认值不会再退化。
    allowed = args.allowed_hosts or (
        f"127.0.0.1,localhost,{CONFIG['PHIX_DEPLOY_HOST']},phix.ing,www.phix.ing")
    body = "\n".join(
        [
            "# phix 服务端运行期环境变量（由 deploy.py 生成；权限 600）",
            "# 本文件里的密钥是「账号令牌签名」与「机器间共享密钥」，改动后果：",
            "#   改 PHIX_SECRET_KEY -> 已发出去的 Bearer 令牌全部失效（客户端要重新登录）",
            "#   改 PHIX_SERVICE_KEY -> 心履那边的 /auth/verify 会 401",
            f"# 生成/更新时间：{time.strftime('%Y-%m-%d %H:%M:%S')}",
            "",
            f"PHIX_SECRET_KEY={secret_key}",
            f"PHIX_SERVICE_KEY={service_key}",
            f"PHIX_ALLOWED_HOSTS={allowed}",
            "PHIX_DEBUG=0",
            "PHIX_REGISTER_LIMIT=10",
            f"PHIX_DB={REMOTE_DB}",
            "",
        ]
    )
    remote.makedirs(REMOTE_ENV_DIR)
    remote.put_text(REMOTE_ENV, body, mode=0o600)
    remote.run(f"chmod 700 {REMOTE_ENV_DIR}; chmod 600 {REMOTE_ENV}", check=False)
    LOG.ok(f"已写入 {REMOTE_ENV}（600）：PHIX_SECRET_KEY / PHIX_SERVICE_KEY / PHIX_ALLOWED_HOSTS / PHIX_DEBUG=0 / PHIX_REGISTER_LIMIT=10 / PHIX_DB")
    LOG.warn("这是首次生成密钥 —— 请把远端 ~/.config/phix/env 另行备份一份（丢了就找不回密文）")
    return 1


def step_backup_db(remote: Remote, args) -> None:
    """迁移前先把远端库里已有的数据备份一份（sqlite3 .backup，热备安全）。

    这是本脚本唯一会「新增」文件的地方（写进 _backups/），不删除任何东西；
    只在 db.sqlite3 确实存在且非空时才会做。刻意保留最近 5 份，不无限堆积。
    """
    LOG.step("迁移前备份远端数据库（只新增备份文件，不动原库）")
    if not remote.file_exists(REMOTE_DB):
        LOG.info("远端还没有 db.sqlite3（首次部署），无需备份")
        return
    if args.dry_run:
        LOG.info("[dry-run] sqlite3 .backup -> " + REMOTE_ROOT + "/_backups/")
        return
    # python3 自带 sqlite3 模块，不依赖命令行 sqlite3 工具
    script = (
        "import sqlite3, pathlib, glob, os\n"
        f"src = {REMOTE_DB!r}\n"
        f"d = pathlib.Path({(REMOTE_ROOT + '/_backups')!r}); d.mkdir(exist_ok=True)\n"
        "import time\n"
        "dst = d / ('db-' + time.strftime('%Y%m%d-%H%M%S') + '.sqlite3')\n"
        "s = sqlite3.connect(src); t = sqlite3.connect(str(dst))\n"
        "with t: s.backup(t)\n"
        "t.close(); s.close()\n"
        "print('backup ->', dst, os.path.getsize(dst), 'bytes')\n"
        "old = sorted(d.glob('db-*.sqlite3'))[:-5]\n"
        "for f in old: f.unlink(); print('prune old', f.name)\n"
    )
    rc, so, se = remote.run(f"python3 - <<'PYEOF'\n{script}PYEOF", timeout=300, check=False)
    LOG.detail(so or "")
    if rc != 0:
        LOG.warn(f"备份失败（rc={rc}）：{se.strip()[:300]}")
        LOG.warn("备份失败不阻断部署，但请人工确认远端磁盘与权限")
    else:
        LOG.ok("已备份到 " + REMOTE_ROOT + "/_backups/（保留最近 5 份）")


def step_migrate(remote: Remote, args) -> None:
    LOG.step("数据库迁移 manage.py migrate --noinput（就地迁移，不动既有数据）")
    if args.dry_run:
        LOG.info("[dry-run] .venv/bin/python manage.py migrate --noinput")
        return
    db_before = remote.file_exists(REMOTE_DB)
    size_before = remote.file_size(REMOTE_DB)
    rc, so, se = remote.run(
        f"cd {REMOTE_ROOT} && set -a && . {REMOTE_ENV} && set +a && "
        f"{REMOTE_PY} manage.py migrate --noinput",
        timeout=600,
        check=False,
    )
    LOG.detail(so or "")
    if se:
        LOG.detail(se[-1500:])
    if rc != 0:
        die("migrate 失败。请检查上方输出。")
    size_after = remote.file_size(REMOTE_DB)
    if db_before:
        LOG.ok(f"既存数据库迁移完成（{size_before} -> {size_after} 字节，原数据保留）")
    else:
        LOG.ok(f"已新建空库 {REMOTE_DB}（{size_after} 字节）")


def step_check(remote: Remote, args) -> None:
    LOG.step("Django 自检 manage.py check")
    if args.dry_run:
        LOG.info("[dry-run] .venv/bin/python manage.py check")
        return
    rc, so, se = remote.run(
        f"cd {REMOTE_ROOT} && set -a && . {REMOTE_ENV} && set +a && "
        f"{REMOTE_PY} manage.py check",
        timeout=300,
        check=False,
    )
    LOG.detail(so or "")
    if rc != 0:
        LOG.detail(se[-1500:])
        die("manage.py check 未通过，先修好再上服务。")
    LOG.ok("Django check 通过")


def step_systemd(remote: Remote, args, changed: bool) -> None:
    LOG.step(f"systemd 单元 {SERVICE_NAME}（安装 / 重载 / 启用 / 重启）")
    bind_host = args.bind_host
    if args.dry_run:
        LOG.info(f"[dry-run] 上传 {UNIT_SRC.name} -> {UNIT_PATH}；daemon-reload；enable --now；is-active")
        LOG.info(f"[dry-run] drop-in {DROPIN_PATH}：ExecStart 绑定 {bind_host}:{PORT}")
        return

    # 先算出「单元文件 / drop-in 内容是否有变」——内容变了就必须重启，
    # 否则 systemctl 会一直跑着旧配置（曾经踩过：drop-in 生效但不重启，还监听 127.0.0.1）
    unit_md5_new = md5_of(UNIT_SRC.read_bytes())
    unit_md5_old = remote.out(f"md5sum {UNIT_PATH} 2>/dev/null | cut -d' ' -f1") if remote.file_exists(UNIT_PATH) else ""
    dropin = (
        "# 由 deploy.py 生成：把监听地址从单元文件里的 127.0.0.1 改为指定地址。\n"
        "# 删除本 drop-in 后 systemctl daemon-reload 即恢复「只监听本机」。\n"
        "[Service]\n"
        "ExecStart=\n"
        f"ExecStart={REMOTE_PY} -m waitress --host={bind_host} --port={PORT} --threads=8 "
        "phixsvc.wsgi:application\n"
    )
    dropin_md5_new = md5_of(dropin.encode("utf-8"))
    dropin_md5_old = remote.out(f"md5sum {DROPIN_PATH} 2>/dev/null | cut -d' ' -f1") if remote.file_exists(DROPIN_PATH) else ""
    unit_changed = unit_md5_new != unit_md5_old
    dropin_changed = dropin_md5_new != dropin_md5_old

    tmp = "/tmp/phix.service.deploy"
    remote.put_file(UNIT_SRC, tmp, mode=0o644)
    remote.sudo(f"install -m 644 -o root -g root {tmp} {UNIT_PATH} && rm -f {tmp}")
    LOG.ok(f"已安装 {UNIT_PATH}" + ("（内容有更新）" if unit_changed else "（内容未变）"))

    tmpd = "/tmp/phix-dropin.conf"
    remote.put_text(tmpd, dropin, mode=0o644)
    remote.sudo(f"mkdir -p {DROPIN_DIR} && install -m 644 -o root -g root {tmpd} {DROPIN_PATH} && rm -f {tmpd}")
    LOG.ok(f"监听地址 drop-in：{bind_host}:{PORT}（{DROPIN_PATH}）"
           + ("，内容有更新" if dropin_changed else "，内容未变"))

    remote.sudo("systemctl daemon-reload")
    rc, so, _ = remote.sudo(f"systemctl enable {SERVICE_NAME}", check=False)
    if rc == 0:
        LOG.ok("已设为开机自启")

    state = remote.out(f"systemctl is-active {SERVICE_NAME} 2>/dev/null")
    need_restart = changed or unit_changed or dropin_changed or state != "active"
    if need_restart:
        why = []
        if changed:
            why.append("代码/依赖/密钥有变动")
        if unit_changed:
            why.append("单元文件有变动")
        if dropin_changed:
            why.append("监听地址有变动")
        if state != "active":
            why.append(f"当前状态 {state or 'unknown'}")
        LOG.info("重启服务（" + "；".join(why) + "）")
        remote.sudo(f"systemctl restart {SERVICE_NAME}", timeout=180)
    else:
        LOG.ok("服务已在运行且本次无改动，跳过重启（幂等）")
    for _ in range(20):
        st = remote.out(f"systemctl is-active {SERVICE_NAME} 2>/dev/null")
        if st == "active":
            break
        time.sleep(0.5)
    st = remote.out(f"systemctl is-active {SERVICE_NAME} 2>/dev/null")
    if st != "active":
        rc, so, se = remote.sudo(f"systemctl status {SERVICE_NAME} --no-pager -l", check=False)
        LOG.detail(so)
        LOG.detail(se)
        rc2, jl, _ = remote.sudo(f"journalctl -u {SERVICE_NAME} -n 40 --no-pager", check=False)
        LOG.detail(jl)
        die(f"{SERVICE_NAME} 未能进入 active（当前：{st}）")
    LOG.ok(f"systemctl is-active {SERVICE_NAME} = active")


def probe_hosts(args) -> list[str]:
    """实际要探测的地址列表：0.0.0.0 不可直连，用 127.0.0.1 代替。"""
    hosts = ["127.0.0.1"]
    b = (args.bind_host or LAN_BIND_HOST).strip()
    if b and b not in ("0.0.0.0", "127.0.0.1", "::", "*"):
        hosts.append(b)
    return hosts


def wait_port_ready(remote: Remote, host: str, timeout: float = 30.0) -> bool:
    """等 TCP 端口真正可连（systemd active ≠ 端口已 bind）。"""
    probe = (
        "import socket,sys;"
        f"s=socket.socket(); s.settimeout(1); sys.exit(0 if s.connect_ex(('{host}',{PORT}))==0 else 1)"
    )
    deadline = time.time() + timeout
    while time.time() < deadline:
        rc, _, _ = remote.run("python3 -c " + shq(probe), check=False)
        if rc == 0:
            return True
        time.sleep(1)
    return False


def step_smoke(remote: Remote, args) -> None:
    LOG.step("端到端冒烟：/api/v1/ping 与 /healthz（不用 curl，用 python3 自带 urllib）")
    hosts = probe_hosts(args)
    if args.dry_run:
        LOG.info("[dry-run] 远端 python3 请求 " + "、".join(f"http://{h}:{PORT}/api/v1/ping" for h in hosts))
        return
    if not wait_port_ready(remote, LISTEN_HOST):
        die(f"等了 30 秒，{LISTEN_HOST}:{PORT} 仍未 listen —— 用 journalctl -u {SERVICE_NAME} -n 50 看原因")
    LOG.ok(f"端口 {PORT} 已 listen")
    # 目标机是全新 Ubuntu，没有 curl；用 python3 标准库最稳（不引入任何新依赖）。
    # 脚本经 base64 传输，避免任何 shell 引号/换行问题。
    py = f'''
import json, os, sys, urllib.request

HOSTS = {hosts!r}
PORT = {PORT}
key = os.environ.get("PHIX_SERVICE_KEY", "")

def get(base, path, headers=None, timeout=10):
    req = urllib.request.Request(base + path, headers=headers or {{}})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return r.status, r.read().decode("utf-8")

ok = True
usable = []

def first_ok(fn, tries=15, delay=1.0):
    """等端口真正 listen：systemd 报 active 之后 waitress 还要一点时间才 bind，
    这里必须重试，否则会误报 Connection refused（踩过）。"""
    import time
    last = None
    for i in range(tries):
        try:
            return fn()
        except Exception as e:
            last = e
            time.sleep(delay)
    raise last

for h in HOSTS:
    base = "http://%s:%d" % (h, PORT)
    try:
        st, body = first_ok(lambda b=base: get(b, "/api/v1/ping"))
        d = json.loads(body)
        print("ping   %-46s HTTP %s ok=%s" % (base, st, d.get("ok")))
        if st != 200 or d.get("ok") is not True:
            print("FAIL: %s 未返回 ok:true" % base); ok = False
        else:
            usable.append(base)
        st2, body2 = get(base, "/healthz")
        print("health %-46s HTTP %s %s" % (base, st2, body2.strip()))
    except Exception as e:
        print("FAIL: %s 请求异常 %s: %s" % (base, type(e).__name__, e)); ok = False

if usable:
    base = usable[0]
    try:
        h = {{"X-Phix-Service-Key": key}} if key else {{}}
        st, body = get(base, "/api/v1/ping", h)
        d = json.loads(body)
        print("service_verify_enabled =", d.get("service_verify_enabled"))
        if d.get("service_verify_enabled") is not True:
            print("WARN: service_verify_enabled 不是 true（心履 /auth/verify 会 401）")
    except Exception as e:
        print("WARN: 服务密钥探测失败", type(e).__name__, e)

print("SMOKE_OK" if ok else "SMOKE_FAIL")
sys.exit(0 if ok else 3)
'''
    b64 = base64.b64encode(py.encode("utf-8")).decode("ascii")
    cmd = f"set -a; . {REMOTE_ENV}; set +a; echo {shq(b64)} | base64 -d | python3 -"
    rc, so, se = remote.run(cmd, timeout=90, check=False)
    LOG.detail(so or "")
    if se.strip():
        LOG.detail(se[-800:])
    if rc != 0 or "SMOKE_OK" not in so:
        die(f"冒烟失败（rc={rc}）：{'、'.join(hosts)}:{PORT} 未按预期应答")
    LOG.ok("远端点自检通过：/api/v1/ping 返回 \"ok\": true，/healthz 200")
    if "service_verify_enabled = True" in so:
        LOG.ok("服务密钥生效：service_verify_enabled = true")
    else:
        LOG.warn("service_verify_enabled 不是 true —— 检查 env 里的 PHIX_SERVICE_KEY 与请求头")


def step_status(remote: Remote, args) -> None:
    LOG.step("远端现状摘要")
    rc, so, _ = remote.sudo(f"systemctl status {SERVICE_NAME} --no-pager -l | head -n 12", check=False)
    LOG.detail(so or "(无输出)")
    LOG.info("目录树：")
    LOG.detail(remote.out(f"ls -la {REMOTE_ROOT}"))
    LOG.info("监听端口：")
    LOG.detail(remote.out(f"ss -tlnp 2>/dev/null | grep {PORT} || echo '(未找到 {PORT})'"))
    LOG.info("数据库：")
    LOG.detail(remote.out(f"ls -la {REMOTE_DB} 2>/dev/null || echo '(无 db.sqlite3)'"))
    LOG.info("密钥文件：")
    LOG.detail(remote.out(f"ls -la {REMOTE_ENV} 2>/dev/null || echo '(无 env)'"))


# ---------------------------------------------------------------------------
# --check 模式：只读体检
# ---------------------------------------------------------------------------


def run_check(remote: Remote) -> int:
    LOG.step("只读体检（--check，不改动远端任何东西）")
    checks: list[tuple[str, bool, str]] = []

    def add(name: str, ok: bool, note: str = "") -> None:
        checks.append((name, ok, note))
        (LOG.ok if ok else LOG.err)(f"{name}{(' — ' + note) if note else ''}")

    add("SSH 可达", True, f"{CONFIG['PHIX_DEPLOY_USER']}@{CONFIG['PHIX_DEPLOY_HOST']}")
    add(f"sudo 可用", remote.sudo("id -u", check=False)[0] == 0)
    venv_ok = remote.run("python3 -m venv /tmp/.phix_chk >/dev/null 2>&1", check=False)[0] == 0
    remote.run("rm -rf /tmp/.phix_chk", check=False)
    add("python3-venv 已装", venv_ok, "" if venv_ok else "需 apt 安装")
    pip_ok = remote.run("python3 -m pip --version >/dev/null 2>&1", check=False)[0] == 0
    add("python3-pip 已装", pip_ok, "" if pip_ok else "需 apt 安装")
    add("工程目录 " + REMOTE_ROOT, remote.file_exists(REMOTE_ROOT))
    add("venv " + REMOTE_VENV, remote.file_exists(REMOTE_PY))
    add("密钥文件 " + REMOTE_ENV, remote.file_exists(REMOTE_ENV), "已存在则不会被覆盖")
    db = remote.file_exists(REMOTE_DB)
    add("数据库 db.sqlite3", db, f"{remote.file_size(REMOTE_DB)} 字节（保留，不覆盖）" if db else "尚未创建，将由 migrate 新建")
    add("单元 " + UNIT_PATH, remote.file_exists(UNIT_PATH))
    st = remote.out(f"systemctl is-active {SERVICE_NAME} 2>/dev/null")
    add(f"{SERVICE_NAME} 运行中", st == "active", st or "unknown")
    if st == "active":
        port_ok = f":{PORT} " in remote.out("ss -tln 2>/dev/null") or f":{PORT}\n" in remote.out("ss -tln 2>/dev/null")
        add(f"监听 {PORT}", port_ok, remote.out(f"ss -tln | grep {PORT} || echo '(未监听)'").strip())
        py = (
            "import urllib.request,sys;"
            f"b=urllib.request.urlopen('http://{LISTEN_HOST}:{PORT}/api/v1/ping',timeout=10).read().decode();"
            "print(b[:120]);"
            "sys.exit(0 if '\"ok\": true' in b or '\"ok\":true' in b else 3)"
        )
        rc, so, _ = remote.run("python3 -c " + shq(py), check=False)
        add("本机 ping 返回 ok:true", rc == 0, (so.strip()[:90] if rc == 0 else ""))
    bad = [c for c in checks if not c[1]]
    LOG._emit("")
    if bad:
        LOG._emit(f"体检结果：{len(checks) - len(bad)}/{len(checks)} 项通过；未通过项需要先跑一次完整部署。")
        return 2
    LOG._emit(f"体检结果：{len(checks)}/{len(checks)} 项全部通过。")
    return 0


# ---------------------------------------------------------------------------
# main
# ---------------------------------------------------------------------------


def main() -> int:
    global CONFIG
    ap = argparse.ArgumentParser(
        description="phix 服务端幂等部署脚本（Windows -> Ubuntu 192.168.5.41）",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "示例：\n"
            "  python -X utf8 deploy.py --check      # 只体检\n"
            "  python -X utf8 deploy.py --dry-run    # 演练\n"
            "  python -X utf8 deploy.py              # 真的部署\n"
        ),
    )
    ap.add_argument("--check", action="store_true", help="只体检，不改动远端")
    ap.add_argument("--dry-run", action="store_true", help="演练：只打印计划，不落盘")
    ap.add_argument("--force", action="store_true", help="忽略文件大小比对，强制重传全部文件（仍不删远端文件）")
    ap.add_argument("--force-env", action="store_true", help="危险：重建远端 env（会踢掉所有登录令牌），仅在你确知后果时用")
    ap.add_argument("--allowed-hosts", default="", help="覆盖 PHIX_ALLOWED_HOSTS，逗号分隔（仅在首次生成 env 时生效）")
    ap.add_argument("--bind-host", default=LAN_BIND_HOST,
                    help=f"服务监听地址（默认 {LAN_BIND_HOST}=局域网可直连；填 127.0.0.1 则只允许本机/反代访问）")
    ap.add_argument("--secret-file", default=str(SECRET_FILE), help="部署凭据文件路径")
    args = ap.parse_args()

    if not UNIT_SRC.exists():
        die(f"缺少 systemd 单元文件：{UNIT_SRC}")
    CONFIG = read_deploy_secret(Path(args.secret_file))

    LOG.head()
    LOG.info(f"目标：{CONFIG['PHIX_DEPLOY_USER']}@{CONFIG['PHIX_DEPLOY_HOST']}  端口 {PORT}  模式："
             f"{'体检(check)' if args.check else ('演练(dry-run)' if args.dry_run else '完整部署')}")
    LOG.info(f"凭据：{args.secret_file}（密码不打印、不进命令行）")

    remote = Remote(CONFIG["PHIX_DEPLOY_HOST"], CONFIG["PHIX_DEPLOY_USER"], CONFIG["PHIX_DEPLOY_PASSWORD"], args.dry_run)
    t0 = time.time()
    try:
        step_connect(remote, args)
        if args.check:
            return run_check(remote)

        step_apt(remote, args)
        changed_files = step_sync(remote, args)
        changed_deps = step_venv(remote, args)
        changed_env = step_env(remote, args)
        step_backup_db(remote, args)
        step_migrate(remote, args)
        step_check(remote, args)
        step_systemd(remote, args, changed=bool(changed_files or changed_deps or changed_env))
        step_smoke(remote, args)
        if not args.dry_run:
            step_status(remote, args)
    except SystemExit:
        raise
    except Exception as exc:  # 兜底：任何异常都友好收尾
        import traceback

        LOG.err(f"意外错误：{type(exc).__name__}: {mask(str(exc))}")
        LOG.detail(mask(traceback.format_exc()))
        return 1
    finally:
        remote.close()

    LOG._emit("")
    LOG._emit("=" * 72)
    if LOG.warnings:
        LOG._emit(f"部署完成（耗时 {time.time() - t0:.1f}s），有 {len(LOG.warnings)} 条提醒：")
        for w in LOG.warnings:
            LOG._emit("  ! " + w)
    else:
        LOG._emit(f"部署完成，全部通过（耗时 {time.time() - t0:.1f}s）。")
    LOG._emit(f"健康检查：http://{CONFIG['PHIX_DEPLOY_HOST']}:{PORT}/api/v1/ping")
    LOG._emit(f"看日志：  ssh {CONFIG['PHIX_DEPLOY_USER']}@{CONFIG['PHIX_DEPLOY_HOST']} 'journalctl -u {SERVICE_NAME} -f'")
    LOG._emit("=" * 72)
    return 0


if __name__ == "__main__":
    sys.exit(main())
