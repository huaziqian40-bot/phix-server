#!/usr/bin/env python3
# -*- coding: utf-8 -*-
r"""phix 每日数据备份 —— 从 Linux 生产机拉取数据到 D:\backup\YYMMDD\phix

备份内容（只存**文字数据**，安装包与图片一律不备份）：

· db.sqlite3        phix 服务端用户库（账号 / Bearer 令牌 / 密文对象）。
                    用 SQLite 的 backup API 在远端生成**一致性快照** ——
                    服务运行中直接拷文件会拷到半写状态，恢复时会损坏。
· env               ~/.config/phix/env（PHIX_SECRET_KEY / PHIX_SERVICE_KEY）。
                    **这一份最重要**：丢了它，云端那堆密文就再也解不开了。
· content.json      官网 CMS 文案与后台改动
· logs.json         「PHIX 日志」（同学送修记录）
· admin_audit.log   管理后台操作审计
· feedback/         反馈表单提交的内容（逐条 json）
· .site_secret / .phix_pubkey / .service_key   站点密钥

**不备份**：`media/downloads`（约 790 MB 的安装包，可从 GitHub Release 重新下载）、
`media/logs`（用户上传的照片，按心履同一约定「只存文字数据」跳过）。

目录约定（2026-09-22 起）：`D:\backup\<YYMMDD>\` 下按服务分子目录 ——
    `xinlv\`  ← `D:\moodsite\backup_linux.py`
    `phix\`   ← 本脚本
改这个路径前先看一眼另一个脚本，两边的日期文件夹必须是同一个。

由 Windows 计划任务「phix每日备份」每天 05:00 调用（pythonw 静默运行）。
幂等：当天已备份则跳过；失败会在 backup.log 留痕。
日志追加到 `D:\backup\backup.log`（与心履那份共用同一个日志）。

【最高纪律】`D:\backup\` 只进不出：只可追加，不可删除/移动/重命名其中任何内容。

用法：
    python  D:\phix\server\deploy\backup_daily.py          # 正常备份
    python  ...\backup_daily.py --force                   # 忽略"今天已备过"
    python  ...\backup_daily.py --dry-run                 # 只列要拉什么，不连也不写
"""
from __future__ import annotations

import base64
import os
import sys
from datetime import datetime
from pathlib import Path

BACKUP_ROOT = r"D:\backup"
#: 本服务在日期文件夹下的子目录名（心履那份脚本用的是 "xinlv"）
DAY_SUBDIR = "phix"
LOG_FILE = os.path.join(BACKUP_ROOT, "backup.log")

SECRET_FILE = Path(r"D:\phix\server\.deploy_secret")

REMOTE_SERVER = "/home/phix/phix-server"          # phix.service 的 WorkingDirectory
REMOTE_ENV = "/home/phix/.config/phix/env"        # EnvironmentFile
REMOTE_SITE = "/home/phix/phix-website"           # phix-site.service 的 WorkingDirectory
REMOTE_TMP_DB = "/tmp/phix_db_backup.sqlite3"
VENV_PY = REMOTE_SERVER + "/.venv/bin/python"

#: (远端路径, 本地文件名) —— 单个文件；缺了只记一笔，不影响其它
FILES = [
    (REMOTE_ENV, "env"),
    (REMOTE_SITE + "/content.json", "content.json"),
    (REMOTE_SITE + "/logs.json", "logs.json"),
    (REMOTE_SITE + "/admin_audit.log", "admin_audit.log"),
    (REMOTE_SITE + "/.site_secret", ".site_secret"),
    (REMOTE_SITE + "/.phix_pubkey", ".phix_pubkey"),
    (REMOTE_SITE + "/.service_key", ".service_key"),
]
#: (远端目录, 本地目录名) —— 目录里逐条拉；空目录也算成功
DIRS = [
    (REMOTE_SITE + "/feedback", "feedback"),
]

#: 远端生成一致性 db 快照的代码（base64 传过去，免得跟 shell 引号打架）
_DB_CODE = (
    "import sqlite3;"
    "s=sqlite3.connect('%(src)s');"
    "d=sqlite3.connect('%(tmp)s');"
    "s.backup(d);d.close();s.close();print('DB-OK')" % {
        "src": REMOTE_SERVER + "/db.sqlite3", "tmp": REMOTE_TMP_DB})
_REMOTE_DB_CMD = ('%s -c "import base64;exec(base64.b64decode(\'%s\'))"'
                  % (VENV_PY, base64.b64encode(_DB_CODE.encode()).decode()))

MANIFEST = """phix 每日数据备份 · {day}
备份时间：{stamp}
来源：{host}（phix 服务端 {server}；官网 {site}）

db.sqlite3         phix 服务端用户库（SQLite backup API 生成的一致性快照）
                   账号、Bearer 令牌、refresh 令牌哈希、端到端加密后的密文对象
env                ~/.config/phix/env —— PHIX_SECRET_KEY / PHIX_SERVICE_KEY
                   【丢了它，云端密文再也解不开】还有 PHIX_ALLOWED_HOSTS 等
content.json       官网 CMS 文案与后台改动
logs.json          「PHIX 日志」（同学送修记录）
admin_audit.log    管理后台操作审计
feedback/          反馈表单提交内容（每条约 200 字节 json）
.site_secret       官网签名 cookie 用
.phix_pubkey       官网固定下来的 phix 服务端公钥（TOFU）
.service_key       官网 ↔ phix 服务端之间的机器间密钥

未备份（有意）：
media/downloads    约 790 MB 的安装包 —— 可从 GitHub Release 重新下载，不属于"数据"
media/logs         用户上传的照片 —— 按"只存文字数据"的约定跳过

恢复要点：db.sqlite3 与 env 必须**成对**恢复 —— 换了 PHIX_SECRET_KEY，
已发出的令牌会全部失效（客户端要重新登录）；丢了 env 则云端密文无法解开。
"""


def _log(msg: str) -> None:
    try:
        os.makedirs(BACKUP_ROOT, exist_ok=True)
        with open(LOG_FILE, "a", encoding="utf-8") as f:
            f.write("[%s] %s\n" % (datetime.now().strftime("%Y-%m-%d %H:%M:%S"), msg))
    except OSError:
        pass


def _say(msg: str) -> None:
    """有人在看的时候（手动跑）也打到屏幕上；pythonw 下 print 会是空操作。"""
    try:
        print(msg)
    except Exception:  # noqa: BLE001  pythonw 没有 stdout
        pass


def read_secret() -> dict:
    conf: dict[str, str] = {}
    if not SECRET_FILE.exists():
        return conf
    for line in SECRET_FILE.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if line and not line.startswith("#") and "=" in line:
            key, value = line.split("=", 1)
            conf[key.strip()] = value.strip()
    return conf


def main() -> int:
    force = "--force" in sys.argv
    dry = "--dry-run" in sys.argv

    day = datetime.now().strftime("%y%m%d")
    target_dir = os.path.join(BACKUP_ROOT, day, DAY_SUBDIR)
    db_target = os.path.join(target_dir, "db.sqlite3")

    if dry:
        _say("将要备份到：%s" % target_dir)
        _say("  一致性快照  %s/db.sqlite3  →  db.sqlite3" % REMOTE_SERVER)
        for remote, name in FILES:
            _say("  文件        %s  →  %s" % (remote, name))
        for remote, name in DIRS:
            _say("  目录        %s  →  %s/" % (remote, name))
        return 0

    if os.path.exists(db_target) and not force:
        _log("今天 %s phix 已备份过（%s 存在），跳过。" % (day, db_target))
        return 0

    conf = read_secret()
    missing = [k for k in ("PHIX_DEPLOY_HOST", "PHIX_DEPLOY_USER", "PHIX_DEPLOY_PASSWORD")
               if not conf.get(k)]
    if missing:
        _log("phix 备份失败：%s 里缺少 %s" % (SECRET_FILE, ", ".join(missing)))
        return 1

    try:
        import paramiko
    except ImportError:
        _log("phix 备份失败：缺少 paramiko，无法连接 Linux。")
        return 1

    host = conf["PHIX_DEPLOY_HOST"]
    ssh = None
    failures = 0
    try:
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        ssh.connect(host, username=conf["PHIX_DEPLOY_USER"],
                    password=conf["PHIX_DEPLOY_PASSWORD"], timeout=20)
        _log("已连接 Linux %s，开始备份 phix %s" % (host, day))

        # 1) 远端用 SQLite backup API 做一致性快照
        _, stdout, stderr = ssh.exec_command(_REMOTE_DB_CMD, timeout=180)
        out = stdout.read().decode("utf-8", "replace").strip()
        err = stderr.read().decode("utf-8", "replace").strip()
        code = stdout.channel.recv_exit_status()
        if code != 0 or "DB-OK" not in out:
            _log("phix 备份失败：远端生成 db 快照出错：%s %s" % (err, out))
            return 1

        os.makedirs(target_dir, exist_ok=True)
        sftp = ssh.open_sftp()

        # 2) 快照 → 本地
        try:
            size = sftp.stat(REMOTE_TMP_DB).st_size
            sftp.get(REMOTE_TMP_DB, db_target)
            _log("已备份 db.sqlite3：%s（%d 字节）" % (db_target, size))
        except Exception as exc:  # noqa: BLE001
            failures += 1
            _log("phix 备份：拉取 db.sqlite3 失败：%s" % exc)

        # 3) 其余单文件
        for remote, name in FILES:
            local = os.path.join(target_dir, name)
            try:
                size = sftp.stat(remote).st_size
                sftp.get(remote, local)
                _log("已备份 %s：%s（%d 字节）" % (name, local, size))
            except FileNotFoundError:
                _log("phix 备份：远端 %s 不存在，跳过。" % remote)
            except Exception as exc:  # noqa: BLE001
                failures += 1
                _log("phix 备份：拉取 %s 失败：%s" % (name, exc))

        # 4) 目录（feedback 逐条拉）
        for remote, name in DIRS:
            local_dir = os.path.join(target_dir, name)
            try:
                entries = [e for e in sftp.listdir_attr(remote) if not e.st_mode & 0o40000]
                os.makedirs(local_dir, exist_ok=True)
                got = 0
                for entry in entries:
                    try:
                        sftp.get(remote + "/" + entry.filename,
                                 os.path.join(local_dir, entry.filename))
                        got += 1
                    except Exception as exc:  # noqa: BLE001
                        failures += 1
                        _log("phix 备份：拉取 %s/%s 失败：%s" % (name, entry.filename, exc))
                _log("已备份 %s/：%d 个文件 → %s" % (name, got, local_dir))
            except FileNotFoundError:
                _log("phix 备份：远端 %s 不存在，跳过。" % remote)
            except Exception as exc:  # noqa: BLE001
                failures += 1
                _log("phix 备份：拉取目录 %s 失败：%s" % (name, exc))

        # 5) 清单（本地生成，说明每个文件是什么、从哪来）
        try:
            Path(target_dir, "MANIFEST.txt").write_text(
                MANIFEST.format(day=day, stamp=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                                host=host, server=REMOTE_SERVER, site=REMOTE_SITE),
                encoding="utf-8")
        except OSError as exc:
            _log("phix 备份：写 MANIFEST.txt 失败：%s" % exc)

        # 6) 清理远端临时文件
        try:
            sftp.remove(REMOTE_TMP_DB)
        except Exception:  # noqa: BLE001
            pass
        sftp.close()

        if failures:
            _log("phix 备份完成但有 %d 项失败：%s" % (failures, target_dir))
            return 1
        _log("phix 备份完成：%s" % target_dir)
        return 0
    except Exception as exc:  # noqa: BLE001
        _log("phix 备份异常：%s" % exc)
        return 1
    finally:
        if ssh is not None:
            try:
                ssh.close()
            except Exception:  # noqa: BLE001
                pass


if __name__ == "__main__":
    sys.exit(main())
