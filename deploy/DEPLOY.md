# phix 服务端 · 部署与运维文档

> 目标机：**192.168.5.41**（Ubuntu 24.04.4 LTS x86_64，4 核 / 7.9G / 114G）
> 部署者：`phix` 用户，sudo 同密码
> 最后一次实际部署验证：2026-09-12 11:32（见文末「验证记录」）
>
> ⛔ **本任务的边界**：心履生产机是 **192.168.5.35**，本文档所有操作**都只针对 .41**，
> 绝不允许连接或改动 .35。`deploy/deploy.py` 里写死了拒绝连接 .35（`FORBIDDEN_HOSTS`）。

---

## 1. 这是什么

phix 服务端是一个**只做三件事**的 Django 服务：管账号、发 Bearer 令牌、存**不透明密文对象**。
它没有任何密码学依赖（除 Django 外只有 waitress），**看不懂用户上传的任何内容**。

| 项 | 值 |
|---|---|
| 工程根（远端） | `/home/phix/phix-server` |
| 运行方式 | systemd 服务 `phix.service` → venv 里的 waitress |
| 监听 | `0.0.0.0:8931`（`0.0.0.0` 由 drop-in 打开，见 §5.3） |
| 端口 | **8931**（**不要用 8000**，那是心履生产机 192.168.5.35 的端口） |
| 数据库 | `/home/phix/phix-server/db.sqlite3`（SQLite，**账号数据的唯一副本**） |
| 密钥文件 | `/home/phix/.config/phix/env`（600，phix 用户可读） |
| 日志 | journald（`journalctl -u phix.service`）+ `logs/phix.log`（2MB×5 轮转） |
| URL 前缀 | `/api/v1/`；另有 `/healthz` 和 `/api/v1/ping` 做健康检查 |
| venv | `/home/phix/phix-server/.venv`（Python 3.12.3 + Django 5.2.17 + waitress 3.x） |

### 1.1 远端目录布局

```
/home/phix/
├── .config/phix/env           # ★ 密钥（600）：PHIX_SECRET_KEY / PHIX_SERVICE_KEY / ...，丢了找不回
├── phix-server/e2e_key.txt    # ★ 传输加密用的 X25519 私钥（600，首次启动生成，**绝不外传**）
├── phix-server/jwt_key.txt    # ★ 令牌签名用的 Ed25519 私钥（600，首次启动生成，**绝不外传**）
└── phix-server/               # 全部自包含在这里，不碰系统其它任何位置
    ├── manage.py
    ├── requirements.txt
    ├── phixsvc/                # 工程配置（settings.py / urls.py / wsgi.py）
    ├── api/                    # 唯一应用（models / utils / views_auth / views_sync / migrations）
    ├── .venv/                  # 虚拟环境（Django + waitress）
    ├── logs/phix.log           # 应用日志（journald 另有一份）
    ├── _backups/db-*.sqlite3   # deploy.py 每次迁移前自动备份，保留最近 5 份
    └── db.sqlite3              # ★ 账号数据唯一副本 —— 绝不删、绝不覆盖
```

系统层面**只多了一个文件** `/etc/systemd/system/phix.service`（加一个 drop-in 目录），
外加为了建 venv 而安装的 apt 包 `python3-venv`、`python3-pip`。除此之外什么都没动。

---

## 2. 环境变量（都在 `/home/phix/.config/phix/env`）

| 变量 | 当前值 | 含义 / 改动后果 |
|---|---|---|
| `PHIX_SECRET_KEY` | 随机 64 字节 url-safe | Django 签名密钥。**改了 = 已发出的 Bearer 令牌全部失效**，客户端要重新登录 |
| `PHIX_SERVICE_KEY` | 来自本机 `D:\phix\server\.service_key` | 服务端到服务端调用 `/auth/verify` 的共享密钥（心履那边用）。**改了 = 心履 `verify` 一律 401**；两者必须一致 |
| `PHIX_ALLOWED_HOSTS` | `127.0.0.1,localhost,192.168.5.41` | Django `ALLOWED_HOSTS`，逗号分隔。**上域名必须把域名加进来**，否则 400 |
| `PHIX_DEBUG` | `0` | 生产必须为 0（为 1 会自动把 `*` 加进 ALLOWED_HOSTS，等于关掉 Host 校验） |
| `PHIX_REGISTER_LIMIT` | `10` | 每 IP 每小时注册上限。压测时临时放大（如 `1000`） |
| `PHIX_DB` | `/home/phix/phix-server/db.sqlite3` | 数据库路径 |
| `PHIX_MAX_PAYLOAD_BYTES` / `PHIX_MAX_OBJECTS` / `PHIX_MAX_TOTAL_BYTES` / `PHIX_MAX_BATCH` / `PHIX_KEEP_REVISIONS` | 未设置（用默认 8MiB / 2000 / 200MiB / 50 / 10） | 同步限额，需要时再往 env 里加 |
| `PHIX_JWT_ACCESS_TTL` | 未设置（= 900 秒） | 访问令牌寿命。**改短 = 更安全但要更频繁续期** |
| `PHIX_REFRESH_TTL` | 未设置（= 30 天） | refresh 令牌寿命（超过就要重新登录） |
| `PHIX_REFRESH_GRACE` | 未设置（= 120 秒） | refresh 轮换宽限期。并发续期在这个窗口内不被当成重放；**设 0 = 最严**（并发续期会被判重放并撤销会话） |
| `PHIX_JWT_LEEWAY` | 未设置（= 60 秒） | 验签允许的时钟偏差 |
| `PHIX_LEGACY_TOKENS` | 未设置（= 1） | 是否还接受老式 40 位 hex 长期令牌。**两端客户端都升级完后设 0** |
| `PHIX_V2_PLAINTEXT_OK` | 未设置（= 宽松，记 warning 后放行） | v2 账号收到 `password` 原文时是否放行。**设 `0` = 硬拒绝**，彻底杜绝"客户端漏发 `auth_hash` → 服务端把口令原文当凭证存下来 → 新旧密码全失效"这种静默写坏。等两端客户端都确认发 AuthHash 之后建议设 0（详见 `phix-协议规范.md` §3.2.1）。会往 `logs/phix.log` 里留 `v2 账号收到口令原文凭据` 的 warning，可以先观察一段时间再收紧 |

改完 env **必须重启服务**才生效：

```bash
sudo systemctl restart phix.service
```

---

## 3. 一页式部署步骤

### 3.1 从 Windows 一键部署（推荐）

前提：本机全局 Python 已装 **paramiko**（已装，`python -c "import paramiko"` 能通过）；
`D:\phix\server\.deploy_secret` 里有 `PHIX_DEPLOY_HOST` / `PHIX_DEPLOY_USER` / `PHIX_DEPLOY_PASSWORD`。

```powershell
cd D:\phix\server\deploy
python -X utf8 deploy.py --check      # ① 只体检，不改远端
python -X utf8 deploy.py --dry-run    # ② 演练，打印将要做的事
python -X utf8 deploy.py              # ③ 真的部署 / 升级（幂等，可反复跑）
```

`deploy.py` 干的 11 件事（每一步都幂等）：

1. ICMP ping + TCP 22 探测，不通就友好报错退出（不产生半截状态）
2. 远端缺 `python3-venv` / `python3-pip` 才装（判定方式是**真的建一个临时 venv 再删掉**，
   因为 `python3 -m venv --help` 在缺包时也返回 0，只看退出码会误判）
3. SFTP 覆盖式上传工程（**白名单 16 个文件**：`manage.py`、`requirements.txt`、`phixsvc/*`、`api/*`；
   **不做任何「先清空再上传」**，远端 `db.sqlite3` 一个字节都不动）
4. 建/复用 `.venv`；`requirements.txt` 的 md5 变了才 `pip install`（变更记录在 `.venv/.phix-requirements.md5`）
5. 生成/复用 `~/.config/phix/env`：**已存在就原样复用，绝不覆盖**（覆盖会踢掉登录令牌）
6. 迁移前把远端 db.sqlite3 热备到 `_backups/`（`sqlite3.backup()`，保留最近 5 份）
7. `manage.py migrate --noinput`
8. `manage.py check`
9. 安装 systemd 单元 + drop-in，`daemon-reload` / `enable`；
   **只有内容真的变了才 `restart`**（第二次跑会输出「跳过重启（幂等）」）
10. 端到端冒烟：用远端 `python3` 的 urllib（**目标机没有 curl**）打 `/api/v1/ping`、`/healthz`，
    并带 `X-Phix-Service-Key` 验证 `service_verify_enabled=true`
11. 打印 `systemctl status` 摘要、目录树、监听端口、数据库与密钥文件状态

参数：

| 参数 | 作用 |
|---|---|
| `--check` | 只读体检（12 项），不改远端 |
| `--dry-run` | 真连一次（只读探测），但不写任何东西 |
| `--force` | 忽略大小比对，强制重传全部文件（仍不删远端文件） |
| `--bind-host 127.0.0.1` | 把监听收回本机（配合 Cloudflare Tunnel 时推荐） |
| `--allowed-hosts a.com,b.com` | 覆盖 ALLOWED_HOSTS（**仅在首次生成 env 时生效**；已存在的 env 不会被覆盖） |
| `--force-env` | ⚠️ 危险：重建 env，会踢掉所有登录令牌、旧密文解不开。非必要不用 |

### 3.2 手工部署（没有 Windows 侧时）

```bash
# ① 系统依赖（只需一次）
sudo apt-get update && sudo apt-get install -y python3-venv python3-pip

# ② 上传代码（用 scp / rsync，别删远端 db.sqlite3）
scp -r phixsvc api manage.py requirements.txt phix@192.168.5.41:/home/phix/phix-server/

# ③ venv 与依赖
cd /home/phix/phix-server && python3 -m venv .venv && .venv/bin/python -m pip install -r requirements.txt

# ④ 密钥（首次；生成一次就留住，别每次重生成）
mkdir -p ~/.config/phix && umask 077
cat > ~/.config/phix/env <<EOF
PHIX_SECRET_KEY=$(python3 -c 'import secrets;print(secrets.token_urlsafe(64))')
PHIX_SERVICE_KEY=$(python3 -c 'import secrets;print(secrets.token_urlsafe(48))')
PHIX_ALLOWED_HOSTS=127.0.0.1,localhost,192.168.5.41
PHIX_DEBUG=0
PHIX_REGISTER_LIMIT=10
PHIX_DB=/home/phix/phix-server/db.sqlite3
EOF
chmod 600 ~/.config/phix/env

# ⑤ 迁移 + 自检
cd /home/phix/phix-server
set -a && . ~/.config/phix/env && set +a
.venv/bin/python manage.py migrate --noinput
.venv/bin/python manage.py check

# ⑥ 装服务
sudo install -m 644 deploy/phix.service /etc/systemd/system/phix.service
sudo systemctl daemon-reload && sudo systemctl enable --now phix.service
systemctl is-active phix.service     # 期望 active
```

> 手工上传不会带上 `deploy/phix.service`（远端本来没有 `deploy/` 目录）。
> 它是**部署工具**，只待在 `D:\phix\server\deploy\`，不上传到服务器 —— 需要时单独 `scp deploy/phix.service` 过去。

---

## 4. 端口与网络

| 端口 | 用途 | 现状 |
|---|---|---|
| 22 | SSH | 唯一的管理入口 |
| 8931 | **phix 服务** | 由 drop-in 打开为 `0.0.0.0`，局域网内 `http://192.168.5.41:8931` 可直连 |
| 8000 | 心履生产机 192.168.5.35 的端口 | **本机绝不使用** |

- 目标机**没有装防火墙**（ufw 未启用），8931 直接可达；将来上域名后建议把监听收回
  `127.0.0.1`（见 §8.4）。
- 社团官网以后要在这台机器上跑，**用别的端口 + 别的子域**，由 Cloudflare 分流；
  两者互不干扰（phix 自包含在 `/home/phix/phix-server`，占 8931）。

---

## 5. systemd 服务

### 5.1 单元文件

远端 `/etc/systemd/system/phix.service`（源文件：`D:\phix\server\deploy\phix.service`）

```ini
[Service]
User=phix
Group=phix
WorkingDirectory=/home/phix/phix-server
EnvironmentFile=/home/phix/.config/phix/env
ExecStart=/home/phix/phix-server/.venv/bin/python -m waitress \
          --host=127.0.0.1 --port=8931 --threads=8 phixsvc.wsgi:application
Restart=always
RestartSec=3
StandardOutput=journal
StandardError=journal
SyslogIdentifier=phix
```

- **`-m waitress` 的参数形式已实测可用**（`waitress.runner.HELP` 明确列出 `--host` / `--port` /
  `--threads`；本地和远端都跑通过），因此**不需要**改成 `run_local.py` 或另写 `serve.py`。
  用绝对路径的 venv python，不依赖 PATH。
- 日志走 journald；应用自己还会往 `logs/phix.log` 写一份轮转日志。

### 5.2 为什么单元文件里写 `127.0.0.1`，实际却监听 `0.0.0.0`

因为局域网客户端（Windows/手机）要能直接连 `192.168.5.41:8931`，而生产习惯上又不该让
应用直接暴露。做法是**不动单元文件**，用一个 drop-in 覆盖：

```ini
# /etc/systemd/system/phix.service.d/10-listen.conf（由 deploy.py 生成）
[Service]
ExecStart=
ExecStart=/home/phix/phix-server/.venv/bin/python -m waitress --host=0.0.0.0 --port=8931 --threads=8 phixsvc.wsgi:application
```

好处：单元文件保持"安全默认"，监听地址的变更独立可见、可审计、可一键回退。

### 5.3 收回本机监听（上域名/接隧道后推荐）

```bash
python -X utf8 deploy.py --bind-host 127.0.0.1     # Windows 侧；或手工删掉 drop-in：
sudo rm /etc/systemd/system/phix.service.d/10-listen.conf && sudo systemctl daemon-reload && sudo systemctl restart phix.service
```

---

## 6. 常用运维命令

在服务器上执行（`ssh phix@192.168.5.41`）：

```bash
# 状态 / 启停
systemctl status phix.service            # 摘要
systemctl is-active phix.service         # active / inactive
sudo systemctl restart phix.service      # 重启（改完 env 必须重启）
sudo systemctl stop phix.service
sudo systemctl start phix.service
systemctl is-enabled phix.service        # enabled = 开机自启

# 日志
journalctl -u phix.service -f            # 实时
journalctl -u phix.service -n 100 --no-pager      # 最近 100 行
journalctl -u phix.service --since today --no-pager
tail -f /home/phix/phix-server/logs/phix.log      # 应用自己的轮转日志

# 健康检查（目标机没有 curl，用 python 或 wget）
python3 -c "import urllib.request;print(urllib.request.urlopen('http://127.0.0.1:8931/api/v1/ping',timeout=5).read().decode())"
wget -qO- http://127.0.0.1:8931/api/v1/ping

# 监听端口 / 进程
ss -tlnp | grep 8931
systemctl show phix.service -p MainPID -p ExecStart -p NRestarts

# 手动跑管理命令（务必先加载 env）
cd /home/phix/phix-server
set -a && . /home/phix/.config/phix/env && set +a
.venv/bin/python manage.py check
.venv/bin/python manage.py migrate --noinput
.venv/bin/python manage.py shell -c "from django.contrib.auth.models import User; print(User.objects.count())"
```

### 6.1 备份 `db.sqlite3`（最重要的一件事）

```bash
# 在线安全备份（推荐；sqlite3 .backup 不会读到写一半的状态）
cd /home/phix/phix-server
python3 -c "
import sqlite3, time
s = sqlite3.connect('db.sqlite3'); d = sqlite3.connect('_backups/manual-%s.sqlite3' % time.strftime('%Y%m%d-%H%M%S'))
with d: s.backup(d)
d.close(); s.close(); print('done')
"

# 或者直接拷（服务在跑时也能得到一个可用副本，但不如上面的 .backup 严谨）
cp -a db.sqlite3 ~/db-$(date +%Y%m%d-%H%M%S).sqlite3
```

把备份拉回本机（Windows 侧）：

```powershell
scp phix@192.168.5.41:/home/phix/phix-server/_backups/db-20260912-113244.sqlite3 D:\phix\backups\
```

> 备份里含**密文对象 + 账号 + 令牌**。它不含用户口令（口令只以 Django 哈希形式存在），
> 但仍然是敏感文件，别丢进公开仓库/网盘。

### 6.2 从备份恢复

```bash
sudo systemctl stop phix.service
cd /home/phix/phix-server
cp -a db.sqlite3 db.sqlite3.before-restore-$(date +%Y%m%d-%H%M%S)   # 先留后路
cp -a _backups/db-20260912-113244.sqlite3 db.sqlite3
sudo systemctl start phix.service
python3 -c "import urllib.request;print(urllib.request.urlopen('http://127.0.0.1:8931/api/v1/ping',timeout=5).read().decode())"
```

### 6.3 升级代码

```powershell
# Windows 侧，改完本地代码后
cd D:\phix\server\deploy
python -X utf8 deploy.py --check     # 先看现状
python -X utf8 deploy.py             # 覆盖式上传 + 迁移 + 自检 + 冒烟
```

改动只有 `api/views_*.py` 之类时，deploy.py 会自动只传变化的文件、跑完冒烟、必要时才重启。

---

## 7. ⛔ 绝对不要做的事

1. **绝不删除或覆盖远端 `db.sqlite3`** —— 它是**账号数据的唯一副本**。
   没有别的副本，删了就没了。`deploy.py` 的上传白名单里根本没有它；
   如果你要手工上传代码，用 `scp` 指定具体文件，**别用 `rsync --delete`、别用"清空目录再上传"**。
2. **`jwt_key.txt` 也是不可再生资产**：它决定令牌签名的真伪。
   换了它 = **所有客户端手里的令牌立刻全部失效**（要重新登录）。
   注意它和 `e2e_key.txt` 一样是**每台服务器各自生成**的：
   如果将来同一套账号要在多台实例上跑（负载均衡），**要么把这一份拷贝过去，
   要么让所有实例共用一个反向代理** —— 否则 A 发的令牌在 B 上验不过。
   现在只有 `.41` 一台，没这个问题。
3. **绝不覆盖远端 `~/.config/phix/env`** —— `PHIX_SECRET_KEY` 一换，所有客户端令牌立即失效；
   `PHIX_SERVICE_KEY` 一换，心履的 `/auth/verify` 全 401。
3. **不动系统里 phix 之外的东西** —— 社团官网以后要在这台机器上跑，别改全局 Python、
   别装全局 pip 包、别改 apt 源、别占用社团官网要用的端口。
4. **不碰 `192.168.5.35`**（心履生产机）。它跑着 `xinlv.service` + `cloudflared`，
   跟 phix 完全无关；本任务一个字节都不动。
5. 别用 8000 端口（心履的端口）。

---

## 8. 接入 Cloudflare 域名的预案（以后买了域名再做）

> 现在的状态：**只在内网跑 HTTP**，没有域名、没有 TLS、没有反代。
> 目标机上也**没有 nginx**（全新机器，`/var/www`、`/opt`、`/srv` 全空）。

### 8.1 选哪个方案

| 方案 | 优点 | 缺点 | 建议 |
|---|---|---|---|
| **Cloudflare Tunnel（cloudflared）** | 不用开端口、不用买公网 IP、自动 HTTPS 证书、和心履生产机 192.168.5.35 的做法一致 | 需要一个 Cloudflare 账号 + 域名托管在 Cloudflare；多一个常驻进程 | ✅ **推荐**，照抄心履的做法 |
| nginx + 端口映射 | 不依赖第三方 | 要开公网端口、要自己弄证书、家宽大多没有公网 IP | ❌ 不推荐 |
| 保持内网 HTTP | 零成本 | 只在内网可用；**登录口令明文过网线** | 仅限现在这个阶段 |

### 8.2 Cloudflare Tunnel 配置要点（与心履同款做法）

1. Cloudflare Dashboard → **Zero Trust → Networks → Tunnels → Create a tunnel**（选 `cloudflared`），
   得到一段 token。
2. 在 `192.168.5.41` 上装 cloudflared（**独立 systemd 服务，与 `phix.service` 互不影响**）：

   ```bash
   # 官方 deb 源（示例，装之前先确认 Cloudflare 当前文档的仓库地址）
   sudo mkdir -p --mode=0755 /usr/share/keyrings
   curl -fsSL https://pkg.cloudflare.com/cloudflare-main.gpg | sudo tee /usr/share/keyrings/cloudflare-main.gpg >/dev/null
   echo "deb [signed-by=/usr/share/keyrings/cloudflare-main.gpg] https://pkg.cloudflare.com/cloudflared any main" \
     | sudo tee /etc/apt/sources.list.d/cloudflared.list
   sudo apt-get update && sudo apt-get install -y cloudflared
   sudo cloudflared service install <你的token>       # 会生成 cloudflared.service 并自启
   systemctl status cloudflared
   ```

3. Tunnel 里加 **Public Hostname**：

   | 字段 | 值 |
   |---|---|
   | Subdomain | `phix`（或你想要的子域） |
   | Domain | 你买的域名 |
   | Type | `HTTP` |
   | URL | `127.0.0.1:8931` ← 注意：指向 **127.0.0.1**，不是 `0.0.0.0` |

   > 社团官网用**另一个子域 + 另一个端口**，同一个 Tunnel 里加第二条 Public Hostname 即可分流。
   > 这样 phix 就能顺便收回本机监听（§5.3），不需要对局域网裸露 8931。

4. **加域名到 `ALLOWED_HOSTS`**（不加大概率返回 400）：

   ```bash
   nano ~/.config/phix/env     # 把域名追加进去，逗号分隔，不要有空格
   # PHIX_ALLOWED_HOSTS=127.0.0.1,localhost,192.168.5.41,phix.你的域名.com
   sudo systemctl restart phix.service
   ```

   Cloudflare Tunnel 转发时 `Host` 头就是公开域名，Django 会拿它做校验；
   `settings.py` 里已经开了 `USE_X_FORWARDED_HOST = True`，所以会读 `X-Forwarded-Host`。

5. 域名侧不需要改 DNS —— 配好 Public Hostname 后 Cloudflare 会自动写 CNAME。
6. `settings.py` 里已经配好 `SECURE_PROXY_SSL_HEADER = ("HTTP_X_FORWARDED_PROTO", "https")`，
   不用改代码。（注意：**别开 `SECURE_SSL_REDIRECT`**，Cloudflare 到源站是 HTTP，
   开了会 301 死循环 —— 心履那边踩过这个坑。）

### 8.3 为什么上了域名**必须**强制 HTTPS

不是因为密文（密文本来就不怕看），而是因为**登录口令**：

- phix 的 `password` 模式下，登录请求里的口令是客户端**明文**发过来的（协议规范 §9.1 明确记录了
  这个取舍）。HTTP 明文传输 = 同网段任何人（或路径上任何一跳）都能抓到口令。
- Bearer 令牌同样裸奔 —— 抓到就能冒充该设备同步全部密文。
- 所以：
  - **上了公网域名 → 必须在 Cloudflare 侧开 Always Use HTTPS，并在 Tunnel 里只允许 HTTPS 入口**；
    同时把监听收回 `127.0.0.1`，让"只能经 Cloudflare 进来"成为物理事实。
  - **局域网阶段**要知道风险：`http://192.168.5.41:8931` 是明文，
    同 WiFi 下的抓包能看到口令。想立刻消除这个风险，就用 `syncphrase` 模式
    （DEK 由独立同步口令包裹，服务端不见用户登录口令 —— 见协议 §2）。
  - 强制 HTTPS 后，口令的暴露面才收敛到"客户端 ↔ Cloudflare 边缘"这一段 TLS 上。

### 8.4 上域名时建议一起做的三件事

```bash
# 1) 收回本机监听：只允许 Cloudflare Tunnel 从本机转发进来看
python -X utf8 deploy.py --bind-host 127.0.0.1     # Windows 侧执行
# 2) ALLOWED_HOSTS 加域名（见 8.2 第 4 步）
# 3) 备份密钥与数据库（有了公网入口，数据更值钱）
cp -a ~/.config/phix/env ~/phix-env.backup-$(date +%Y%m%d)
```

---

## 9. 排障

| 现象 | 原因 / 处置 |
|---|---|
| `systemctl is-active` = `inactive`/`failed` | `journalctl -u phix.service -n 50 --no-pager` 看 traceback；最常见是 env 里密钥不对或 `requirements` 没装完 |
| 浏览器/客户端 400 Bad Request | `ALLOWED_HOSTS` 里没有这个 Host（上域名后最常见）。加进 env 再重启 |
| 8931 连不上 | ① `ss -tlnp \| grep 8931` 看有没有 listen；② drop-in 是否还在（§5.3）；③ 客户端和服务器是不是同一网段 |
| `service_verify_enabled: false` | env 里 `PHIX_SERVICE_KEY` 为空或服务没重启 |
| `Connection refused` 刚重启就出现 | waitress 在 systemd 报 active 之后还要一小会儿才 bind（`deploy.py` 已内置重试，手工排查时等 1~2 秒） |
| 客户端突然要重新登录 | `PHIX_SECRET_KEY` 被改了（令牌签名对不上）。**不是 bug，是密钥变了** |
| 心履 `verify` 401 | 两边 `PHIX_SERVICE_KEY` 不一致 |
| 客户端频繁收到 `token_expired` | 正常（访问令牌 15 分钟）；**客户端应当自动续期**。若续期一路 401，看是不是 refresh 被重复使用过（服务端会撤销整个会话，日志里有「refresh 重放！」） |
| 日志里出现「refresh 重放！」 | 同一个 refresh 在宽限期外被用了两次 = 疑似令牌被偷，服务端按设计**撤销了整个会话**。若确认是自家客户端并发导致，把 `PHIX_REFRESH_GRACE` 调大 |
| 所有客户端突然全部掉线 | 看 `jwt_key.txt` 有没有被换过（换了 = 已签发的令牌全部验签失败）。这个文件与 `~/.config/phix/env` 一样，**属于不可再生资产，要备份** |
| 磁盘涨 | `logs/phix.log`（已轮转）、`_backups/`（保留 5 份）、`journalctl --vacuum-size=200M` |

### 9.1 ⚠️ PowerShell 5.1 读中文响应会乱码（实测坑，务必知道）

服务端返回的响应头是 `Content-Type: application/json`（**不带 charset**）。
PowerShell 5.1 的 `Invoke-RestMethod` / `Invoke-WebRequest` 在这种情况下**按 Latin-1 解码**响应体，
于是中文变成 `æµè¯è´¦å·` 这种乱码 —— **数据在服务端是好的，纯粹是 PS 侧的显示/解析问题**。

实测（`D:\phix\_recon\ps_zh_check.ps1`）：

```
① Invoke-RestMethod 登录 → ok=True，但 username 显示 æµè¯è´¦å·44367a
③ 自己读字节流 + UTF-8 解码 → username = 测试账号44367a        ← 正确
④ 把 ① 的乱码按 Latin-1 还原成字节再 UTF-8 解码 → 测试账号44367a  ← 与 ③ 一致，证明服务端没错
```

正确姿势：

```powershell
function Get-JsonUtf8($uri, $token) {
    $req = [System.Net.WebRequest]::Create($uri)
    if ($token) { $req.Headers.Add('Authorization', "Bearer $token") }
    $resp = $req.GetResponse()
    $sr = New-Object System.IO.StreamReader($resp.GetResponseStream(), [System.Text.Encoding]::UTF8)
    $text = $sr.ReadToEnd(); $sr.Close(); $resp.Close()
    return ($text | ConvertFrom-Json)
}
$me = Get-JsonUtf8 'http://192.168.5.41:8931/api/v1/auth/me' $token
$me.username      # ← 中文正确
```

发中文 body 也一样要显式：**先落 UTF-8 文件，再读成字符串并带上 charset**，别用 `Get-Content`（PS 5.1 默认按 GBK 读）：

```powershell
$bytes = [System.IO.File]::ReadAllBytes('D:\body.json')          # 文件必须是 UTF-8
$text  = [System.Text.Encoding]::UTF8.GetString($bytes)          # 千万别用 Get-Content
Invoke-RestMethod -Uri $uri -Method Post -Body $text -ContentType 'application/json; charset=utf-8'
```

> 真正用 phix 的客户端是 Python / Electron，本来就走 UTF-8，不受这个影响；
> 这条只影响**在 Windows 上用 PowerShell 调试**的时候。

---

## 10. 验证记录（2026-09-12 实机）

| 项 | 结果 |
|---|---|
| 首次部署 | `deploy.py` 退出码 0；apt 装了 `python3-venv` `python3-pip`；新建空库 163840 字节 |
| `systemctl is-active phix.service` | `active`（enabled，开机自启） |
| 监听 | `0.0.0.0:8931`（主进程 `.venv/bin/python -m waitress ... phixsvc.wsgi:application`） |
| Windows 侧 `Invoke-RestMethod http://192.168.5.41:8931/api/v1/ping` | `ok=True` `service=phix` `version=1` `service_verify_enabled=True` |
| 冒烟（远端） | `/api/v1/ping` → `{"ok": true, ...}`，`/healthz` → `{"ok": true, ...}` |
| 幂等第 2 跑 | 16/16 文件「未变跳过」、依赖未变、env 未覆盖、`No migrations to apply`、**跳过重启**、退出码 0 |
| 幂等前后 db 校验 | md5 **完全一致**（`03448e76…`）、163840 字节、用户/令牌/密钥材料/对象计数不变 |
| 幂等前后业务数据 | 临时测试账号重新登录成功、旧 token 仍可用、2 个密文对象 revision 与 sha256 **一字不差** |
| 中文往返 | 中文用户名 / 中文设备名 / 中文密文对象 全部原样存取（见 §9.1） |
| 测试数据清理 | 本轮验证造的 6 个临时账号已从远端删除（连带的令牌/密钥材料/密文对象随之删除）；**清理后库为全空**：`auth_user=0`、`phix_device_token=0`、`phix_user_key_material=0`、`phix_sync_object=0`。真实账号数据从未存在过，也没有被本任务碰过 |
| 最终验收 | `deploy.py` 退出码 0 + `deploy.py --check` 12/12 项通过（`_backups/` 里保留最近 5 份自动备份） |

### 10.1 目标机被本任务改动的全部内容（一览）

```
新增：/etc/systemd/system/phix.service                     systemd 单元
新增：/etc/systemd/system/phix.service.d/10-listen.conf    监听地址 drop-in
新增：/home/phix/phix-server/                              工程 + venv + db.sqlite3 + logs + _backups
新增：/home/phix/.config/phix/env                          密钥（600）
安装：apt 包 python3-venv、python3-pip（除此之外没装任何东西）
未动：系统其它任何位置、其它服务、其它用户、192.168.5.35
```

---

## 11. 相关文件

| 文件 | 说明 |
|---|---|
| `D:\phix\server\deploy\deploy.py` | 幂等部署脚本（Windows 侧跑，paramiko） |
| `D:\phix\server\deploy\phix.service` | systemd 单元源文件 |
| `D:\phix\server\deploy\DEPLOY.md` | 本文档 |
| `D:\phix\server\.deploy_secret` | 部署凭据（本机专用，**不入库、不外发**） |
| `D:\phix\server\README.md` | 服务端概览（数据模型、安全要点） |
| `D:\phix\phix-协议规范.md` | 客户端 ↔ 服务端协议（§8 部署形态） |
