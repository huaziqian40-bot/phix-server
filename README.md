# phix 服务端

统一账号 + 端到端加密云同步服务。**协议规范见 [docs/协议规范.md](docs/协议规范.md)** ——
那份文档同时约束服务端与两端客户端（`Pinghe-Launcher-Lite` 的 Python 实现、
`PH-Launcher` 的 JS 实现）；任何一端要改协议都得先改它，且**两端参数必须逐字节一致**。

**服务端只做三件事**：管账号、发 Bearer 令牌、存**不透明密文对象**。
它没有任何密码学依赖（除 Django 外只有 waitress），**看不懂用户上传的任何内容**。

---

## 快速开始（本地）

Python 3.11+。依赖只有 Django 与 waitress（`requirements.txt`）：

```bash
python -m venv .venv
. .venv/bin/activate          # Windows: .venv\Scripts\activate
pip install -r requirements.txt
python manage.py migrate
python run_local.py           # → http://127.0.0.1:8931
```

健康检查：

```bash
curl http://127.0.0.1:8931/api/v1/ping
# {"ok": true, "version": 1, "service": "phix", "kdf_algos": [...], "key_modes": [...], "enc": 1}
```

自测（需要服务在跑；`.service_key` 首次启动会自动生成）：

```bash
export PHIX_SERVICE_KEY=$(cat .service_key)     # Windows: $env:PHIX_SERVICE_KEY = (Get-Content .service_key -Raw).Trim()
python -X utf8 devtools/selftest.py             # 服务端自测
python -X utf8 devtools/test_sync_e2e.py        # 两端同步自测（数据用副本，不碰真库）
```

> 这些脚本只依赖本仓库内容 + 一个空的 SQLite 库，**不需要任何生产环境**。
> `devtools/` 不参与部署，可以放心跑。

---

## 目录

```
server/
├── manage.py               Django 入口
├── run_local.py            本地启动（自动读 .service_key）
├── requirements.txt        Django + waitress（requests/cryptography 仅自测用）
├── phixsvc/                工程配置
│   ├── settings.py         环境变量、限额、密钥
│   ├── urls.py             /api/v1/ 与 /healthz
│   └── wsgi.py
├── api/
│   ├── models.py           DeviceToken / UserKeyMaterial / SyncObject / SyncRevision
│   ├── utils.py            JSON 收发、统一错误、Bearer 认证、限流、对象名校验
│   ├── views_auth.py       注册 / 登录 / 令牌 / 密钥材料 / 恢复 / 服务端 verify
│   ├── views_sync.py       清单 / 取 / 推 / 批 / 墓碑 / 历史版本
│   └── urls.py
├── devtools/               自测脚本（**不部署**）
├── deploy/                 部署脚本与文档（见 deploy/DEPLOY.md）
├── db.sqlite3              SQLite（**账号数据的唯一副本，绝不删**）
└── secret_key.txt          首次启动自动生成（Git 忽略）
```

---

## 环境变量

| 变量 | 默认 | 说明 |
|---|---|---|
| `PHIX_DEBUG` | `0` | 生产必须为 0 |
| `PHIX_ALLOWED_HOSTS` | `127.0.0.1,localhost,192.168.5.41` | 逗号分隔；接域名后要把域名加进来 |
| `PHIX_SECRET_KEY` | 自动生成到 `secret_key.txt` | 部署时用环境变量给 |
| `PHIX_SERVICE_KEY` | 空 | **心履等服务端到服务端调用 `/auth/verify` 的共享密钥**；不设则该接口一律 403 |
| `PHIX_DB` | `<工程根>/db.sqlite3` | 数据库路径 |
| `PHIX_MAX_PAYLOAD_BYTES` | 8 MiB | 单对象密文上限 |
| `PHIX_MAX_OBJECTS` | 2000 | 每账号对象数上限 |
| `PHIX_MAX_TOTAL_BYTES` | 200 MiB | 每账号总容量 |
| `PHIX_MAX_BATCH` | 50 | 单次批量上限 |
| `PHIX_KEEP_REVISIONS` | 10 | 每对象保留的历史版本数 |
| `PHIX_REGISTER_LIMIT` | 10 | 每 IP 每小时注册上限（本地压测可放大） |

---

## 数据模型（服务端看到的只有这些）

| 表 | 里面是什么 |
|---|---|
| `phix_device_token` | 40 位 hex 令牌、设备名、最后使用时间、吊销时间 |
| `phix_user_key_material` | **全是密文**：盐、`key_wrap`（包裹后的 DEK）、`recovery_wrap`、`key_check`、`key_check_plain`、模式、版本 |
| `phix_sync_object` | 对象名、revision、密文信封、密文 sha256、大小、设备、墓碑 |
| `phix_sync_revision` | 最近 10 个历史版本的密文 |

**服务端永远拿不到**：用户口令、KEK、DEK、以及任何明文数据。

> `key_check_plain` 是**唯一的例外性质**：它是一串随机明文，注册时收下、此后任何接口都不下发；
> 它用来做「客户端是否真的持有 DEK」的持有性证明（见协议 §2.4）。它本身不是密钥，
> 泄露它也无法解出任何密文。

---

## 安全要点（改动前先读）

1. **口令 → KEK → DEK → 对象密钥** 四层。换密码只重新包裹 DEK，云端密文一个字节都不动。
2. **两族 AAD**：身份族绑 username、对象族绑 `user_id + 对象名`。服务端张冠李戴就解不开。
3. **乐观锁**：客户端必须带 `base_revision`，对不上就 409，**绝不静默覆盖**。
4. **限流在进程内存里**（与心履 `core/ratelimit.py` 同思路）。将来多进程部署必须换成共享存储。
5. **没有 cookie、没有 session**，因此没有启用 CSRF 中间件——没有 cookie 就没有 CSRF 面。
6. 服务端**绝不记录请求体**（里面有登录口令）。

---

## 仓库里没有什么（有意排除）

这个仓库**只有源码**。下列内容**不在**这里，与心履（`xinlv-web` 等）的做法一致：

| 排除项 | 为什么 |
|---|---|
| `db.sqlite3` | **真实用户数据**：账号、Bearer 令牌、refresh 令牌哈希，以及端到端加密后的密文对象。服务端解不开密文，但账号与令牌是实打实的用户数据 |
| `secret_key.txt` | 部署时生成的令牌签名密钥（改了 → 已发出的令牌全部失效） |
| `.service_key` | 与官网 / 心履之间的机器间密钥 |
| `.deploy_secret` | 部署凭据（主机 / 用户 / 口令） |
| `e2e_key.txt` · `jwt_key.txt` | 本机联调用密钥 |
| `logs/` · `.venv/` | 运行日志与虚拟环境 |

所以生产机上改完代码后，`deploy/deploy.py` 只推源码；`~/.config/phix/env` 与
`db.sqlite3` **远端原样保留，绝不覆盖**（那份 env 丢了就找不回密文）。

## 相关仓库

- [`phix-website`](https://github.com/huaziqian40-bot/phix-website) —— 官网与网页端（phix.ing）
- [`Pinghe-Launcher-Lite`](https://github.com/huaziqian40-bot/Pinghe-Launcher-Lite) —— 轻量版桌面客户端
- [`PH-Launcher`](https://github.com/XKRyan/PH-Launcher) —— 完整版桌面客户端（上游）
- 心履：`xinlv-web` / `xinlv-windows` / `xinlv-macos` / `xinlv-android`
