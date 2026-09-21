"""phix 数据模型。

三张核心表：
- DeviceToken      设备令牌（一个账号多设备，可单独吊销）
- UserKeyMaterial  密钥材料（**全是密文**：包裹后的 DEK、盐、自检块、模式）
- SyncObject       同步对象（不透明密文 + 单调递增 revision）
- SyncRevision     历史版本（保留最近 N 个，便于回滚）

服务端**看不到**：用户口令、KEK、DEK、任何明文数据。
"""
import hashlib
import hmac
import secrets
from datetime import datetime, timedelta, timezone as dt_timezone

from django.conf import settings
from django.contrib.auth.models import User
from django.db import models
from django.utils import timezone


def refresh_digest(plaintext: str) -> str:
    """refresh 令牌的**查找用**摘要（hex）。

    这是"指纹"而非"慢哈希"：令牌本身是 320 位随机值，没有可猜的空间。
    """
    return hashlib.sha256((plaintext or "").encode("utf-8")).hexdigest()


class DeviceToken(models.Model):
    """按设备的长期令牌（40 位 hex，与心履 ApiToken 同风格）。

    **P3 之后退居二线**：新登录不再发它，改成 `TokenSession` + JWT。
    这张表留着是因为"老客户端手里的令牌要能继续用"（`PHIX_LEGACY_TOKENS`），
    等两端客户端都换完、老令牌自然过期后可以整体清掉。
    """

    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name="phix_tokens")
    key = models.CharField(max_length=64, unique=True, db_index=True)
    device = models.CharField(max_length=100, blank=True, default="")
    created_at = models.DateTimeField(auto_now_add=True)
    last_used_at = models.DateTimeField(null=True, blank=True)
    revoked_at = models.DateTimeField(null=True, blank=True)

    class Meta:
        db_table = "phix_device_token"
        ordering = ["-created_at"]

    def __str__(self):
        return f"token:{self.user.username}:{self.device or self.key[:6]}"

    @classmethod
    def mint(cls, user, device=""):
        return cls.objects.create(
            user=user, key=secrets.token_hex(20), device=(device or "")[:100]
        )

    @property
    def alive(self):
        return self.revoked_at is None


class TokenSession(models.Model):
    """一次登录会话（对应 `加密链路思路.md` §7：JWT + refresh 轮换）。

    一个会话 = 一台设备的一次登录。**访问令牌（JWT，15 分钟）不落库**，
    只落这个会话与它的 refresh 令牌哈希：

    - `refresh_hash`  **只存哈希**（Django PBKDF2）。明文 refresh 只在签发那一刻
      返回给客户端一次，服务端此后无法复原它 —— 与口令同一待遇。
    - `prev_*` / `rotated_at` **轮换宽限期**：客户端并发请求时可能有两个请求同时
      拿着同一个 refresh 来续期。这**不是攻击**（同一个会话、同一台设备、
      几秒钟内），所以给它一个"退回刚发出的那一个"的宽限窗口；
      超出窗口再用旧 refresh = **真的重放** → 撤销整个会话。
      （这条是设计文档 §7 的"重复使用 → 撤销整个会话"，只是加了并发宽限。）
    - `jkt`  DPoP 绑定的客户端公钥指纹。**非空时，所有请求都必须带匹配的 DPoP 证明**。
    - `revoked_*`  注销后立即失效（访问令牌哪怕还没过期也照样被拒）。
    """

    REVOKE_REASONS = [
        ("logout", "用户登出"),
        ("reuse", "refresh 令牌被重复使用（疑似被偷）"),
        ("manual", "用户在设备列表里手动注销"),
        ("all", "退出全部设备"),
        ("rotate_fail", "轮换时校验失败"),
    ]

    user = models.ForeignKey(User, on_delete=models.CASCADE,
                             related_name="phix_sessions")
    device = models.CharField(max_length=100, blank=True, default="")
    refresh_hash = models.CharField(max_length=256, db_index=True)
    refresh_algo = models.CharField(max_length=32, default="sha256")
    prev_refresh_hash = models.CharField(max_length=256, blank=True, default="",
                                         db_index=True)
    prev_refresh_until = models.DateTimeField(null=True, blank=True)
    rotated_at = models.DateTimeField(null=True, blank=True)
    jkt = models.CharField(max_length=64, blank=True, default="", db_index=True)
    created_at = models.DateTimeField(auto_now_add=True)
    last_seen_at = models.DateTimeField(null=True, blank=True)
    last_ip = models.CharField(max_length=64, blank=True, default="")
    revoked_at = models.DateTimeField(null=True, blank=True)
    revoked_reason = models.CharField(max_length=16, blank=True, default="")

    class Meta:
        db_table = "phix_token_session"
        ordering = ["-created_at"]
        indexes = [models.Index(fields=["user", "revoked_at"])]

    def __str__(self):
        return f"session:{self.user.username}:{self.device or self.id}"

    # ---- 状态 ----

    @property
    def alive(self):
        if self.revoked_at is not None:
            return False
        return timezone.now() < self.expires_at

    @property
    def expires_at(self):
        ttl = int(getattr(settings, "PHIX_REFRESH_TTL", 30 * 24 * 3600))
        return self.created_at + timedelta(seconds=ttl)

    # ---- refresh 令牌 ----

    # **为什么这里用 SHA-256 而不是 PBKDF2**：refresh 令牌是 320 位随机串，
    # 不是人选的密码 —— 暴力破解在算力上不可能，慢哈希没有意义，
    # 反而会把"找出持令牌的是哪个会话"变成一次 N 次哈希的线性扫描。
    # 这里要的是**快速、可索引、单次比对**（并用常量时间比较）。
    # 用户口令/登录凭证那两处仍然老老实实用 PBKDF2（见 auth_user.password）。

    def set_refresh(self, plaintext: str):
        self.refresh_hash = refresh_digest(plaintext)
        self.refresh_algo = "sha256"

    def check_refresh(self, plaintext: str) -> bool:
        if not plaintext or not self.refresh_hash:
            return False
        return hmac.compare_digest(refresh_digest(plaintext), self.refresh_hash)

    def check_prev_refresh(self, plaintext: str) -> bool:
        """宽限窗口内的"刚被换掉的那个"。"""
        if not self.prev_refresh_hash or self.prev_refresh_until is None:
            return False
        if timezone.now() > self.prev_refresh_until:
            return False
        return hmac.compare_digest(refresh_digest(plaintext), self.prev_refresh_hash)

    @classmethod
    def start(cls, user, device="", jkt=""):
        """开一个新会话并签发 refresh 令牌。返回 (session, refresh 明文)。"""
        token = secrets.token_urlsafe(40)
        sess = cls(user=user, device=(device or "")[:100], jkt=jkt or "")
        sess.set_refresh(token)
        sess.save()
        return sess, token

    def rotate(self, grace_seconds: int | None = None):
        """轮换：把当前 refresh 挪到"宽限期"位，再发一个新的。

        返回 (新 refresh 明文, 宽限到期时刻)。

        **明文只出现这一次**，库里只有哈希 —— 所以宽限期内**不会重发**它，
        只会发一个新的 access（见 `views_auth._rotate_access`）。宁可让客户端
        多续一次期，也不给"旧的能换出当前那个"留口子。
        """
        grace = grace_seconds
        if grace is None:
            grace = int(getattr(settings, "PHIX_REFRESH_GRACE", 120))
        token = secrets.token_urlsafe(40)
        until = timezone.now() + timedelta(seconds=grace)
        self.prev_refresh_hash = self.refresh_hash
        self.prev_refresh_until = until
        self.rotated_at = timezone.now()
        self.set_refresh(token)
        self.save(update_fields=["prev_refresh_hash", "prev_refresh_until",
                                 "rotated_at", "refresh_hash", "refresh_algo"])
        return token, until

    def revoke(self, reason="manual"):
        self.revoked_at = timezone.now()
        self.revoked_reason = (reason or "manual")[:16]
        self.save(update_fields=["revoked_at", "revoked_reason"])

    def as_dict(self, current_sid=None, legacy=None):
        return {
            "id": self.id,
            "device": self.device,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "last_seen_at": self.last_seen_at.isoformat() if self.last_seen_at else None,
            "last_ip": self.last_ip,
            "revoked": self.revoked_at is not None,
            "revoked_reason": self.revoked_reason,
            "expires_at": self.expires_at.isoformat(),
            "dpop_bound": bool(self.jkt),
            "current": current_sid is not None and self.id == current_sid,
            # 老式长期令牌挂在哪个会话上（None = 独立的老记录）
            "legacy_token_id": legacy,
        }


class JtiBlacklist(models.Model):
    """单个访问令牌的撤销名单（注销一台设备之外的精细撤销）。

    正常情况下不需要它：**注销会话**就够（会话状态在库里，请求时一对就知道）。
    它服务于"只作废手里这一个 JWT、别动会话"的场景（比如怀疑某条日志泄露了令牌）。
    `expires_at` 到了就说明这个 JWT 本来也过期了，可以清理。
    """

    jti = models.CharField(max_length=64, unique=True, db_index=True)
    sid = models.PositiveIntegerField(default=0, db_index=True)
    expires_at = models.DateTimeField(db_index=True)
    created_at = models.DateTimeField(auto_now_add=True)
    reason = models.CharField(max_length=64, blank=True, default="")

    class Meta:
        db_table = "phix_jti_blacklist"
        ordering = ["-created_at"]

    @classmethod
    def add(cls, jti, sid, exp, reason=""):
        when = datetime.fromtimestamp(int(exp), tz=dt_timezone.utc)
        return cls.objects.get_or_create(
            jti=jti,
            defaults={"sid": int(sid or 0), "expires_at": when,
                      "reason": (reason or "")[:64]},
        )

    @classmethod
    def blocked(cls, jti) -> bool:
        if not jti:
            return False
        return cls.objects.filter(jti=jti, expires_at__gt=timezone.now()).exists()

    @classmethod
    def gc(cls):
        return cls.objects.filter(expires_at__lt=timezone.now()).delete()


class UserKeyMaterial(models.Model):
    """密钥材料。所有字段都是客户端生成的不透明字符串，服务端只做搬运。

    - kdf_salt        scrypt 用的盐（hex）
    - key_wrap        用「口令派生的 KEK」AES-GCM 包裹后的 DEK
    - recovery_salt   恢复码用的盐（hex）
    - recovery_wrap   用「恢复码派生的 KEK」包裹的同一把 DEK
    - key_check       用 `key = HKDF(DEK, "__keycheck__")`、身份族 AAD 加密的
                      **一串服务端已知的随机明文**，用来校验口令对不对
    - key_check_plain 上面那个随机明文的 hex。**只在注册接口收下，此后任何接口都不返回**。
                      客户端要证明"我手里有 DEK"，就得把服务端存的 `key_check` 解出这个值 ——
                      只有真正持有 DEK 的一方能做到（报一串公开常量不算证明）。
    - key_mode        password（同步口令=登录密码）| syncphrase（独立同步口令）
    - key_version     每次重新包裹 +1（客户端据此判断本地缓存是否过期）
    """

    user = models.OneToOneField(
        User, on_delete=models.CASCADE, related_name="phix_keys", primary_key=True
    )
    kdf_algo = models.CharField(max_length=32, default="scrypt-n15-r8-p1")
    kdf_salt = models.CharField(max_length=64)
    # **登录凭证专用的盐**：与 kdf_salt 分开。
    # kdf_salt 会随着"换包裹口令"变，而 AuthHash 必须永远稳定 ——
    # 共用一个盐会导致切同步口令后登录直接失败（实测踩过）。
    auth_salt = models.CharField(max_length=64, default="")
    key_wrap = models.TextField()
    recovery_salt = models.CharField(max_length=64)
    recovery_wrap = models.TextField()
    key_check = models.TextField()
    key_check_plain = models.CharField(max_length=128, default="")
    key_mode = models.CharField(max_length=16, default="password")
    key_version = models.PositiveIntegerField(default=1)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        db_table = "phix_user_key_material"

    def as_public_dict(self):
        """返回给客户端的密钥材料（全是密文，可以安全下发）。"""
        return {
            "kdf_algo": self.kdf_algo,
            "kdf_salt": self.kdf_salt,
            "auth_salt": self.auth_salt,
            "key_wrap": self.key_wrap,
            "recovery_salt": self.recovery_salt,
            "recovery_wrap": self.recovery_wrap,
            "key_check": self.key_check,
            "key_mode": self.key_mode,
            "key_version": self.key_version,
        }


class SyncObject(models.Model):
    """一个具名同步对象。payload 是客户端加密后的信封字符串，服务端不解析。"""

    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name="phix_objects")
    name = models.CharField(max_length=128, db_index=True)
    revision = models.PositiveIntegerField(default=0)
    device = models.CharField(max_length=100, blank=True, default="")
    payload = models.TextField(blank=True, default="")
    size = models.PositiveIntegerField(default=0)
    sha256 = models.CharField(max_length=64, blank=True, default="")
    deleted = models.BooleanField(default=False)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        db_table = "phix_sync_object"
        unique_together = (("user", "name"),)
        indexes = [models.Index(fields=["user", "updated_at"])]

    def __str__(self):
        return f"{self.user.username}/{self.name}@{self.revision}"

    def as_manifest_dict(self):
        return {
            "name": self.name,
            "revision": self.revision,
            "updated_at": self.updated_at.isoformat() if self.updated_at else None,
            "size": self.size,
            "sha256": self.sha256,
            "device": self.device,
            "deleted": self.deleted,
        }


class SyncRevision(models.Model):
    """历史版本（只留密文）。保留最近 PHIX_KEEP_REVISIONS 个。"""

    object = models.ForeignKey(
        SyncObject, on_delete=models.CASCADE, related_name="history"
    )
    revision = models.PositiveIntegerField()
    payload = models.TextField(blank=True, default="")
    size = models.PositiveIntegerField(default=0)
    sha256 = models.CharField(max_length=64, blank=True, default="")
    device = models.CharField(max_length=100, blank=True, default="")
    deleted = models.BooleanField(default=False)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        db_table = "phix_sync_revision"
        unique_together = (("object", "revision"),)
        ordering = ["-revision"]

    @property
    def keep_limit(self):
        return getattr(settings, "PHIX_KEEP_REVISIONS", 10)


def purge_old_revisions(obj, keep=None):
    """只保留最近 keep 个历史版本。"""
    keep = keep if keep is not None else getattr(settings, "PHIX_KEEP_REVISIONS", 10)
    ids = list(
        SyncRevision.objects.filter(object=obj)
        .order_by("-revision")
        .values_list("id", flat=True)[keep:]
    )
    if ids:
        SyncRevision.objects.filter(id__in=ids).delete()


def utcnow():
    return timezone.now()
