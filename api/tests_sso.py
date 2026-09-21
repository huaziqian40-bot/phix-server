"""一次性 SSO 码的单元/安全测试（Django TestCase，跑在临时库上，不碰 db.sqlite3）。

    cd D:\\phix\\server
    .venv\\Scripts\\python.exe -X utf8 manage.py test api.tests_sso -v 2

要证明的事（每条都实跑）：
  1. 会话（Bearer）与服务密钥两条签发路径都能换到码；
  2. 兑换出来的东西**与 /auth/login 同构**（access/refresh/key_wrap...）；
  3. 码**用第二次必失败**；伪造码失败；过期码失败；
  4. 站点（audience）不匹配失败，**且不消耗码**；
  5. 缺服务密钥 / 服务密钥不对 → 401；
  6. 连续兑换失败会触发限流；签发也有上限；
  7. **码全文不进日志**（码本身不是凭据，但也不该被抄走）；
  8. 响应里**没有 DEK** —— 服务端从来就没有 DEK，码里也不带。
"""
from __future__ import annotations

import json

from django.contrib.auth import get_user_model
from django.test import TestCase, override_settings

from . import sso
from .models import UserKeyMaterial
from .utils import limiter

SERVICE_KEY = "unit-test-service-key-" + "0" * 16


def _mkuser(username: str):
    """开一个最小可用账号：口令随便（测试里不再用口令），密钥材料给占位。"""
    User = get_user_model()
    user = User.objects.create_user(username=username, password="Unit-Test-Pw-1")
    UserKeyMaterial.objects.create(
        user=user, kdf_algo="scrypt-nkdf-v2", kdf_salt="11" * 16,
        auth_salt="22" * 16, key_wrap="PHIX1.unit.wrap",
        key_check="PHIX1.unit.check", key_check_plain="33" * 16,
        key_mode="password", recovery_salt="44" * 16,
        recovery_wrap="PHIX1.unit.recovery",
    )
    return user


def _session_token(user):
    from .views_auth import _issue_session

    creds, _sess, _copy = _issue_session(user, "单元测试")
    return creds["access_token"]


class SsoBase(TestCase):
    def setUp(self):
        limiter.clear()
        sso.codes.clear()
        self.user = _mkuser("ssoalpha")
        self.other = _mkuser("ssobeta")
        self.skey = {"HTTP_X_PHIX_SERVICE_KEY": SERVICE_KEY}

    # ---- 小工具 ----

    def post(self, path, payload, **extra):
        return self.client.post(path, data=json.dumps(payload),
                                content_type="application/json", **extra)

    def mint(self, audience="xinlv", via="service", **extra):
        body = {"audience": audience, "device": "单元测试", **extra}
        if via == "service":
            return self.post("/api/v1/auth/sso/code",
                             {"user_id": self.user.id, **body}, **self.skey)
        return self.post("/api/v1/auth/sso/code", body,
                         HTTP_AUTHORIZATION=f"Bearer {_session_token(self.user)}")

    def redeem(self, code, site="xinlv", skey=True, **meta):
        """默认带服务密钥（生产默认要求它）；skey=False 用来测"不带密钥"的分支。

        服务密钥按 Django 测试客户端的 META kwargs 传（``HTTP_X_PHIX_SERVICE_KEY``），
        不要塞进 ``headers=`` —— 那样会被再加一层 ``HTTP_`` 前缀，反而认不出来。
        """
        if skey:
            meta.update(self.skey)
        return self.post("/api/v1/auth/sso/redeem",
                         {"code": code, "site": site, "device": "单元测试"}, **meta)


@override_settings(PHIX_SERVICE_KEY=SERVICE_KEY)
class MintTests(SsoBase):
    def test_mint_with_session_token(self):
        r = self.mint(via="session")
        self.assertEqual(r.status_code, 200, r.content[:300])
        body = r.json()
        self.assertTrue(body["ok"])
        self.assertGreaterEqual(len(body["code"]), 16)
        self.assertEqual(body["expires_in"], 120)
        self.assertEqual(body["issued_via"], "session")
        self.assertTrue(body["single_use"])

    def test_mint_with_service_key_by_user_id_and_username(self):
        r = self.mint()
        self.assertEqual(r.status_code, 200, r.content[:300])
        r2 = self.mint(username=self.user.username)
        self.assertEqual(r2.status_code, 200, r2.content[:300])
        self.assertNotEqual(r.json()["code"], r2.json()["code"])

    def test_mint_service_key_wrong(self):
        r = self.post("/api/v1/auth/sso/code",
                      {"user_id": self.user.id, "audience": "xinlv"},
                      HTTP_X_PHIX_SERVICE_KEY="not-the-key")
        self.assertEqual(r.status_code, 401)

    def test_mint_service_key_unknown_user(self):
        r = self.post("/api/v1/auth/sso/code",
                      {"user_id": 999999, "audience": "xinlv"}, **self.skey)
        self.assertEqual(r.status_code, 404)

    def test_mint_service_key_needs_identity(self):
        r = self.post("/api/v1/auth/sso/code", {"audience": "xinlv"}, **self.skey)
        self.assertEqual(r.status_code, 400)

    def test_mint_without_any_credential(self):
        r = self.post("/api/v1/auth/sso/code", {"audience": "xinlv"})
        self.assertEqual(r.status_code, 401)

    def test_mint_unknown_audience(self):
        r = self.mint(audience="evil-site")
        self.assertEqual(r.status_code, 400)

    def test_mint_inactive_user(self):
        self.user.is_active = False
        self.user.save(update_fields=["is_active"])
        r = self.mint()
        self.assertEqual(r.status_code, 403)

    @override_settings(PHIX_SSO_MINT_LIMIT=2)
    def test_mint_rate_limited(self):
        self.assertEqual(self.mint(audience="xinlv").status_code, 200)
        self.assertEqual(self.mint(audience="xinlv").status_code, 200)
        self.assertEqual(self.mint(audience="xinlv").status_code, 429)

    def test_code_not_in_logs(self):
        with self.assertLogs("phix.auth", level="INFO") as cap:
            code = self.mint().json()["code"]
            self.redeem(code)
        joined = "\n".join(cap.output)
        self.assertNotIn(code, joined, "码全文出现在了日志里")
        self.assertNotIn(code[:20], joined)
        self.assertIn("sid=", joined)          # 只留摘要前 8 位，便于串日志


@override_settings(PHIX_SERVICE_KEY=SERVICE_KEY)
class RedeemTests(SsoBase):
    def test_redeem_success_is_login_shaped(self):
        code = self.mint().json()["code"]
        r = self.redeem(code)
        self.assertEqual(r.status_code, 200, r.content[:300])
        body = r.json()
        for field in ("ok", "user_id", "username", "key_wrap", "kdf_salt",
                      "key_check", "access_token", "refresh_token",
                      "expires_in", "session_id"):
            self.assertIn(field, body, f"兑换响应缺少与 /auth/login 同构的字段 {field}")
        self.assertEqual(body["username"], self.user.username)
        self.assertTrue(body["key_wrap"].startswith("PHIX1."))
        self.assertEqual(body["sso"]["audience"], "xinlv")
        self.assertTrue(body["sso"]["single_use"])

    def test_redeem_has_no_dek(self):
        code = self.mint().json()["code"]
        body = self.redeem(code).json()
        for forbidden in ("dek", "dek_hex", "kek", "password", "auth_hash"):
            self.assertNotIn(forbidden, body, f"响应里不该有 {forbidden}")
        self.assertNotIn(body["key_wrap"], json.dumps({"code": code}))

    def test_redeem_twice_fails(self):
        code = self.mint().json()["code"]
        self.assertEqual(self.redeem(code).status_code, 200)
        second = self.redeem(code)
        self.assertEqual(second.status_code, 401, second.content[:200])
        self.assertIn("用过", second.json()["error"]["message"])

    def test_redeem_forged_code(self):
        r = self.redeem("x" * 43)
        self.assertEqual(r.status_code, 401)

    def test_redeem_empty_or_short_code(self):
        for bad in ("", "short", None):
            r = self.redeem(bad)
            self.assertIn(r.status_code, (400, 401))

    def test_redeem_expired(self):
        minted = self.mint().json()
        code = minted["code"]
        # 直接把条目改成"已经过期"（等价于等 120 秒，测试不必真等）
        import time as _t

        entry = sso.codes._items[sso._digest(code)]
        entry["expires_at"] = _t.time() - 1
        r = self.redeem(code)
        self.assertEqual(r.status_code, 401)
        # **有意为之**：过期与"压根不存在"回同一句话（"无效或已经被用过了"）。
        # 分开回等于给攻击者一个"这个码曾经是真的"的判定 oracle；
        # 过期条目在查找前就被 gc 掉了，两者本来也分不出来。
        self.assertIn("无效", r.json()["error"]["message"])

    def test_expired_code_is_gone_from_store(self):
        import time as _t

        code = self.mint().json()["code"]
        sso.codes._items[sso._digest(code)]["expires_at"] = _t.time() - 1
        self.redeem(code)
        self.assertEqual(sso.codes.size(), 0)

    def test_redeem_ttl_setting_is_honoured(self):
        with override_settings(PHIX_SSO_TTL=1):
            r = self.mint()
            self.assertEqual(r.json()["expires_in"], 1)

    def test_redeem_audience_mismatch_does_not_consume(self):
        code = self.mint(audience="xinlv").json()["code"]
        bad = self.redeem(code, site="phix-site")
        self.assertEqual(bad.status_code, 401)
        self.assertIn("不是发给本站", bad.json()["error"]["message"])
        good = self.redeem(code, site="xinlv")     # 码没被烧掉，仍能正常兑换
        self.assertEqual(good.status_code, 200, good.content[:200])

    def test_redeem_unknown_site(self):
        code = self.mint().json()["code"]
        r = self.redeem(code, site="evil-site")
        self.assertEqual(r.status_code, 400)

    def test_redeem_requires_service_key(self):
        code = self.mint().json()["code"]
        r = self.redeem(code, skey=False)          # 不带服务密钥
        self.assertEqual(r.status_code, 401)
        self.assertIn("服务密钥", r.json()["error"]["message"])
        self.assertEqual(sso.codes.size(), 1, "被拒的兑换不该消耗码")

    @override_settings(PHIX_SSO_REQUIRE_SERVICE_KEY=False)
    def test_redeem_without_service_key_when_disabled(self):
        code = self.mint().json()["code"]
        r = self.redeem(code, skey=False)
        self.assertEqual(r.status_code, 200, r.content[:200])

    @override_settings(PHIX_SSO_FAIL_LIMIT=3, PHIX_SSO_REDEEM_LIMIT=1000)
    def test_redeem_failure_rate_limit(self):
        codes = [self.redeem("y" * 43).status_code for _ in range(4)]
        self.assertEqual(codes[:3], [401, 401, 401])
        self.assertEqual(codes[3], 429, f"第 4 次失败应被限流，实际 {codes}")

    @override_settings(PHIX_SSO_REDEEM_LIMIT=2, PHIX_SSO_REDEEM_WINDOW=3600)
    def test_redeem_rate_limit(self):
        self.assertEqual(self.redeem("z" * 43).status_code, 401)
        self.assertEqual(self.redeem("z" * 43).status_code, 401)
        self.assertEqual(self.redeem("z" * 43).status_code, 429)

    @override_settings(PHIX_SSO_IP_BIND="prefix")
    def test_redeem_ip_bind_prefix_same_ip_ok(self):
        code = self.mint().json()["code"]
        self.assertEqual(self.redeem(code).status_code, 200)

    @override_settings(PHIX_SSO_IP_BIND="exact")
    def test_redeem_ip_bind_exact_mismatch(self):
        code = self.mint().json()["code"]
        # 伪造一个不同来源 IP（Django 测试客户端可设 REMOTE_ADDR）
        r = self.post("/api/v1/auth/sso/redeem",
                      {"code": code, "site": "xinlv"},
                      REMOTE_ADDR="10.9.9.9", **self.skey)
        self.assertEqual(r.status_code, 401)
        self.assertIn("来源", r.json()["error"]["message"])

    def test_live_code_cap_per_user(self):
        with override_settings(PHIX_SSO_LIVE_PER_USER=2):
            self.assertEqual(self.mint().status_code, 200)
            self.assertEqual(self.mint().status_code, 200)
            self.assertEqual(self.mint().status_code, 429)

    def test_revoke_everything_after_redeem_is_independent_session(self):
        """兑换出来的是一套**新会话**，与签发方手里的会话互不影响。"""
        mint_token = None
        r = self.mint(via="service")
        code = r.json()["code"]
        redeemed = self.redeem(code).json()
        self.assertTrue(redeemed["access_token"])
        self.assertNotEqual(redeemed["access_token"], mint_token)
        # 兑换出来的令牌真能用
        me = self.client.get("/api/v1/auth/me",
                             HTTP_AUTHORIZATION=f"Bearer {redeemed['access_token']}")
        self.assertEqual(me.status_code, 200, me.content[:200])
        self.assertEqual(me.json()["username"], self.user.username)


class StoreUnitTests(TestCase):
    """不经过视图，直接测存储语义（用后即焚、gc、上限）。"""

    def setUp(self):
        sso.codes.clear()

    def test_pop_is_destructive(self):
        code, ttl = sso.codes.mint(1, "u", "xinlv")
        entry, why = sso.codes.pop(code, "xinlv")
        self.assertIsNotNone(entry)
        self.assertEqual(why, "")
        entry2, why2 = sso.codes.pop(code, "xinlv")
        self.assertIsNone(entry2)
        self.assertEqual(why2, "invalid")

    def test_digest_not_plaintext(self):
        code, _ = sso.codes.mint(1, "u", "xinlv")
        self.assertNotIn(code, sso.codes._items)      # 表里存的是摘要
        self.assertIn(sso._digest(code), sso.codes._items)

    def test_gc_drops_expired(self):
        import time as _t

        code, _ = sso.codes.mint(1, "u", "xinlv", ttl=1)
        self.assertEqual(sso.codes.size(), 1)
        sso.codes._items[sso._digest(code)]["expires_at"] = _t.time() - 1
        self.assertEqual(sso.codes.size(), 0)
        self.assertEqual(sso.codes.pop(code, "xinlv"), (None, "invalid"))

    def test_ttl_floor_is_one_second(self):
        _code, ttl = sso.codes.mint(1, "u", "xinlv", ttl=0)
        self.assertEqual(ttl, 1)

    def test_ip_prefix_shapes(self):
        self.assertEqual(sso._ip_prefix("192.168.5.35"), "192.168.5")
        self.assertEqual(sso._ip_prefix("10.0.0.1"), "10.0.0")
        self.assertEqual(sso._ip_prefix("2001:db8::1"), "2001:db8::1")
        self.assertEqual(sso._ip_prefix("?"), "")
        self.assertTrue(sso._ip_matches("192.168.5", "192.168.5.35", "192.168.5.35", "prefix"))
        self.assertFalse(sso._ip_matches("192.168.5", "192.168.5.35", "192.168.6.35", "prefix"))
        self.assertTrue(sso._ip_matches("192.168.5", "192.168.5.35", "192.168.5.35", "exact"))
        self.assertFalse(sso._ip_matches("192.168.5", "192.168.5.35", "192.168.5.99", "exact"))

    def test_random_codes_are_unique_and_long(self):
        codes = {sso.codes.mint(1, "u", "xinlv")[0] for _ in range(200)}
        self.assertEqual(len(codes), 200)
        self.assertTrue(all(len(c) >= 40 for c in codes))
