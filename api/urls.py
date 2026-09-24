"""phix API 路由（前缀 /api/v1/）。"""
from django.urls import path

from . import sso as sso_views
from . import views_auth as a
from . import views_sync as s
from . import views_updates as u

urlpatterns = [
    # 连通性
    path("ping", a.ping, name="phix-ping"),

    # 应用内自动更新（免鉴权、限流；清单见 updates.json）
    path("update/check", u.update_check, name="phix-update-check"),

    # 认证
    path("auth/register", a.register, name="phix-register"),
    path("auth/login", a.login, name="phix-login"),
    path("auth/refresh", a.refresh, name="phix-refresh"),
    path("auth/me", a.me, name="phix-me"),
    path("auth/logout", a.logout, name="phix-logout"),
    path("auth/password", a.change_password, name="phix-password"),
    path("auth/rewrap", a.rewrap, name="phix-rewrap"),
    path("auth/recover", a.recover, name="phix-recover"),
    path("auth/keymaterial", a.key_material, name="phix-keymaterial"),
    path("auth/devices", a.devices, name="phix-devices"),
    path("auth/devices/revoke", a.revoke_devices, name="phix-revoke"),
    path("auth/verify", a.verify, name="phix-verify"),
    # P3：JWT —— 公钥（免认证）与令牌自省（服务密钥）
    path("auth/jwks", a.jwks, name="phix-jwks"),
    path("auth/introspect", a.introspect, name="phix-introspect"),

    # 跨站免密登录：一次性码（签发 / 兑换），见 api/sso.py
    path("auth/sso/code", sso_views.sso_code, name="phix-sso-code"),
    path("auth/sso/redeem", sso_views.sso_redeem, name="phix-sso-redeem"),

    # 管理端点（服务密钥保护）
    path("admin/users", a.admin_users, name="phix-admin-users"),
    path("admin/user/<int:user_id>/flags", a.admin_user_flags, name="phix-admin-user-flags"),

    # 云同步
    path("sync/manifest", s.manifest, name="phix-manifest"),
    path("sync/objects/batch", s.batch, name="phix-batch"),
    path("sync/objects/<str:name>", s.object_view, name="phix-object"),
    path("sync/objects/<str:name>/revisions", s.revisions, name="phix-object-revisions"),
]
