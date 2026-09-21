"""清理**本地开发库**里的测试账号（只删本项目测试前缀，绝不模糊匹配）。

    D:\\phix\\server\\.venv\\Scripts\\python.exe -X utf8 D:\\phix\\server\\devtools\\clean_dev_db.py
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
os.environ.setdefault("DJANGO_SETTINGS_MODULE", "phixsvc.settings")

import django  # noqa: E402

django.setup()

from django.contrib.auth import get_user_model  # noqa: E402

from api.models import (DeviceToken, SyncObject, SyncRevision,  # noqa: E402
                        UserKeyMaterial)

PREFIXES = ("e2e_", "pllsess_", "selftest_", "xinlv_", "bridge_", "panel",
            "nodee2e_", "forgot", "cross", "stress", "docchk", "phlsess",
            "nodesess", "phix_", "nodesmoke_", "pyselftest_", "limitprobe_",
            "sizeprobe_", "e2etr", "e2eenc", "authh", "ahprf", "ahsalt",
            "nodetr", "nodev2_", "noderec_", "aadprobe_", "bigprobe_", "bigprobe",
            "getbody_", "kdfprobe_", "namprobe_",
            # 2026-09-12：子代理探针与追踪账号残留
            "probeb_", "probec_", "trace_", "probe", "nodeprobe_",
            "ahprobe_", "syncprobe_", "wrap_", "recoverprobe_",
            "xinlvprobe", "xinlvchk", "v2guard", "jwt",
            # 2026-09-12：心履老用户登录自动迁移（test_xinlv_migrate_on_login.py）的账号
            "xlmig",
            # 2026-09-12：PLL 客户端接入 P3（test_pll_jwt.py）的账号
            "plljwt", "limitchk", "perfchk",
            # 2026-09-12：PHL（Node）客户端接入 P3（test_phl_jwt.py）的账号
            "phljwt",
            # 2026-09-12：两客户端令牌落盘键名对齐（test_token_keys.py）的账号
            "keyalign",
            # PLL 首启引导 + profile 测试（test_pll_onboard.py）的账号
            "onboard", "webc",
            # 2026-09-12：官网 smoke 测试账号
            "site",
            # 2026-09-12：官网四项改造（test_phix_site.py / 截图脚本 / test_legacy_login.py）账号
            "psite", "_migtest_", "uishot", "uichk", "admtest",
            "fbshot", "screenshot", "legstaff",
            # 2026-09-13：PHIX 日志功能测试账号
            "logchk", "logtest", "logdemo",
            # 2026-09-13：Pinghe Launcher 网页端（AI 接口 / 五页 / 抓取层 / 配置统一）测试账号
            "appai", "appweb", "apptest", "webapp", "apprwtmp", "appdemo",
            # 2026-09-13：网页端收尾阶段的临时账号前缀
            "app409", "appdbg", "appprobe", "mobtest", "mobprobe", "viewshot", "viewcheck", "authshot", "tabprobe", "logprobe", "ssochk", "sso-e2e", "acctest", "appui", "dbg", "shot")

U = get_user_model()
targets = [u for u in U.objects.order_by("id")
           if u.username.startswith(PREFIXES)]
print(f"本地库里共 {U.objects.count()} 个账号，其中测试账号 {len(targets)} 个：")
for u in targets:
    print("  -", u.username)
if not targets:
    raise SystemExit(0)

answer = os.environ.get("PHIX_CLEAN_YES")
if answer != "1":
    print("\n这是只读预演。要真的删除，请设 PHIX_CLEAN_YES=1 再跑一次。")
    raise SystemExit(0)

for u in targets:
    SyncRevision.objects.filter(object__user=u).delete()
    SyncObject.objects.filter(user=u).delete()
    UserKeyMaterial.objects.filter(user=u).delete()
    DeviceToken.objects.filter(user=u).delete()
    u.delete()
print(f"\n已删除 {len(targets)} 个测试账号。")
print("剩余账号:", U.objects.count(), " 剩余对象:", SyncObject.objects.count())
left = sorted(u.username for u in U.objects.all())
if left:
    print("剩余账号清单:", left)
