"""只读列出**本地开发库**的账号与对象（看清再决定，绝不盲删）。

    D:\\phix\\server\\.venv\\Scripts\\python.exe -X utf8 D:\\phix\\server\\devtools\\list_local.py
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
os.environ.setdefault("DJANGO_SETTINGS_MODULE", "phixsvc.settings")

import django  # noqa: E402

django.setup()

from django.contrib.auth import get_user_model  # noqa: E402

from api.models import DeviceToken, SyncObject, UserKeyMaterial  # noqa: E402

U = get_user_model()
print("账号总数:", U.objects.count(), " 对象总数:", SyncObject.objects.count())
for u in U.objects.order_by("id"):
    objs = SyncObject.objects.filter(user=u)
    toks = DeviceToken.objects.filter(user=u)
    km = UserKeyMaterial.objects.filter(user=u).first()
    print("  id=%-3s %-30s 对象=%-3s 令牌=%-2s kdf=%s 加入=%s"
          % (u.id, u.username, objs.count(), toks.count(),
             getattr(km, "kdf_algo", "-"), u.date_joined.strftime("%Y-%m-%d %H:%M")))
    for o in objs.order_by("name")[:12]:
        print("        · %-24s rev=%-3s %7s B" % (o.name, o.revision, o.size))
