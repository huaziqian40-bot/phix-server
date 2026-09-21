from django.apps import AppConfig
from django.db.backends.signals import connection_created


def _sqlite_pragmas(sender, connection, **kwargs):
    """SQLite 并发调优。

    waitress 是 8 线程的，多个请求同时写就会撞上 "database is locked" ——实测
    批量写入时真的抛过 ``OperationalError: database is locked``（整批 500）。
    这里开 WAL（读写可以并行）+ 忙等 20 秒 + synchronous=NORMAL：
    对这个量级的自托管服务是标准做法，单机可靠性没有损失。
    """
    if connection.vendor != "sqlite":
        return
    try:
        cur = connection.cursor()
        cur.execute("PRAGMA journal_mode=WAL;")
        cur.execute("PRAGMA synchronous=NORMAL;")
        cur.execute("PRAGMA busy_timeout=20000;")
    except Exception:  # noqa: BLE001  连不上/只读时不该让启动挂掉
        pass


class ApiConfig(AppConfig):
    default_auto_field = "django.db.models.BigAutoField"
    name = "api"
    verbose_name = "phix 账户与云同步"

    def ready(self):
        connection_created.connect(_sqlite_pragmas, dispatch_uid="phix.sqlite_pragmas")
