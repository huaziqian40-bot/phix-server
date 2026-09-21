"""本地启动脚本：自动带上 .service_key 里的服务密钥。

生产（Linux）由 systemd 的 EnvironmentFile 提供同一变量，见 DEPLOY.md。
"""
import os
import sys
from pathlib import Path

HOST = sys.argv[1] if len(sys.argv) > 1 else "127.0.0.1"
PORT = int(sys.argv[2]) if len(sys.argv) > 2 else 8931
ROOT = Path(__file__).resolve().parent

key_file = ROOT / ".service_key"
if key_file.exists() and not os.environ.get("PHIX_SERVICE_KEY"):
    os.environ["PHIX_SERVICE_KEY"] = key_file.read_text(encoding="utf-8").strip()

os.environ.setdefault("DJANGO_SETTINGS_MODULE", "phixsvc.settings")
os.environ.setdefault("PHIX_DEBUG", "1")

import django  # noqa: E402

django.setup()

from waitress import serve  # noqa: E402

from phixsvc.wsgi import application  # noqa: E402

if __name__ == "__main__":
    print(f"[phix] 服务已启动： http://{HOST}:{PORT}   （Ctrl+C 停止）", flush=True)
    print(f"[phix] 健康检查：   http://{HOST}:{PORT}/api/v1/ping", flush=True)
    print(f"[phix] 心履 verify：{'已启用服务密钥' if os.environ.get('PHIX_SERVICE_KEY') else '未设置服务密钥'}", flush=True)
    serve(application, host=HOST, port=PORT, threads=8, ident="phix")
