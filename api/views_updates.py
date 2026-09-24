# -*- coding: utf-8 -*-
"""phix 更新检查接口（应用内自动更新）。

客户端启动时调用 `GET /api/v1/update/check?product=phl&platform=win`
（免登录、免鉴权，公开端点，带简单限流），返回该产品该平台的最新版本信息。

清单文件（`<BASE_DIR>/updates.json`）由**发布脚本**生成 —— 每次构建后自动
更新各端最新版本 / 下载 URL / sha256 / 大小。视图只读它，不含任何业务逻辑。

URL 指向官网静态下载（`https://phix.ing/media/downloads/...`），文件已随
官网部署就位；这里只做「版本 + 校验信息」的权威来源。

安全：这是公开只读端点，响应不含任何敏感信息；限流防刷（每 IP 每分钟 20 次）。
"""
from __future__ import annotations

import json
import logging
from pathlib import Path

from django.conf import settings
from django.views.decorators.http import require_GET

from .utils import client_ip, err, limiter, ok

log = logging.getLogger("phix.updates")

UPDATES_FILE = Path(getattr(settings, "PHIX_UPDATES_FILE", "")) if getattr(settings, "PHIX_UPDATES_FILE", "") else Path(settings.BASE_DIR) / "updates.json"
#: 每 IP 每分钟最多多少次 update/check 请求（客户端启动只查一次，足够）
_RL = ("updates", 20, 60)

_PLATFORM_ALIASES = {
    # 客户端传来的 platform → 清单里的键
    "win": "win", "windows": "win", "win32": "win",
    "mac": "mac", "macos": "mac", "darwin": "mac",
    "android": "android",
}


def _load_manifest():
    try:
        if not UPDATES_FILE.exists():
            return None
        return json.loads(UPDATES_FILE.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        log.exception("读取 updates.json 失败")
        return None


@require_GET
def update_check(request):
    if limiter.hit(f"{_RL[0]}:{client_ip(request)}", _RL[1], _RL[2]):
        return err("rate_limited", "请求太频繁，请稍后再试", 429)

    product = (request.GET.get("product") or "").strip().lower()
    platform = (request.GET.get("platform") or "").strip().lower()
    platform = _PLATFORM_ALIASES.get(platform, platform)
    if not product or not platform:
        return err("bad_request", "缺少 product 或 platform 参数", 400)

    manifest = _load_manifest()
    if not manifest:
        return err("server_error", "更新清单暂不可用", 503)

    prod = manifest.get("products", {}).get(product)
    if not prod:
        return err("not_found", f"未知产品: {product}", 404)

    entry = prod.get("platforms", {}).get(platform)
    if not entry:
        return err("not_found", f"产品 {product} 没有 {platform} 平台信息", 404)

    return ok({
        "product": product,
        "platform": platform,
        "latest_version": entry.get("version"),
        "min_supported": entry.get("min_supported", ""),
        "force_update": bool(entry.get("force_update", False)),
        "url": entry.get("url"),
        "sha256": entry.get("sha256"),
        "size": entry.get("size"),
        "release_notes": entry.get("notes", ""),
        "published_at": manifest.get("updated_at", ""),
    })
