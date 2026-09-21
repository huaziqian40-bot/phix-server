"""phix 服务端中间件。

两个职责：

1. `ProtocolErrorMiddleware` —— 把 Django 抛出来的协议级错误翻成规范里的 JSON 错误。
   没有它的话：
   - 请求体超过 ``DATA_UPLOAD_MAX_MEMORY_SIZE`` → Django 抛 ``RequestDataTooBig``
     → 客户端收到一个 **500 HTML 错误页**，而不是协议 §4.7 定义的
     ``{"error": {"code": "payload_too_large"}}``。
   - Host 头不合法等等 ``SuspiciousOperation`` 也一样。

2. `E2EEnvelopeMiddleware` —— **应用层加密传输**（见 `api/e2e.py` 与
   `加密链路思路.md` §3）。带 ``X-Phix-Enc: 1`` 的请求：体是密文，先解开再交给视图；
   响应体再加密回去。**没有这个头就完全走原来的明文路径**，老客户端与 curl 调试不受影响。
"""
import json

from django.core.exceptions import RequestDataTooBig, SuspiciousOperation
from django.http import JsonResponse

from . import e2e


def _json_err(code, message, status):
    return JsonResponse({"ok": False, "error": {"code": code, "message": message}},
                        status=status,
                        json_dumps_params={"ensure_ascii": False})


class ProtocolErrorMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        try:
            return self.get_response(request)
        except RequestDataTooBig:
            return _json_err("payload_too_large",
                             "请求体太大（超过服务端允许的上限）", 413)
        except SuspiciousOperation:
            return _json_err("bad_request", "请求不合法", 400)


class E2EEnvelopeMiddleware:
    """应用层加密传输。开关：``PHIX_E2E_ENABLED``（默认开）。"""

    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        from django.conf import settings

        if not getattr(settings, "PHIX_E2E_ENABLED", True):
            return self.get_response(request)
        if request.META.get(e2e.HEADER) != "1":
            return self.get_response(request)          # 明文路径，行为完全不变
        path = request.path
        if not path.startswith("/api/"):
            return _json_err("bad_request", "这个路径不支持加密信封", 400)

        try:
            envelope = json.loads(request.body.decode("utf-8"))
            if not isinstance(envelope, dict):
                raise ValueError("信封必须是 JSON 对象")
            inner, session_key = e2e.open_request(request.method, path, envelope)
        except Exception as exc:  # noqa: BLE001
            return _json_err("bad_request", f"信封有问题：{exc}", 400)

        err = e2e.check_freshness(inner.get("ts"), inner.get("nonce"))
        if err:
            return _json_err("bad_request", err, 400)

        # 查询串也可以放在信封里（这样 URL 里什么都不泄露）
        if isinstance(inner.get("q"), str):
            request.META["QUERY_STRING"] = inner["q"]

        body = inner.get("b")
        raw = json.dumps(body if body is not None else {},
                         ensure_ascii=False).encode("utf-8")
        request._body = raw
        request.phix_session_key = session_key

        response = self.get_response(request)

        if getattr(response, "phix_plain", False):
            return response
        try:
            sealed = e2e.seal_response(session_key, request.method, path,
                                       response.content)
        except Exception:  # noqa: BLE001  加密失败宁可回明文也别 500
            return response
        out = JsonResponse(sealed, status=response.status_code,
                           json_dumps_params={"ensure_ascii": False})
        out["X-Phix-Enc"] = "1"
        return out
