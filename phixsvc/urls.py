"""phix 服务端 URL 路由。"""
from django.http import JsonResponse
from django.urls import include, path


def healthz(_request):
    return JsonResponse({"ok": True, "service": "phix", "version": 1})


urlpatterns = [
    path("api/v1/", include("api.urls")),
    path("healthz", healthz),
]
