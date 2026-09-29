"""phix 同步视图：不透明密文对象的仓库 + 乐观并发控制。

服务端在这一层**完全无知**：它不知道对象里是选课还是日程，也不知道内容是什么。
它只保证：
- `revision` 单调递增（每次成功写入 +1）
- 客户端必须带 `base_revision`，对不上就 409（绝不静默覆盖）
- 名字、大小、配额受控
"""
import logging

from django.conf import settings
from django.db import transaction
from django.db.models import Max, Sum
from django.utils import timezone
from django.views.decorators.http import require_GET, require_POST, require_http_methods

from .models import SyncObject, SyncRevision, purge_old_revisions
from .utils import (check_object_name, err, iso, json_body, limiter, ok,
                    require_token, sha256_hex)
from . import syncwatch

log = logging.getLogger("phix.sync")


def _quota_used(user):
    return SyncObject.objects.filter(user=user).aggregate(s=Sum("size"))["s"] or 0


def _write_object(user, name, base_revision, payload, device, deleted=False):
    """写一个对象。返回 (result_dict, error_response_or_None)。"""
    size = len(payload.encode("utf-8")) if payload else 0
    if size > settings.PHIX_MAX_PAYLOAD_BYTES:
        return None, err("payload_too_large",
                         f"单个对象最大 {settings.PHIX_MAX_PAYLOAD_BYTES // 1024 // 1024} MiB", 413)

    with transaction.atomic():
        obj = (
            SyncObject.objects.select_for_update()
            .filter(user=user, name=name)
            .first()
        )
        current_rev = obj.revision if obj else 0

        if base_revision is None:
            base_revision = 0
        try:
            base_revision = int(base_revision)
        except (TypeError, ValueError):
            return None, err("bad_request", "base_revision 必须是整数")

        if base_revision != current_rev:
            return None, err(
                "revision_conflict",
                f"远端已经是第 {current_rev} 版，你基于第 {base_revision} 版提交",
                409,
                current={
                    "revision": current_rev,
                    "updated_at": iso(obj.updated_at) if obj else None,
                    "sha256": obj.sha256 if obj else "",
                },
            )

        # 配额（新建对象才需要检查增量）
        if obj is None:
            if SyncObject.objects.filter(user=user).count() >= settings.PHIX_MAX_OBJECTS:
                return None, err("quota_exceeded", "对象数量已达上限", 413)
        used = _quota_used(user) - (obj.size if obj else 0)
        if used + size > settings.PHIX_MAX_TOTAL_BYTES:
            return None, err("quota_exceeded", "云端空间已满", 413)

        new_rev = current_rev + 1
        digest = sha256_hex(payload) if payload else ""

        if obj is None:
            obj = SyncObject.objects.create(
                user=user, name=name, revision=new_rev, device=device[:100],
                payload=payload or "", size=size, sha256=digest, deleted=deleted,
            )
        else:
            obj.revision = new_rev
            obj.device = device[:100]
            obj.payload = payload or ""
            obj.size = size
            obj.sha256 = digest
            obj.deleted = deleted
            obj.save(update_fields=["revision", "device", "payload", "size",
                                    "sha256", "deleted", "updated_at"])

        SyncRevision.objects.create(
            object=obj, revision=new_rev, payload=payload or "", size=size,
            sha256=digest, device=device[:100], deleted=deleted,
        )
        purge_old_revisions(obj)

    # 叫醒所有挂在 /sync/watch 上的客户端：云端变了，别再等了。
    # 放在事务外 —— 万一 notify 出问题，也绝不能把已经写成功的对象回滚掉。
    syncwatch.bump()

    return {
        "name": obj.name,
        "revision": obj.revision,
        "updated_at": iso(obj.updated_at),
        "size": obj.size,
        "sha256": obj.sha256,
        "deleted": obj.deleted,
    }, None


# ---------------- 清单 ----------------

@require_GET
@require_token
def manifest(request):
    user = request.phix_user
    rows = SyncObject.objects.filter(user=user).order_by("name")
    used = sum(r.size for r in rows)
    return ok({
        "version": 1,
        "server_time": timezone.now().isoformat(),
        "user_id": user.id,
        "username": user.username,
        "quota": {
            "used_bytes": used,
            "limit_bytes": settings.PHIX_MAX_TOTAL_BYTES,
            "objects": len(rows),
            "limit_objects": settings.PHIX_MAX_OBJECTS,
        },
        "objects": [r.as_manifest_dict() for r in rows],
    })


# ---------------- 长轮询：有变化就立刻回 ----------------

def _cursor(user) -> str:
    """这个账号云端状态的**不透明光标**。

    只看两样：对象条数 + 最新一次写入时间。任何写入/删除都会把 `updated_at`
    推到最新，所以光标必然变化；没变化就说明这一轮真的什么都没发生。

    从库里现算（而不是记在进程内存里），换 worker、重启服务都不会漏变化。
    """
    agg = SyncObject.objects.filter(user=user).aggregate(
        n=Sum("size"), latest=Max("updated_at"))
    latest = agg["latest"]
    return f"{SyncObject.objects.filter(user=user).count()}:{iso(latest) if latest else ''}"


@require_GET
@require_token
def watch(request):
    """挂着不回，直到云端变了或超时。

    查询参数 `cursor`：客户端上次拿到的光标（不传 = 立刻返回当前状态）。
    响应 `{"changed": bool, "cursor": "...", "server_time": "..."}`。
    客户端拿到 `changed=true` 就立刻跑一次正常同步；`false` 说明只是超时，再挂一次即可。

    为什么值得：原来客户端要自己定时间隔去问（PHL 1 秒、PHL Lite 10 分钟），
    延迟最坏等于那个间隔。挂在这里之后，别的设备一改，这边一个 RTT 就知道。
    """
    user = request.phix_user
    since = str(request.GET.get("cursor") or "").strip()
    if not since:
        # 没带光标：当作"第一次问"，直接把当前光标给出去，不挂。
        return ok({"changed": False, "cursor": _cursor(user),
                   "server_time": timezone.now().isoformat()})

    # 挂起期间一直占着一个 waitress 线程，所以名额有限（见 syncwatch.WATCH_SLOTS）。
    # 拿不到名额就**立刻**回，并明确告诉客户端"过 retry_after 秒再来" ——
    # 不这么说的话客户端会把"被打回"当成"超时"，立刻重挂，变成热循环。
    if not syncwatch.try_acquire_slot():
        return ok({"changed": False, "cursor": _cursor(user),
                   "retry_after": syncwatch.BUSY_RETRY_AFTER_SECONDS,
                   "server_time": timezone.now().isoformat()})
    try:
        changed, cursor = syncwatch.wait_for_change(lambda: _cursor(user), since)
    finally:
        # 客户端中途断开时 waitress 会直接抛异常打断这里，所以必须 finally 还名额，
        # 否则漏还几次之后长轮询就被永久关掉了。
        syncwatch.release_slot()
    if changed:
        rows = SyncObject.objects.filter(user=user).order_by("name")
        # 顺带把清单带上：客户端拿到就能直接决定要拉哪几个，
        # 省掉"醒了 → 再单独问一次清单"的往返。
        return ok({
            "changed": True,
            "cursor": cursor,
            "server_time": timezone.now().isoformat(),
            "objects": [r.as_manifest_dict() for r in rows],
        })
    return ok({"changed": False, "cursor": cursor,
               "server_time": timezone.now().isoformat()})


# ---------------- 单对象 ----------------

def get_object(request, name):
    if not check_object_name(name):
        return err("name_invalid", "对象名不合法", 400)
    obj = SyncObject.objects.filter(user=request.phix_user, name=name).first()
    if obj is None or (obj.deleted and obj.revision == 0):
        return err("not_found", "云端没有这个对象", 404)
    return ok({
        "name": obj.name,
        "revision": obj.revision,
        "updated_at": iso(obj.updated_at),
        "device": obj.device,
        "deleted": obj.deleted,
        "size": obj.size,
        "sha256": obj.sha256,
        "payload": None if obj.deleted else obj.payload,
    })


def put_object(request, name):
    if not check_object_name(name):
        return err("name_invalid", "对象名不合法", 400)
    data = json_body(request)
    if data is None:
        return err("bad_request", "请求格式错误")
    if limiter.hit(f"put:{request.phix_user.id}", limit=600, window_seconds=60):
        return err("rate_limited", "写入太频繁", 429)

    deleted = data.get("deleted") is True
    payload = data.get("payload")
    if deleted:
        payload = ""
    elif not isinstance(payload, str) or not payload:
        return err("bad_request", "payload 必须是非空字符串（密文信封）")
    elif not payload.startswith("PHIX1."):
        return err("bad_request", "payload 必须是 PHIX1 信封")

    res, e = _write_object(
        request.phix_user, name, data.get("base_revision"), payload,
        data.get("device", ""), deleted=deleted,
    )
    if e:
        return e
    log.info("push user=%s name=%s rev=%s size=%s",
             request.phix_user.username, name, res["revision"], res["size"])
    return ok(res)


def delete_object(request, name):
    """删除 = 写墓碑（revision 照常 +1），防止被别的设备同步回来。"""
    if not check_object_name(name):
        return err("name_invalid", "对象名不合法", 400)
    obj = SyncObject.objects.filter(user=request.phix_user, name=name).first()
    if obj is None:
        return err("not_found", "云端没有这个对象", 404)
    base = request.GET.get("base_revision")
    res, e = _write_object(
        request.phix_user, name, base if base is not None else obj.revision,
        "", getattr(request, "phix_token").device, deleted=True,
    )
    if e:
        return e
    return ok(res)


# ---------------- 批量 ----------------

@require_POST
@require_token
def batch(request):
    data = json_body(request)
    if data is None:
        return err("bad_request", "请求格式错误")
    items = data.get("objects")
    if not isinstance(items, list) or not items:
        return err("bad_request", "objects 必须是非空数组")
    if len(items) > settings.PHIX_MAX_BATCH:
        return err("bad_request", f"单次最多 {settings.PHIX_MAX_BATCH} 个对象")
    user = request.phix_user
    if limiter.hit(f"batch:{user.id}", limit=120, window_seconds=60):
        return err("rate_limited", "写入太频繁", 429)

    results = []
    for it in items:
        if not isinstance(it, dict):
            results.append({"name": None, "ok": False, "code": "bad_request"})
            continue
        name = it.get("name")
        if not check_object_name(name):
            results.append({"name": name, "ok": False, "code": "name_invalid"})
            continue
        deleted = it.get("deleted") is True
        payload = it.get("payload")
        if deleted:
            payload = ""
        elif not isinstance(payload, str) or not payload.startswith("PHIX1."):
            results.append({"name": name, "ok": False, "code": "bad_request"})
            continue
        res, e = _write_object(user, name, it.get("base_revision"), payload,
                               it.get("device", ""), deleted=deleted)
        if e:
            body = e.content
            import json as _json

            try:
                parsed = _json.loads(body.decode("utf-8"))
                code = parsed.get("error", {}).get("code", "server_error")
            except Exception:  # noqa: BLE001
                code = "server_error"
            cur = SyncObject.objects.filter(user=user, name=name).first()
            results.append({
                "name": name, "ok": False, "code": code,
                "current": ({"revision": cur.revision,
                             "updated_at": iso(cur.updated_at)} if cur else None),
            })
        else:
            results.append({"name": name, "ok": True, "revision": res["revision"],
                            "updated_at": res["updated_at"], "sha256": res["sha256"]})
    return ok({"results": results})


# ---------------- 历史版本 ----------------

@require_GET
@require_token
def revisions(request, name):
    if not check_object_name(name):
        return err("name_invalid", "对象名不合法", 400)
    obj = SyncObject.objects.filter(user=request.phix_user, name=name).first()
    if obj is None:
        return err("not_found", "云端没有这个对象", 404)
    want = request.GET.get("rev")
    qs = obj.history.all()
    if want is not None:
        try:
            want = int(want)
        except ValueError:
            return err("bad_request", "rev 必须是整数")
        row = qs.filter(revision=want).first()
        if row is None:
            return err("not_found", "没有这个历史版本", 404)
        return ok({
            "name": name, "revision": row.revision,
            "updated_at": iso(row.created_at), "device": row.device,
            "deleted": row.deleted, "size": row.size, "sha256": row.sha256,
            "payload": None if row.deleted else row.payload,
        })
    return ok({
        "name": name,
        "revisions": [
            {"revision": r.revision, "updated_at": iso(r.created_at),
             "device": r.device, "size": r.size, "sha256": r.sha256,
             "deleted": r.deleted}
            for r in qs
        ],
    })


# ---------------- 单对象入口（GET / PUT / DELETE 分发） ----------------

@require_http_methods(["GET", "PUT", "DELETE"])
@require_token
def object_view(request, name):
    if request.method == "GET":
        return get_object(request, name)
    if request.method == "PUT":
        return put_object(request, name)
    return delete_object(request, name)
