# -*- coding: utf-8 -*-
"""长轮询（`/api/v1/sync/watch`）的测试。

分三层：
  1. `syncwatch` 纯逻辑（不起 Django / 不碰库）；
  2. 光标本身：写入或删除必须让它变化，否则客户端永远等不到；
  3. 视图：真的通过 HTTP 挂住、真的被写入叫醒。
"""
from __future__ import annotations

import threading
import time
from unittest import mock

from django.contrib.auth import get_user_model
from django.test import Client, TestCase, TransactionTestCase

from api import syncwatch
from api.models import SyncObject
from api.utils import limiter


def _session_token(user):
    from .views_auth import _issue_session

    creds, _sess, _copy = _issue_session(user, "长轮询测试")
    return creds["access_token"]


class SyncWatchUnitTest(TestCase):
    """纯逻辑：不碰数据库。"""

    def test_returns_immediately_when_cursor_already_differs(self):
        t0 = time.monotonic()
        changed, cursor = syncwatch.wait_for_change(lambda: "2", "1", max_hold=5)
        self.assertTrue(changed)
        self.assertEqual(cursor, "2")
        self.assertLess(time.monotonic() - t0, 0.5, "光标已经不同就该立刻回")

    def test_times_out_without_a_change(self):
        t0 = time.monotonic()
        changed, cursor = syncwatch.wait_for_change(lambda: "1", "1", max_hold=0.4)
        took = time.monotonic() - t0
        self.assertFalse(changed, "没人改就该超时返回 changed=False")
        self.assertEqual(cursor, "1")
        self.assertGreaterEqual(took, 0.35)
        self.assertLess(took, 2.0, "不该挂过头")

    def test_rechecks_the_cursor_repeatedly(self):
        """挂起期间要反复回查 —— 多 worker 时 notify 叫不到这个进程，全靠它兜底。"""
        calls = {"n": 0}

        def read():
            calls["n"] += 1
            return "1"

        changed, _ = syncwatch.wait_for_change(read, "1", max_hold=0.3)
        self.assertFalse(changed)
        self.assertGreater(calls["n"], 1, "应该反复回查，而不是睡一觉就完")

    def test_bump_wakes_the_waiter_immediately(self):
        """这是长轮询相对"定时间隔去问"的全部价值：别人一改，这边马上醒。"""
        state = {"bumped": False, "changed": None, "took": None}

        def read():
            return "2" if state["bumped"] else "1"

        def waiter():
            t0 = time.monotonic()
            state["changed"], _ = syncwatch.wait_for_change(read, "1", max_hold=10)
            state["took"] = time.monotonic() - t0

        th = threading.Thread(target=waiter)
        th.start()
        time.sleep(0.3)
        state["bumped"] = True
        syncwatch.bump()
        th.join(timeout=5)
        self.assertFalse(th.is_alive(), "bump 之后应该立刻返回，不该继续挂着")
        self.assertTrue(state["changed"])
        self.assertLess(state["took"], 2.0, f"应该被叫醒，实际等了 {state['took']}")


class SyncWatchCursorTest(TestCase):
    """光标是这套机制的正确性核心：任何变化都必须让它变。"""

    def setUp(self):
        limiter.clear()
        self.user = get_user_model().objects.create_user(
            username="watchcursor", password="Unit-Test-Pw-1")

    def _cursor(self):
        from api.views_sync import _cursor
        return _cursor(self.user)

    def test_cursor_changes_when_an_object_is_written(self):
        before = self._cursor()
        SyncObject.objects.create(user=self.user, name="settings.ui", revision=1,
                                  device="t", payload="x", size=1, sha256="a" * 64)
        self.assertNotEqual(before, self._cursor(), "写入必须让光标变化")

    def test_cursor_changes_on_delete(self):
        obj = SyncObject.objects.create(user=self.user, name="schedule", revision=1,
                                        device="t", payload="x", size=1, sha256="a" * 64)
        before = self._cursor()
        obj.deleted = True
        obj.revision = 2
        obj.payload = ""
        obj.save(update_fields=["deleted", "revision", "payload", "updated_at"])
        self.assertNotEqual(before, self._cursor(), "删除也要让光标变化")

    def test_cursor_is_stable_without_changes(self):
        SyncObject.objects.create(user=self.user, name="timetable", revision=1,
                                  device="t", payload="x", size=1, sha256="a" * 64)
        self.assertEqual(self._cursor(), self._cursor(), "没变化时光标必须一样")


class SyncWatchViewTest(TransactionTestCase):
    """视图层：真的走 HTTP，真的挂住，真的被写入叫醒。"""

    def setUp(self):
        limiter.clear()
        self.user = get_user_model().objects.create_user(
            username="watchview", password="Unit-Test-Pw-1")
        self.token = _session_token(self.user)
        self.client = Client()

    def _watch(self, cursor=""):
        url = "/api/v1/sync/watch"
        if cursor:
            url += f"?cursor={cursor}"
        return self.client.get(url, HTTP_AUTHORIZATION=f"Bearer {self.token}")

    def test_without_cursor_returns_current_state_immediately(self):
        t0 = time.monotonic()
        resp = self._watch()
        self.assertEqual(resp.status_code, 200)
        body = resp.json()
        self.assertTrue(body.get("ok"))
        self.assertFalse(body.get("changed"))
        self.assertTrue(body.get("cursor"), "要给出光标，客户端下次带着它来")
        self.assertLess(time.monotonic() - t0, 1.0, "没带光标时不该挂")

    def test_returns_immediately_when_already_out_of_date(self):
        first = self._watch().json()["cursor"]
        SyncObject.objects.create(user=self.user, name="settings.ui", revision=1,
                                  device="t", payload="x", size=1, sha256="a" * 64)
        t0 = time.monotonic()
        body = self._watch(first).json()
        self.assertTrue(body["changed"], "光标过期就该立刻说变了")
        self.assertLess(time.monotonic() - t0, 1.0)
        self.assertIn("objects", body, "变了就顺带把清单带上，省一次往返")

    def test_hangs_then_times_out(self):
        cursor = self._watch().json()["cursor"]
        with mock.patch.object(syncwatch, "MAX_HOLD_SECONDS", 0.6):
            t0 = time.monotonic()
            body = self._watch(cursor).json()
            took = time.monotonic() - t0
        self.assertFalse(body["changed"], "没人改就该超时返回")
        self.assertGreaterEqual(took, 0.5)
        self.assertLess(took, 3.0)
        self.assertEqual(body["cursor"], cursor)

    def test_write_from_another_thread_wakes_it_up(self):
        """真实场景：另一台设备写进来，挂着的这个请求应该马上返回。"""
        cursor = self._watch().json()["cursor"]
        result: dict = {}

        def writer():
            time.sleep(0.4)
            SyncObject.objects.create(user=self.user, name="schedule", revision=1,
                                      device="another-device", payload="y", size=1,
                                      sha256="b" * 64)
            syncwatch.bump()

        th = threading.Thread(target=writer)
        th.start()
        t0 = time.monotonic()
        body = self._watch(cursor).json()
        result["took"] = time.monotonic() - t0
        th.join(timeout=5)
        self.assertTrue(body["changed"], "别的设备写了，就该说变了")
        self.assertLess(result["took"], 3.0, f"应该被叫醒，实际等了 {result['took']:.2f}s")

    def test_requires_auth(self):
        resp = self.client.get("/api/v1/sync/watch")
        self.assertIn(resp.status_code, (401, 403), "长轮询也要鉴权，不能白挂")
