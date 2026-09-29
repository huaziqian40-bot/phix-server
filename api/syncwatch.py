# -*- coding: utf-8 -*-
"""长轮询：让客户端"有变化就立刻知道"，而不是自己定时去问。

用户 2026-09-28 要求把同步延迟压到秒级。原来的做法是客户端定时全量同步
（PHL 每秒一次、PHL Lite 每 10 分钟一次），延迟最坏等于那个间隔。

这里加一个 `GET /api/v1/sync/watch`：请求进来后服务端**挂着不回**，
直到这个账号的云端真的变了（或者挂满 ~25 秒超时），再返回。
客户端拿到"变了"就立刻跑一次正常的同步 —— 延迟从"一个轮询间隔"变成"一个 RTT"。

为什么不用 WebSocket：服务端是 Django + **Waitress**（纯 WSGI，不支持 WS），
上 WS 要换 ASGI + Channels + Redis + 改 systemd 与 Cloudflare 配置，
而在这个场景里长轮询和 WS 的延迟都是**一个 RTT**，人眼分不出来。
长轮询在现有栈上零基础设施改动就能跑。详见 `docs/同步实时化.md`。

**正确性靠数据库，不靠这个进程内的计数器**：光标（cursor）是从库里的
`SyncObject` 现算的，所以换 worker、重启服务都不会漏掉变化；
进程内的 `Condition` 只是让"变了"能立刻叫醒等待的请求，不做判断依据。

**挂起请求是有代价的**：waitress 每个连接占一个线程，所以这里用 `WATCH_SLOTS`
限住同时挂起的个数，超出的立刻打回让客户端短轮询 —— 详见那个常量的注释。
"""
from __future__ import annotations

import os
import threading
import time

#: 一次长轮询最多挂多久（秒）。比 Cloudflare 的 ~100 秒空闲断连留足余量，
#: 也让客户端在 NAT/代理掐连接之前自己先返回。
MAX_HOLD_SECONDS = 25.0

#: 即便没人 notify，也至少每隔这么久回库里看一眼。
#: 进程内 notify 只覆盖"写请求也在这台 worker 上"这一种情况；
#: 多 worker 时另一个 worker 写的就收不到 notify，靠这个兜底。
POLL_FALLBACK_SECONDS = 2.0

#: 同时最多挂起多少个长轮询。
#:
#: **这个上限是必须的，不是保守**：waitress 是线程池模型（`--threads=N`），
#: 一个挂起的请求就**实打实占住一个线程**整整 25 秒。假如线程数是 8 而同时
#: 有 8 个客户端挂在这儿，服务端就再也接不了任何别的请求 —— 连"把数据写进去、
#: 好让长轮询醒过来"的那个写请求都要排队，同步从"秒级"直接退化成"卡住"。
#: 也就是说：没有上限的长轮询会把线程池饿死，而且是自己饿死自己。
#:
#: 所以这里拿不到名额就**立刻返回**（`changed=false` + `retry_after`），
#: 让客户端退化成短轮询。客户端最多多等 `retry_after` 秒，仍然是秒级，
#: 但服务端任何时候都留得下线程干正事。
#: 默认值取得比"线程池的 1/4"还保守一点（见 deploy 里的 `--threads`）；
#: 可用环境变量 `PHIX_WATCH_SLOTS` 覆盖。
WATCH_SLOTS = max(1, int(os.environ.get("PHIX_WATCH_SLOTS") or 0) or 6)

#: 拿不到名额时让客户端等多久再来（秒）。**必须给这个提示**：客户端分辨不出
#: "正常挂满 25 秒超时"（应当立刻再挂）和"名额满了被立刻打回"（立刻再挂就是
#: 热循环打服务器），只能靠服务端明确说一声。
BUSY_RETRY_AFTER_SECONDS = 1.0

_cond = threading.Condition()
_generation = 0
_slots = threading.BoundedSemaphore(WATCH_SLOTS)


def try_acquire_slot() -> bool:
    """试着占一个"挂起名额"。拿不到返回 False，调用方应立刻回 `retry_after`。"""
    return _slots.acquire(blocking=False)


def release_slot() -> None:
    """还名额。**必须放在 finally 里** —— 客户端提前断开时 waitress 会抛异常，
    漏还几次名额之后长轮询就等于被永久关掉了。"""
    try:
        _slots.release()
    except ValueError:  # 还多了：说明调用方写错了，但绝不该因此把请求打成 500
        pass


def free_slots() -> int:
    """还剩几个名额（观测用：`/healthz` 或排查"为什么客户端在短轮询"时看）。"""
    return getattr(_slots, "_value", -1)


def bump() -> None:
    """有对象被写入/删除时调一次：叫醒所有正在等的人。"""
    global _generation
    with _cond:
        _generation += 1
        _cond.notify_all()


def generation() -> int:
    with _cond:
        return _generation


def wait_for_bump(since_generation: int, timeout: float) -> bool:
    """等价于 `sleep(timeout)`，但只要有人 bump 就立刻醒。返回是否被 bump 叫醒。"""
    with _cond:
        if _generation != since_generation:
            return True
        _cond.wait(timeout)
        return _generation != since_generation


def wait_for_change(read_cursor, since_cursor: str, max_hold: float | None = None):
    """挂着等，直到 `read_cursor()` 算出来的光标和 `since_cursor` 不一样。

    返回 `(changed, cursor)`：`changed=False` 表示挂满超时了（客户端应立刻再挂一次）。
    `read_cursor` 是一个无参函数，返回当前光标字符串 —— 由调用方决定怎么算
    （见 `views_sync._cursor`），这里不碰数据库，方便单测。

    `max_hold=None` 表示用模块级的 `MAX_HOLD_SECONDS`。**注意是调用时才读**，
    不能写成默认参数值 —— 那是定义时就绑定了，改模块常量（或测试里 patch）
    不会生效（写这一版时就踩过，测试里挂了整整 25 秒）。
    """
    if max_hold is None:
        max_hold = MAX_HOLD_SECONDS
    deadline = time.monotonic() + max_hold
    current = read_cursor()
    if current != since_cursor:
        return True, current
    while True:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            return False, read_cursor()
        gen = generation()
        wait_for_bump(gen, min(POLL_FALLBACK_SECONDS, remaining))
        current = read_cursor()
        if current != since_cursor:
            return True, current
