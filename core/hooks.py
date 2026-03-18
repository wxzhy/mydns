from __future__ import annotations

"""三阶段流水线 Hook 协议定义与调度器。"""

from collections.abc import Iterable
from typing import Protocol

import dns.rcode
import dns.rrset

from core.context import QueryContext


class RequestHook(Protocol):
    async def before_upstream(self, context: QueryContext) -> None:
        """上游请求前执行。

        可设置 context.rcode / context.answer 来短路后续解析流程。
        """


class UpstreamHook(Protocol):
    async def after_upstream(
        self,
        context: QueryContext,
        rcode: dns.rcode.Rcode,
        answer: list[dns.rrset.RRset],
        resolver_name: str,
    ) -> None:
        """每个上游 resolver 返回后执行（副作用，如日志、测速）。

        并发解析时多个 resolver 共享同一 context，每次调用的结果通过参数传入。
        """


class ResponseHook(Protocol):
    async def before_response(self, context: QueryContext) -> None:
        """最终响应发回客户端前执行。

        可直接修改 context.rcode / context.answer。
        """


PipelineHook = RequestHook | UpstreamHook | ResponseHook


class RequestHooks:
    """按顺序执行 request/upstream/response 三类 hook。"""

    def __init__(self, hooks: Iterable[PipelineHook] | None = None) -> None:
        self._hooks = tuple(hooks or ())

    async def run_before_upstream(self, context: QueryContext) -> None:
        """执行请求阶段 Hook，若已生成应答则提前结束。"""
        for hook in self._hooks:
            before_upstream = getattr(hook, "before_upstream", None)
            if not callable(before_upstream):
                continue
            await before_upstream(context)
            if context.has_answer:
                return

    async def run_after_upstream(
        self,
        context: QueryContext,
        rcode: dns.rcode.Rcode,
        answer: list[dns.rrset.RRset],
        resolver_name: str,
    ) -> None:
        """执行每个 resolver 返回后的 Hook。"""
        for hook in self._hooks:
            after_upstream = getattr(hook, "after_upstream", None)
            if not callable(after_upstream):
                continue
            await after_upstream(context, rcode, answer, resolver_name)

    async def run_before_response(self, context: QueryContext) -> None:
        """执行响应阶段 Hook。"""
        for hook in self._hooks:
            before_response = getattr(hook, "before_response", None)
            if not callable(before_response):
                continue
            await before_response(context)
