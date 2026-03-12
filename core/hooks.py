from __future__ import annotations

from collections.abc import Iterable
from typing import Protocol, TypeAlias

import dns.message

from core.context import QueryContext

HookReturn: TypeAlias = dns.message.Message | None


class RequestHook(Protocol):
    async def before_upstream(
        self,
        context: QueryContext,
        query: dns.message.Message,
    ) -> HookReturn:
        """上游请求前执行。

        返回 DNS 响应可直接短路后续解析流程。
        返回 None 则继续执行后续 hook / resolver。
        """


class UpstreamHook(Protocol):
    async def after_upstream(
        self,
        context: QueryContext,
        query: dns.message.Message,
        response: dns.message.Message,
        resolver_name: str,
    ) -> HookReturn:
        """每个上游 resolver 返回后执行。

        返回 DNS 响应可覆盖当前结果。
        返回 None 则保持当前结果不变。
        """


class ResponseHook(Protocol):
    async def before_response(
        self,
        context: QueryContext,
        query: dns.message.Message,
        response: dns.message.Message,
    ) -> HookReturn:
        """最终响应发回客户端前执行。

        返回 DNS 响应可覆盖当前结果。
        返回 None 则保持当前结果不变。
        """


PipelineHook: TypeAlias = RequestHook | UpstreamHook | ResponseHook


class RequestHooks:
    def __init__(self, hooks: Iterable[PipelineHook] | None = None) -> None:
        self._hooks = tuple(hooks or ())

    async def run_before_upstream(
        self,
        context: QueryContext,
        query: dns.message.Message,
    ) -> dns.message.Message | None:
        for hook in self._hooks:
            before_upstream = getattr(hook, "before_upstream", None)
            if not callable(before_upstream):
                continue
            result = await before_upstream(context, query)
            if result is not None:
                return result
        return None

    async def run_after_upstream(
        self,
        context: QueryContext,
        query: dns.message.Message,
        response: dns.message.Message,
        resolver_name: str,
    ) -> dns.message.Message:
        current_response = response
        for hook in self._hooks:
            after_upstream = getattr(hook, "after_upstream", None)
            if not callable(after_upstream):
                continue
            result = after_upstream(
                context,
                query,
                current_response,
                resolver_name,
            )
            result = await result
            if result is not None:
                current_response = result
        return current_response

    async def run_before_response(
        self,
        context: QueryContext,
        query: dns.message.Message,
        response: dns.message.Message,
    ) -> dns.message.Message:
        current_response = response
        for hook in self._hooks:
            before_response = getattr(hook, "before_response", None)
            if not callable(before_response):
                continue
            result = before_response(
                context,
                query,
                current_response,
            )
            result = await result
            if result is not None:
                current_response = result
        return current_response
