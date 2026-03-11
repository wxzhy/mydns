from __future__ import annotations

from collections.abc import Awaitable, Iterable
from inspect import isawaitable
from typing import Protocol, TypeAlias

import dns.message

from core.context import QueryContext

HookReturn: TypeAlias = dns.message.Message | None
HookReturnOrAwaitable: TypeAlias = HookReturn | Awaitable[HookReturn]


class RequestHook(Protocol):
    def before_upstream(
        self,
        context: QueryContext,
        query: dns.message.Message,
    ) -> HookReturnOrAwaitable:
        """Run before forwarding to upstream.

        Return a DNS response message to short-circuit upstream resolution.
        Return None to continue to next hook / resolver.
        """


class RequestHooks:
    def __init__(self, hooks: Iterable[RequestHook] | None = None) -> None:
        self._hooks = tuple(hooks or ())

    async def run_before_upstream(
        self,
        context: QueryContext,
        query: dns.message.Message,
    ) -> dns.message.Message | None:
        for hook in self._hooks:
            result = hook.before_upstream(context, query)
            if isawaitable(result):
                result = await result
            if result is not None:
                return result
        return None
