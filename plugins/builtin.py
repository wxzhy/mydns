"""内置 Hook 插件。"""

from __future__ import annotations

from core.context import QueryContext
from core.hooks import RequestHook, ResolverHook, ResponseHook
from core.models import ResolverResult


class NoopRequestHook(RequestHook):
    """请求阶段空操作插件。"""

    async def on_request(self, ctx: QueryContext) -> None:
        _ = ctx


class NoopResolverHook(ResolverHook):
    """上游结果阶段空操作插件。"""

    async def on_resolver_result(
        self,
        ctx: QueryContext,
        result: ResolverResult,
    ) -> ResolverResult | None:
        _ = ctx
        return result


class NoopResponseHook(ResponseHook):
    """响应阶段空操作插件。"""

    async def on_response(self, ctx: QueryContext) -> None:
        _ = ctx
