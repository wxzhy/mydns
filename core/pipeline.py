"""DNS 三阶段流水线。"""

from __future__ import annotations

import dns.rcode

from core.context import QueryContext
from core.hooks import RequestHook, Resolver, ResolverHook, ResponseHook
from core.models import Answer
from core.resolver_manager import ResolverManager
from core.selector import select_best_answer


class Pipeline:
    """请求处理管道：request -> upstream -> response。"""

    def __init__(
        self,
        *,
        resolvers: list[Resolver] | None = None,
        resolver_hooks: list[ResolverHook] | None = None,
        request_hooks: list[RequestHook] | None = None,
        response_hooks: list[ResponseHook] | None = None,
        resolver_manager: ResolverManager | None = None,
        upstream_timeout_s: float = 0.8,
    ) -> None:
        self.request_hooks = request_hooks or []
        self.response_hooks = response_hooks or []
        self.resolver_manager = resolver_manager or ResolverManager(
            resolvers=resolvers,
            resolver_hooks=resolver_hooks,
        )
        self.upstream_timeout_s = upstream_timeout_s

    async def process(self, ctx: QueryContext) -> Answer:
        """执行完整流水线并返回最终响应。"""
        await self._run_request_hooks(ctx)
        if not ctx.stop:
            await self._run_upstream(ctx)

        if ctx.final_answer is None:
            ctx.final_answer = self._fallback_answer(ctx)

        await self._run_response_hooks(ctx)
        return ctx.final_answer

    async def _run_request_hooks(self, ctx: QueryContext) -> None:
        for hook in self.request_hooks:
            await hook.on_request(ctx)
            if ctx.stop:
                break

    async def _run_upstream(self, ctx: QueryContext) -> None:
        await self.resolver_manager.collect(ctx, self.upstream_timeout_s)

    async def _run_response_hooks(self, ctx: QueryContext) -> None:
        for hook in self.response_hooks:
            await hook.on_response(ctx)

    def _fallback_answer(self, ctx: QueryContext) -> Answer:
        return select_best_answer(ctx)
