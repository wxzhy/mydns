"""上游解析器并发管理。"""

from __future__ import annotations

import asyncio
import time

from core.context import QueryContext
from core.hooks import Resolver, ResolverHook
from core.models import ResolverResult


class ResolverManager:
    """负责筛选上游、并发请求与 resolver hook 调用。"""

    def __init__(
        self,
        resolvers: list[Resolver] | None = None,
        resolver_hooks: list[ResolverHook] | None = None,
    ) -> None:
        self.resolvers = resolvers or []
        self.resolver_hooks = resolver_hooks or []

    async def collect(self, ctx: QueryContext, timeout_s: float) -> None:
        """并发收集上游结果，并写入 ctx.candidates。"""
        matched = [r for r in self.resolvers if self._resolver_match_tags(r, ctx.tags)]
        if not matched:
            return

        loop = asyncio.get_running_loop()
        deadline = loop.time() + timeout_s
        pending = {
            asyncio.create_task(self._query_one(resolver, ctx, timeout_s))
            for resolver in matched
        }

        while pending:
            remaining = deadline - loop.time()
            if remaining <= 0:
                break

            done, pending = await asyncio.wait(
                pending,
                timeout=remaining,
                return_when=asyncio.FIRST_COMPLETED,
            )
            if not done:
                break

            for task in done:
                result = task.result()
                processed = await self._run_resolver_hooks(ctx, result)
                if processed is not None:
                    ctx.candidates.append(processed)

        for task in pending:
            task.cancel()
        if pending:
            await asyncio.gather(*pending, return_exceptions=True)

    @staticmethod
    def _resolver_match_tags(resolver: Resolver, tags: set[str]) -> bool:
        if not getattr(resolver, "tags", None):
            return True
        return bool(resolver.tags & tags)

    async def _query_one(
        self,
        resolver: Resolver,
        ctx: QueryContext,
        timeout_s: float,
    ) -> ResolverResult:
        start = time.perf_counter()
        try:
            answer = await asyncio.wait_for(
                resolver.resolve(ctx.query, timeout_s),
                timeout=timeout_s,
            )
            error: Exception | None = None
        except Exception as exc:
            answer = None
            error = exc
        elapsed_ms = (time.perf_counter() - start) * 1000
        return ResolverResult(
            resolver_name=resolver.name,
            answer=answer,
            elapsed_ms=elapsed_ms,
            error=error,
        )

    async def _run_resolver_hooks(
        self,
        ctx: QueryContext,
        result: ResolverResult,
    ) -> ResolverResult | None:
        current: ResolverResult | None = result
        for hook in self.resolver_hooks:
            if current is None:
                return None
            current = await hook.on_resolver_result(ctx, current)
        return current
