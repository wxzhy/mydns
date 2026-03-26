"""DNS 三阶段流水线。"""

from __future__ import annotations

import dns.rcode

from core.answer import Answer
from core.cache import fail_pending_request, resolve_pending_request
from core.context import QueryContext
from core.hooks import RequestHook, ResolverHook, ResponseHook
from core.models import Query
from logger import get_logger
from resolver.resolver import Resolver
from upstream.resolver_manager import ResolverManager


logger = get_logger("core.pipeline")


class Pipeline:
    """请求处理管道：request -> upstream -> response。"""

    def __init__(
        self,
        *,
        resolvers: list[Resolver] | None = None,
        resolver_hooks: list[ResolverHook] | None = None,
        request_hooks: list[RequestHook] | None = None,
        response_hooks: list[ResponseHook] | None = None,
        upstream_timeout_s: float = 0.8,
    ) -> None:
        self.request_hooks = request_hooks or []
        self.response_hooks = response_hooks or []
        # 固定在初始化阶段创建 resolver manager。
        self.resolver_manager = ResolverManager(
            resolvers=resolvers,
            resolver_hooks=resolver_hooks,
        )
        self.upstream_timeout_s = upstream_timeout_s

    async def process(self, ctx: QueryContext) -> Answer:
        """执行完整流水线并返回最终响应。"""
        return await self._process_with_timeout(ctx, self.upstream_timeout_s)

    async def resolve(
        self,
        query: Query,
        timeout_s: float | None = None,
    ) -> Answer:
        """以 resolver 风格发起一次内部查询，并返回最终 Answer。"""
        ctx = QueryContext(query=query)
        effective_timeout_s = self.upstream_timeout_s if timeout_s is None else timeout_s
        return await self._process_with_timeout(ctx, effective_timeout_s)

    async def _process_with_timeout(
        self,
        ctx: QueryContext,
        timeout_s: float,
    ) -> Answer:
        try:
            ctx.state["pipeline"] = self
            logger.debug(
                "处理请求 qname=%s qtype=%s client=%s tags=%s",
                ctx.query.qname.to_text(),
                ctx.query.qtype,
                ctx.query.client_addr,
                sorted(ctx.tags),
            )
            await self._run_request_hooks(ctx)
            if not ctx.stop:
                await self._run_upstream(ctx, timeout_s)
            else:
                logger.debug("请求被request hook短路 qname=%s", ctx.query.qname.to_text())

            await self._run_response_hooks(ctx)
            if ctx.final_answer is None:
                ctx.final_answer = self._fallback_answer(ctx)
            await resolve_pending_request(ctx.state, ctx.final_answer)
            logger.debug(
                "响应完成 qname=%s qtype=%s rcode=%s rrset_count=%s candidate_count=%s",
                ctx.query.qname.to_text(),
                ctx.query.qtype,
                ctx.final_answer.response.rcode(),
                len(ctx.final_answer.response.answer),
                len(ctx.candidates),
            )
            return ctx.final_answer
        except BaseException as exc:
            await fail_pending_request(ctx.state, exc)
            raise

    async def _run_request_hooks(self, ctx: QueryContext) -> None:
        for hook in self.request_hooks:
            await hook.on_request(ctx)
            if ctx.stop:
                break

    async def _run_upstream(self, ctx: QueryContext, timeout_s: float) -> None:
        await self.resolver_manager.collect(ctx, timeout_s)

    async def _run_response_hooks(self, ctx: QueryContext) -> None:
        for hook in self.response_hooks:
            await hook.on_response(ctx)

    def _fallback_answer(self, ctx: QueryContext) -> Answer:
        logger.debug(
            "响应阶段未生成最终答案，返回SERVFAIL qname=%s qtype=%s candidates=%s",
            ctx.query.qname.to_text(),
            ctx.query.qtype,
            [
                {
                    "resolver": item.resolver_name,
                    "elapsed_ms": item.elapsed_ms,
                    "rcode": item.answer.response.rcode()
                    if item.answer is not None
                    else None,
                    "error": repr(item.error) if item.error else None,
                }
                for item in ctx.candidates
            ],
        )
        return Answer.from_query(ctx.query, rcode=dns.rcode.SERVFAIL, tags=ctx.tags)
