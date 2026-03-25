"""上游解析器并发管理。"""

from __future__ import annotations

import asyncio
import time

import dns.rcode
import dns.rdatatype

from core.context import QueryContext
from core.hooks import ResolverHook
from core.models import ResolverResult
from logger import get_logger
from resolver.resolver import Resolver


logger = get_logger("upstream.resolver_manager")


class ResolverManager:
    """负责筛选上游、并发请求与 resolver hook 调用。"""

    def __init__(
        self,
        resolvers: list[Resolver] | None = None,
        resolver_hooks: list[ResolverHook] | None = None,
        resolver_hook_timeout_s: float = 0.25,
    ) -> None:
        self.resolvers = resolvers or []
        self.resolver_hooks = resolver_hooks or []
        self.resolver_hook_timeout_s = max(0.01, resolver_hook_timeout_s)

    async def collect(self, ctx: QueryContext, timeout_s: float) -> None:
        """并发收集上游结果，并写入 ctx.candidates。"""
        matched = [r for r in self.resolvers if self._resolver_match_tags(r, ctx.tags)]
        wait_all = _need_wait_all_results(ctx.query.qtype)
        logger.debug(
            "开始上游并发查询 qname=%s qtype=%s tags=%s matched=%s timeout=%.3fs strategy=%s",
            ctx.query.qname.to_text(),
            ctx.query.qtype,
            sorted(ctx.tags),
            [x.name for x in matched],
            timeout_s,
            "wait_all" if wait_all else "first_success",
        )
        if not matched:
            return

        for resolver in matched:
            effective_timeout_s = resolver.effective_timeout(timeout_s)
            logger.debug(
                "并发调度 resolver=%s qname=%s qtype=%s timeout=%.3fs",
                resolver.name,
                ctx.query.qname.to_text(),
                ctx.query.qtype,
                effective_timeout_s,
            )

        tasks = [
            asyncio.create_task(self._query_one(resolver, ctx, timeout_s))
            for resolver in matched
        ]

        for completed in asyncio.as_completed(tasks):
            result = await completed
            processed = await self._run_resolver_hooks(ctx, result)
            if processed is not None:
                ctx.candidates.append(processed)
                logger.debug(
                    "上游结果保留 resolver=%s elapsed_ms=%.2f rcode=%s error=%s",
                    processed.resolver_name,
                    processed.elapsed_ms or -1,
                    processed.answer.response.rcode()
                    if processed.answer is not None
                    else None,
                    repr(processed.error) if processed.error else None,
                )
                if not wait_all and _is_normal_result(processed):
                    ctx.final_answer = processed.answer
                    logger.debug(
                        "非A/AAAA已获得首个正常结果 resolver=%s，写入final_answer并提前结束等待",
                        processed.resolver_name,
                    )
                    break
            else:
                logger.debug(
                    "上游结果被hook丢弃 resolver=%s",
                    result.resolver_name,
                )

        pending = [task for task in tasks if not task.done()]
        for task in pending:
            task.cancel()
        if pending:
            await asyncio.gather(*pending, return_exceptions=True)
            logger.debug(
                "已取消未完成上游任务 qname=%s qtype=%s canceled=%s",
                ctx.query.qname.to_text(),
                ctx.query.qtype,
                len(pending),
            )

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
        effective_timeout_s = resolver.effective_timeout(timeout_s)
        logger.debug(
            "上游请求开始 resolver=%s qname=%s qtype=%s timeout=%.3fs",
            resolver.name,
            ctx.query.qname.to_text(),
            ctx.query.qtype,
            effective_timeout_s,
        )
        try:
            answer = await asyncio.wait_for(
                resolver.resolve(ctx.query, effective_timeout_s),
                timeout=effective_timeout_s,
            )
            answer.tags = set(ctx.tags)
            error: Exception | None = None
            logger.debug(
                "收到上游响应 resolver=%s qname=%s qtype=%s rcode=%s rrset_count=%s",
                resolver.name,
                ctx.query.qname.to_text(),
                ctx.query.qtype,
                answer.response.rcode(),
                len(answer.response.answer),
            )
        except Exception as exc:
            answer = None
            error = exc
            logger.debug(
                "上游请求异常 resolver=%s qname=%s qtype=%s err=%r",
                resolver.name,
                ctx.query.qname.to_text(),
                ctx.query.qtype,
                exc,
            )
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
            try:
                current = await asyncio.wait_for(
                    hook.on_resolver_result(ctx, current),
                    timeout=self.resolver_hook_timeout_s,
                )
            except TimeoutError:
                # 单个 hook 超时不影响本次请求，保留当前结果继续。
                logger.debug(
                    "resolver hook超时，已忽略 resolver=%s hook=%s qname=%s qtype=%s timeout=%.3fs",
                    current.resolver_name,
                    hook.__class__.__name__,
                    ctx.query.qname.to_text(),
                    ctx.query.qtype,
                    self.resolver_hook_timeout_s,
                )
            except Exception:
                # 单个 hook 异常不应影响整个请求流程，保留当前结果继续后续处理。
                logger.exception(
                    "resolver hook异常，已忽略 resolver=%s hook=%s qname=%s qtype=%s",
                    current.resolver_name,
                    hook.__class__.__name__,
                    ctx.query.qname.to_text(),
                    ctx.query.qtype,
                )
        return current


def _need_wait_all_results(qtype: dns.rdatatype.RdataType) -> bool:
    return qtype in {dns.rdatatype.A, dns.rdatatype.AAAA}


def _is_normal_result(result: ResolverResult) -> bool:
    return (
        result.error is None
        and result.answer is not None
        and result.answer.response.rcode() == dns.rcode.NOERROR
    )
