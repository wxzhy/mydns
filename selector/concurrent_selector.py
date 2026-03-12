from __future__ import annotations

import asyncio
from dataclasses import dataclass
from time import monotonic
from typing import Sequence

import dns.message

from core.context import QueryContext
from resolvers.resolver import Resolver


@dataclass(slots=True)
class ResolverRaceResult:
    """并发竞速结果。"""

    response: dns.message.Message
    winner: Resolver
    elapsed_ms: float
    errors: tuple[str, ...]


@dataclass(slots=True)
class ResolverBatchSuccess:
    """单个上游成功结果。"""

    resolver: Resolver
    response: dns.message.Message
    elapsed_ms: float


@dataclass(slots=True)
class ResolverBatchResult:
    """并发请求全部上游后的聚合结果。"""

    successes: tuple[ResolverBatchSuccess, ...]
    errors: tuple[str, ...]


async def resolve_fastest(
    resolvers: Sequence[Resolver],
    context: QueryContext,
    query: dns.message.Message,
) -> ResolverRaceResult:
    """并发请求所有 resolver，返回首个成功结果。"""
    if not resolvers:
        raise ValueError("Resolver 列表不能为空。")

    started_at = monotonic()
    tasks: dict[asyncio.Task[dns.message.Message], Resolver] = {
        asyncio.create_task(resolver.resolve(context, query)): resolver
        for resolver in resolvers
    }
    errors: list[str] = []

    try:
        while tasks:
            done, _ = await asyncio.wait(
                tasks.keys(),
                return_when=asyncio.FIRST_COMPLETED,
            )
            for task in done:
                resolver = tasks.pop(task)
                try:
                    response = task.result()
                except Exception as exc:  # pragma: no cover
                    errors.append(f"{resolver.name}: {exc}")
                    continue

                for pending_task in tasks:
                    pending_task.cancel()
                if tasks:
                    await asyncio.gather(*tasks.keys(), return_exceptions=True)

                return ResolverRaceResult(
                    response=response,
                    winner=resolver,
                    elapsed_ms=(monotonic() - started_at) * 1000,
                    errors=tuple(errors),
                )
    except asyncio.CancelledError:  # pragma: no cover
        for task in tasks:
            task.cancel()
        if tasks:
            await asyncio.gather(*tasks.keys(), return_exceptions=True)
        raise

    error_detail = "; ".join(errors) if errors else "无可用错误详情"
    raise RuntimeError(f"所有 Resolver 均解析失败：{error_detail}")


async def resolve_all(
    resolvers: Sequence[Resolver],
    context: QueryContext,
    query: dns.message.Message,
) -> ResolverBatchResult:
    """并发请求全部 resolver，收集所有成功响应。"""
    if not resolvers:
        raise ValueError("Resolver 列表不能为空。")

    async def _call_one(
        resolver: Resolver,
    ) -> tuple[Resolver, dns.message.Message | None, float, Exception | None]:
        started_at = monotonic()
        try:
            response = await resolver.resolve(context, query)
        except Exception as exc:  # pragma: no cover
            return resolver, None, (monotonic() - started_at) * 1000, exc
        return resolver, response, (monotonic() - started_at) * 1000, None

    tasks = [asyncio.create_task(_call_one(resolver)) for resolver in resolvers]
    successes: list[ResolverBatchSuccess] = []
    errors: list[str] = []

    try:
        for task in asyncio.as_completed(tasks):
            resolver, response, elapsed_ms, error = await task
            if error is not None:
                errors.append(f"{resolver.name}: {error}")
                continue
            if response is None:  # pragma: no cover
                errors.append(f"{resolver.name}: empty response")
                continue
            successes.append(
                ResolverBatchSuccess(
                    resolver=resolver,
                    response=response,
                    elapsed_ms=elapsed_ms,
                )
            )
    except asyncio.CancelledError:  # pragma: no cover
        for task in tasks:
            task.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)
        raise

    return ResolverBatchResult(
        successes=tuple(successes),
        errors=tuple(errors),
    )
