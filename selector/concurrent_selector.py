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
