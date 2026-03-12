from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass

import dns.message

from core.context import QueryContext


@dataclass(slots=True)
class ResolverStats:
    """Resolver 运行时统计信息。"""

    success_count: int = 0
    failure_count: int = 0
    last_rtt_ms: float | None = None
    avg_rtt_ms: float | None = None


class Resolver(ABC):
    def __init__(self, name: str) -> None:
        self._name = name
        self._stats = ResolverStats()

    @property
    def name(self) -> str:
        return self._name

    @property
    def stats(self) -> ResolverStats:
        return self._stats

    def mark_success(self, rtt_ms: float) -> None:
        stats = self._stats
        stats.success_count += 1
        stats.last_rtt_ms = rtt_ms
        if stats.avg_rtt_ms is None:
            stats.avg_rtt_ms = rtt_ms
            return
        previous_successes = stats.success_count - 1
        stats.avg_rtt_ms = (
            (stats.avg_rtt_ms * previous_successes) + rtt_ms
        ) / stats.success_count

    def mark_failure(self) -> None:
        self._stats.failure_count += 1

    def stats_snapshot(self) -> dict[str, float | int | None]:
        return {
            "success_count": self._stats.success_count,
            "failure_count": self._stats.failure_count,
            "last_rtt_ms": self._stats.last_rtt_ms,
            "avg_rtt_ms": self._stats.avg_rtt_ms,
        }

    @abstractmethod
    async def resolve(
        self,
        context: QueryContext,
        query: dns.message.Message,
    ) -> dns.message.Message:
        """执行一次 DNS 解析并返回响应。"""
