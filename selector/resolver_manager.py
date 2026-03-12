from __future__ import annotations

from collections.abc import Iterable
from time import monotonic

import dns.message
import dns.rcode

from config import UpstreamConfig
from core.context import QueryContext
from core.hooks import RequestHooks
from logger import get_logger
from resolvers.resolver import Resolver
from resolvers.udp_resolver import UdpUpstreamResolver
from selector.concurrent_selector import resolve_fastest

logger = get_logger(__name__)


class ResolverManager(Resolver):
    """统一管理多个 resolver，并对外提供单一 resolve 入口。"""

    def __init__(self, resolvers: Iterable[Resolver]) -> None:
        super().__init__(name="resolver-manager")
        self._resolvers = tuple(resolvers)
        if not self._resolvers:
            raise ValueError("ResolverManager 至少需要一个 resolver。")

    @classmethod
    def from_upstreams(
        cls,
        upstreams: Iterable[UpstreamConfig],
        hooks: RequestHooks | None = None,
    ) -> "ResolverManager":
        """根据上游配置批量创建 resolver。"""
        resolvers = [UdpUpstreamResolver(upstream, hooks=hooks) for upstream in upstreams]
        return cls(resolvers)

    @property
    def resolvers(self) -> tuple[Resolver, ...]:
        return self._resolvers

    def upstream_stats(self) -> dict[str, dict[str, float | int | None]]:
        """导出所有上游 resolver 的统计快照。"""
        return {
            resolver.name: resolver.stats_snapshot() for resolver in self._resolvers
        }

    async def resolve(
        self,
        context: QueryContext,
        query: dns.message.Message,
    ) -> dns.message.Message:
        started_at = monotonic()
        context.resolver_attempts = len(self._resolvers)

        if len(self._resolvers) == 1:
            resolver = self._resolvers[0]
            try:
                response = await resolver.resolve(context, query)
            except Exception as exc:  # pragma: no cover
                self.mark_failure()
                context.resolve_rtt_ms = (monotonic() - started_at) * 1000
                context.resolver_errors = [f"{resolver.name}: {exc}"]
                logger.error(
                    "Resolver 解析失败 resolver=%s txid=%s qname=%s qtype=%s error=%s",
                    resolver.name,
                    context.txid if context.txid is not None else "-",
                    context.query_name or "-",
                    context.query_type or "-",
                    exc,
                )
                return self._make_servfail(query)

            total_ms = (monotonic() - started_at) * 1000
            context.selected_resolver = resolver.name
            context.resolve_rtt_ms = total_ms
            context.resolver_errors = []
            context.tags["resolver_winner"] = resolver.name
            self.mark_success(total_ms)
            return response

        try:
            race_result = await resolve_fastest(
                resolvers=self._resolvers,
                context=context,
                query=query,
            )
        except Exception as exc:  # pragma: no cover
            self.mark_failure()
            context.resolve_rtt_ms = (monotonic() - started_at) * 1000
            context.resolver_errors = [str(exc)]
            logger.error(
                "并发解析全部失败 txid=%s qname=%s qtype=%s error=%s",
                context.txid if context.txid is not None else "-",
                context.query_name or "-",
                context.query_type or "-",
                exc,
            )
            return self._make_servfail(query)

        context.selected_resolver = race_result.winner.name
        context.resolve_rtt_ms = race_result.elapsed_ms
        context.resolver_errors = list(race_result.errors)
        context.tags["resolver_winner"] = race_result.winner.name
        if race_result.errors:
            context.tags["resolver_failures"] = list(race_result.errors)

        self.mark_success(race_result.elapsed_ms)
        logger.info(
            "并发解析完成 winner=%s rtt=%.2fms txid=%s qname=%s qtype=%s",
            race_result.winner.name,
            race_result.elapsed_ms,
            context.txid if context.txid is not None else "-",
            context.query_name or "-",
            context.query_type or "-",
        )
        return race_result.response

    @staticmethod
    def _make_servfail(query: dns.message.Message) -> dns.message.Message:
        response = dns.message.make_response(query)
        response.set_rcode(dns.rcode.SERVFAIL)
        return response
