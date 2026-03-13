from __future__ import annotations

from collections.abc import Iterable
from time import monotonic

import dns.message
import dns.rcode
import dns.rdatatype

from config import UpstreamConfig
from core.context import QueryContext
from core.hooks import RequestHooks
from logger import get_logger
from resolvers.doh_resolver import DohUpstreamResolver
from resolvers.doq_resolver import DoqUpstreamResolver
from resolvers.dnscrypt_resolver import DnscryptUpstreamResolver
from resolvers.dot_resolver import DotUpstreamResolver
from resolvers.resolver import BaseUpstreamResolver, ResolverProtocol
from resolvers.tcp_resolver import TcpUpstreamResolver
from resolvers.udp_resolver import UdpUpstreamResolver
from selector.benchmark_selector import resolve_with_ip_benchmark
from selector.concurrent_selector import resolve_fastest

logger = get_logger(__name__)

RESOLVER_BY_PROTOCOL: dict[str, type[BaseUpstreamResolver]] = {
    "udp": UdpUpstreamResolver,
    "tcp": TcpUpstreamResolver,
    "dot": DotUpstreamResolver,
    "doh": DohUpstreamResolver,
    "doq": DoqUpstreamResolver,
    "dnscrypt": DnscryptUpstreamResolver,
}


class ResolverManager:
    """统一管理多个 resolver，并对外提供单一 resolve 入口。"""

    def __init__(self, resolvers: Iterable[ResolverProtocol]) -> None:
        self._name = "resolver-manager"
        self._resolvers = tuple(resolvers)
        if not self._resolvers:
            raise ValueError("ResolverManager 至少需要一个 resolver。")

    @property
    def name(self) -> str:
        return self._name

    @classmethod
    def from_upstreams(
        cls,
        upstreams: Iterable[UpstreamConfig],
        hooks: RequestHooks | None = None,
    ) -> "ResolverManager":
        """根据上游配置批量创建 resolver。"""
        resolvers: list[ResolverProtocol] = []
        for upstream in upstreams:
            resolver_type = RESOLVER_BY_PROTOCOL.get(upstream.protocol)
            if resolver_type is None:
                raise ValueError(
                    f"Unsupported upstream protocol `{upstream.protocol}` for {upstream.host}."
                )
            resolvers.append(resolver_type(upstream, hooks=hooks))
        return cls(resolvers)

    @property
    def resolvers(self) -> tuple[ResolverProtocol, ...]:
        return self._resolvers

    def stats_snapshot(self) -> dict[str, float | int | None]:
        return {
            "success_count": None,
            "failure_count": None,
            "last_rtt_ms": None,
            "avg_rtt_ms": None,
        }

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
        enable_ip_benchmark = _should_enable_ip_benchmark(query)
        context.tags["enable_ip_benchmark"] = enable_ip_benchmark
        context.resolver_attempts = len(self._resolvers)

        if enable_ip_benchmark:
            return await self._resolve_with_benchmark(
                context=context,
                query=query,
                started_at=started_at,
            )

        if len(self._resolvers) == 1:
            return await self._resolve_single(
                context=context,
                query=query,
                started_at=started_at,
            )

        return await self._resolve_fastest(
            context=context,
            query=query,
            started_at=started_at,
        )

    async def _resolve_with_benchmark(
        self,
        context: QueryContext,
        query: dns.message.Message,
        started_at: float,
    ) -> dns.message.Message:
        try:
            benchmark_result = await resolve_with_ip_benchmark(
                resolvers=self._resolvers,
                context=context,
                query=query,
            )
        except Exception as exc:  # pragma: no cover
            context.resolve_rtt_ms = (monotonic() - started_at) * 1000
            context.resolver_errors = [str(exc)]
            context.selected_ip = None
            context.selected_ip_rtt_ms = None
            logger.error(
                "并发解析/测速失败 txid=%s qname=%s qtype=%s error=%s",
                context.txid if context.txid is not None else "-",
                context.query_name or "-",
                context.query_type or "-",
                exc,
            )
            return self._make_servfail(query)

        context.selected_resolver = benchmark_result.winner.name
        context.resolve_rtt_ms = benchmark_result.elapsed_ms
        context.resolver_errors = list(benchmark_result.errors)
        context.selected_ip = benchmark_result.selected_ip
        context.selected_ip_rtt_ms = benchmark_result.selected_ip_rtt_ms
        context.tags["resolver_winner"] = benchmark_result.winner.name
        if benchmark_result.errors:
            context.tags["resolver_failures"] = list(benchmark_result.errors)
        if benchmark_result.selected_ip is not None:
            context.tags["selected_ip_source_resolver"] = benchmark_result.winner.name

        logger.info(
            "并发解析+测速完成 winner=%s rtt=%.2fms txid=%s qname=%s qtype=%s selected_ip=%s selected_ip_rtt=%s",
            benchmark_result.winner.name,
            benchmark_result.elapsed_ms,
            context.txid if context.txid is not None else "-",
            context.query_name or "-",
            context.query_type or "-",
            benchmark_result.selected_ip or "-",
            (
                f"{benchmark_result.selected_ip_rtt_ms:.2f}ms"
                if benchmark_result.selected_ip_rtt_ms is not None
                else "-"
            ),
        )
        return benchmark_result.response

    async def _resolve_single(
        self,
        context: QueryContext,
        query: dns.message.Message,
        started_at: float,
    ) -> dns.message.Message:
        resolver = self._resolvers[0]
        try:
            response = await resolver.resolve(context, query)
        except Exception as exc:  # pragma: no cover
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
        return response

    async def _resolve_fastest(
        self,
        context: QueryContext,
        query: dns.message.Message,
        started_at: float,
    ) -> dns.message.Message:
        try:
            race_result = await resolve_fastest(
                resolvers=self._resolvers,
                context=context,
                query=query,
            )
        except Exception as exc:  # pragma: no cover
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


def _should_enable_ip_benchmark(query: dns.message.Message) -> bool:
    if len(query.question) != 1:
        return False
    rdtype = query.question[0].rdtype
    return rdtype in (dns.rdatatype.A, dns.rdatatype.AAAA)
