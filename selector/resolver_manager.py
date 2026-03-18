from __future__ import annotations

from collections.abc import Iterable, Mapping, Sequence
from time import monotonic

import dns.rcode

from config import UpstreamConfig
from core.context import QueryContext
from core.hooks import RequestHooks
from logger import get_logger
from resolvers.doh_resolver import DohUpstreamResolver
from resolvers.doq_resolver import DoqUpstreamResolver
from resolvers.dnscrypt_resolver import DnscryptUpstreamResolver
from resolvers.dot_resolver import DotUpstreamResolver
from resolvers.resolver import BaseUpstreamResolver, DnsAnswer, ResolverProtocol
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

DEFAULT_TAG = "default"
ResolverTable = dict[str, ResolverProtocol]
ResolverGroupTable = dict[str, ResolverTable]


class ResolverManager:
    """统一管理多个 resolver，并按 tag 分组调度。"""

    def __init__(
        self, resolver_groups: Mapping[str, Mapping[str, ResolverProtocol]]
    ) -> None:
        self._name = "resolver-manager"
        self._resolver_groups: ResolverGroupTable = {
            tag: dict(table) for tag, table in resolver_groups.items()
        }
        default_table = self._resolver_groups.get(DEFAULT_TAG, {})
        if not default_table:
            raise ValueError("ResolverManager 至少需要一个 default 组 resolver。")

    @property
    def name(self) -> str:
        return self._name

    @classmethod
    def from_upstreams(
        cls,
        upstreams: Iterable[UpstreamConfig],
        hooks: RequestHooks | None = None,
    ) -> "ResolverManager":
        """根据上游配置批量创建 resolver，并自动加入 default 组。"""
        groups: ResolverGroupTable = {DEFAULT_TAG: {}}

        for index, upstream in enumerate(upstreams):
            resolver_type = RESOLVER_BY_PROTOCOL.get(upstream.protocol)
            if resolver_type is None:
                raise ValueError(
                    f"Unsupported upstream protocol `{upstream.protocol}` for {upstream.host}."
                )

            resolver = resolver_type(upstream, hooks=hooks)
            resolver_key = _build_resolver_key(index=index, resolver=resolver)

            # 所有 resolver 一律加入 default 组。
            _insert_resolver(groups[DEFAULT_TAG], resolver_key, resolver)

            # 除 default 以外，再加入自身 tag 分组。
            tag = upstream.tag.strip() or DEFAULT_TAG
            if tag != DEFAULT_TAG:
                group = groups.setdefault(tag, {})
                _insert_resolver(group, resolver_key, resolver)

        return cls(groups)

    @property
    def resolvers(self) -> ResolverTable:
        """返回 default 组 resolver 表。"""
        return self._resolver_groups[DEFAULT_TAG]

    @property
    def resolver_groups(self) -> ResolverGroupTable:
        """返回全部 resolver 分组表。"""
        return {tag: dict(table) for tag, table in self._resolver_groups.items()}

    def stats_snapshot(self) -> dict[str, float | int | None]:
        return {
            "success_count": None,
            "failure_count": None,
            "last_rtt_ms": None,
            "avg_rtt_ms": None,
        }

    def upstream_stats(self) -> dict[str, dict[str, float | int | None]]:
        """导出所有上游 resolver 的统计快照（按唯一名称去重）。"""
        stats: dict[str, dict[str, float | int | None]] = {}
        seen_resolver_ids: set[int] = set()

        for table in self._resolver_groups.values():
            for resolver in table.values():
                resolver_id = id(resolver)
                if resolver_id in seen_resolver_ids:
                    continue
                seen_resolver_ids.add(resolver_id)

                name = resolver.name
                if name in stats:
                    suffix = 2
                    while f"{name}#{suffix}" in stats:
                        suffix += 1
                    name = f"{name}#{suffix}"
                stats[name] = resolver.stats_snapshot()
        return stats

    async def resolve(self, context: QueryContext) -> DnsAnswer:
        started_at = monotonic()
        requested_tag, selected_tag, resolvers = self._pick_resolvers_by_context(
            context
        )
        enable_ip_benchmark = _should_enable_ip_benchmark(context)
        context.tags["enable_ip_benchmark"] = enable_ip_benchmark
        context.tags["resolver_group"] = selected_tag
        if requested_tag != selected_tag:
            context.tags["resolver_group_requested"] = requested_tag

        context.resolver_attempts = len(resolvers)
        if enable_ip_benchmark:
            return await self._resolve_with_benchmark(
                context=context,
                started_at=started_at,
                resolvers=resolvers,
            )

        if len(resolvers) == 1:
            return await self._resolve_single(
                context=context,
                started_at=started_at,
                resolver=resolvers[0],
            )

        return await self._resolve_fastest(
            context=context,
            started_at=started_at,
            resolvers=resolvers,
        )

    def _pick_resolvers_by_context(
        self,
        context: QueryContext,
    ) -> tuple[str, str, tuple[ResolverProtocol, ...]]:
        requested_tag = (context.tag or DEFAULT_TAG).strip() or DEFAULT_TAG
        selected_tag = requested_tag

        table = self._resolver_groups.get(selected_tag)
        if not table:
            selected_tag = DEFAULT_TAG
            table = self._resolver_groups[DEFAULT_TAG]
            logger.warning(
                "resolver 分组不存在，回退 default requested_tag=%s txid=%s qname=%s qtype=%s",
                requested_tag,
                context.txid if context.txid is not None else "-",
                context.query_name or "-",
                context.query_type or "-",
            )

        return requested_tag, selected_tag, tuple(table.values())

    async def _resolve_with_benchmark(
        self,
        context: QueryContext,
        started_at: float,
        resolvers: Sequence[ResolverProtocol],
    ) -> DnsAnswer:
        try:
            benchmark_result = await resolve_with_ip_benchmark(
                resolvers=resolvers,
                context=context,
            )
        except Exception as exc:  # pragma: no cover
            context.resolve_rtt_ms = (monotonic() - started_at) * 1000
            context.resolver_errors = [str(exc)]
            context.selected_ips = []
            context.selected_ip = None
            context.selected_ip_rtt_ms = None
            logger.error(
                "并发解析/测速失败 txid=%s qname=%s qtype=%s error=%s",
                context.txid if context.txid is not None else "-",
                context.query_name or "-",
                context.query_type or "-",
                exc,
            )
            return _make_servfail()

        context.selected_resolver = benchmark_result.winner.name
        context.resolve_rtt_ms = benchmark_result.elapsed_ms
        context.resolver_errors = list(benchmark_result.errors)
        context.selected_ips = list(benchmark_result.selected_ips)
        context.selected_ip = benchmark_result.selected_ip
        context.selected_ip_rtt_ms = benchmark_result.selected_ip_rtt_ms
        context.tags["resolver_winner"] = benchmark_result.winner.name
        if benchmark_result.errors:
            context.tags["resolver_failures"] = list(benchmark_result.errors)
        if benchmark_result.selected_ips:
            context.tags["selected_ips"] = list(benchmark_result.selected_ips)
        if benchmark_result.selected_ip is not None:
            context.tags["selected_ip_source_resolver"] = (
                benchmark_result.selected_ip_source_resolver
                or benchmark_result.winner.name
            )

        logger.info(
            "并发解析+测速完成 winner=%s ip_source=%s rtt=%.2fms txid=%s qname=%s qtype=%s selected_ips=%s primary_ip_rtt=%s",
            benchmark_result.winner.name,
            benchmark_result.selected_ip_source_resolver
            or benchmark_result.winner.name,
            benchmark_result.elapsed_ms,
            context.txid if context.txid is not None else "-",
            context.query_name or "-",
            context.query_type or "-",
            ", ".join(benchmark_result.selected_ips) or "-",
            (
                f"{benchmark_result.selected_ip_rtt_ms:.2f}ms"
                if benchmark_result.selected_ip_rtt_ms is not None
                else "-"
            ),
        )
        return benchmark_result.rcode, benchmark_result.answer

    async def _resolve_single(
        self,
        context: QueryContext,
        started_at: float,
        resolver: ResolverProtocol,
    ) -> DnsAnswer:
        try:
            rcode, answer = await resolver.resolve(context)
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
            return _make_servfail()

        total_ms = (monotonic() - started_at) * 1000
        context.selected_resolver = resolver.name
        context.resolve_rtt_ms = total_ms
        context.resolver_errors = []
        context.selected_ips = []
        context.selected_ip = None
        context.selected_ip_rtt_ms = None
        context.tags["resolver_winner"] = resolver.name
        return rcode, answer

    async def _resolve_fastest(
        self,
        context: QueryContext,
        started_at: float,
        resolvers: Sequence[ResolverProtocol],
    ) -> DnsAnswer:
        try:
            race_result = await resolve_fastest(resolvers=resolvers, context=context)
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
            return _make_servfail()

        context.selected_resolver = race_result.winner.name
        context.resolve_rtt_ms = race_result.elapsed_ms
        context.resolver_errors = list(race_result.errors)
        context.selected_ips = []
        context.selected_ip = None
        context.selected_ip_rtt_ms = None
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
        return race_result.rcode, race_result.answer


def _make_servfail() -> DnsAnswer:
    return dns.rcode.SERVFAIL, []


def _build_resolver_key(index: int, resolver: ResolverProtocol) -> str:
    return f"upstream-{index + 1}@{resolver.name}"


def _insert_resolver(
    table: ResolverTable,
    key: str,
    resolver: ResolverProtocol,
) -> None:
    candidate = key
    suffix = 2
    while candidate in table:
        candidate = f"{key}#{suffix}"
        suffix += 1
    table[candidate] = resolver


def _should_enable_ip_benchmark(context: QueryContext) -> bool:
    qtype = (context.query_type or "").strip().upper()
    return qtype in ("A", "AAAA")
