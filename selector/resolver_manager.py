from __future__ import annotations

from collections.abc import Iterable
from time import monotonic

import dns.message
import dns.rdataclass
import dns.rdatatype
import dns.rcode
import dns.rrset

from config import UpstreamConfig
from core.context import QueryContext
from core.hooks import RequestHooks
from logger import get_logger
from resolvers.resolver import Resolver
from selector.benchmark.scorer import choose_fastest_ip
from resolvers.udp_resolver import UdpUpstreamResolver
from selector.concurrent_selector import ResolverBatchSuccess, resolve_all, resolve_fastest

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

        if self._is_ip_benchmark_query(query):
            try:
                response = await self._resolve_a_or_aaaa_with_ip_benchmark(
                    context=context,
                    query=query,
                    started_at=started_at,
                )
            except Exception as exc:  # pragma: no cover
                self.mark_failure()
                context.resolve_rtt_ms = (monotonic() - started_at) * 1000
                context.resolver_errors = [str(exc)]
                logger.error(
                    "A/AAAA 策略失败 txid=%s qname=%s qtype=%s error=%s",
                    context.txid if context.txid is not None else "-",
                    context.query_name or "-",
                    context.query_type or "-",
                    exc,
                )
                return self._make_servfail(query)
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

    async def _resolve_a_or_aaaa_with_ip_benchmark(
        self,
        context: QueryContext,
        query: dns.message.Message,
        started_at: float,
    ) -> dns.message.Message:
        query_rdtype = query.question[0].rdtype
        batch_result = await resolve_all(
            resolvers=self._resolvers,
            context=context,
            query=query,
        )
        if not batch_result.successes:
            details = "; ".join(batch_result.errors) if batch_result.errors else "-"
            raise RuntimeError(f"所有 Resolver 均解析失败：{details}")

        context.resolver_errors = list(batch_result.errors)
        context.selected_ip = None
        context.selected_ip_rtt_ms = None
        if batch_result.errors:
            context.tags["resolver_failures"] = list(batch_result.errors)

        candidates = self._collect_ip_candidates(
            successes=batch_result.successes,
            query_rdtype=query_rdtype,
        )
        if not candidates:
            fallback_success = min(
                batch_result.successes,
                key=lambda item: item.elapsed_ms,
            )
            return self._finalize_selected_response(
                context=context,
                started_at=started_at,
                resolver_name=fallback_success.resolver.name,
                response=fallback_success.response,
            )

        ip_score = await choose_fastest_ip(candidates.keys())
        if ip_score is None:
            fallback_success = min(
                batch_result.successes,
                key=lambda item: item.elapsed_ms,
            )
            return self._finalize_selected_response(
                context=context,
                started_at=started_at,
                resolver_name=fallback_success.resolver.name,
                response=fallback_success.response,
            )

        selected_success = candidates[ip_score.ip]
        selected_response = self._build_selected_ip_response(
            source_response=selected_success.response,
            selected_ip=ip_score.ip,
            query_rdtype=query_rdtype,
        )
        context.selected_ip = ip_score.ip
        context.selected_ip_rtt_ms = ip_score.best_ms
        context.tags["fastest_ip"] = ip_score.ip
        context.tags["fastest_ip_ms"] = ip_score.best_ms
        context.tags["fastest_ip_ping_ms"] = ip_score.ping_ms
        context.tags["fastest_ip_tcp_443_ms"] = ip_score.tcp_443_ms
        context.tags["fastest_ip_tcp_80_ms"] = ip_score.tcp_80_ms
        return self._finalize_selected_response(
            context=context,
            started_at=started_at,
            resolver_name=selected_success.resolver.name,
            response=selected_response,
        )

    @staticmethod
    def _is_ip_benchmark_query(query: dns.message.Message) -> bool:
        if not query.question:
            return False
        return query.question[0].rdtype in (dns.rdatatype.A, dns.rdatatype.AAAA)

    @staticmethod
    def _collect_ip_candidates(
        successes: tuple[ResolverBatchSuccess, ...],
        query_rdtype: dns.rdatatype.RdataType,
    ) -> dict[str, ResolverBatchSuccess]:
        candidates: dict[str, ResolverBatchSuccess] = {}
        for success in successes:
            for rrset in success.response.answer:
                if rrset.rdtype != query_rdtype:
                    continue
                for record in rrset:
                    ip = record.to_text().strip()
                    existing = candidates.get(ip)
                    if existing is None or success.elapsed_ms < existing.elapsed_ms:
                        candidates[ip] = success
        return candidates

    @staticmethod
    def _build_selected_ip_response(
        source_response: dns.message.Message,
        selected_ip: str,
        query_rdtype: dns.rdatatype.RdataType,
    ) -> dns.message.Message:
        """保留同源 CNAME，只返回最快 IP。"""
        cloned_response = dns.message.from_wire(source_response.to_wire())
        cname_rrsets: list[dns.rrset.RRset] = []
        selected_rrset: dns.rrset.RRset | None = None

        for rrset in cloned_response.answer:
            if rrset.rdtype == dns.rdatatype.CNAME:
                cname_rrsets.append(rrset)
                continue
            if rrset.rdtype != query_rdtype or selected_rrset is not None:
                continue

            if not any(record.to_text().strip() == selected_ip for record in rrset):
                continue

            selected_rrset = dns.rrset.from_text(
                rrset.name.to_text(),
                rrset.ttl,
                dns.rdataclass.to_text(rrset.rdclass),
                dns.rdatatype.to_text(rrset.rdtype),
                selected_ip,
            )

        if selected_rrset is None:
            return cloned_response

        cloned_response.answer = [*cname_rrsets, selected_rrset]
        return cloned_response

    def _finalize_selected_response(
        self,
        context: QueryContext,
        started_at: float,
        resolver_name: str,
        response: dns.message.Message,
    ) -> dns.message.Message:
        total_ms = (monotonic() - started_at) * 1000
        context.selected_resolver = resolver_name
        context.resolve_rtt_ms = total_ms
        context.tags["resolver_winner"] = resolver_name
        self.mark_success(total_ms)
        logger.info(
            "并发解析完成 winner=%s rtt=%.2fms txid=%s qname=%s qtype=%s",
            resolver_name,
            total_ms,
            context.txid if context.txid is not None else "-",
            context.query_name or "-",
            context.query_type or "-",
        )
        return response

    @staticmethod
    def _make_servfail(query: dns.message.Message) -> dns.message.Message:
        response = dns.message.make_response(query)
        response.set_rcode(dns.rcode.SERVFAIL)
        return response
