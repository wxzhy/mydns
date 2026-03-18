from __future__ import annotations

from abc import ABC, abstractmethod
from ipaddress import ip_network
from time import monotonic
from typing import Protocol, TypeAlias

import dns.edns
import dns.message
import dns.rcode
import dns.rrset

from config import UpstreamConfig
from core.context import QueryContext
from core.hooks import RequestHooks
from logger import get_logger

logger = get_logger(__name__)

DnsAnswer: TypeAlias = tuple[dns.rcode.Rcode, list[dns.rrset.RRset]]


class ResolverProtocol(Protocol):
    @property
    def name(self) -> str:
        """Resolver 唯一标识名。"""

    @property
    def tag(self) -> str:
        """Resolver 所属分组标签。"""

    def stats_snapshot(self) -> dict[str, float | int | None]:
        """返回运行时统计快照。"""

    async def resolve(self, context: QueryContext) -> DnsAnswer:
        """执行一次 DNS 解析并返回 (rcode, answer_rrsets)。"""


class BaseUpstreamResolver(ABC):
    """上游 resolver 基类，统一异常处理、统计和 hook 调用。"""

    protocol = "upstream"

    def __init__(
        self,
        upstream: UpstreamConfig,
        hooks: RequestHooks | None = None,
    ) -> None:
        self._name = f"{self.protocol}://{upstream.host}:{upstream.port}"
        self._tag: str = upstream.tag or "default"
        self._success_count = 0
        self._failure_count = 0
        self._last_rtt_ms: float | None = None
        self._avg_rtt_ms: float | None = None
        self._upstream = upstream
        self._hooks = hooks or RequestHooks()
        self._ecs_option = self._build_ecs_option(upstream.ecs)

    @property
    def name(self) -> str:
        return self._name

    @property
    def tag(self) -> str:
        return self._tag

    async def resolve(self, context: QueryContext) -> DnsAnswer:
        query = context.raw_query
        if query is None:
            raise ValueError("QueryContext.raw_query 不能为空。")
        started_at = monotonic()
        try:
            upstream_query = self._build_upstream_query(query)
            response = await self._perform_query(upstream_query)
            rcode = response.rcode()
            answer = list(response.answer)
            await self._hooks.run_after_upstream(
                context=context,
                rcode=rcode,
                answer=answer,
                resolver_name=self.name,
            )
        except Exception as exc:  # pragma: no cover
            self.mark_failure()
            elapsed_ms = (monotonic() - started_at) * 1000
            logger.warning(
                "上游解析失败 resolver=%s protocol=%s rtt=%.2fms txid=%s qname=%s qtype=%s ecs=%s error=%s",
                self.name,
                self.protocol,
                elapsed_ms,
                context.txid if context.txid is not None else "-",
                context.query_name or "-",
                context.query_type or "-",
                context.ecs or "-",
                exc,
            )
            raise

        elapsed_ms = (monotonic() - started_at) * 1000
        self.mark_success(elapsed_ms)
        return rcode, answer

    @abstractmethod
    async def _perform_query(self, query: dns.message.Message) -> dns.message.Message:
        """具体上游查询实现。"""

    def mark_success(self, rtt_ms: float) -> None:
        self._success_count += 1
        self._last_rtt_ms = rtt_ms
        if self._avg_rtt_ms is None:
            self._avg_rtt_ms = rtt_ms
            return
        previous_successes = self._success_count - 1
        self._avg_rtt_ms = (
            (self._avg_rtt_ms * previous_successes) + rtt_ms
        ) / self._success_count

    def mark_failure(self) -> None:
        self._failure_count += 1

    def stats_snapshot(self) -> dict[str, float | int | None]:
        return {
            "success_count": self._success_count,
            "failure_count": self._failure_count,
            "last_rtt_ms": self._last_rtt_ms,
            "avg_rtt_ms": self._avg_rtt_ms,
        }

    def _build_upstream_query(self, query: dns.message.Message) -> dns.message.Message:
        if self._ecs_option is None:
            return query

        query_with_ecs = dns.message.from_wire(query.to_wire())
        options = [
            option
            for option in query_with_ecs.options
            if not isinstance(option, dns.edns.ECSOption)
        ]
        options.append(self._ecs_option)

        edns_level = query_with_ecs.edns if query_with_ecs.edns >= 0 else 0
        payload = query_with_ecs.payload if query_with_ecs.payload > 0 else 1232
        request_payload = (
            query_with_ecs.request_payload
            if query_with_ecs.request_payload > 0
            else payload
        )
        query_with_ecs.use_edns(
            edns=edns_level,
            ednsflags=query_with_ecs.ednsflags,
            payload=payload,
            request_payload=request_payload,
            options=options,
        )
        return query_with_ecs

    @staticmethod
    def _build_ecs_option(ecs: str | None) -> dns.edns.ECSOption | None:
        if ecs is None:
            return None
        network = ip_network(ecs, strict=False)
        return dns.edns.ECSOption(
            address=str(network.network_address),
            srclen=network.prefixlen,
        )
