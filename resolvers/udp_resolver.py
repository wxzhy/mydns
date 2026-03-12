from __future__ import annotations

from time import monotonic

import dns.asyncquery
import dns.message

from config import UpstreamConfig
from core.context import QueryContext
from logger import get_logger
from resolvers.resolver import Resolver
from utils.dns_result import summarize_dns_result

logger = get_logger(__name__)


class UdpUpstreamResolver(Resolver):
    """单个上游 UDP Resolver。"""

    def __init__(self, upstream: UpstreamConfig) -> None:
        super().__init__(name=f"{upstream.host}:{upstream.port}")
        self._upstream = upstream

    async def resolve(
        self,
        context: QueryContext,
        query: dns.message.Message,
    ) -> dns.message.Message:
        started_at = monotonic()
        try:
            response = await dns.asyncquery.udp(
                q=query,
                where=self._upstream.host,
                port=self._upstream.port,
                timeout=self._upstream.timeout,
                ignore_unexpected=True,
            )
        except Exception as exc:  # pragma: no cover
            self.mark_failure()
            elapsed_ms = (monotonic() - started_at) * 1000
            logger.warning(
                "上游解析失败 resolver=%s rtt=%.2fms txid=%s qname=%s qtype=%s ecs=%s error=%s",
                self.name,
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
        logger.debug(
            "上游返回 resolver=%s rtt=%.2fms txid=%s qname=%s qtype=%s result=%s",
            self.name,
            elapsed_ms,
            context.txid if context.txid is not None else "-",
            context.query_name or "-",
            context.query_type or "-",
            summarize_dns_result(response),
        )
        return response
