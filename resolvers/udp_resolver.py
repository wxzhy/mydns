from __future__ import annotations

from collections.abc import Iterable

import dns.asyncquery
import dns.message
import dns.rcode

from config import UpstreamConfig
from core.context import QueryContext
from logger import get_logger
from resolvers.resolver import Resolver

logger = get_logger(__name__)


class UdpUpstreamResolver(Resolver):
    def __init__(self, upstreams: Iterable[UpstreamConfig]) -> None:
        self._upstreams = tuple(upstreams)
        if not self._upstreams:
            raise ValueError("UdpUpstreamResolver requires at least one upstream.")

    async def resolve(
        self,
        context: QueryContext,
        query: dns.message.Message,
        query_wire: bytes,
    ) -> bytes:
        last_error: Exception | None = None

        for upstream in self._upstreams:
            try:
                response = await dns.asyncquery.udp(
                    q=query,
                    where=upstream.host,
                    port=upstream.port,
                    timeout=upstream.timeout,
                    ignore_unexpected=True,
                )
                return response.to_wire()
            except Exception as exc:  # pragma: no cover
                last_error = exc
                logger.warning(
                    "Upstream failed host=%s port=%s txid=%s qname=%s qtype=%s ecs=%s error=%s",
                    upstream.host,
                    upstream.port,
                    context.txid if context.txid is not None else "-",
                    context.query_name or "-",
                    context.query_type or "-",
                    context.ecs or "-",
                    exc,
                )

        if last_error:
            logger.error(
                "All upstream DNS servers failed txid=%s qname=%s qtype=%s ecs=%s",
                context.txid if context.txid is not None else "-",
                context.query_name or "-",
                context.query_type or "-",
                context.ecs or "-",
            )

        fallback = dns.message.make_response(query)
        fallback.set_rcode(dns.rcode.SERVFAIL)
        return fallback.to_wire()
