from __future__ import annotations

import dns.edns
import dns.message
import dns.rcode
import dns.rdatatype

from core.context import ClientAddress, QueryContext
from logger import get_logger
from resolvers.resolver import Resolver

logger = get_logger(__name__)


class RequestPipeline:
    def __init__(self, resolver: Resolver) -> None:
        self._resolver = resolver

    async def handle_datagram(
        self,
        payload: bytes,
        client: ClientAddress,
    ) -> bytes | None:
        if not payload:
            return None

        context = QueryContext(client=client)
        query = self._decode_query(payload, context)
        if query is None:
            return None

        try:
            return await self._resolver.resolve(context, query, payload)
        except Exception:
            logger.exception(
                "Resolver crashed for %s:%s",
                context.client_host,
                context.client_port,
            )
            failure = dns.message.make_response(query)
            failure.set_rcode(dns.rcode.SERVFAIL)
            return failure.to_wire()

    def _decode_query(
        self,
        payload: bytes,
        context: QueryContext,
    ) -> dns.message.Message | None:
        try:
            query = dns.message.from_wire(payload)
        except Exception:
            logger.warning(
                "Invalid DNS datagram dropped from %s:%s",
                context.client_host,
                context.client_port,
            )
            return None

        if query.question:
            first_q = query.question[0]
            context.query_name = first_q.name.to_text()
            context.query_type = dns.rdatatype.to_text(first_q.rdtype)
        context.txid = query.id
        context.ecs = self._extract_ecs(query)

        return query

    @staticmethod
    def _extract_ecs(query: dns.message.Message) -> str | None:
        for option in query.options:
            if isinstance(option, dns.edns.ECSOption):
                return f"{option.address}/{option.srclen}"
        return None
