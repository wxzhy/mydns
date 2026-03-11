from __future__ import annotations

import dns.message
import dns.rcode

from core.context import ClientAddress, QueryContext
from core.hooks import RequestHooks
from logger import get_logger
from resolvers.resolver import Resolver
from utils.decode_query import decode_query

logger = get_logger(__name__)


class RequestPipeline:
    def __init__(self, resolver: Resolver, hooks: RequestHooks | None = None) -> None:
        self._resolver = resolver
        self._hooks = hooks or RequestHooks()

    async def handle_datagram(
        self,
        payload: bytes,
        client: ClientAddress,
    ) -> dns.message.Message | None:
        if not payload:
            return None

        context = QueryContext(client=client)
        query = decode_query(payload, context)
        if query is None:
            return None

        try:
            hook_response = await self._hooks.run_before_upstream(context, query)
        except Exception:
            logger.exception(
                "Request hook crashed for %s:%s",
                context.client_host,
                context.client_port,
            )
            failure = dns.message.make_response(query)
            failure.set_rcode(dns.rcode.SERVFAIL)
            return failure

        if hook_response is not None:
            return hook_response

        try:
            return await self._resolver.resolve(context, query)
        except Exception:
            logger.exception(
                "Resolver crashed for %s:%s",
                context.client_host,
                context.client_port,
            )
            failure = dns.message.make_response(query)
            failure.set_rcode(dns.rcode.SERVFAIL)
            return failure
