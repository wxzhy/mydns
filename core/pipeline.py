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
        context.raw_query = query

        try:
            hook_response = await self._hooks.run_before_upstream(context, query)
        except Exception:
            logger.exception(
                "请求规则处理异常 client=%s:%s",
                context.client_host,
                context.client_port,
            )
            failure = dns.message.make_response(query)
            failure.set_rcode(dns.rcode.SERVFAIL)
            response = failure
            response_source = "request-hook-error"
        else:
            if hook_response is not None:
                response = hook_response
                response_source = "request-hook-short-circuit"
            else:
                try:
                    response = await self._resolver.resolve(context, query)
                    response_source = "resolver"
                except Exception:
                    logger.exception(
                        "Resolver 处理异常 client=%s:%s winner=%s rtt=%s",
                        context.client_host,
                        context.client_port,
                        context.selected_resolver or "-",
                        (
                            f"{context.resolve_rtt_ms:.2f}ms"
                            if context.resolve_rtt_ms is not None
                            else "-"
                        ),
                    )
                    failure = dns.message.make_response(query)
                    failure.set_rcode(dns.rcode.SERVFAIL)
                    response = failure
                    response_source = "resolver-error-fallback"

        context.tags["response_source"] = response_source

        try:
            response = await self._hooks.run_before_response(context, query, response)
        except Exception:
            logger.exception(
                "响应处理 Hook 异常 client=%s:%s txid=%s qtype=%s domain=%s",
                context.client_host,
                context.client_port,
                context.txid if context.txid is not None else "-",
                context.query_type or "-",
                context.query_name or "-",
            )
            failure = dns.message.make_response(query)
            failure.set_rcode(dns.rcode.SERVFAIL)
            response = failure
            response_source = "response-hook-error-fallback"
            context.tags["response_source"] = response_source

        context.raw_response = response
        return response
