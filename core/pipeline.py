from __future__ import annotations

import dns.message
import dns.rcode

from core.context import ClientAddress, QueryContext
from core.hooks import RequestHooks
from logger import get_logger
from resolvers.resolver import Resolver
from utils.decode_query import decode_query
from utils.dns_result import summarize_dns_result

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
        logger.debug(
            "收到请求 client=%s:%s txid=%s qtype=%s domain=%s ecs=%s size=%s",
            context.client_host,
            context.client_port,
            context.txid if context.txid is not None else "-",
            context.query_type or "-",
            context.query_name or "-",
            context.ecs or "-",
            len(payload),
        )

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
            return failure

        if hook_response is not None:
            logger.debug(
                "最终结果(规则命中) client=%s:%s txid=%s qtype=%s domain=%s result=%s",
                context.client_host,
                context.client_port,
                context.txid if context.txid is not None else "-",
                context.query_type or "-",
                context.query_name or "-",
                summarize_dns_result(hook_response),
            )
            return hook_response

        try:
            response = await self._resolver.resolve(context, query)
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
            logger.debug(
                "最终结果(异常兜底) client=%s:%s txid=%s qtype=%s domain=%s result=%s",
                context.client_host,
                context.client_port,
                context.txid if context.txid is not None else "-",
                context.query_type or "-",
                context.query_name or "-",
                summarize_dns_result(failure),
            )
            return failure

        logger.debug(
            "最终结果 client=%s:%s txid=%s qtype=%s domain=%s winner=%s attempts=%s rtt=%s result=%s",
            context.client_host,
            context.client_port,
            context.txid if context.txid is not None else "-",
            context.query_type or "-",
            context.query_name or "-",
            context.selected_resolver or "-",
            context.resolver_attempts,
            f"{context.resolve_rtt_ms:.2f}ms"
            if context.resolve_rtt_ms is not None
            else "-",
            summarize_dns_result(response),
        )
        return response
