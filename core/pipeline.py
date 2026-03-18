from __future__ import annotations

"""请求处理流水线：request -> upstream -> response。"""

import dns.flags
import dns.message
import dns.rcode

from cache.dns_cache import DnsLruCache
from core.context import ClientAddress, QueryContext
from core.hooks import RequestHooks
from logger import get_logger
from resolvers.resolver import ResolverProtocol
from utils.decode_query import decode_query

logger = get_logger(__name__)


class RequestPipeline:
    """单次 DNS 请求流水线处理器。"""

    def __init__(
        self,
        resolver: ResolverProtocol,
        hooks: RequestHooks | None = None,
        dns_cache: DnsLruCache | None = None,
    ) -> None:
        self._resolver = resolver
        self._hooks = hooks or RequestHooks()
        self._dns_cache = dns_cache

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

        response_source: str

        try:
            await self._hooks.run_before_upstream(context)
        except Exception:
            logger.exception(
                "请求规则处理异常 client=%s:%s",
                context.client_host,
                context.client_port,
            )
            context.set_answer(dns.rcode.SERVFAIL)
            response_source = "request-hook-error"
        else:
            if context.tags.get("drop_request"):
                logger.debug(
                    "请求被丢弃 client=%s:%s txid=%s qtype=%s domain=%s reason=%s",
                    context.client_host,
                    context.client_port,
                    context.txid if context.txid is not None else "-",
                    context.query_type or "-",
                    context.query_name or "-",
                    context.tags.get("drop_reason", "-"),
                )
                return None

            if context.has_answer:
                response_source = "request-hook-short-circuit"
                context.tags["cache"] = "skipped"
            else:
                if self._check_cache(context):
                    response_source = "cache-hit"
                    context.tags["cache"] = "hit"
                else:
                    context.tags["cache"] = "miss"
                    try:
                        rcode, answer = await self._resolver.resolve(context)
                        context.set_answer(rcode, answer)
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
                        context.set_answer(dns.rcode.SERVFAIL)
                        response_source = "resolver-error-fallback"

        context.tags["response_source"] = response_source

        try:
            await self._hooks.run_before_response(context)
        except Exception:
            logger.exception(
                "响应处理 Hook 异常 client=%s:%s txid=%s qtype=%s domain=%s",
                context.client_host,
                context.client_port,
                context.txid if context.txid is not None else "-",
                context.query_type or "-",
                context.query_name or "-",
            )
            context.set_answer(dns.rcode.SERVFAIL)
            response_source = "response-hook-error-fallback"
            context.tags["response_source"] = response_source

        if response_source != "cache-hit":
            self._update_cache(context)
        return _build_wire_response(context)

    def _check_cache(self, context: QueryContext) -> bool:
        if self._dns_cache is None:
            return False
        try:
            return self._dns_cache.get(context)
        except Exception:  # pragma: no cover
            logger.exception("DNS 缓存读取失败")
            return False

    def _update_cache(self, context: QueryContext) -> None:
        if self._dns_cache is None:
            return
        try:
            self._dns_cache.put(context)
        except Exception:  # pragma: no cover
            logger.exception("DNS 缓存写入失败")


def _build_wire_response(context: QueryContext) -> dns.message.Message:
    """将 context 中的 (rcode, answer) 组装为最终的 DNS 响应报文。"""
    query = context.raw_query
    if query is None:  # pragma: no cover
        raise ValueError("构造响应失败：QueryContext.raw_query 为空。")

    response = dns.message.make_response(query)
    if context.rcode is None:
        response.set_rcode(dns.rcode.SERVFAIL)
    else:
        response.set_rcode(context.rcode)
    response.flags |= dns.flags.RA
    if context.answer:
        response.answer = list(context.answer)
    return response
