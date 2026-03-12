from __future__ import annotations

import dns.message

from core.context import QueryContext
from core.hooks import ResponseHook
from logger import get_logger
from utils.dns_result import summarize_dns_result

logger = get_logger(__name__)


class ResponseDebugHook(ResponseHook):
    """最终响应阶段调试日志。"""

    async def before_response(
        self,
        context: QueryContext,
        query: dns.message.Message,
        response: dns.message.Message,
    ) -> dns.message.Message | None:
        logger.debug(
            "最终结果 source=%s client=%s:%s txid=%s qtype=%s domain=%s winner=%s attempts=%s rtt=%s selected_ip=%s selected_ip_rtt=%s result=%s",
            context.tags.get("response_source", "-"),
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
            context.selected_ip or "-",
            (
                f"{context.selected_ip_rtt_ms:.2f}ms"
                if context.selected_ip_rtt_ms is not None
                else "-"
            ),
            summarize_dns_result(response),
        )
        return None


def build_response_hooks(enable_debug: bool = True) -> tuple[ResponseHook, ...]:
    hooks: list[ResponseHook] = []
    if enable_debug:
        hooks.append(ResponseDebugHook())
    return tuple(hooks)


def build_default_response_hooks() -> tuple[ResponseHook, ...]:
    return build_response_hooks()


__all__ = [
    "ResponseDebugHook",
    "build_response_hooks",
    "build_default_response_hooks",
]
