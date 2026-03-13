from __future__ import annotations

import dns.message

from core.context import QueryContext
from core.hooks import UpstreamHook
from logger import get_logger
from rules.upstream.ip_benchmark import IpBenchmarkUpstreamHook
from utils.dns_result import summarize_dns_result

logger = get_logger(__name__)


class UpstreamDebugHook(UpstreamHook):
    """上游阶段调试日志。"""

    async def after_upstream(
        self,
        context: QueryContext,
        query: dns.message.Message,
        response: dns.message.Message,
        resolver_name: str,
    ) -> dns.message.Message | None:
        logger.debug(
            "上游返回 resolver=%s txid=%s qtype=%s domain=%s result=%s",
            resolver_name,
            context.txid if context.txid is not None else "-",
            context.query_type or "-",
            context.query_name or "-",
            summarize_dns_result(response),
        )
        return None


def build_upstream_hooks(enable_debug: bool = True) -> tuple[UpstreamHook, ...]:
    hooks: list[UpstreamHook] = []
    if enable_debug:
        hooks.append(UpstreamDebugHook())
    hooks.append(IpBenchmarkUpstreamHook())
    return tuple(hooks)


def build_default_upstream_hooks() -> tuple[UpstreamHook, ...]:
    return build_upstream_hooks()


__all__ = [
    "IpBenchmarkUpstreamHook",
    "UpstreamDebugHook",
    "build_upstream_hooks",
    "build_default_upstream_hooks",
]
