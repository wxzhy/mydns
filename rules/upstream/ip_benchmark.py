from __future__ import annotations

import asyncio

import dns.message
import dns.opcode
import dns.rdatatype

from core.context import QueryContext
from core.hooks import UpstreamHook
from logger import get_logger
from rules.upstream.benchmark.scorer import score_ip

logger = get_logger(__name__)

_BENCHMARK_LOCK_TAG = "_ip_benchmark_lock"


class IpBenchmarkUpstreamHook(UpstreamHook):
    """上游阶段：提取所有 IP 候选，去重后并发测速，结果写入 context。"""

    def __init__(self, probe_timeout_ms: int = 1200) -> None:
        self._probe_timeout_ms = probe_timeout_ms

    async def after_upstream(
        self,
        context: QueryContext,
        query: dns.message.Message,
        response: dns.message.Message,
        resolver_name: str,
    ) -> dns.message.Message | None:
        if not _is_supported_query(context, query):
            return None

        response_ips = _extract_response_ips(response)
        if not response_ips:
            return None

        new_ips = await _add_new_candidate_ips(context, response_ips)
        if not new_ips:
            return None

        probe_results = await asyncio.gather(
            *(self._probe_ip(ip) for ip in new_ips),
            return_exceptions=True,
        )
        for ip, result in zip(new_ips, probe_results):
            if isinstance(result, Exception):  # pragma: no cover
                rtt_ms = None
            else:
                rtt_ms = result
            context.ip_benchmark_results[ip] = rtt_ms
            logger.debug(
                "上游IP测速 resolver=%s txid=%s qtype=%s domain=%s ip=%s rtt=%s",
                resolver_name,
                context.txid if context.txid is not None else "-",
                context.query_type or "-",
                context.query_name or "-",
                ip,
                _fmt_rtt(rtt_ms),
            )
        return None

    async def _probe_ip(self, ip: str) -> float | None:
        score = await score_ip(ip, timeout_ms=self._probe_timeout_ms)
        if score is None:
            return None
        return score.best_ms


# 兼容旧名称，避免历史导入路径失效。
FastestIpUpstreamHook = IpBenchmarkUpstreamHook


async def _add_new_candidate_ips(
    context: QueryContext,
    response_ips: tuple[str, ...],
) -> tuple[str, ...]:
    lock = _get_benchmark_lock(context)
    async with lock:
        new_ips: list[str] = []
        for ip in response_ips:
            if ip in context.candidate_ips:
                continue
            context.candidate_ips.add(ip)
            new_ips.append(ip)
        return tuple(new_ips)


def _get_benchmark_lock(context: QueryContext) -> asyncio.Lock:
    lock = context.tags.get(_BENCHMARK_LOCK_TAG)
    if isinstance(lock, asyncio.Lock):
        return lock

    lock = asyncio.Lock()
    context.tags[_BENCHMARK_LOCK_TAG] = lock
    return lock


def _is_supported_query(
    context: QueryContext,
    query: dns.message.Message,
) -> bool:
    if context.tags.get("enable_ip_benchmark") is False:
        return False

    context_qtype = (context.query_type or "").strip().upper()
    if context_qtype and context_qtype not in ("A", "AAAA"):
        return False

    if query.opcode() != dns.opcode.QUERY:
        return False
    if len(query.question) != 1:
        return False

    rdtype = query.question[0].rdtype
    if rdtype not in (dns.rdatatype.A, dns.rdatatype.AAAA):
        return False

    if context_qtype:
        query_qtype = dns.rdatatype.to_text(rdtype).upper()
        if query_qtype != context_qtype:
            return False
    return True


def _extract_response_ips(response: dns.message.Message) -> tuple[str, ...]:
    ips: list[str] = []
    seen: set[str] = set()
    for rrset in response.answer:
        if rrset.rdtype not in (dns.rdatatype.A, dns.rdatatype.AAAA):
            continue
        for rdata in rrset:
            ip_text = getattr(rdata, "address", None) or rdata.to_text()
            if ip_text in seen:
                continue
            seen.add(ip_text)
            ips.append(ip_text)
    return tuple(ips)


def _fmt_rtt(value: float | None) -> str:
    if value is None:
        return "-"
    return f"{value:.2f}ms"


__all__ = [
    "IpBenchmarkUpstreamHook",
    "FastestIpUpstreamHook",
]
