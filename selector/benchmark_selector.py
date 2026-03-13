from __future__ import annotations

from dataclasses import dataclass
from time import monotonic
from typing import Sequence

import dns.message
import dns.rcode
import dns.rdataclass
import dns.rdatatype
import dns.rrset

from core.context import QueryContext
from logger import get_logger
from resolvers.resolver import ResolverProtocol
from selector.concurrent_selector import ResolverBatchSuccess, resolve_all

logger = get_logger(__name__)

_SUPPORTED_TYPES = (dns.rdatatype.A, dns.rdatatype.AAAA)


@dataclass(slots=True)
class BenchmarkSelectResult:
    """IP 测速聚合选择结果。"""

    response: dns.message.Message
    winner: ResolverProtocol
    elapsed_ms: float
    errors: tuple[str, ...]
    selected_ip: str | None
    selected_ip_rtt_ms: float | None
    selected_ip_source_resolver: str | None


@dataclass(slots=True)
class _IpResponseCandidate:
    ip: str
    owner: str
    ttl: int
    rdtype: dns.rdatatype.RdataType
    rtt_ms: float
    success: ResolverBatchSuccess


async def resolve_with_ip_benchmark(
    resolvers: Sequence[ResolverProtocol],
    context: QueryContext,
    query: dns.message.Message,
) -> BenchmarkSelectResult:
    """并发请求上游，聚合 context 中测速结果并构造最终响应。"""
    if not resolvers:
        raise ValueError("Resolver 列表不能为空。")

    started_at = monotonic()
    batch_result = await resolve_all(
        resolvers=resolvers,
        context=context,
        query=query,
    )
    if not batch_result.successes:
        details = "; ".join(batch_result.errors) if batch_result.errors else "-"
        raise RuntimeError(f"所有 Resolver 均解析失败：{details}")

    noerror_successes = tuple(
        item
        for item in batch_result.successes
        if item.response.rcode() == dns.rcode.NOERROR
    )
    if not noerror_successes:
        details = _collect_non_noerror_errors(batch_result.successes, batch_result.errors)
        raise RuntimeError(f"所有 Resolver 均未返回 NOERROR：{details}")

    base_success = min(noerror_successes, key=lambda item: item.elapsed_ms)

    selected_candidate = _pick_best_candidate(
        query=query,
        successes=noerror_successes,
        ip_benchmark_results=context.ip_benchmark_results,
    )

    if selected_candidate is None:
        logger.debug(
            "benchmark_selector 未命中可用测速结果，回退最快NOERROR响应 resolver=%s txid=%s qtype=%s domain=%s",
            base_success.resolver.name,
            context.txid if context.txid is not None else "-",
            context.query_type or "-",
            context.query_name or "-",
        )
        return BenchmarkSelectResult(
            response=dns.message.from_wire(base_success.response.to_wire()),
            winner=base_success.resolver,
            elapsed_ms=(monotonic() - started_at) * 1000,
            errors=batch_result.errors,
            selected_ip=None,
            selected_ip_rtt_ms=None,
            selected_ip_source_resolver=None,
        )

    selected_response = _rewrite_response_with_selected_ip(
        base_response=base_success.response,
        candidate=selected_candidate,
    )
    logger.debug(
        "benchmark_selector 选中IP base=%s ip_source=%s txid=%s qtype=%s domain=%s ip=%s rtt=%.2fms",
        base_success.resolver.name,
        selected_candidate.success.resolver.name,
        context.txid if context.txid is not None else "-",
        context.query_type or "-",
        context.query_name or "-",
        selected_candidate.ip,
        selected_candidate.rtt_ms,
    )
    return BenchmarkSelectResult(
        response=selected_response,
        winner=base_success.resolver,
        elapsed_ms=(monotonic() - started_at) * 1000,
        errors=batch_result.errors,
        selected_ip=selected_candidate.ip,
        selected_ip_rtt_ms=selected_candidate.rtt_ms,
        selected_ip_source_resolver=selected_candidate.success.resolver.name,
    )


def _pick_best_candidate(
    query: dns.message.Message,
    successes: tuple[ResolverBatchSuccess, ...],
    ip_benchmark_results: dict[str, float | None],
) -> _IpResponseCandidate | None:
    if not query.question:
        return None

    query_rdtype = query.question[0].rdtype
    if query_rdtype not in (dns.rdatatype.A, dns.rdatatype.AAAA):
        return None

    best: _IpResponseCandidate | None = None
    for success in successes:
        for rrset in success.response.answer:
            if rrset.rdtype != query_rdtype:
                continue
            owner = rrset.name.to_text()
            ttl = int(rrset.ttl)
            for rdata in rrset:
                ip_text = getattr(rdata, "address", None) or rdata.to_text()
                rtt_ms = ip_benchmark_results.get(ip_text)
                if rtt_ms is None:
                    continue

                candidate = _IpResponseCandidate(
                    ip=ip_text,
                    owner=owner,
                    ttl=ttl,
                    rdtype=query_rdtype,
                    rtt_ms=rtt_ms,
                    success=success,
                )
                if best is None or _is_better(candidate, best):
                    best = candidate
    return best


def _is_better(
    current: _IpResponseCandidate,
    previous: _IpResponseCandidate,
) -> bool:
    if current.rtt_ms < previous.rtt_ms:
        return True
    if current.rtt_ms > previous.rtt_ms:
        return False
    return current.success.elapsed_ms < previous.success.elapsed_ms


def _rewrite_response_with_selected_ip(
    base_response: dns.message.Message,
    candidate: _IpResponseCandidate,
) -> dns.message.Message:
    rewritten = dns.message.from_wire(base_response.to_wire())
    filtered_answers = [
        rrset
        for rrset in rewritten.answer
        if rrset.rdtype != candidate.rdtype
    ]
    selected_rrset = dns.rrset.from_text(
        candidate.owner,
        candidate.ttl,
        dns.rdataclass.IN,
        candidate.rdtype,
        candidate.ip,
    )
    filtered_answers.append(selected_rrset)
    rewritten.answer = filtered_answers
    return rewritten


def _collect_non_noerror_errors(
    successes: tuple[ResolverBatchSuccess, ...],
    errors: tuple[str, ...],
) -> str:
    details = list(errors)
    for item in successes:
        details.append(
            f"{item.resolver.name}: rcode={dns.rcode.to_text(item.response.rcode())}"
        )
    return "; ".join(details) if details else "-"
