from __future__ import annotations

from dataclasses import dataclass
from time import monotonic
from typing import Sequence

import dns.rcode
import dns.rdataclass
import dns.rdatatype
import dns.rrset

from core.context import QueryContext
from logger import get_logger
from resolvers.resolver import ResolverProtocol
from selector.concurrent_selector import ResolverBatchSuccess, resolve_all

logger = get_logger(__name__)

_DEFAULT_SELECTED_IP_COUNT = 3
_MAX_SELECTED_IP_COUNT = 8


@dataclass(slots=True)
class BenchmarkSelectResult:
    """IP 测速聚合选择结果。"""

    rcode: dns.rcode.Rcode
    answer: list[dns.rrset.RRset]
    winner: ResolverProtocol
    elapsed_ms: float
    errors: tuple[str, ...]
    selected_ips: tuple[str, ...]
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
) -> BenchmarkSelectResult:
    """并发请求上游，聚合 context 中测速结果并构造最终响应。"""
    if not resolvers:
        raise ValueError("上游解析器列表不能为空。")

    started_at = monotonic()
    batch_result = await resolve_all(resolvers=resolvers, context=context)
    if not batch_result.successes:
        details = "; ".join(batch_result.errors) if batch_result.errors else "-"
        raise RuntimeError(f"所有 Resolver 均解析失败：{details}")

    noerror_successes = tuple(
        item for item in batch_result.successes if item.rcode == dns.rcode.NOERROR
    )
    if not noerror_successes:
        details = _collect_non_noerror_errors(
            batch_result.successes, batch_result.errors
        )
        raise RuntimeError(f"所有 Resolver 均未返回 NOERROR：{details}")

    base_success = min(noerror_successes, key=lambda item: item.elapsed_ms)
    selected_limit = _resolve_selected_ip_count(context)

    selected_candidates = _pick_best_candidates(
        context=context,
        successes=noerror_successes,
        limit=selected_limit,
    )

    if not selected_candidates:
        logger.debug(
            "测速聚合未命中可用结果，回退最快 NOERROR 响应 resolver=%s txid=%s qtype=%s domain=%s",
            base_success.resolver.name,
            context.txid if context.txid is not None else "-",
            context.query_type or "-",
            context.query_name or "-",
        )
        return BenchmarkSelectResult(
            rcode=base_success.rcode,
            answer=list(base_success.answer),
            winner=base_success.resolver,
            elapsed_ms=(monotonic() - started_at) * 1000,
            errors=batch_result.errors,
            selected_ips=(),
            selected_ip=None,
            selected_ip_rtt_ms=None,
            selected_ip_source_resolver=None,
        )

    selected_answer = _rewrite_answer_with_selected_ips(
        base_answer=base_success.answer,
        candidates=selected_candidates,
    )
    selected_ips = tuple(item.ip for item in selected_candidates)
    primary = selected_candidates[0]
    logger.debug(
        "测速聚合选中 IP base=%s txid=%s qtype=%s domain=%s ips=%s primary_source=%s primary_rtt=%.2fms",
        base_success.resolver.name,
        context.txid if context.txid is not None else "-",
        context.query_type or "-",
        context.query_name or "-",
        ", ".join(selected_ips),
        primary.success.resolver.name,
        primary.rtt_ms,
    )
    return BenchmarkSelectResult(
        rcode=base_success.rcode,
        answer=selected_answer,
        winner=base_success.resolver,
        elapsed_ms=(monotonic() - started_at) * 1000,
        errors=batch_result.errors,
        selected_ips=selected_ips,
        selected_ip=primary.ip,
        selected_ip_rtt_ms=primary.rtt_ms,
        selected_ip_source_resolver=primary.success.resolver.name,
    )


def _pick_best_candidates(
    context: QueryContext,
    successes: tuple[ResolverBatchSuccess, ...],
    limit: int,
) -> tuple[_IpResponseCandidate, ...]:
    if limit <= 0:
        return ()

    qtype_text = (context.query_type or "").strip().upper()
    if qtype_text not in ("A", "AAAA"):
        return ()

    query_rdtype = dns.rdatatype.from_text(qtype_text)
    candidates_by_ip: dict[str, _IpResponseCandidate] = {}
    for success in successes:
        for rrset in success.answer:
            if rrset.rdtype != query_rdtype:
                continue
            owner = rrset.name.to_text()
            ttl = int(rrset.ttl)
            for rdata in rrset:
                ip_text = getattr(rdata, "address", None) or rdata.to_text()
                rtt_ms = context.ip_benchmark_results.get(ip_text)
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
                previous = candidates_by_ip.get(ip_text)
                if previous is None or _is_better(candidate, previous):
                    candidates_by_ip[ip_text] = candidate

    ranked = sorted(candidates_by_ip.values(), key=_candidate_sort_key)
    return tuple(ranked[:limit])


def _is_better(
    current: _IpResponseCandidate,
    previous: _IpResponseCandidate,
) -> bool:
    if current.rtt_ms < previous.rtt_ms:
        return True
    if current.rtt_ms > previous.rtt_ms:
        return False
    return current.success.elapsed_ms < previous.success.elapsed_ms


def _candidate_sort_key(candidate: _IpResponseCandidate) -> tuple[float, float, str]:
    return (
        candidate.rtt_ms,
        candidate.success.elapsed_ms,
        candidate.ip,
    )


def _rewrite_answer_with_selected_ips(
    base_answer: list[dns.rrset.RRset],
    candidates: tuple[_IpResponseCandidate, ...],
) -> list[dns.rrset.RRset]:
    if not candidates:
        return list(base_answer)

    rdtype = candidates[0].rdtype
    owner, ttl = _resolve_target_rr_meta(base_answer, candidates)
    filtered = [rrset for rrset in base_answer if rrset.rdtype != rdtype]
    ips = [candidate.ip for candidate in candidates]
    selected_rrset = dns.rrset.from_text(
        owner,
        ttl,
        dns.rdataclass.IN,
        rdtype,
        *ips,
    )
    filtered.append(selected_rrset)
    return filtered


def _resolve_target_rr_meta(
    base_answer: list[dns.rrset.RRset],
    candidates: tuple[_IpResponseCandidate, ...],
) -> tuple[str, int]:
    rdtype = candidates[0].rdtype
    for rrset in base_answer:
        if rrset.rdtype != rdtype:
            continue
        return rrset.name.to_text(), int(rrset.ttl)
    primary = candidates[0]
    return primary.owner, primary.ttl


def _resolve_selected_ip_count(context: QueryContext) -> int:
    value = context.tags.get("ip_benchmark_top_n")
    if value is None:
        return _DEFAULT_SELECTED_IP_COUNT
    try:
        parsed = int(value)
    except (TypeError, ValueError):
        return _DEFAULT_SELECTED_IP_COUNT
    if parsed <= 0:
        return _DEFAULT_SELECTED_IP_COUNT
    return min(parsed, _MAX_SELECTED_IP_COUNT)


def _collect_non_noerror_errors(
    successes: tuple[ResolverBatchSuccess, ...],
    errors: tuple[str, ...],
) -> str:
    details = list(errors)
    for item in successes:
        details.append(f"{item.resolver.name}: rcode={dns.rcode.to_text(item.rcode)}")
    return "; ".join(details) if details else "-"
