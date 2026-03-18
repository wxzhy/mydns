"""响应聚合与选择策略。"""

from __future__ import annotations

from math import inf

import dns.rcode
import dns.rdatatype
import dns.rrset

from core.context import QueryContext
from core.models import Answer, ResolverResult


def select_best_answer(ctx: QueryContext) -> Answer:
    """根据查询类型选择最合适的响应。"""
    candidates = [x for x in ctx.candidates if x.answer is not None]
    if not candidates:
        return Answer(rcode=dns.rcode.SERVFAIL)

    if ctx.query.qtype in {dns.rdatatype.A, dns.rdatatype.AAAA}:
        selected = _select_fastest_ips(candidates, qtype=ctx.query.qtype, limit=2)
        if selected is not None:
            return selected

    return _select_fastest_success(candidates)


def _select_fastest_success(candidates: list[ResolverResult]) -> Answer:
    ordered = sorted(candidates, key=_candidate_speed_key)
    return ordered[0].answer


def _select_fastest_ips(
    candidates: list[ResolverResult],
    qtype: dns.rdatatype.RdataType,
    limit: int,
) -> Answer | None:
    ordered = sorted(candidates, key=_candidate_speed_key)
    selected_rrset: dns.rrset.RRset | None = None
    selected_rdata = []
    seen: set[str] = set()
    cname_chain: list[dns.rrset.RRset] = []

    for item in ordered:
        answer = item.answer
        if answer is None or answer.rcode != dns.rcode.NOERROR:
            continue

        if not cname_chain:
            cname_chain = [rr for rr in answer.rrsets if rr.rdtype == dns.rdatatype.CNAME]

        for rrset in answer.rrsets:
            if rrset.rdtype != qtype:
                continue
            if selected_rrset is None:
                selected_rrset = rrset
            for rdata in rrset:
                text = rdata.to_text()
                if text in seen:
                    continue
                selected_rdata.append(rdata)
                seen.add(text)
                if len(selected_rdata) >= limit:
                    break
            if len(selected_rdata) >= limit:
                break
        if len(selected_rdata) >= limit:
            break

    if selected_rrset is None or not selected_rdata:
        return None

    merged = dns.rrset.RRset(
        selected_rrset.name,
        selected_rrset.rdclass,
        selected_rrset.rdtype,
    )
    merged.ttl = selected_rrset.ttl
    for rdata in selected_rdata:
        merged.add(rdata, merged.ttl)

    return Answer(rcode=dns.rcode.NOERROR, rrsets=[*cname_chain, merged])


def _candidate_speed_key(item: ResolverResult) -> float:
    if item.elapsed_ms is None:
        return inf
    return item.elapsed_ms
