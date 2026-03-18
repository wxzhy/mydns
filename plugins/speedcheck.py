"""测速相关插件。"""

from __future__ import annotations

from collections.abc import Awaitable, Callable

import dns.rdata
import dns.rdatatype
import dns.rrset

from core.context import QueryContext
from core.hooks import ResolverHook, ResponseHook
from core.models import ResolverResult
from logger import get_logger
from upstream.speedcheck import probe_ips


logger = get_logger("plugins.speedcheck")
ProbeIPsFunc = Callable[[list[str], float], Awaitable[dict[str, float | None]]]


class SpeedCheckResolverHook(ResolverHook):
    """对 A/AAAA 候选 IP 执行测速，并写入上下文状态。"""

    def __init__(
        self,
        *,
        timeout_s: float = 0.8,
        probe_func: ProbeIPsFunc | None = None,
    ) -> None:
        self.timeout_s = timeout_s
        self.probe_func = probe_func or probe_ips

    async def on_resolver_result(
        self,
        ctx: QueryContext,
        result: ResolverResult,
    ) -> ResolverResult | None:
        if result.answer is None or result.error is not None:
            return result
        if ctx.query.qtype not in {dns.rdatatype.A, dns.rdatatype.AAAA}:
            return result

        ips = _extract_ips(result.answer.rrsets, qtype=ctx.query.qtype)
        if not ips:
            return result

        tested = await self.probe_func(ips, self.timeout_s)
        merged = ctx.state.setdefault("ip_rtt_ms", {})
        for ip, rtt in tested.items():
            if rtt is None:
                continue
            current = merged.get(ip)
            merged[ip] = rtt if current is None else min(current, rtt)
        logger.debug(
            "测速完成 resolver=%s qname=%s qtype=%s ips=%s rtt=%s",
            result.resolver_name,
            ctx.query.qname.to_text(),
            ctx.query.qtype,
            ips,
            tested,
        )
        return result


class RewriteAnswerByRTTHook(ResponseHook):
    """按测速结果改写 A/AAAA 响应中的 IP 顺序与集合。"""

    def __init__(self, max_return_ips: int = 2) -> None:
        self.max_return_ips = max_return_ips

    async def on_response(self, ctx: QueryContext) -> None:
        answer = ctx.final_answer
        if answer is None:
            return
        if ctx.query.qtype not in {dns.rdatatype.A, dns.rdatatype.AAAA}:
            return

        ip_rtt: dict[str, float] = ctx.state.get("ip_rtt_ms", {})
        if not ip_rtt:
            return

        target_rrsets = [x for x in answer.rrsets if x.rdtype == ctx.query.qtype]
        if not target_rrsets:
            return

        rrset = target_rrsets[0]
        original_count = max(1, len(rrset))
        limit = min(self.max_return_ips, original_count)
        ranked_ips = [ip for ip, _ in sorted(ip_rtt.items(), key=lambda item: item[1])]
        if not ranked_ips:
            return

        selected_ips = ranked_ips[:limit]
        rewritten = dns.rrset.RRset(rrset.name, rrset.rdclass, rrset.rdtype)
        rewritten.ttl = rrset.ttl
        for ip in selected_ips:
            rdata = dns.rdata.from_text(rrset.rdclass, rrset.rdtype, ip)
            rewritten.add(rdata, rewritten.ttl)

        new_rrsets: list[dns.rrset.RRset] = []
        replaced = False
        for item in answer.rrsets:
            if item.rdtype == ctx.query.qtype:
                if not replaced:
                    new_rrsets.append(rewritten)
                    replaced = True
                continue
            new_rrsets.append(item)
        answer.rrsets = new_rrsets
        logger.debug(
            "响应IP改写 qname=%s qtype=%s selected=%s rtt=%s",
            ctx.query.qname.to_text(),
            ctx.query.qtype,
            selected_ips,
            ip_rtt,
        )


def _extract_ips(rrsets: list[dns.rrset.RRset], qtype: dns.rdatatype.RdataType) -> list[str]:
    ips: list[str] = []
    for rrset in rrsets:
        if rrset.rdtype != qtype:
            continue
        for rdata in rrset:
            text = rdata.to_text()
            if text not in ips:
                ips.append(text)
    return ips
