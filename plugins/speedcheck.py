"""测速相关插件。"""

from __future__ import annotations

import asyncio
from collections.abc import Awaitable, Callable

import dns.rcode
import dns.name
import dns.rdata
import dns.rdataclass
import dns.rdatatype
import dns.rrset

from core.context import QueryContext
from core.hooks import ResolverHook, ResponseHook
from core.models import Answer, ResolverResult
from logger import get_logger
from plugins.utils.speedcheck import probe_ips
from upstream.selector import select_best_answer


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
            logger.debug(
                "测速跳过 resolver=%s reason=answer_or_error answer=%s error=%s",
                result.resolver_name,
                result.answer is not None,
                repr(result.error) if result.error else None,
            )
            return result
        if ctx.query.qtype not in {dns.rdatatype.A, dns.rdatatype.AAAA}:
            logger.debug(
                "测速跳过 resolver=%s qtype=%s reason=unsupported_qtype",
                result.resolver_name,
                ctx.query.qtype,
            )
            return result

        ips = _extract_ips(result.answer.rrsets, qtype=ctx.query.qtype)
        if not ips:
            logger.debug(
                "测速跳过 resolver=%s qname=%s qtype=%s reason=no_ip_rrset",
                result.resolver_name,
                ctx.query.qname.to_text(),
                ctx.query.qtype,
            )
            return result

        # 单个请求内的测速结果统一记录在 ctx.ip_list 中。
        ctx.ip_list.ips.update(ips)
        pending = [ip for ip in ips if ip not in ctx.ip_list.results]
        tested: dict[str, float | None] = {}
        logger.debug(
            "测速准备 resolver=%s qname=%s qtype=%s ips=%s pending=%s cached=%s",
            result.resolver_name,
            ctx.query.qname.to_text(),
            ctx.query.qtype,
            ips,
            pending,
            ctx.ip_list.results,
        )
        if pending:
            try:
                tested = await asyncio.wait_for(
                    self.probe_func(pending, self.timeout_s),
                    timeout=self.timeout_s,
                )
            except TimeoutError:
                tested = {ip: None for ip in pending}
                logger.debug(
                    "测速超时 resolver=%s qname=%s qtype=%s pending=%s timeout=%.3fs",
                    result.resolver_name,
                    ctx.query.qname.to_text(),
                    ctx.query.qtype,
                    pending,
                    self.timeout_s,
                )
            except Exception as exc:
                tested = {ip: None for ip in pending}
                logger.debug(
                    "测速异常 resolver=%s qname=%s qtype=%s pending=%s err=%r",
                    result.resolver_name,
                    ctx.query.qname.to_text(),
                    ctx.query.qtype,
                    pending,
                    exc,
                )
            for ip, rtt in tested.items():
                ctx.ip_list.results[ip] = rtt

        # 日志里保留本次真实发起测速的 IP，便于定位重复去重效果。
        logger.debug(
            "测速完成 resolver=%s qname=%s qtype=%s ips=%s pending=%s rtt=%s cache=%s",
            result.resolver_name,
            ctx.query.qname.to_text(),
            ctx.query.qtype,
            ips,
            pending,
            tested,
            ctx.ip_list.results,
        )
        return result


class RewriteAnswerByRTTHook(ResponseHook):
    """在响应阶段构造基础答案，并按 RTT 回填 A/AAAA RRSet。"""

    def __init__(
        self,
        max_return_ips: int = 2,
        ttl_s: int = 900,
    ) -> None:
        self.max_return_ips = max_return_ips
        self.ttl_s = max(600, min(900, ttl_s))

    async def on_response(self, ctx: QueryContext) -> None:
        if ctx.final_answer is None:
            logger.debug(
                "响应基础构造 qname=%s qtype=%s candidates=%s",
                ctx.query.qname.to_text(),
                ctx.query.qtype,
                len(ctx.candidates),
            )
            ctx.final_answer = select_best_answer(ctx)

        answer = ctx.final_answer
        if answer is None:
            logger.debug("响应改写跳过 qname=%s reason=no_final_answer", ctx.query.qname.to_text())
            return
        if answer.rcode != dns.rcode.NOERROR:
            logger.debug(
                "响应改写跳过 qname=%s qtype=%s reason=rcode_not_noerror rcode=%s",
                ctx.query.qname.to_text(),
                ctx.query.qtype,
                answer.rcode,
            )
            return
        if ctx.query.qtype not in {dns.rdatatype.A, dns.rdatatype.AAAA}:
            logger.debug(
                "响应改写跳过 qname=%s qtype=%s reason=unsupported_qtype",
                ctx.query.qname.to_text(),
                ctx.query.qtype,
            )
            return

        ip_rtt = {ip: rtt for ip, rtt in ctx.ip_list.results.items() if rtt is not None}
        if not ip_rtt:
            logger.debug(
                "响应改写跳过 qname=%s qtype=%s reason=no_rtt_data",
                ctx.query.qname.to_text(),
                ctx.query.qtype,
            )
            return

        ranked_ips = [ip for ip, _ in sorted(ip_rtt.items(), key=lambda item: item[1])]
        if not ranked_ips:
            return

        target_rrsets = [x for x in answer.rrsets if x.rdtype == ctx.query.qtype]
        if target_rrsets:
            rrset = target_rrsets[0]
            original_count = max(1, len(rrset))
            limit = min(self.max_return_ips, original_count, len(ranked_ips))
            selected_ips = ranked_ips[:limit]
            old_ips = [rdata.to_text() for rdata in rrset]
            owner_name = rrset.name
            rdclass = rrset.rdclass
            backfilled = False
        else:
            limit = min(self.max_return_ips, len(ranked_ips))
            selected_ips = ranked_ips[:limit]
            old_ips = []
            owner_name, rdclass = _resolve_owner_name_and_class(ctx, answer)
            backfilled = True

        if not selected_ips:
            return

        cname_count = sum(1 for x in answer.rrsets if x.rdtype == dns.rdatatype.CNAME)
        rewritten = _build_ip_rrset(
            owner_name=owner_name,
            rdclass=rdclass,
            qtype=ctx.query.qtype,
            ips=selected_ips,
            ttl_s=self.ttl_s,
        )

        if target_rrsets:
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
        else:
            answer.rrsets.append(rewritten)

        logger.debug(
            "响应IP改写 qname=%s qtype=%s cname_count=%s old_ips=%s new_ips=%s ttl=%s backfilled=%s rtt=%s",
            ctx.query.qname.to_text(),
            ctx.query.qtype,
            cname_count,
            old_ips,
            selected_ips,
            rewritten.ttl,
            backfilled,
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


def _resolve_owner_name_and_class(
    ctx: QueryContext,
    answer: Answer,
) -> tuple[dns.name.Name, dns.rdataclass.RdataClass]:
    rrsets = answer.rrsets
    cname_rrsets = [item for item in rrsets if item.rdtype == dns.rdatatype.CNAME]
    if cname_rrsets:
        last = cname_rrsets[-1]
        first_cname = next(iter(last), None)
        if first_cname is not None and hasattr(first_cname, "target"):
            return first_cname.target, last.rdclass
        return last.name, last.rdclass
    return ctx.query.qname, dns.rdataclass.IN


def _build_ip_rrset(
    owner_name: dns.name.Name,
    rdclass: dns.rdataclass.RdataClass,
    qtype: dns.rdatatype.RdataType,
    ips: list[str],
    ttl_s: int,
) -> dns.rrset.RRset:
    rrset = dns.rrset.RRset(owner_name, rdclass, qtype)
    rrset.ttl = ttl_s
    for ip in ips:
        rdata = dns.rdata.from_text(rdclass, qtype, ip)
        rrset.add(rdata, rrset.ttl)
    return rrset
