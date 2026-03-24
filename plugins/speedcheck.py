"""测速相关插件。"""

from __future__ import annotations

import asyncio
from collections.abc import Awaitable, Callable

import dns.rcode
import dns.name
import dns.rdata
import dns.rdataclass
import dns.rdatatype
import dns.resolver
import dns.rrset
import time
from core.answer import Answer
from core.context import QueryContext
from core.hooks import ResolverHook, ResponseHook
from core.models import ResolverResult
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
        qname_text = ctx.query.qname.to_text()
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

        # 统一从 Answer.rrset 读取 IP 候选，避免扫描 response.answer 的冗余逻辑。
        ips = _extract_ips(result.answer, qtype=ctx.query.qtype)
        if not ips:
            logger.debug(
                "测速跳过 resolver=%s qname=%s qtype=%s reason=no_ip_rrset",
                result.resolver_name,
                qname_text,
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
            qname_text,
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
                    qname_text,
                    ctx.query.qtype,
                    pending,
                    self.timeout_s,
                )
            except Exception as exc:
                tested = {ip: None for ip in pending}
                logger.debug(
                    "测速异常 resolver=%s qname=%s qtype=%s pending=%s err=%r",
                    result.resolver_name,
                    qname_text,
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
            qname_text,
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
        qname_text = ctx.query.qname.to_text()
        if ctx.final_answer is None:
            logger.debug(
                "响应基础构造 qname=%s qtype=%s candidates=%s",
                qname_text,
                ctx.query.qtype,
                len(ctx.candidates),
            )
            ctx.final_answer = select_best_answer(ctx)

        answer = ctx.final_answer
        if answer is None:
            logger.debug(
                "响应改写跳过 qname=%s reason=no_final_answer",
                qname_text,
            )
            return
        assert isinstance(answer, Answer)
        if answer.response.rcode() != dns.rcode.NOERROR:
            logger.debug(
                "响应改写跳过 qname=%s qtype=%s reason=rcode_not_noerror rcode=%s",
                qname_text,
                ctx.query.qtype,
                answer.response.rcode(),
            )
            return
        if ctx.query.qtype not in {dns.rdatatype.A, dns.rdatatype.AAAA}:
            logger.debug(
                "响应改写跳过 qname=%s qtype=%s reason=unsupported_qtype",
                qname_text,
                ctx.query.qtype,
            )
            return

        # 仅使用已有测速结果（None 表示失败/超时）参与排序。
        ip_rtt = {ip: rtt for ip, rtt in ctx.ip_list.results.items() if rtt is not None}
        if not ip_rtt:
            logger.debug(
                "响应改写跳过 qname=%s qtype=%s reason=no_rtt_data",
                qname_text,
                ctx.query.qtype,
            )
            return

        ranked_ips = [ip for ip, _ in sorted(ip_rtt.items(), key=lambda item: item[1])]
        if not ranked_ips:
            return

        chain = answer.chaining_result
        owner_name = answer.chaining_result.canonical_name or answer.qname
        limit = min(self.max_return_ips, len(ranked_ips))
        selected_ips = ranked_ips[:limit]
        if not selected_ips:
            return

        # `chaining_result` 与 `rrset` 在 Answer 中是独立部分：
        # 这里只替换 rrset，CNAME 链保持由 chaining_result 负责。
        rewritten = _build_ip_rrset(
            owner_name=owner_name,
            rdclass=answer.rdclass,
            qtype=answer.rdtype,
            ips=selected_ips,
            ttl_s=self.ttl_s,
        )
        answer.replace_rrset(
            rewritten,
            preserve_expiration=time.time() + self.ttl_s,
        )
        cname_count = len(chain.cnames)

        logger.debug(
            "响应IP改写 qname=%s qtype=%s cname_count=%s new_ips=%s ttl=%s rtt=%s",
            qname_text,
            ctx.query.qtype,
            cname_count,
            selected_ips,
            rewritten.ttl,
            ip_rtt,
        )


def _extract_ips(
    answer: Answer,
    *,
    qtype: dns.rdatatype.RdataType,
) -> list[str]:
    """从 Answer.rrset 提取 A/AAAA 地址，保持原顺序并去重。"""
    rrset = answer.rrset
    if rrset is None or rrset.rdtype != qtype:
        return []

    ips: list[str] = []
    seen: set[str] = set()
    for rdata in rrset:
        ip_text = rdata.to_text()
        if ip_text in seen:
            continue
        seen.add(ip_text)
        ips.append(ip_text)
    return ips


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
