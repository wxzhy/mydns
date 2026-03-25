"""基于 CNAME 链的标签匹配与 uncloaking 过滤。"""

from __future__ import annotations

import dns.rcode
import dns.rdata
import dns.rdataclass
import dns.rdatatype
import dns.rrset

from core.answer import Answer
from core.context import QueryContext
from core.domainset import domainset
from core.hooks import ResolverHook
from core.models import ResolverResult
from logger import get_logger


logger = get_logger("plugins.tagset")

_ADS_TAG = "ads"
_LOCALHOST_A = "127.0.0.1"
_LOCALHOST_AAAA = "::1"
_DEFAULT_TTL_S = 60


class TagSetResolverHook(ResolverHook):
    """根据 CNAME 链补充 answer.tags，并对 ads 结果做 uncloaking 拦截。"""

    async def on_resolver_result(
        self,
        ctx: QueryContext,
        result: ResolverResult,
    ) -> ResolverResult | None:
        answer = result.answer
        if answer is None or result.error is not None:
            return result

        matched_tags = _merge_cname_tags(answer)
        if matched_tags:
            _log_cname_tag_match(ctx, result, matched_tags)

        if _ADS_TAG not in answer.tags:
            return result

        result.answer = _build_blocked_answer(ctx, answer)
        logger.debug(
            "CNAME uncloaking拦截 resolver=%s qname=%s qtype=%s tags=%s rrset_count=%s",
            result.resolver_name,
            ctx.query.qname.to_text(),
            ctx.query.qtype,
            sorted(result.answer.tags),
            len(result.answer.response.answer),
        )
        return result


def _merge_cname_tags(answer: Answer) -> set[str]:
    """扫描 CNAME 链，把命中的 domainset tag 合并进 answer.tags。"""
    matched_tags = _match_cname_tags(answer)
    if matched_tags:
        answer.tags.update(matched_tags)
    return matched_tags


def _match_cname_tags(answer: Answer) -> set[str]:
    chain = getattr(answer, "chaining_result", None)
    if chain is None or not chain.cnames:
        return set()

    matched_tags: set[str] = set()
    for rrset in chain.cnames:
        for rdata in rrset:
            matched_tags.update(domainset.match_tags(rdata.to_text()))

    canonical_name = getattr(chain, "canonical_name", None)
    if canonical_name is not None:
        matched_tags.update(domainset.match_tags(canonical_name.to_text()))
    return matched_tags


def _log_cname_tag_match(
    ctx: QueryContext,
    result: ResolverResult,
    matched_tags: set[str],
) -> None:
    logger.debug(
        "CNAME标签命中 resolver=%s qname=%s matched=%s tags=%s",
        result.resolver_name,
        ctx.query.qname.to_text(),
        sorted(matched_tags),
        sorted(result.answer.tags) if result.answer is not None else [],
    )


def _build_blocked_answer(ctx: QueryContext, answer: Answer) -> Answer:
    if ctx.query.qtype in {dns.rdatatype.A, dns.rdatatype.AAAA}:
        # 地址查询直接回本地回环地址，保留已有 CNAME 链和其他元信息。
        rrset = _build_localhost_rrset(answer, qtype=ctx.query.qtype)
        answer.set_rcode(dns.rcode.NOERROR, update_message=False)
        answer.replace_rrset(rrset, preserve_expiration=answer.expiration)
        return answer

    # 非地址查询返回空 NOERROR，避免继续泄露真实记录。
    return Answer.from_query(
        ctx.query,
        rcode=dns.rcode.NOERROR,
        nameserver=answer.nameserver,
        port=answer.port,
        tags=answer.tags,
    )


def _build_localhost_rrset(
    answer: Answer,
    *,
    qtype: dns.rdatatype.RdataType,
) -> dns.rrset.RRset:
    rrset = answer.rrset
    owner_name = (
        rrset.name
        if rrset is not None
        else (answer.chaining_result.canonical_name or answer.qname)
    )
    ttl_s = rrset.ttl if rrset is not None else _DEFAULT_TTL_S
    target_ip = _LOCALHOST_A if qtype == dns.rdatatype.A else _LOCALHOST_AAAA

    rewritten = dns.rrset.RRset(owner_name, answer.rdclass, qtype)
    rewritten.ttl = ttl_s
    rewritten.add(dns.rdata.from_text(answer.rdclass, qtype, target_ip), ttl_s)
    return rewritten
