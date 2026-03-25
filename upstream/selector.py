"""响应聚合与选择策略。"""

from __future__ import annotations

from math import inf

import dns.rcode

from core.answer import Answer
from core.context import QueryContext
from core.models import ResolverResult
from logger import get_logger


logger = get_logger("upstream.selector")


def select_best_answer(ctx: QueryContext) -> Answer:
    """选择基础结果：优先最快正常响应。"""
    candidates = [x for x in ctx.candidates if x.answer is not None]
    if not candidates:
        logger.debug(
            "基础结果选择失败 qname=%s qtype=%s reason=no_answer_candidate",
            ctx.query.qname.to_text(),
            ctx.query.qtype,
        )
        return Answer.from_query(ctx.query, rcode=dns.rcode.SERVFAIL)
    tagged = _select_tagged_answer(candidates, tag="ads")
    if tagged is not None:
        logger.debug(
            "基础结果选择命中ads qname=%s qtype=%s tags=%s rrset_count=%s",
            ctx.query.qname.to_text(),
            ctx.query.qtype,
            sorted(tagged.tags),
            len(tagged.response.answer),
        )
        return tagged
    selected = _select_fastest_normal(candidates)
    logger.debug(
        "基础结果选择完成 qname=%s qtype=%s selected_rcode=%s rrset_count=%s",
        ctx.query.qname.to_text(),
        ctx.query.qtype,
        selected.response.rcode(),
        len(selected.response.answer),
    )
    return selected


def _select_fastest_normal(candidates: list[ResolverResult]) -> Answer:
    """返回最快 NOERROR；若不存在则回退最快响应。"""
    ordered = sorted(candidates, key=_candidate_speed_key)
    for item in ordered:
        if item.answer.response.rcode() == dns.rcode.NOERROR:
            return item.answer
    return ordered[0].answer


def _select_tagged_answer(
    candidates: list[ResolverResult],
    *,
    tag: str,
) -> Answer | None:
    for item in candidates:
        answer = item.answer
        if answer is None:
            continue
        if tag in answer.tags:
            return answer
    return None


def _candidate_speed_key(item: ResolverResult) -> float:
    if item.elapsed_ms is None:
        return inf
    return item.elapsed_ms
