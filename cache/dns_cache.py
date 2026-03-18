from __future__ import annotations

"""DNS 缓存实现。

以 QueryContext 的抽象字段（rcode + answer）为中心，
只缓存 NOERROR 且 answer 非空的响应。
"""

from time import time
from typing import Final

import dns.flags
import dns.message
import dns.name
import dns.rdataclass
import dns.rdatatype
import dns.rcode
import dns.resolver
import dns.rrset

from core.context import QueryContext

CacheKey = tuple[
    dns.name.Name,
    dns.rdatatype.RdataType,
    dns.rdataclass.RdataClass,
]

MIN_CACHEABLE_TTL: Final[int] = 1


class CachedDnsAnswer(dns.resolver.Answer):
    """缓存条目：保存响应副本与缓存时间，用于 TTL 衰减。"""

    def __init__(
        self,
        qname: dns.name.Name,
        rdtype: dns.rdatatype.RdataType,
        rdclass: dns.rdataclass.RdataClass,
        response_wire: bytes,
        cached_at: float,
        minimum_ttl: int,
    ) -> None:
        response = dns.message.from_wire(response_wire)
        super().__init__(qname, rdtype, rdclass, response)
        self.response_wire = response_wire
        self.cached_at = cached_at
        self.minimum_ttl = minimum_ttl
        self.expiration = cached_at + minimum_ttl


class DnsLruCache(dns.resolver.LRUCache):
    """
    基于 dnspython LRUCache 的简化 DNS 缓存：
    - 仅缓存 NOERROR 且 answer 非空的结果
    - 仅处理 answer 区，不处理 authority/additional
    """

    def __init__(self, max_size: int = 10000) -> None:
        super().__init__(max_size=max_size)

    def get(self, context: QueryContext) -> bool:
        """命中缓存时将 rcode/answer 写入 context，返回 True；否则返回 False。"""
        query = context.raw_query
        if query is None:
            return False
        key = _build_key_from_query(query)
        if key is None:
            return False

        cached_answer = super().get(key)
        if not isinstance(cached_answer, CachedDnsAnswer):
            return False

        cached_message = dns.message.from_wire(cached_answer.response_wire)
        _refresh_answer_ttl(cached_message, cached_answer)

        context.set_answer(cached_message.rcode(), list(cached_message.answer))
        return True

    def put(self, context: QueryContext) -> None:
        """缓存 context 中的 rcode/answer（仅 NOERROR 且非空）。"""
        if not _is_cacheable(context.rcode, context.answer):
            return

        query = context.raw_query
        if query is None:
            return
        key = _build_key_from_query(query)
        if key is None:
            return

        minimum_ttl = _extract_min_answer_ttl(context.answer or [])
        if minimum_ttl is None or minimum_ttl < MIN_CACHEABLE_TTL:
            return

        cache_message = _build_cache_message(context)
        response_wire = cache_message.to_wire()
        cached_at = time()
        cached = CachedDnsAnswer(
            qname=key[0],
            rdtype=key[1],
            rdclass=key[2],
            response_wire=response_wire,
            cached_at=cached_at,
            minimum_ttl=minimum_ttl,
        )
        super().put(key, cached)


def _build_key_from_query(query: dns.message.Message) -> CacheKey | None:
    if not query.question:
        return None
    question = query.question[0]
    return (
        question.name.canonicalize(),
        question.rdtype,
        question.rdclass,
    )


def _is_cacheable(
    rcode: dns.rcode.Rcode | None,
    answer: list[dns.rrset.RRset] | None,
) -> bool:
    if rcode != dns.rcode.NOERROR:
        return False
    if not answer:
        return False
    return True


def _extract_min_answer_ttl(
    answer_rrsets: list[dns.rrset.RRset],
) -> int | None:
    ttl_values: list[int] = []
    for rrset in answer_rrsets:
        if rrset.rdtype == dns.rdatatype.OPT:
            continue
        ttl_values.append(max(0, int(rrset.ttl)))
    if not ttl_values:
        return None
    return min(ttl_values)


def _refresh_answer_ttl(
    response: dns.message.Message,
    cached_answer: CachedDnsAnswer,
) -> None:
    ttl_decay = int(max(0.0, time() - cached_answer.cached_at))
    if ttl_decay <= 0:
        return
    for rrset in response.answer:
        if rrset.rdtype == dns.rdatatype.OPT:
            continue
        rrset.ttl = max(0, int(rrset.ttl) - ttl_decay)


def _build_cache_message(context: QueryContext) -> dns.message.Message:
    """根据 context 抽象响应字段构造用于缓存的响应报文。"""
    query = context.raw_query
    if query is None:  # pragma: no cover
        raise ValueError("缓存写入需要 QueryContext.raw_query。")
    if context.rcode is None:  # pragma: no cover
        raise ValueError("缓存写入需要 QueryContext.rcode。")

    response = dns.message.make_response(query)
    response.set_rcode(context.rcode)
    response.flags = dns.flags.QR | (query.flags & dns.flags.RD)
    response.answer = list(context.answer or [])
    return response
