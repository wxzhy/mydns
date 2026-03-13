from __future__ import annotations

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

    def get_response(self, query: dns.message.Message) -> dns.message.Message | None:
        key = self._build_key_from_query(query)
        if key is None:
            return None

        cached_answer = super().get(key)
        if not isinstance(cached_answer, CachedDnsAnswer):
            return None

        cached_message = dns.message.from_wire(cached_answer.response_wire)
        self._refresh_answer_ttl(cached_message, cached_answer)
        response = self._build_response_from_query(query, cached_message)
        return response

    def put_response(
        self,
        query: dns.message.Message,
        response: dns.message.Message,
    ) -> None:
        if not self._is_cacheable(response):
            return

        key = self._build_key_from_query(query)
        if key is None:
            return

        minimum_ttl = self._extract_min_answer_ttl(response.answer)
        if minimum_ttl is None or minimum_ttl < MIN_CACHEABLE_TTL:
            return

        # 缓存中仅保留与 answer 相关的响应内容。
        cache_message = self._build_cache_message(query, response)
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

    @staticmethod
    def _build_key_from_query(query: dns.message.Message) -> CacheKey | None:
        if not query.question:
            return None
        question = query.question[0]
        return (
            question.name.canonicalize(),
            question.rdtype,
            question.rdclass,
        )

    @staticmethod
    def _is_cacheable(response: dns.message.Message) -> bool:
        if response.rcode() != dns.rcode.NOERROR:
            return False
        if not response.answer:
            return False
        if response.flags & dns.flags.TC:
            return False
        return True

    @staticmethod
    def _extract_min_answer_ttl(
        answer_rrsets: list[dns.rrset.RRset] | tuple[dns.rrset.RRset, ...],
    ) -> int | None:
        ttl_values: list[int] = []
        for rrset in answer_rrsets:
            if rrset.rdtype == dns.rdatatype.OPT:
                continue
            ttl_values.append(max(0, int(rrset.ttl)))
        if not ttl_values:
            return None
        return min(ttl_values)

    @staticmethod
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

    @staticmethod
    def _build_cache_message(
        query: dns.message.Message,
        upstream_response: dns.message.Message,
    ) -> dns.message.Message:
        response = dns.message.make_response(query)
        response.set_rcode(upstream_response.rcode())
        # 保留来自上游的关键响应标志位。
        response.flags = dns.flags.QR | (query.flags & dns.flags.RD)
        response.flags |= upstream_response.flags & (
            dns.flags.RA | dns.flags.AA | dns.flags.AD | dns.flags.CD
        )
        response.answer = list(upstream_response.answer)
        return response

    @staticmethod
    def _build_response_from_query(
        query: dns.message.Message,
        cached_message: dns.message.Message,
    ) -> dns.message.Message:
        response = dns.message.make_response(query)
        response.set_rcode(cached_message.rcode())
        response.flags = dns.flags.QR | (query.flags & dns.flags.RD)
        response.flags |= cached_message.flags & (
            dns.flags.RA | dns.flags.AA | dns.flags.AD | dns.flags.CD
        )
        response.answer = list(cached_message.answer)
        return response
