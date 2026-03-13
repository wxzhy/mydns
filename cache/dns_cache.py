from __future__ import annotations

from dataclasses import dataclass
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


@dataclass(slots=True, frozen=True)
class CachedAnswerMeta:
    """缓存元数据，用于 TTL 递减计算。"""

    response_wire: bytes
    cached_at: float
    minimum_ttl: int


class CachedDnsAnswer(dns.resolver.Answer):
    """附带缓存元数据的 Answer。"""

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
        self.meta = CachedAnswerMeta(
            response_wire=response_wire,
            cached_at=cached_at,
            minimum_ttl=minimum_ttl,
        )
        # 显式使用我们计算出的最小 TTL，避免 Answer 默认 TTL 在某些异常响应中过大。
        self.expiration = cached_at + minimum_ttl


class DnsLruCache(dns.resolver.LRUCache):
    """基于 dnspython LRUCache 的 DNS 响应缓存。"""

    def __init__(self, max_size: int = 10000) -> None:
        super().__init__(max_size=max_size)

    def get_response(self, query: dns.message.Message) -> dns.message.Message | None:
        """按 query 的问题段读取缓存，命中后复用当前请求 ID。"""
        key = self._build_key_from_query(query)
        if key is None:
            return None

        cached_answer = super().get(key)
        if cached_answer is None:
            return None
        if not isinstance(cached_answer, dns.resolver.Answer):  # pragma: no cover
            return None

        response = self._clone_cached_response(cached_answer)
        self._refresh_response_ttl(response, cached_answer)
        response.id = query.id
        return response

    def put_response(
        self,
        query: dns.message.Message,
        response: dns.message.Message,
    ) -> None:
        """根据响应 TTL 写入缓存。"""
        if not self._is_cacheable(response):
            return

        key = self._build_key_from_query(query)
        if key is None:
            return

        min_ttl = self._extract_min_ttl(response)
        if min_ttl is None or min_ttl < MIN_CACHEABLE_TTL:
            return

        # 存储独立副本，避免后续处理链修改影响缓存内容。
        cloned = dns.message.from_wire(response.to_wire())
        wire = cloned.to_wire()
        cached_at = time()
        answer = CachedDnsAnswer(
            qname=key[0],
            rdtype=key[1],
            rdclass=key[2],
            response_wire=wire,
            cached_at=cached_at,
            minimum_ttl=min_ttl,
        )
        # 按 LRUCache 原始签名写入：(key, dns.resolver.Answer)。
        super().put(key, answer)

    @staticmethod
    def _build_key_from_query(query: dns.message.Message) -> CacheKey | None:
        if not query.question:
            return None
        question = query.question[0]
        normalized_name = question.name.canonicalize()
        return (
            normalized_name,
            question.rdtype,
            question.rdclass,
        )

    @staticmethod
    def _extract_min_ttl(response: dns.message.Message) -> int | None:
        # 优先使用 Answer 区 TTL，避免 Authority/Additional 的 0 TTL 误伤正向缓存。
        answer_ttl = DnsLruCache._min_ttl_from_rrsets(response.answer)
        if answer_ttl is not None:
            return answer_ttl

        # 负缓存优先按 SOA 规则计算（RFC 2308）：min(SOA RR TTL, SOA.MINIMUM)。
        negative_ttl = DnsLruCache._extract_negative_ttl(response)
        if negative_ttl is not None:
            return negative_ttl

        # 兜底：仅在无 Answer/无 SOA 时，才考虑 Authority/Additional。
        return DnsLruCache._min_ttl_from_rrsets(
            [*response.authority, *response.additional]
        )

    @staticmethod
    def _is_cacheable(response: dns.message.Message) -> bool:
        rcode = response.rcode()
        if rcode in (dns.rcode.SERVFAIL, dns.rcode.REFUSED, dns.rcode.FORMERR):
            return False
        if response.flags & dns.flags.TC:
            return False
        return True

    @staticmethod
    def _min_ttl_from_rrsets(
        rrsets: list[dns.rrset.RRset] | tuple[dns.rrset.RRset, ...],
    ) -> int | None:
        ttl_values: list[int] = []
        for rrset in rrsets:
            # OPT 记录的 ttl 字段并非缓存 TTL。
            if rrset.rdtype == dns.rdatatype.OPT:
                continue
            ttl_values.append(max(0, int(rrset.ttl)))
        if not ttl_values:
            return None
        return min(ttl_values)

    @staticmethod
    def _extract_negative_ttl(response: dns.message.Message) -> int | None:
        candidates: list[int] = []
        for rrset in response.authority:
            if rrset.rdtype != dns.rdatatype.SOA:
                continue
            rrset_ttl = max(0, int(rrset.ttl))
            if not rrset:
                candidates.append(rrset_ttl)
                continue
            for rdata in rrset:
                minimum = max(0, int(getattr(rdata, "minimum", rrset_ttl)))
                candidates.append(min(rrset_ttl, minimum))
        if not candidates:
            return None
        return min(candidates)

    @staticmethod
    def _clone_cached_response(cached_answer: dns.resolver.Answer) -> dns.message.Message:
        if isinstance(cached_answer, CachedDnsAnswer):
            return dns.message.from_wire(cached_answer.meta.response_wire)
        return dns.message.from_wire(cached_answer.response.to_wire())

    @staticmethod
    def _refresh_response_ttl(
        response: dns.message.Message,
        cached_answer: dns.resolver.Answer,
    ) -> None:
        now = time()
        if isinstance(cached_answer, CachedDnsAnswer):
            age_seconds = max(0.0, now - cached_answer.meta.cached_at)
        else:
            minimum_ttl = getattr(
                getattr(cached_answer, "chaining_result", None),
                "minimum_ttl",
                None,
            )
            if minimum_ttl is None:
                age_seconds = 0.0
            else:
                created_at = cached_answer.expiration - float(minimum_ttl)
                age_seconds = max(0.0, now - created_at)

        ttl_decay = int(age_seconds)
        if ttl_decay <= 0:
            return

        for rrset in [*response.answer, *response.authority, *response.additional]:
            if rrset.rdtype == dns.rdatatype.OPT:
                continue
            rrset.ttl = max(0, int(rrset.ttl) - ttl_decay)
