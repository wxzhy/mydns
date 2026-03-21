"""DNS 缓存实现。"""

from __future__ import annotations

from math import ceil
import time

import dns.message
import dns.name
import dns.rdataclass
import dns.rdatatype
import dns.resolver

from core.models import Query


CacheKey = tuple[
    dns.name.Name,
    dns.rdatatype.RdataType,
    dns.rdataclass.RdataClass,
]


def build_cache_key(query: Query) -> CacheKey:
    """从 Query 构建缓存键。"""
    rdclass = dns.rdataclass.IN
    if query.message is not None and query.message.question:
        rdclass = query.message.question[0].rdclass
    return (query.qname, query.qtype, rdclass)


class AnswerLRUCache(dns.resolver.LRUCache):
    """基于 dnspython 的 LRU Cache，支持响应 TTL 改写。"""

    def put(self, key: CacheKey, value: dns.resolver.Answer) -> None:
        # 缓存内部只保存副本，避免调用方后续修改污染缓存。
        super().put(key, self._clone_answer(value))

    def get(self, key: CacheKey) -> dns.resolver.Answer | None:
        cached = super().get(key)
        if cached is None:
            return None
        remaining_ttl = max(0, ceil(cached.expiration - time.time()))
        return self.rewrite_rrset_ttl(
            cached,
            ttl_s=remaining_ttl,
            preserve_expiration=cached.expiration,
        )

    def rewrite_rrset_ttl(
        self,
        answer: dns.resolver.Answer,
        *,
        ttl_s: int,
        preserve_expiration: float | None = None,
    ) -> dns.resolver.Answer:
        """返回一个新 Answer，并把 answer section 内 RRSet 的 TTL 改为指定值。"""
        ttl = max(0, int(ttl_s))
        cloned = self._clone_answer(answer)
        for rrset in cloned.response.answer:
            rrset.ttl = ttl
        cloned.response.index = None
        rebuilt = dns.resolver.Answer(
            cloned.qname,
            cloned.rdtype,
            cloned.rdclass,
            cloned.response,
            nameserver=cloned.nameserver,
            port=cloned.port,
        )
        if preserve_expiration is not None:
            rebuilt.expiration = preserve_expiration
        return rebuilt

    @staticmethod
    def _clone_answer(answer: dns.resolver.Answer) -> dns.resolver.Answer:
        response_copy = dns.message.from_wire(answer.response.to_wire())
        cloned = dns.resolver.Answer(
            answer.qname,
            answer.rdtype,
            answer.rdclass,
            response_copy,
            nameserver=answer.nameserver,
            port=answer.port,
        )
        cloned.expiration = answer.expiration
        return cloned
