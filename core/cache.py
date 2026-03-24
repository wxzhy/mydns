"""DNS 缓存实现。"""

from __future__ import annotations

from math import ceil
import time

import dns.message
import dns.name
import dns.rdataclass
import dns.rdatatype
import dns.resolver

from core.answer import Answer
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

    def get(self, key: CacheKey) -> Answer | None:
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
    ) -> Answer:
        """返回一个新 Answer，并把 answer section 内 RRSet 的 TTL 改为指定值。"""
        ttl = max(0, int(ttl_s))
        cloned = self._clone_answer(answer)
        response = cloned.to_message()
        for rrset in response.answer:
            rrset.ttl = ttl
        response.index = None
        return Answer(
            cloned.qname,
            cloned.rdtype,
            cloned.rdclass,
            response,
            nameserver=cloned.nameserver,
            port=cloned.port,
            expiration=preserve_expiration,
        )

    @staticmethod
    def _clone_answer(answer: dns.resolver.Answer) -> Answer:
        return Answer.from_answer(answer)
