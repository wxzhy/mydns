"""DNS 缓存实现。"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass
from math import ceil
import time
from typing import Any

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


@dataclass(slots=True, frozen=True)
class PendingRequest:
    """记录一次同 key 请求合并的归属信息。"""

    cache: "AnswerLRUCache"
    key: CacheKey
    owner: bool


def build_cache_key(query: Query) -> CacheKey:
    """从 Query 构建缓存键。"""
    rdclass = dns.rdataclass.IN
    if query.message is not None and query.message.question:
        rdclass = query.message.question[0].rdclass
    return (query.qname, query.qtype, rdclass)


class AnswerLRUCache(dns.resolver.LRUCache):
    """基于 dnspython 的 LRU Cache，支持响应 TTL 改写。"""

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self._pending_lock = asyncio.Lock()
        self._pending: dict[CacheKey, asyncio.Future[Answer]] = {}

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

    async def acquire_pending(self, key: CacheKey) -> tuple[PendingRequest, asyncio.Future[Answer]]:
        """为同 key 请求建立或复用 in-flight future。"""
        async with self._pending_lock:
            future = self._pending.get(key)
            if future is None:
                future = asyncio.get_running_loop().create_future()
                self._pending[key] = future
                return PendingRequest(cache=self, key=key, owner=True), future
            return PendingRequest(cache=self, key=key, owner=False), future

    async def resolve_pending(
        self,
        key: CacheKey,
        answer: dns.resolver.Answer,
    ) -> None:
        """完成同 key in-flight 请求，并向等待者广播最终结果。"""
        async with self._pending_lock:
            future = self._pending.get(key)
            if future is None:
                return
            if not future.done():
                future.set_result(self._clone_answer(answer))
            self._pending.pop(key, None)

    async def fail_pending(self, key: CacheKey, exc: BaseException) -> None:
        """让等待中的同 key 请求共享同一个异常。"""
        async with self._pending_lock:
            future = self._pending.get(key)
            if future is None:
                return
            if not future.done():
                future.set_exception(exc)
            self._pending.pop(key, None)


def get_pending_request(state: dict[str, Any]) -> PendingRequest | None:
    pending = state.get("cache_pending_request")
    if isinstance(pending, PendingRequest):
        return pending
    return None


async def resolve_pending_request(
    state: dict[str, Any],
    answer: dns.resolver.Answer | None,
) -> None:
    pending = get_pending_request(state)
    if pending is None or not pending.owner or answer is None:
        return
    await pending.cache.resolve_pending(pending.key, answer)


async def fail_pending_request(
    state: dict[str, Any],
    exc: BaseException,
) -> None:
    pending = get_pending_request(state)
    if pending is None or not pending.owner:
        return
    await pending.cache.fail_pending(pending.key, exc)
