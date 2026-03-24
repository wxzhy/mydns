"""缓存类与缓存插件测试。"""

from __future__ import annotations

import time
import unittest

import dns.name
import dns.rcode
import dns.rdatatype
import dns.rrset

from core.answer import Answer
from core.cache import AnswerLRUCache, build_cache_key
from core.context import QueryContext
from core.models import Query
from core.pipeline import Pipeline
from plugins.cache import CacheHook
from plugins.speedcheck import RewriteAnswerByRTTHook
from resolver.resolver import Resolver


def _make_query(
    qtype: dns.rdatatype.RdataType = dns.rdatatype.A,
) -> Query:
    return Query(
        client_addr=("127.0.0.1", 5335),
        qname=dns.name.from_text("www.example.com."),
        qtype=qtype,
    )


class _CountingResolver(Resolver):
    name = "counting"
    tags = {"default"}

    def __init__(self, *, rcode: dns.rcode.Rcode = dns.rcode.NOERROR) -> None:
        self.calls = 0
        self.rcode = rcode

    async def resolve(self, query: Query, timeout_s: float) -> Answer:
        _ = timeout_s
        self.calls += 1
        rrsets: list[dns.rrset.RRset] | None = None
        if self.rcode == dns.rcode.NOERROR and query.qtype == dns.rdatatype.A:
            rrsets = [dns.rrset.from_text(query.qname.to_text(), 30, "IN", "A", "1.1.1.1")]
        return Answer.from_query(query, rcode=self.rcode, rrsets=rrsets)


class TestAnswerLRUCache(unittest.TestCase):
    def test_get_should_rewrite_rrset_ttl_by_remaining_lifetime(self) -> None:
        cache = AnswerLRUCache(max_size=8)
        query = _make_query()
        rrset = dns.rrset.from_text("www.example.com.", 30, "IN", "A", "1.1.1.1")
        answer = Answer.from_query(query, rcode=dns.rcode.NOERROR, rrsets=[rrset])
        key = build_cache_key(query)

        cache.put(key, answer)
        with cache.lock:
            cache.data[key].value.expiration = time.time() + 5.2

        cached = cache.get(key)
        self.assertIsNotNone(cached)
        assert cached is not None
        self.assertIsNot(cached, answer)
        self.assertGreaterEqual(cached.response.answer[0].ttl, 4)
        self.assertLessEqual(cached.response.answer[0].ttl, 6)

        with cache.lock:
            self.assertEqual(cache.data[key].value.response.answer[0].ttl, 30)


class TestCacheHook(unittest.IsolatedAsyncioTestCase):
    async def test_cache_hit_should_short_circuit_upstream(self) -> None:
        resolver = _CountingResolver()
        cache_hook = CacheHook(cache=AnswerLRUCache(max_size=64))
        pipeline = Pipeline(
            resolvers=[resolver],
            request_hooks=[cache_hook],
            response_hooks=[RewriteAnswerByRTTHook(), cache_hook],
        )

        first_ctx = QueryContext(query=_make_query())
        first_answer = await pipeline.process(first_ctx)
        self.assertEqual(first_answer.response.rcode(), dns.rcode.NOERROR)
        self.assertEqual(resolver.calls, 1)

        second_ctx = QueryContext(query=_make_query())
        second_answer = await pipeline.process(second_ctx)
        self.assertEqual(second_answer.response.rcode(), dns.rcode.NOERROR)
        self.assertTrue(second_ctx.stop)
        self.assertTrue(second_ctx.state["cache_hit"])
        self.assertEqual(resolver.calls, 1)

    async def test_default_should_not_cache_nxdomain(self) -> None:
        resolver = _CountingResolver(rcode=dns.rcode.NXDOMAIN)
        cache_hook = CacheHook(cache=AnswerLRUCache(max_size=64))
        pipeline = Pipeline(
            resolvers=[resolver],
            request_hooks=[cache_hook],
            response_hooks=[RewriteAnswerByRTTHook(), cache_hook],
        )

        await pipeline.process(QueryContext(query=_make_query()))
        await pipeline.process(QueryContext(query=_make_query()))
        self.assertEqual(resolver.calls, 2)

    async def test_two_hook_instances_with_same_cache_name_should_share_cache(self) -> None:
        resolver = _CountingResolver()
        request_hook = CacheHook(cache_name="test-shared-cache", max_size=64)
        response_hook = CacheHook(cache_name="test-shared-cache", max_size=64)
        pipeline = Pipeline(
            resolvers=[resolver],
            request_hooks=[request_hook],
            response_hooks=[RewriteAnswerByRTTHook(), response_hook],
        )

        await pipeline.process(QueryContext(query=_make_query()))
        await pipeline.process(QueryContext(query=_make_query()))
        self.assertEqual(resolver.calls, 1)


if __name__ == "__main__":
    unittest.main()
