"""Step 1: 核心抽象与接口骨架测试。"""

from __future__ import annotations

import unittest

import dns.name
import dns.rcode
import dns.rdatatype

from core.answer import Answer
from core.context import QueryContext
from core.hooks import RequestHook, ResolverHook, ResponseHook
from core.models import Query, ResolverResult
from resolver.resolver import Resolver


class _DummyRequestHook(RequestHook):
    async def on_request(self, ctx: QueryContext) -> None:
        ctx.state["request"] = True


class _DummyResolverHook(ResolverHook):
    async def on_resolver_result(
        self,
        ctx: QueryContext,
        result: ResolverResult,
    ) -> ResolverResult | None:
        ctx.state["resolver_hook"] = result.resolver_name
        return result


class _DummyResponseHook(ResponseHook):
    async def on_response(self, ctx: QueryContext) -> None:
        ctx.state["response"] = True


class _DummyResolver(Resolver):
    name = "dummy"
    tags = {"default"}

    async def resolve(self, query: Query, timeout_s: float) -> Answer:
        _ = query, timeout_s
        return Answer.from_query(query, rcode=dns.rcode.NOERROR)


class TestCoreStep1(unittest.IsolatedAsyncioTestCase):
    def setUp(self) -> None:
        self.query = Query(
            client_addr=("127.0.0.1", 5335),
            qname=dns.name.from_text("example.com."),
            qtype=dns.rdatatype.A,
        )

    def test_answer_defaults(self) -> None:
        answer = Answer.from_query(self.query, rcode=dns.rcode.NOERROR)
        self.assertEqual(answer.response.rcode(), dns.rcode.NOERROR)
        self.assertEqual(answer.response.answer, [])

    def test_context_defaults(self) -> None:
        ctx = QueryContext(query=self.query)
        self.assertFalse(ctx.stop)
        self.assertEqual(ctx.tags, {"default"})
        self.assertEqual(ctx.candidates, [])
        self.assertEqual(ctx.ip_list.ips, set())
        self.assertEqual(ctx.ip_list.results, {})
        self.assertIsNone(ctx.final_answer)
        self.assertEqual(ctx.state, {})

    async def test_interfaces_minimal_impl(self) -> None:
        ctx = QueryContext(query=self.query)
        req_hook = _DummyRequestHook()
        resolver = _DummyResolver()
        resolver_hook = _DummyResolverHook()
        resp_hook = _DummyResponseHook()

        await req_hook.on_request(ctx)
        answer = await resolver.resolve(self.query, timeout_s=0.1)
        result = ResolverResult(
            resolver_name=resolver.name,
            answer=answer,
            elapsed_ms=10.0,
        )
        hooked = await resolver_hook.on_resolver_result(ctx, result)
        self.assertIsNotNone(hooked)
        ctx.candidates.append(hooked)
        ctx.final_answer = hooked.answer
        await resp_hook.on_response(ctx)

        self.assertTrue(ctx.state["request"])
        self.assertEqual(ctx.state["resolver_hook"], "dummy")
        self.assertTrue(ctx.state["response"])
        self.assertEqual(ctx.final_answer.response.rcode(), dns.rcode.NOERROR)


if __name__ == "__main__":
    unittest.main()
