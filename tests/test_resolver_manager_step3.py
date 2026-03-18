"""Step 3: ResolverManager 并发与 resolver hook 测试。"""

from __future__ import annotations

import asyncio
import time
import unittest

import dns.name
import dns.rcode
import dns.rdatatype

from core.context import QueryContext
from core.hooks import Resolver, ResolverHook
from core.models import Answer, Query, ResolverResult
from core.resolver_manager import ResolverManager


class _SleepResolver(Resolver):
    def __init__(
        self,
        name: str,
        delay_s: float,
        answer: Answer | None = None,
        error: Exception | None = None,
        tags: set[str] | None = None,
    ) -> None:
        self.name = name
        self.delay_s = delay_s
        self.answer = answer or Answer(rcode=dns.rcode.NOERROR)
        self.error = error
        self.tags = tags or {"default"}

    async def resolve(self, query: Query, timeout_s: float) -> Answer:
        _ = query, timeout_s
        await asyncio.sleep(self.delay_s)
        if self.error is not None:
            raise self.error
        return self.answer


class _DropErrorHook(ResolverHook):
    async def on_resolver_result(
        self,
        ctx: QueryContext,
        result: ResolverResult,
    ) -> ResolverResult | None:
        ctx.state.setdefault("resolver_hook_calls", []).append(result.resolver_name)
        if result.error is not None:
            return None
        return result


class _RewriteRcodeHook(ResolverHook):
    async def on_resolver_result(
        self,
        ctx: QueryContext,
        result: ResolverResult,
    ) -> ResolverResult | None:
        _ = ctx
        if result.answer is not None:
            result.answer.rcode = dns.rcode.NOERROR
        return result


class TestResolverManagerStep3(unittest.IsolatedAsyncioTestCase):
    def setUp(self) -> None:
        query = Query(
            client_addr=("127.0.0.1", 5353),
            qname=dns.name.from_text("example.com."),
            qtype=dns.rdatatype.A,
        )
        self.ctx = QueryContext(query=query)

    async def test_concurrent_collect(self) -> None:
        manager = ResolverManager(
            resolvers=[
                _SleepResolver("r1", delay_s=0.12),
                _SleepResolver("r2", delay_s=0.12),
            ]
        )
        start = time.perf_counter()
        await manager.collect(self.ctx, timeout_s=0.4)
        duration = time.perf_counter() - start

        self.assertLess(duration, 0.2)
        self.assertEqual(len(self.ctx.candidates), 2)

    async def test_timeout_and_tag_filter(self) -> None:
        manager = ResolverManager(
            resolvers=[
                _SleepResolver("slow", delay_s=0.4, tags={"default"}),
                _SleepResolver("fast", delay_s=0.02, tags={"default"}),
                _SleepResolver("cn-only", delay_s=0.01, tags={"cn"}),
            ]
        )

        start = time.perf_counter()
        await manager.collect(self.ctx, timeout_s=0.08)
        duration = time.perf_counter() - start

        names = {x.resolver_name for x in self.ctx.candidates}
        self.assertLess(duration, 0.2)
        self.assertIn("fast", names)
        self.assertNotIn("cn-only", names)

    async def test_exception_isolation_and_hook_rewrite(self) -> None:
        manager = ResolverManager(
            resolvers=[
                _SleepResolver("bad", delay_s=0.01, error=RuntimeError("boom")),
                _SleepResolver(
                    "good",
                    delay_s=0.01,
                    answer=Answer(rcode=dns.rcode.NXDOMAIN),
                ),
            ],
            resolver_hooks=[_DropErrorHook(), _RewriteRcodeHook()],
        )

        await manager.collect(self.ctx, timeout_s=0.2)
        calls = self.ctx.state["resolver_hook_calls"]
        self.assertEqual(len(calls), 2)
        self.assertEqual(set(calls), {"bad", "good"})
        self.assertEqual(len(self.ctx.candidates), 1)
        self.assertEqual(self.ctx.candidates[0].resolver_name, "good")
        self.assertEqual(self.ctx.candidates[0].answer.rcode, dns.rcode.NOERROR)


if __name__ == "__main__":
    unittest.main()
