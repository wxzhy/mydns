"""Step 3: ResolverManager 并发与 resolver hook 测试。"""

from __future__ import annotations

import asyncio
import time
import unittest

import dns.name
import dns.rcode
import dns.rdatatype

from core.context import QueryContext
from core.hooks import ResolverHook
from core.models import Answer, Query, ResolverResult
from resolver.resolver import Resolver
from upstream.resolver_manager import ResolverManager


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


class _TimingHook(ResolverHook):
    def __init__(self) -> None:
        self.first_called_at: float | None = None
        self.total_calls = 0

    async def on_resolver_result(
        self,
        ctx: QueryContext,
        result: ResolverResult,
    ) -> ResolverResult | None:
        _ = ctx
        self.total_calls += 1
        if self.first_called_at is None:
            self.first_called_at = time.perf_counter()
        return result


class _RaiseHook(ResolverHook):
    async def on_resolver_result(
        self,
        ctx: QueryContext,
        result: ResolverResult,
    ) -> ResolverResult | None:
        _ = ctx, result
        raise RuntimeError("hook boom")


class TestResolverManagerStep3(unittest.IsolatedAsyncioTestCase):
    def setUp(self) -> None:
        self.ctx = self._new_ctx(dns.rdatatype.A)

    @staticmethod
    def _new_ctx(qtype: dns.rdatatype.RdataType) -> QueryContext:
        return QueryContext(
            query=Query(
                client_addr=("127.0.0.1", 5335),
                qname=dns.name.from_text("example.com."),
                qtype=qtype,
            )
        )

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

    async def test_non_a_returns_first_normal(self) -> None:
        ctx = self._new_ctx(dns.rdatatype.TXT)
        manager = ResolverManager(
            resolvers=[
                _SleepResolver("fast-error", delay_s=0.01, error=RuntimeError("err")),
                _SleepResolver("fast-nxd", delay_s=0.02, answer=Answer(rcode=dns.rcode.NXDOMAIN)),
                _SleepResolver("fast-good", delay_s=0.05, answer=Answer(rcode=dns.rcode.NOERROR)),
                _SleepResolver("slow-good", delay_s=0.2, answer=Answer(rcode=dns.rcode.NOERROR)),
            ]
        )
        start = time.perf_counter()
        await manager.collect(ctx, timeout_s=0.5)
        duration = time.perf_counter() - start

        names = [x.resolver_name for x in ctx.candidates]
        self.assertLess(duration, 0.18)
        self.assertIn("fast-good", names)
        self.assertNotIn("slow-good", names)

    async def test_a_waits_all_resolver_and_hook(self) -> None:
        ctx = self._new_ctx(dns.rdatatype.A)
        manager = ResolverManager(
            resolvers=[
                _SleepResolver("fast", delay_s=0.02, answer=Answer(rcode=dns.rcode.NOERROR)),
                _SleepResolver("slow", delay_s=0.16, answer=Answer(rcode=dns.rcode.NOERROR)),
            ]
        )
        start = time.perf_counter()
        await manager.collect(ctx, timeout_s=0.4)
        duration = time.perf_counter() - start

        self.assertGreaterEqual(duration, 0.14)
        self.assertEqual({x.resolver_name for x in ctx.candidates}, {"fast", "slow"})

    async def test_slow_resolver_not_block_fast_hook_execution(self) -> None:
        ctx = self._new_ctx(dns.rdatatype.A)
        timing_hook = _TimingHook()
        manager = ResolverManager(
            resolvers=[
                _SleepResolver("fast", delay_s=0.02, answer=Answer(rcode=dns.rcode.NOERROR)),
                _SleepResolver("slow", delay_s=0.20, answer=Answer(rcode=dns.rcode.NOERROR)),
            ],
            resolver_hooks=[timing_hook],
        )
        start = time.perf_counter()
        await manager.collect(ctx, timeout_s=0.5)
        end = time.perf_counter()

        self.assertEqual(timing_hook.total_calls, 2)
        self.assertIsNotNone(timing_hook.first_called_at)
        first_latency = timing_hook.first_called_at - start
        total_latency = end - start
        self.assertLess(first_latency, 0.08)
        self.assertGreater(total_latency, 0.18)

    async def test_hook_exception_should_not_break_request(self) -> None:
        manager = ResolverManager(
            resolvers=[
                _SleepResolver("good", delay_s=0.01, answer=Answer(rcode=dns.rcode.NOERROR)),
            ],
            resolver_hooks=[_RaiseHook()],
        )

        await manager.collect(self.ctx, timeout_s=0.2)
        self.assertEqual(len(self.ctx.candidates), 1)
        self.assertEqual(self.ctx.candidates[0].resolver_name, "good")
        self.assertIsNotNone(self.ctx.candidates[0].answer)
        self.assertEqual(self.ctx.candidates[0].answer.rcode, dns.rcode.NOERROR)


if __name__ == "__main__":
    unittest.main()
