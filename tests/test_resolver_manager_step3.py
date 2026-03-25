"""Step 3: ResolverManager 并发与 resolver hook 测试。"""

from __future__ import annotations

import asyncio
import time
import unittest

import dns.message
import dns.name
import dns.opcode
import dns.rcode
import dns.rdataclass
import dns.rdatatype

from core.answer import Answer
from core.context import QueryContext
from core.hooks import ResolverHook
from core.models import Query, ResolverResult
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
        timeout: float | None = None,
    ) -> None:
        self.name = name
        self.delay_s = delay_s
        self.answer = answer
        self.error = error
        self.tags = tags or {"default"}
        self.timeout = timeout
        self.last_timeout_s: float | None = None

    async def resolve(self, query: Query, timeout_s: float) -> Answer:
        _ = query
        self.last_timeout_s = timeout_s
        await asyncio.sleep(self.delay_s)
        if self.error is not None:
            raise self.error
        if self.answer is not None:
            return self.answer
        return Answer.from_query(query, rcode=dns.rcode.NOERROR)


class _RecordHook(ResolverHook):
    async def on_resolver_result(
        self,
        ctx: QueryContext,
        result: ResolverResult,
    ) -> ResolverResult | None:
        ctx.state.setdefault("resolver_hook_calls", []).append(result.resolver_name)
        return result


class _MutateAnswerHook(ResolverHook):
    def __init__(
        self,
        *,
        rcode: dns.rcode.Rcode = dns.rcode.NXDOMAIN,
        tag: str = "hooked",
    ) -> None:
        self.rcode = rcode
        self.tag = tag

    async def on_resolver_result(
        self,
        ctx: QueryContext,
        result: ResolverResult,
    ) -> ResolverResult | None:
        _ = ctx
        if result.answer is not None:
            assert isinstance(result.answer, Answer)
            result.answer.tags.add(self.tag)
            result.answer.set_rcode(self.rcode)
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


class _SlowHook(ResolverHook):
    def __init__(self, sleep_s: float) -> None:
        self.sleep_s = sleep_s

    async def on_resolver_result(
        self,
        ctx: QueryContext,
        result: ResolverResult,
    ) -> ResolverResult | None:
        _ = ctx
        await asyncio.sleep(self.sleep_s)
        if result.answer is not None:
            assert isinstance(result.answer, Answer)
            result.answer.set_rcode(dns.rcode.NXDOMAIN)
        return result


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

    async def test_resolver_specific_timeout_should_override_global_timeout(self) -> None:
        slow = _SleepResolver("slow", delay_s=0.3, timeout=0.05)
        manager = ResolverManager(resolvers=[slow])

        start = time.perf_counter()
        await manager.collect(self.ctx, timeout_s=0.4)
        duration = time.perf_counter() - start

        self.assertLess(duration, 0.15)
        self.assertEqual(slow.last_timeout_s, 0.05)
        self.assertEqual(len(self.ctx.candidates), 1)
        self.assertIsNotNone(self.ctx.candidates[0].error)

    async def test_hook_should_skip_error_result_and_keep_candidate(self) -> None:
        manager = ResolverManager(
            resolvers=[
                _SleepResolver("bad", delay_s=0.01, error=RuntimeError("boom")),
                _SleepResolver(
                    "good",
                    delay_s=0.01,
                    answer=Answer.from_query(self.ctx.query, rcode=dns.rcode.NOERROR),
                ),
            ],
            resolver_hooks=[_RecordHook(), _MutateAnswerHook()],
        )

        await manager.collect(self.ctx, timeout_s=0.2)
        calls = self.ctx.state["resolver_hook_calls"]
        self.assertEqual(calls, ["good"])
        self.assertEqual(len(self.ctx.candidates), 2)
        candidates = {item.resolver_name: item for item in self.ctx.candidates}
        self.assertIsNotNone(candidates["bad"].error)
        self.assertIsNotNone(candidates["good"].answer)
        self.assertEqual(candidates["good"].answer.response.rcode(), dns.rcode.NXDOMAIN)
        self.assertIn("hooked", candidates["good"].answer.tags)

    async def test_hook_should_skip_non_noerror_response(self) -> None:
        manager = ResolverManager(
            resolvers=[
                _SleepResolver(
                    "nxdomain",
                    delay_s=0.01,
                    answer=Answer.from_query(self.ctx.query, rcode=dns.rcode.NXDOMAIN),
                ),
            ],
            resolver_hooks=[_RecordHook(), _MutateAnswerHook()],
        )

        await manager.collect(self.ctx, timeout_s=0.2)

        self.assertNotIn("resolver_hook_calls", self.ctx.state)
        self.assertEqual(len(self.ctx.candidates), 1)
        self.assertIsNotNone(self.ctx.candidates[0].answer)
        self.assertEqual(
            self.ctx.candidates[0].answer.response.rcode(),
            dns.rcode.NXDOMAIN,
        )
        self.assertNotIn("hooked", self.ctx.candidates[0].answer.tags)

    async def test_hook_should_skip_invalid_opcode_response(self) -> None:
        ctx = self._new_ctx(dns.rdatatype.A)
        answer = Answer.from_query(ctx.query, rcode=dns.rcode.NOERROR)
        answer.response.set_opcode(dns.opcode.NOTIFY)
        manager = ResolverManager(
            resolvers=[
                _SleepResolver(
                    "invalid-opcode",
                    delay_s=0.01,
                    answer=answer,
                ),
            ],
            resolver_hooks=[_RecordHook(), _MutateAnswerHook()],
        )

        await manager.collect(ctx, timeout_s=0.2)

        self.assertNotIn("resolver_hook_calls", ctx.state)
        self.assertEqual(len(ctx.candidates), 1)
        self.assertIsNotNone(ctx.candidates[0].answer)
        self.assertEqual(ctx.candidates[0].answer.response.opcode(), dns.opcode.NOTIFY)
        self.assertEqual(ctx.candidates[0].answer.response.rcode(), dns.rcode.NOERROR)
        self.assertNotIn("hooked", ctx.candidates[0].answer.tags)

    async def test_hook_should_skip_invalid_qclass_response(self) -> None:
        request = dns.message.make_query(
            "example.com.",
            dns.rdatatype.A,
            dns.rdataclass.CH,
        )
        ctx = QueryContext(
            query=Query(
                client_addr=("127.0.0.1", 5335),
                qname=dns.name.from_text("example.com."),
                qtype=dns.rdatatype.A,
                message=request,
            )
        )
        manager = ResolverManager(
            resolvers=[
                _SleepResolver(
                    "invalid-qclass",
                    delay_s=0.01,
                    answer=Answer.from_query(ctx.query, rcode=dns.rcode.NOERROR),
                ),
            ],
            resolver_hooks=[_RecordHook(), _MutateAnswerHook()],
        )

        await manager.collect(ctx, timeout_s=0.2)

        self.assertNotIn("resolver_hook_calls", ctx.state)
        self.assertEqual(len(ctx.candidates), 1)
        self.assertIsNotNone(ctx.candidates[0].answer)
        self.assertEqual(
            ctx.candidates[0].answer.response.question[0].rdclass,
            dns.rdataclass.CH,
        )
        self.assertEqual(ctx.candidates[0].answer.response.rcode(), dns.rcode.NOERROR)
        self.assertNotIn("hooked", ctx.candidates[0].answer.tags)

    async def test_answer_tags_should_copy_context_tags(self) -> None:
        self.ctx.tags = {"cn", "default"}
        manager = ResolverManager(
            resolvers=[
                _SleepResolver(
                    "good",
                    delay_s=0.01,
                    answer=Answer.from_query(self.ctx.query, rcode=dns.rcode.NOERROR),
                ),
            ]
        )

        await manager.collect(self.ctx, timeout_s=0.2)

        self.assertEqual(len(self.ctx.candidates), 1)
        self.assertIsNotNone(self.ctx.candidates[0].answer)
        self.assertEqual(self.ctx.candidates[0].answer.tags, {"cn", "default"})

    async def test_non_a_returns_first_normal(self) -> None:
        ctx = self._new_ctx(dns.rdatatype.TXT)
        manager = ResolverManager(
            resolvers=[
                _SleepResolver("fast-error", delay_s=0.01, error=RuntimeError("err")),
                _SleepResolver("fast-nxd", delay_s=0.02, answer=Answer.from_query(ctx.query, rcode=dns.rcode.NXDOMAIN)),
                _SleepResolver("fast-good", delay_s=0.05, answer=Answer.from_query(ctx.query, rcode=dns.rcode.NOERROR)),
                _SleepResolver("slow-good", delay_s=0.2, answer=Answer.from_query(ctx.query, rcode=dns.rcode.NOERROR)),
            ]
        )
        start = time.perf_counter()
        await manager.collect(ctx, timeout_s=0.5)
        duration = time.perf_counter() - start

        names = [x.resolver_name for x in ctx.candidates]
        self.assertLess(duration, 0.18)
        self.assertIn("fast-good", names)
        self.assertNotIn("slow-good", names)
        self.assertIsNotNone(ctx.final_answer)
        self.assertEqual(ctx.final_answer.response.rcode(), dns.rcode.NOERROR)

    async def test_a_waits_all_resolver_and_hook(self) -> None:
        ctx = self._new_ctx(dns.rdatatype.A)
        manager = ResolverManager(
            resolvers=[
                _SleepResolver("fast", delay_s=0.02, answer=Answer.from_query(ctx.query, rcode=dns.rcode.NOERROR)),
                _SleepResolver("slow", delay_s=0.16, answer=Answer.from_query(ctx.query, rcode=dns.rcode.NOERROR)),
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
                _SleepResolver("fast", delay_s=0.02, answer=Answer.from_query(ctx.query, rcode=dns.rcode.NOERROR)),
                _SleepResolver("slow", delay_s=0.20, answer=Answer.from_query(ctx.query, rcode=dns.rcode.NOERROR)),
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
                _SleepResolver(
                    "good",
                    delay_s=0.01,
                    answer=Answer.from_query(self.ctx.query, rcode=dns.rcode.NOERROR),
                ),
            ],
            resolver_hooks=[_RaiseHook()],
        )

        await manager.collect(self.ctx, timeout_s=0.2)
        self.assertEqual(len(self.ctx.candidates), 1)
        self.assertEqual(self.ctx.candidates[0].resolver_name, "good")
        self.assertIsNotNone(self.ctx.candidates[0].answer)
        self.assertEqual(self.ctx.candidates[0].answer.response.rcode(), dns.rcode.NOERROR)

    async def test_hook_timeout_should_not_block_request(self) -> None:
        manager = ResolverManager(
            resolvers=[
                _SleepResolver(
                    "good",
                    delay_s=0.01,
                    answer=Answer.from_query(self.ctx.query, rcode=dns.rcode.NOERROR),
                ),
            ],
            resolver_hooks=[_SlowHook(0.2)],
            resolver_hook_timeout_s=0.05,
        )

        start = time.perf_counter()
        await manager.collect(self.ctx, timeout_s=0.2)
        duration = time.perf_counter() - start

        self.assertLess(duration, 0.13)
        self.assertEqual(len(self.ctx.candidates), 1)
        self.assertIsNotNone(self.ctx.candidates[0].answer)
        self.assertEqual(self.ctx.candidates[0].answer.response.rcode(), dns.rcode.NOERROR)


if __name__ == "__main__":
    unittest.main()
