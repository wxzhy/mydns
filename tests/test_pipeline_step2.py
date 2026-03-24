"""Step 2: 三阶段流水线编排测试。"""

from __future__ import annotations

import unittest

import dns.name
import dns.rcode
import dns.rdatatype

from core.answer import Answer
from core.context import QueryContext
from core.hooks import RequestHook, ResponseHook
from core.models import Query
from core.pipeline import Pipeline
from plugins.speedcheck import RewriteAnswerByRTTHook
from resolver.resolver import Resolver


class _TrackRequestHook(RequestHook):
    def __init__(self, events: list[str], stop: bool = False) -> None:
        self.events = events
        self.stop = stop

    async def on_request(self, ctx: QueryContext) -> None:
        self.events.append("request")
        if self.stop:
            ctx.final_answer = Answer.from_query(ctx.query, rcode=dns.rcode.NXDOMAIN)
            ctx.stop = True


class _TrackResponseHook(ResponseHook):
    def __init__(self, events: list[str]) -> None:
        self.events = events

    async def on_response(self, ctx: QueryContext) -> None:
        _ = ctx
        self.events.append("response")


class _TrackResolver(Resolver):
    def __init__(self, events: list[str], answer: Answer) -> None:
        self.name = "track"
        self.tags = {"default"}
        self.events = events
        self.answer = answer

    async def resolve(self, query: Query, timeout_s: float) -> Answer:
        _ = query, timeout_s
        self.events.append("upstream")
        return self.answer


class _FailIfCalledResolver(Resolver):
    name = "fail-if-called"
    tags = {"default"}

    async def resolve(
        self, query: Query, timeout_s: float
    ) -> Answer:  # pragma: no cover
        _ = query, timeout_s
        raise AssertionError("短路后不应再访问上游")


class TestPipelineStep2(unittest.IsolatedAsyncioTestCase):
    def setUp(self) -> None:
        query = Query(
            client_addr=("127.0.0.1", 5335),
            qname=dns.name.from_text("example.com."),
            qtype=dns.rdatatype.A,
        )
        self.ctx = QueryContext(query=query)

    async def test_pipeline_order(self) -> None:
        events: list[str] = []
        pipeline = Pipeline(
            resolvers=[_TrackResolver(events, Answer.from_query(self.ctx.query, rcode=dns.rcode.NOERROR))],
            request_hooks=[_TrackRequestHook(events)],
            response_hooks=[RewriteAnswerByRTTHook(), _TrackResponseHook(events)],
        )

        answer = await pipeline.process(self.ctx)
        self.assertEqual(answer.response.rcode(), dns.rcode.NOERROR)
        self.assertEqual(events, ["request", "upstream", "response"])

    async def test_request_short_circuit(self) -> None:
        events: list[str] = []
        pipeline = Pipeline(
            resolvers=[_FailIfCalledResolver()],
            request_hooks=[_TrackRequestHook(events, stop=True)],
            response_hooks=[RewriteAnswerByRTTHook(), _TrackResponseHook(events)],
        )

        answer = await pipeline.process(self.ctx)
        self.assertEqual(answer.response.rcode(), dns.rcode.NXDOMAIN)
        self.assertEqual(events, ["request", "response"])

    async def test_empty_candidates_return_servfail(self) -> None:
        events: list[str] = []
        pipeline = Pipeline(
            resolvers=[],
            request_hooks=[_TrackRequestHook(events)],
            response_hooks=[RewriteAnswerByRTTHook(), _TrackResponseHook(events)],
        )

        answer = await pipeline.process(self.ctx)
        self.assertEqual(answer.response.rcode(), dns.rcode.SERVFAIL)
        self.assertEqual(events, ["request", "response"])


if __name__ == "__main__":
    unittest.main()
