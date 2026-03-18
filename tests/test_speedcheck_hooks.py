"""测速插件测试。"""

from __future__ import annotations

import unittest

import dns.name
import dns.rcode
import dns.rdatatype
import dns.rrset

from core.context import QueryContext
from core.models import Answer, Query, ResolverResult
from plugins.speedcheck import RewriteAnswerByRTTHook, SpeedCheckResolverHook


def _make_ctx(qtype: dns.rdatatype.RdataType) -> QueryContext:
    return QueryContext(
        query=Query(
            client_addr=("127.0.0.1", 5335),
            qname=dns.name.from_text("www.example.com."),
            qtype=qtype,
        )
    )


def _make_a_answer(*ips: str) -> Answer:
    rr = dns.rrset.from_text("www.example.com.", 30, "IN", "A", *ips)
    return Answer(rcode=dns.rcode.NOERROR, rrsets=[rr])


class TestSpeedcheckHooks(unittest.IsolatedAsyncioTestCase):
    async def test_resolver_hook_collect_rtt(self) -> None:
        async def fake_probe(ips: list[str], timeout_s: float) -> dict[str, float | None]:
            _ = timeout_s
            return {ip: (10.0 if ip == "1.1.1.1" else 20.0) for ip in ips}

        hook = SpeedCheckResolverHook(probe_func=fake_probe)
        ctx = _make_ctx(dns.rdatatype.A)
        result = ResolverResult(
            resolver_name="r1",
            answer=_make_a_answer("1.1.1.1", "2.2.2.2"),
            elapsed_ms=5.0,
        )
        output = await hook.on_resolver_result(ctx, result)

        self.assertIs(output, result)
        self.assertEqual(ctx.ip_list.results["1.1.1.1"], 10.0)
        self.assertEqual(ctx.ip_list.results["2.2.2.2"], 20.0)
        self.assertEqual(ctx.ip_list.ips, {"1.1.1.1", "2.2.2.2"})

    async def test_response_hook_rewrite_by_rtt(self) -> None:
        hook = RewriteAnswerByRTTHook(max_return_ips=2)
        ctx = _make_ctx(dns.rdatatype.A)
        cname = dns.rrset.from_text(
            "www.example.com.",
            30,
            "IN",
            "CNAME",
            "edge.example.com.",
        )
        a_rr = dns.rrset.from_text("edge.example.com.", 30, "IN", "A", "9.9.9.9", "8.8.8.8")
        ctx.final_answer = Answer(rcode=dns.rcode.NOERROR, rrsets=[cname, a_rr])
        ctx.ip_list.results = {
            "1.1.1.1": 5.0,
            "8.8.8.8": 20.0,
            "9.9.9.9": 30.0,
        }

        await hook.on_response(ctx)

        rewritten = [x for x in ctx.final_answer.rrsets if x.rdtype == dns.rdatatype.A][0]
        ips = [rdata.to_text() for rdata in rewritten]
        self.assertEqual(ips, ["1.1.1.1", "8.8.8.8"])
        self.assertEqual(rewritten.ttl, 900)

    async def test_non_a_record_not_rewrite(self) -> None:
        hook = RewriteAnswerByRTTHook(max_return_ips=2)
        ctx = _make_ctx(dns.rdatatype.TXT)
        txt = dns.rrset.from_text("www.example.com.", 30, "IN", "TXT", "\"hello\"")
        ctx.final_answer = Answer(rcode=dns.rcode.NOERROR, rrsets=[txt])
        ctx.ip_list.results = {"1.1.1.1": 5.0}

        await hook.on_response(ctx)
        self.assertEqual(ctx.final_answer.rrsets[0][0].to_text(), "\"hello\"")

    async def test_response_hook_build_base_answer_when_final_missing(self) -> None:
        hook = RewriteAnswerByRTTHook(max_return_ips=2)
        ctx = _make_ctx(dns.rdatatype.TXT)
        txt_fast = dns.rrset.from_text("www.example.com.", 30, "IN", "TXT", "\"fast\"")
        txt_slow = dns.rrset.from_text("www.example.com.", 30, "IN", "TXT", "\"slow\"")
        ctx.candidates = [
            ResolverResult(
                resolver_name="slow",
                answer=Answer(rcode=dns.rcode.NOERROR, rrsets=[txt_slow]),
                elapsed_ms=50.0,
            ),
            ResolverResult(
                resolver_name="fast",
                answer=Answer(rcode=dns.rcode.NOERROR, rrsets=[txt_fast]),
                elapsed_ms=10.0,
            ),
        ]

        await hook.on_response(ctx)

        self.assertIsNotNone(ctx.final_answer)
        self.assertEqual(ctx.final_answer.rcode, dns.rcode.NOERROR)
        self.assertEqual(ctx.final_answer.rrsets[0][0].to_text(), "\"fast\"")

    async def test_response_hook_backfill_when_target_rrset_missing(self) -> None:
        hook = RewriteAnswerByRTTHook(max_return_ips=2, ttl_s=900)
        ctx = _make_ctx(dns.rdatatype.A)
        cname = dns.rrset.from_text(
            "www.example.com.",
            30,
            "IN",
            "CNAME",
            "edge.example.com.",
        )
        ctx.final_answer = Answer(rcode=dns.rcode.NOERROR, rrsets=[cname])
        ctx.ip_list.results = {
            "1.1.1.1": 5.0,
            "2.2.2.2": 10.0,
        }

        await hook.on_response(ctx)

        a_rrset = [x for x in ctx.final_answer.rrsets if x.rdtype == dns.rdatatype.A][0]
        self.assertEqual(a_rrset.name.to_text(), "edge.example.com.")
        self.assertEqual([rdata.to_text() for rdata in a_rrset], ["1.1.1.1", "2.2.2.2"])
        self.assertEqual(a_rrset.ttl, 900)

    async def test_duplicate_ips_probe_once_per_request(self) -> None:
        calls: list[list[str]] = []

        async def fake_probe(ips: list[str], timeout_s: float) -> dict[str, float | None]:
            _ = timeout_s
            calls.append(list(ips))
            return {ip: float(index + 1) for index, ip in enumerate(ips)}

        hook = SpeedCheckResolverHook(probe_func=fake_probe)
        ctx = _make_ctx(dns.rdatatype.A)

        r1 = ResolverResult(
            resolver_name="r1",
            answer=_make_a_answer("1.1.1.1", "2.2.2.2"),
            elapsed_ms=5.0,
        )
        r2 = ResolverResult(
            resolver_name="r2",
            answer=_make_a_answer("2.2.2.2", "3.3.3.3"),
            elapsed_ms=6.0,
        )

        await hook.on_resolver_result(ctx, r1)
        await hook.on_resolver_result(ctx, r2)

        self.assertEqual(calls[0], ["1.1.1.1", "2.2.2.2"])
        self.assertEqual(calls[1], ["3.3.3.3"])
        self.assertEqual(len(calls), 2)


if __name__ == "__main__":
    unittest.main()
