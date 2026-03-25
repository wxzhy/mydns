"""CNAME tag / uncloaking 相关测试。"""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

import dns.name
import dns.rcode
import dns.rdatatype
import dns.rrset

from core.answer import Answer
from core.context import QueryContext
from core.domainset import init_domainset
from core.models import Query, ResolverResult
from plugins.speedcheck import SpeedCheckResolverHook
from plugins.tagset import TagSetResolverHook
from upstream.selector import select_best_answer


def _make_query(qtype: dns.rdatatype.RdataType) -> Query:
    return Query(
        client_addr=("127.0.0.1", 5335),
        qname=dns.name.from_text("www.example.com."),
        qtype=qtype,
    )


def _make_ctx(qtype: dns.rdatatype.RdataType) -> QueryContext:
    return QueryContext(query=_make_query(qtype))


def _make_cname_a_answer(ip: str) -> Answer:
    cname = dns.rrset.from_text(
        "www.example.com.",
        60,
        "IN",
        "CNAME",
        "tracker.ads.example.",
    )
    rrset = dns.rrset.from_text("tracker.ads.example.", 60, "IN", "A", ip)
    return Answer.from_query(
        _make_query(dns.rdatatype.A),
        rrsets=[cname, rrset],
        tags={"default"},
    )


class TestTagSetResolverHook(unittest.IsolatedAsyncioTestCase):
    async def test_cname_tag_should_add_tags_and_block_a_answer(self) -> None:
        try:
            with tempfile.TemporaryDirectory() as td:
                base = Path(td)
                (base / "ads.txt").write_text("ads.example\n", encoding="utf-8")
                init_domainset({"ads": ["ads.txt"]}, base_dir=base)

                hook = TagSetResolverHook()
                ctx = _make_ctx(dns.rdatatype.A)
                result = ResolverResult(
                    resolver_name="r1",
                    answer=_make_cname_a_answer("203.0.113.10"),
                    elapsed_ms=5.0,
                )

            output = await hook.on_resolver_result(ctx, result)

            assert output is not None
            assert output.answer is not None
            self.assertEqual(output.answer.tags, {"default", "ads"})
            self.assertEqual(
                [rrset.rdtype for rrset in output.answer.response.answer],
                [dns.rdatatype.CNAME, dns.rdatatype.A],
            )
            self.assertEqual(
                [rdata.to_text() for rdata in output.answer.rrset],
                ["127.0.0.1"],
            )
        finally:
            init_domainset({})

    async def test_cname_tag_should_return_empty_noerror_for_non_address_query(self) -> None:
        try:
            with tempfile.TemporaryDirectory() as td:
                base = Path(td)
                (base / "ads.txt").write_text("ads.example\n", encoding="utf-8")
                init_domainset({"ads": ["ads.txt"]}, base_dir=base)

                hook = TagSetResolverHook()
                ctx = _make_ctx(dns.rdatatype.TXT)
                cname = dns.rrset.from_text(
                    "www.example.com.",
                    60,
                    "IN",
                    "CNAME",
                    "tracker.ads.example.",
                )
                txt = dns.rrset.from_text(
                    "tracker.ads.example.",
                    60,
                    "IN",
                    "TXT",
                    '"blocked"',
                )
                result = ResolverResult(
                    resolver_name="r1",
                    answer=Answer.from_query(
                        ctx.query,
                        rrsets=[cname, txt],
                        tags={"default"},
                    ),
                    elapsed_ms=5.0,
                )

            output = await hook.on_resolver_result(ctx, result)

            assert output is not None
            assert output.answer is not None
            self.assertEqual(output.answer.tags, {"default", "ads"})
            self.assertEqual(output.answer.response.rcode(), dns.rcode.NOERROR)
            self.assertEqual(output.answer.response.answer, [])
        finally:
            init_domainset({})


class TestAdsFlow(unittest.IsolatedAsyncioTestCase):
    async def test_speedcheck_should_skip_ads_tagged_result(self) -> None:
        calls: list[list[str]] = []

        async def fake_probe(
            ips: list[str],
            timeout_s: float,
        ) -> dict[str, float | None]:
            _ = timeout_s
            calls.append(list(ips))
            return {ip: 1.0 for ip in ips}

        hook = SpeedCheckResolverHook(probe_func=fake_probe)
        ctx = _make_ctx(dns.rdatatype.A)
        answer = Answer.from_query(
            ctx.query,
            rrsets=[dns.rrset.from_text("www.example.com.", 60, "IN", "A", "127.0.0.1")],
            tags={"default", "ads"},
        )
        result = ResolverResult("r1", answer, elapsed_ms=1.0)

        output = await hook.on_resolver_result(ctx, result)

        self.assertIs(output, result)
        self.assertEqual(calls, [])
        self.assertEqual(ctx.ip_list.results, {})
        self.assertEqual(ctx.ip_list.ips, set())

    async def test_selector_should_return_ads_answer_directly(self) -> None:
        ctx = _make_ctx(dns.rdatatype.A)
        normal = Answer.from_query(
            ctx.query,
            rrsets=[dns.rrset.from_text("www.example.com.", 60, "IN", "A", "8.8.8.8")],
            tags={"default"},
        )
        blocked = Answer.from_query(
            ctx.query,
            rrsets=[dns.rrset.from_text("www.example.com.", 60, "IN", "A", "127.0.0.1")],
            tags={"default", "ads"},
        )
        ctx.candidates = [
            ResolverResult("fast-normal", normal, elapsed_ms=1.0),
            ResolverResult("ads-blocked", blocked, elapsed_ms=50.0),
        ]

        selected = select_best_answer(ctx)

        self.assertIs(selected, blocked)
        self.assertEqual(selected.tags, {"default", "ads"})


if __name__ == "__main__":
    unittest.main()
