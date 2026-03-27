"""HTTPS 记录响应插件测试。"""

from __future__ import annotations

import tempfile
import unittest
import warnings
from pathlib import Path

import dns.message
import dns.name
import dns.opcode
import dns.rdataclass
import dns.rdatatype
from async_lru import AlruCacheLoopResetWarning
from dns.rdtypes import svcbbase

from core.answer import Answer
from core.context import QueryContext
from core.ipset import init_ipset
from core.models import Query
from core.response_guard import response_guard_reason
from plugins.https_record import HttpsRecordResponseHook, _fetch_cached_ech_value


def _make_query(
    qtype: dns.rdatatype.RdataType,
    *,
    qname: str = "svc.example.com.",
) -> Query:
    return Query(
        client_addr=("127.0.0.1", 5335),
        qname=dns.name.from_text(qname),
        qtype=qtype,
    )


def _make_ctx(
    qtype: dns.rdatatype.RdataType,
    *,
    qname: str = "svc.example.com.",
) -> QueryContext:
    return QueryContext(query=_make_query(qtype, qname=qname))


def _make_https_answer(
    *records: str,
    qname: str = "svc.example.com.",
    tags: set[str] | None = None,
) -> Answer:
    rrset = dns.rrset.from_text(qname, 60, "IN", "HTTPS", *records)
    return Answer.from_query(
        _make_query(dns.rdatatype.HTTPS, qname=qname),
        rrsets=[rrset],
        tags=tags or {"default"},
    )


def _make_ip_answer(
    qtype: dns.rdatatype.RdataType,
    *ips: str,
    qname: str = "svc.example.com.",
    tags: set[str] | None = None,
) -> Answer:
    rrset = dns.rrset.from_text(
        qname,
        60,
        "IN",
        dns.rdatatype.to_text(qtype),
        *ips,
    )
    return Answer.from_query(
        _make_query(qtype, qname=qname),
        rrsets=[rrset],
        tags=tags or {"default"},
    )


def _make_ech_source_answer() -> Answer:
    return _make_https_answer(
        '1 . ech="AA=="',
        qname="cloudflare-ech.com.",
        tags={"default"},
    )


def _first_rdata(answer: Answer):
    rrset = answer.rrset
    assert rrset is not None
    return next(iter(rrset))


class _FakePipeline:
    def __init__(self, responses: dict[tuple[str, int], Answer]) -> None:
        self.responses = responses
        self.calls: list[tuple[str, int, float | None]] = []

    async def resolve(self, query: Query, timeout_s: float | None = None) -> Answer:
        key = (query.qname.to_text(), int(query.qtype))
        self.calls.append((query.qname.to_text(), int(query.qtype), timeout_s))
        if key not in self.responses:
            raise AssertionError(f"unexpected resolve: {key!r}")
        return Answer.from_answer(self.responses[key])

    def count_calls(self, qname: str, qtype: dns.rdatatype.RdataType) -> int:
        return sum(
            1
            for call_qname, call_qtype, _ in self.calls
            if call_qname == qname and call_qtype == int(qtype)
        )


class TestResponseGuardHelper(unittest.TestCase):
    def test_should_return_none_for_valid_response(self) -> None:
        query = dns.message.make_query(
            "example.com.", dns.rdatatype.A, dns.rdataclass.IN
        )
        response = dns.message.make_response(query)
        response.set_rcode(dns.rcode.NOERROR)

        self.assertIsNone(response_guard_reason(response))

    def test_should_return_custom_reason_when_not_noerror(self) -> None:
        query = dns.message.make_query(
            "example.com.", dns.rdatatype.A, dns.rdataclass.IN
        )
        response = dns.message.make_response(query)
        response.set_rcode(dns.rcode.SERVFAIL)

        self.assertEqual(
            response_guard_reason(response, noerror_reason="rcode_not_noerror"),
            "rcode_not_noerror",
        )

    def test_should_return_invalid_qclass_when_question_not_in(self) -> None:
        query = dns.message.make_query(
            "example.com.", dns.rdatatype.A, dns.rdataclass.CH
        )
        response = dns.message.make_response(query)

        self.assertEqual(response_guard_reason(response), "invalid_qclass")


class TestHttpsRecordResponseHook(unittest.IsolatedAsyncioTestCase):
    @classmethod
    def setUpClass(cls) -> None:
        super().setUpClass()
        warnings.filterwarnings("ignore", category=AlruCacheLoopResetWarning)

    def tearDown(self) -> None:
        init_ipset({})
        _fetch_cached_ech_value.cache_clear()

    async def test_should_skip_non_https_query(self) -> None:
        hook = HttpsRecordResponseHook()
        ctx = _make_ctx(dns.rdatatype.A)
        ctx.final_answer = _make_https_answer('1 . alpn="h2,h3"')
        ctx.state["pipeline"] = _FakePipeline({})

        await hook.on_response(ctx)

        rdata = _first_rdata(ctx.final_answer)
        self.assertIn(svcbbase.ParamKey.ALPN, rdata.params)

    async def test_should_skip_invalid_opcode(self) -> None:
        hook = HttpsRecordResponseHook()
        ctx = _make_ctx(dns.rdatatype.HTTPS)
        ctx.final_answer = _make_https_answer('1 . alpn="h2,h3"')
        ctx.final_answer.response.set_opcode(dns.opcode.STATUS)
        ctx.state["pipeline"] = _FakePipeline({})

        await hook.on_response(ctx)

        rdata = _first_rdata(ctx.final_answer)
        self.assertEqual(rdata.params[svcbbase.ParamKey.ALPN].ids, (b"h2", b"h3"))

    async def test_should_skip_invalid_qclass(self) -> None:
        hook = HttpsRecordResponseHook()
        ctx = _make_ctx(dns.rdatatype.HTTPS)
        ctx.final_answer = _make_https_answer('1 . alpn="h2,h3"')
        ctx.final_answer.response.question[0].rdclass = dns.rdataclass.CH
        ctx.state["pipeline"] = _FakePipeline({})

        await hook.on_response(ctx)

        rdata = _first_rdata(ctx.final_answer)
        self.assertEqual(rdata.params[svcbbase.ParamKey.ALPN].ids, (b"h2", b"h3"))

    async def test_should_skip_when_result_tags_match_skip_list(self) -> None:
        hook = HttpsRecordResponseHook(skip_result_tags={"ads"})
        ctx = _make_ctx(dns.rdatatype.HTTPS)
        ctx.final_answer = _make_https_answer(
            '1 . alpn="h2,h3"', tags={"default", "ads"}
        )
        ctx.state["pipeline"] = _FakePipeline({})

        await hook.on_response(ctx)

        rdata = _first_rdata(ctx.final_answer)
        self.assertEqual(rdata.params[svcbbase.ParamKey.ALPN].ids, (b"h2", b"h3"))

    async def test_should_remove_only_h3_from_alpn(self) -> None:
        hook = HttpsRecordResponseHook(cloudflare_tags=[])
        ctx = _make_ctx(dns.rdatatype.HTTPS)
        ctx.final_answer = _make_https_answer('1 . alpn="h2,h3,h3-29"')
        ctx.state["pipeline"] = _FakePipeline({})

        await hook.on_response(ctx)

        rdata = _first_rdata(ctx.final_answer)
        self.assertEqual(
            rdata.params[svcbbase.ParamKey.ALPN].ids,
            (b"h2", b"h3-29"),
        )

    async def test_should_drop_empty_alpn_and_no_default_alpn(self) -> None:
        hook = HttpsRecordResponseHook(cloudflare_tags=[])
        ctx = _make_ctx(dns.rdatatype.HTTPS)
        ctx.final_answer = _make_https_answer('1 . alpn="h3" no-default-alpn')
        ctx.state["pipeline"] = _FakePipeline({})

        await hook.on_response(ctx)

        rdata = _first_rdata(ctx.final_answer)
        self.assertNotIn(svcbbase.ParamKey.ALPN, rdata.params)
        self.assertNotIn(svcbbase.ParamKey.NO_DEFAULT_ALPN, rdata.params)

    async def test_should_remove_both_hints_when_both_exist(self) -> None:
        hook = HttpsRecordResponseHook(cloudflare_tags=[])
        ctx = _make_ctx(dns.rdatatype.HTTPS)
        ctx.final_answer = _make_https_answer(
            '1 . ipv4hint="1.1.1.1" ipv6hint="2606:4700::1111"',
        )
        ctx.state["pipeline"] = _FakePipeline({})

        await hook.on_response(ctx)

        rdata = _first_rdata(ctx.final_answer)
        self.assertNotIn(svcbbase.ParamKey.IPV4HINT, rdata.params)
        self.assertNotIn(svcbbase.ParamKey.IPV6HINT, rdata.params)

    async def test_should_keep_single_hint(self) -> None:
        hook = HttpsRecordResponseHook(cloudflare_tags=[])
        ctx = _make_ctx(dns.rdatatype.HTTPS)
        ctx.final_answer = _make_https_answer('1 . ipv4hint="1.1.1.1"')
        ctx.state["pipeline"] = _FakePipeline({})

        await hook.on_response(ctx)

        rdata = _first_rdata(ctx.final_answer)
        self.assertIn(svcbbase.ParamKey.IPV4HINT, rdata.params)

    async def test_should_inject_ech_when_answer_tags_match_cloudflare(self) -> None:
        hook = HttpsRecordResponseHook(cloudflare_tags={"cloudflare"})
        pipeline = _FakePipeline(
            {
                (
                    "cloudflare-ech.com.",
                    int(dns.rdatatype.HTTPS),
                ): _make_ech_source_answer(),
            }
        )
        ctx = _make_ctx(dns.rdatatype.HTTPS)
        ctx.final_answer = _make_https_answer(
            '1 . alpn="h2,h3"',
            tags={"default", "cloudflare"},
        )
        ctx.state["pipeline"] = pipeline

        await hook.on_response(ctx)

        rdata = _first_rdata(ctx.final_answer)
        self.assertEqual(rdata.params[svcbbase.ParamKey.ALPN].ids, (b"h2",))
        self.assertIn(svcbbase.ParamKey.ECH, rdata.params)
        self.assertEqual(
            pipeline.count_calls("cloudflare-ech.com.", dns.rdatatype.HTTPS),
            1,
        )

    async def test_should_inject_ech_when_hint_ip_matches_cloudflare_tag(self) -> None:
        with tempfile.TemporaryDirectory(prefix="mydns-https-hook-ipset-") as td:
            base = Path(td)
            (base / "cloudflare.txt").write_text("1.1.1.0/24\n", encoding="utf-8")
            init_ipset({"cloudflare": ["cloudflare.txt"]}, base_dir=base)

            hook = HttpsRecordResponseHook(cloudflare_tags={"cloudflare"})
            pipeline = _FakePipeline(
                {
                    (
                        "cloudflare-ech.com.",
                        int(dns.rdatatype.HTTPS),
                    ): _make_ech_source_answer(),
                }
            )
            ctx = _make_ctx(dns.rdatatype.HTTPS)
            ctx.final_answer = _make_https_answer('1 . ipv4hint="1.1.1.1"')
            ctx.state["pipeline"] = pipeline

            await hook.on_response(ctx)

        rdata = _first_rdata(ctx.final_answer)
        self.assertIn(svcbbase.ParamKey.ECH, rdata.params)

    async def test_should_inject_ech_when_subquery_result_matches_cloudflare(
        self,
    ) -> None:
        hook = HttpsRecordResponseHook(cloudflare_tags={"cloudflare"})
        pipeline = _FakePipeline(
            {
                ("svc.example.com.", int(dns.rdatatype.A)): _make_ip_answer(
                    dns.rdatatype.A,
                    "1.1.1.1",
                    qname="svc.example.com.",
                    tags={"default", "cloudflare"},
                ),
                ("svc.example.com.", int(dns.rdatatype.AAAA)): Answer.from_query(
                    _make_query(dns.rdatatype.AAAA, qname="svc.example.com."),
                    tags={"default"},
                ),
                (
                    "cloudflare-ech.com.",
                    int(dns.rdatatype.HTTPS),
                ): _make_ech_source_answer(),
            }
        )
        ctx = _make_ctx(dns.rdatatype.HTTPS)
        ctx.final_answer = _make_https_answer('1 . alpn="h2"')
        ctx.state["pipeline"] = pipeline

        await hook.on_response(ctx)

        rdata = _first_rdata(ctx.final_answer)
        self.assertIn(svcbbase.ParamKey.ECH, rdata.params)
        self.assertEqual(
            pipeline.count_calls("svc.example.com.", dns.rdatatype.A),
            1,
        )
        self.assertEqual(
            pipeline.count_calls("svc.example.com.", dns.rdatatype.AAAA),
            1,
        )

    async def test_should_dedupe_subqueries_for_multi_rdata_https_rrset(self) -> None:
        hook = HttpsRecordResponseHook(cloudflare_tags={"cloudflare"})
        pipeline = _FakePipeline(
            {
                ("svc.example.com.", int(dns.rdatatype.A)): _make_ip_answer(
                    dns.rdatatype.A,
                    "1.1.1.1",
                    qname="svc.example.com.",
                    tags={"default", "cloudflare"},
                ),
                ("svc.example.com.", int(dns.rdatatype.AAAA)): Answer.from_query(
                    _make_query(dns.rdatatype.AAAA, qname="svc.example.com."),
                    tags={"default"},
                ),
                (
                    "cloudflare-ech.com.",
                    int(dns.rdatatype.HTTPS),
                ): _make_ech_source_answer(),
            }
        )
        ctx = _make_ctx(dns.rdatatype.HTTPS)
        ctx.final_answer = _make_https_answer('1 . alpn="h2"', '2 . alpn="h2"')
        ctx.state["pipeline"] = pipeline

        await hook.on_response(ctx)

        rrset = ctx.final_answer.rrset
        assert rrset is not None
        self.assertEqual(len(rrset), 2)
        for rdata in rrset:
            self.assertIn(svcbbase.ParamKey.ECH, rdata.params)

        self.assertEqual(
            pipeline.count_calls("svc.example.com.", dns.rdatatype.A),
            1,
        )
        self.assertEqual(
            pipeline.count_calls("svc.example.com.", dns.rdatatype.AAAA),
            1,
        )

    async def test_should_not_overwrite_existing_ech(self) -> None:
        hook = HttpsRecordResponseHook(cloudflare_tags={"cloudflare"})
        pipeline = _FakePipeline({})
        ctx = _make_ctx(dns.rdatatype.HTTPS)
        ctx.final_answer = _make_https_answer(
            '1 . ech="AA=="',
            tags={"default", "cloudflare"},
        )
        ctx.state["pipeline"] = pipeline

        await hook.on_response(ctx)

        self.assertEqual(pipeline.calls, [])

    async def test_should_cache_ech_fetch_for_same_pipeline(self) -> None:
        hook = HttpsRecordResponseHook(cloudflare_tags={"cloudflare"})
        pipeline = _FakePipeline(
            {
                (
                    "cloudflare-ech.com.",
                    int(dns.rdatatype.HTTPS),
                ): _make_ech_source_answer(),
            }
        )

        ctx1 = _make_ctx(dns.rdatatype.HTTPS, qname="svc1.example.com.")
        ctx1.final_answer = _make_https_answer(
            '1 . alpn="h2"',
            qname="svc1.example.com.",
            tags={"default", "cloudflare"},
        )
        ctx1.state["pipeline"] = pipeline

        ctx2 = _make_ctx(dns.rdatatype.HTTPS, qname="svc2.example.com.")
        ctx2.final_answer = _make_https_answer(
            '1 . alpn="h2"',
            qname="svc2.example.com.",
            tags={"default", "cloudflare"},
        )
        ctx2.state["pipeline"] = pipeline

        await hook.on_response(ctx1)
        await hook.on_response(ctx2)

        self.assertEqual(
            pipeline.count_calls("cloudflare-ech.com.", dns.rdatatype.HTTPS),
            1,
        )


if __name__ == "__main__":
    unittest.main()
