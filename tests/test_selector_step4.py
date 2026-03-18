"""Step 4: 响应聚合与选择策略测试。"""

from __future__ import annotations

import unittest

import dns.name
import dns.rcode
import dns.rdatatype
import dns.rrset

from core.context import QueryContext
from core.models import Answer, Query, ResolverResult
from upstream.selector import select_best_answer


def _make_query(qtype: dns.rdatatype.RdataType) -> Query:
    return Query(
        client_addr=("127.0.0.1", 5335),
        qname=dns.name.from_text("www.example.com."),
        qtype=qtype,
    )


def _answer_with_a(ip: str) -> Answer:
    cname_1 = dns.rrset.from_text(
        "www.example.com.",
        60,
        "IN",
        "CNAME",
        "geo.example.com.",
    )
    cname_2 = dns.rrset.from_text(
        "geo.example.com.",
        60,
        "IN",
        "CNAME",
        "edge.example.com.",
    )
    a_rr = dns.rrset.from_text("edge.example.com.", 60, "IN", "A", ip)
    return Answer(rcode=dns.rcode.NOERROR, rrsets=[cname_1, cname_2, a_rr])


def _answer_with_aaaa(ipv6: str) -> Answer:
    cname = dns.rrset.from_text(
        "www.example.com.",
        60,
        "IN",
        "CNAME",
        "edge.example.com.",
    )
    aaaa_rr = dns.rrset.from_text("edge.example.com.", 60, "IN", "AAAA", ipv6)
    return Answer(rcode=dns.rcode.NOERROR, rrsets=[cname, aaaa_rr])


class TestSelectorStep4(unittest.TestCase):
    def test_a_fastest_two_ips_with_cname_chain(self) -> None:
        ctx = QueryContext(query=_make_query(dns.rdatatype.A))
        ctx.candidates = [
            ResolverResult("slow", _answer_with_a("1.1.1.1"), elapsed_ms=40),
            ResolverResult("fast", _answer_with_a("2.2.2.2"), elapsed_ms=10),
            ResolverResult("dup", _answer_with_a("2.2.2.2"), elapsed_ms=20),
        ]

        answer = select_best_answer(ctx)
        self.assertEqual(answer.rcode, dns.rcode.NOERROR)
        self.assertEqual(
            [x.rdtype for x in answer.rrsets],
            [dns.rdatatype.CNAME, dns.rdatatype.CNAME, dns.rdatatype.A],
        )

        a_rrset = answer.rrsets[-1]
        ips = {rdata.to_text() for rdata in a_rrset}
        self.assertEqual(ips, {"1.1.1.1", "2.2.2.2"})
        self.assertEqual(len(a_rrset), 2)

    def test_aaaa_fastest_two_ips(self) -> None:
        ctx = QueryContext(query=_make_query(dns.rdatatype.AAAA))
        ctx.candidates = [
            ResolverResult("r1", _answer_with_aaaa("2001:db8::1"), elapsed_ms=15),
            ResolverResult("r2", _answer_with_aaaa("2001:db8::2"), elapsed_ms=10),
            ResolverResult("r3", _answer_with_aaaa("2001:db8::2"), elapsed_ms=20),
        ]

        answer = select_best_answer(ctx)
        aaaa_rrset = [x for x in answer.rrsets if x.rdtype == dns.rdatatype.AAAA][0]
        ips = {rdata.to_text() for rdata in aaaa_rrset}
        self.assertEqual(ips, {"2001:db8::1", "2001:db8::2"})

    def test_non_a_type_fastest_response_passthrough(self) -> None:
        txt_slow = Answer(
            rcode=dns.rcode.NOERROR,
            rrsets=[dns.rrset.from_text("example.com.", 60, "IN", "TXT", '"slow"')],
        )
        txt_fast = Answer(
            rcode=dns.rcode.NOERROR,
            rrsets=[dns.rrset.from_text("example.com.", 60, "IN", "TXT", '"fast"')],
        )
        nxdomain = Answer(rcode=dns.rcode.NXDOMAIN, rrsets=[])

        ctx = QueryContext(query=_make_query(dns.rdatatype.TXT))
        ctx.candidates = [
            ResolverResult("nxd", nxdomain, elapsed_ms=5),
            ResolverResult("slow", txt_slow, elapsed_ms=40),
            ResolverResult("fast", txt_fast, elapsed_ms=10),
        ]

        answer = select_best_answer(ctx)
        self.assertEqual(answer.rcode, dns.rcode.NXDOMAIN)


if __name__ == "__main__":
    unittest.main()
