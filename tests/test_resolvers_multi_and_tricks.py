"""多协议 resolver 与 trick resolver 测试。"""

from __future__ import annotations

import unittest

import dns.asyncquery
import dns.message
import dns.name
import dns.rcode
import dns.rdatatype
import dns.rrset

from core.models import Query
from resolver.https_resolver import HttpsUpstreamResolver
from resolver.quic_resolver import QuicUpstreamResolver
from resolver.tcp_resolver import TcpUpstreamResolver
from resolver.tls_resolver import TlsUpstreamResolver


def _make_query(qtype: dns.rdatatype.RdataType = dns.rdatatype.A) -> Query:
    return Query(
        client_addr=("127.0.0.1", 5335),
        qname=dns.name.from_text("www.example.com."),
        qtype=qtype,
    )


def _build_response(request: dns.message.Message) -> dns.message.Message:
    response = dns.message.make_response(request)
    response.set_rcode(dns.rcode.NOERROR)
    response.answer.append(
        dns.rrset.from_text("www.example.com.", 60, "IN", "A", "1.1.1.1")
    )
    response.use_edns(options=list(request.options))
    return response


class TestMultiResolversAndTricks(unittest.IsolatedAsyncioTestCase):
    async def test_tcp_resolver_uses_asyncquery_tcp(self) -> None:
        query = _make_query()
        captured: dict[str, object] = {}
        original = dns.asyncquery.tcp

        async def fake_tcp(request: dns.message.Message, **kwargs: object) -> dns.message.Message:
            captured["kwargs"] = kwargs
            return _build_response(request)

        dns.asyncquery.tcp = fake_tcp
        try:
            resolver = TcpUpstreamResolver(name="tcp", address="1.1.1.1")
            answer = await resolver.resolve(query, timeout_s=0.5)
        finally:
            dns.asyncquery.tcp = original

        self.assertEqual(answer.response.rcode(), dns.rcode.NOERROR)
        self.assertEqual(len(answer.response.answer), 1)
        self.assertEqual(captured["kwargs"]["where"], "1.1.1.1")
        self.assertEqual(captured["kwargs"]["port"], 53)

    async def test_tls_resolver_uses_asyncquery_tls(self) -> None:
        query = _make_query()
        captured: dict[str, object] = {}
        original = dns.asyncquery.tls

        async def fake_tls(request: dns.message.Message, **kwargs: object) -> dns.message.Message:
            captured["kwargs"] = kwargs
            return _build_response(request)

        dns.asyncquery.tls = fake_tls
        try:
            resolver = TlsUpstreamResolver(
                name="tls",
                address="1.1.1.1",
                server_hostname="dns.example",
            )
            answer = await resolver.resolve(query, timeout_s=0.5)
        finally:
            dns.asyncquery.tls = original

        self.assertEqual(answer.response.rcode(), dns.rcode.NOERROR)
        self.assertEqual(captured["kwargs"]["where"], "1.1.1.1")
        self.assertEqual(captured["kwargs"]["server_hostname"], "dns.example")

    async def test_https_resolver_uses_asyncquery_https(self) -> None:
        query = _make_query()
        captured: dict[str, object] = {}
        original = dns.asyncquery.https

        async def fake_https(request: dns.message.Message, **kwargs: object) -> dns.message.Message:
            captured["kwargs"] = kwargs
            return _build_response(request)

        dns.asyncquery.https = fake_https
        try:
            resolver = HttpsUpstreamResolver(
                name="https",
                address="dns.example",
                path="/dns-query",
                bootstrap_address="1.1.1.1",
            )
            answer = await resolver.resolve(query, timeout_s=0.5)
        finally:
            dns.asyncquery.https = original

        self.assertEqual(answer.response.rcode(), dns.rcode.NOERROR)
        self.assertEqual(captured["kwargs"]["where"], "https://dns.example")
        self.assertEqual(captured["kwargs"]["path"], "/dns-query")
        self.assertEqual(captured["kwargs"]["bootstrap_address"], "1.1.1.1")

    async def test_quic_resolver_uses_asyncquery_quic(self) -> None:
        query = _make_query()
        captured: dict[str, object] = {}
        original = dns.asyncquery.quic

        async def fake_quic(request: dns.message.Message, **kwargs: object) -> dns.message.Message:
            captured["kwargs"] = kwargs
            return _build_response(request)

        dns.asyncquery.quic = fake_quic
        try:
            resolver = QuicUpstreamResolver(
                name="doq",
                address="1.1.1.1",
                server_hostname="dns.example",
            )
            answer = await resolver.resolve(query, timeout_s=0.5)
        finally:
            dns.asyncquery.quic = original

        self.assertEqual(answer.response.rcode(), dns.rcode.NOERROR)
        self.assertEqual(captured["kwargs"]["where"], "1.1.1.1")
        self.assertEqual(captured["kwargs"]["server_hostname"], "dns.example")

if __name__ == "__main__":
    unittest.main()
