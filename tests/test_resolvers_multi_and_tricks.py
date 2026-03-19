"""多协议 resolver 与 trick resolver 测试。"""

from __future__ import annotations

import asyncio
import unittest

import dns.asyncquery
import dns.edns
import dns.exception
import dns.flags
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
from resolver.tricks.tcp_trick import TcpTrickResolver
from resolver.tricks.udp_trick import UdpTrickResolver


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


class _FakeReader:
    async def readexactly(self, n: int) -> bytes:
        _ = n
        return b""


class _FakeWriter:
    def __init__(self) -> None:
        self.chunks: list[bytes] = []
        self.closed = False

    def write(self, data: bytes) -> None:
        self.chunks.append(data)

    async def drain(self) -> None:
        return None

    def close(self) -> None:
        self.closed = True

    async def wait_closed(self) -> None:
        return None


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

        self.assertEqual(answer.rcode, dns.rcode.NOERROR)
        self.assertEqual(len(answer.rrsets), 1)
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

        self.assertEqual(answer.rcode, dns.rcode.NOERROR)
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

        self.assertEqual(answer.rcode, dns.rcode.NOERROR)
        self.assertEqual(captured["kwargs"]["where"], "dns.example")
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

        self.assertEqual(answer.rcode, dns.rcode.NOERROR)
        self.assertEqual(captured["kwargs"]["where"], "1.1.1.1")
        self.assertEqual(captured["kwargs"]["server_hostname"], "dns.example")

    async def test_udp_trick_add_padding_and_validate_response(self) -> None:
        query = _make_query()
        resolver = UdpTrickResolver(
            name="udp-trick",
            address="1.1.1.1",
            padding_bytes=16,
            require_opt_response=True,
        )
        captured: dict[str, object] = {}
        original = dns.asyncquery.udp

        async def fake_udp(request: dns.message.Message, **kwargs: object) -> dns.message.Message:
            captured["request"] = request
            captured["kwargs"] = kwargs
            return _build_response(request)

        dns.asyncquery.udp = fake_udp
        try:
            answer = await resolver.resolve(query, timeout_s=0.5)
        finally:
            dns.asyncquery.udp = original

        request = captured["request"]
        self.assertEqual(answer.rcode, dns.rcode.NOERROR)
        self.assertTrue(captured["kwargs"]["ignore_unexpected"])
        self.assertTrue(any(x.otype == dns.edns.OptionType.PADDING for x in request.options))

    async def test_udp_trick_reject_response_without_opt(self) -> None:
        query = _make_query()
        resolver = UdpTrickResolver(
            name="udp-trick",
            address="1.1.1.1",
            require_opt_response=True,
        )
        original = dns.asyncquery.udp

        async def fake_udp(request: dns.message.Message, **kwargs: object) -> dns.message.Message:
            _ = kwargs
            response = dns.message.Message(id=request.id)
            response.flags |= dns.flags.QR
            response.question = list(request.question)
            response.answer.append(
                dns.rrset.from_text("www.example.com.", 60, "IN", "A", "1.1.1.1")
            )
            return response

        dns.asyncquery.udp = fake_udp
        try:
            with self.assertRaises(dns.exception.DNSException):
                await resolver.resolve(query, timeout_s=0.5)
        finally:
            dns.asyncquery.udp = original

    async def test_tcp_trick_split_send(self) -> None:
        query = _make_query()
        resolver = TcpTrickResolver(
            name="tcp-trick",
            address="1.1.1.1",
            split_at=4,
            inter_chunk_delay_ms=0,
        )
        writer = _FakeWriter()
        original_open_connection = asyncio.open_connection
        original_receive = TcpTrickResolver._receive_response

        async def fake_open_connection(host: str, port: int) -> tuple[_FakeReader, _FakeWriter]:
            self.assertEqual(host, "1.1.1.1")
            self.assertEqual(port, 53)
            return _FakeReader(), writer

        async def fake_receive_response(reader: asyncio.StreamReader) -> dns.message.Message:
            _ = reader
            request_wire = b"".join(writer.chunks)[2:]
            request = dns.message.from_wire(request_wire)
            return _build_response(request)

        asyncio.open_connection = fake_open_connection
        TcpTrickResolver._receive_response = staticmethod(fake_receive_response)
        try:
            answer = await resolver.resolve(query, timeout_s=0.5)
        finally:
            asyncio.open_connection = original_open_connection
            TcpTrickResolver._receive_response = staticmethod(original_receive)

        self.assertEqual(answer.rcode, dns.rcode.NOERROR)
        self.assertTrue(writer.closed)
        self.assertGreaterEqual(len(writer.chunks), 2)
        request_wire = b"".join(writer.chunks)[2:]
        payload_size = int.from_bytes(b"".join(writer.chunks)[:2], "big")
        self.assertEqual(payload_size, len(request_wire))


if __name__ == "__main__":
    unittest.main()
