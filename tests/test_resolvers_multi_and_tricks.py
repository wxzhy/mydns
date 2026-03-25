"""多协议 resolver 与 trick resolver 测试。"""

from __future__ import annotations

import unittest

import dns.asyncquery
import dns.edns
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
from resolver.tricks import TrickyDatagramSocket, TrickyStreamSocket
from resolver.udp_resolver import UdpUpstreamResolver


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

    async def test_tcp_resolver_should_use_tricky_socket_when_enabled(self) -> None:
        query = _make_query()
        captured: dict[str, object] = {}
        original_tcp = dns.asyncquery.tcp
        original_connect = TrickyStreamSocket.connect

        async def fake_tcp(
            request: dns.message.Message, **kwargs: object
        ) -> dns.message.Message:
            captured["kwargs"] = kwargs
            sock = kwargs.get("sock")
            if sock is not None:
                await sock.close()
            return _build_response(request)

        async def fake_connect(
            self, address: tuple[str, int], timeout: float | None
        ) -> None:
            _ = (address, timeout)

        dns.asyncquery.tcp = fake_tcp
        TrickyStreamSocket.connect = fake_connect
        try:
            resolver = TcpUpstreamResolver(
                name="tcp-tricky",
                address="1.1.1.1",
                use_tricks=True,
            )
            answer = await resolver.resolve(query, timeout_s=0.5)
        finally:
            dns.asyncquery.tcp = original_tcp
            TrickyStreamSocket.connect = original_connect

        self.assertEqual(answer.response.rcode(), dns.rcode.NOERROR)
        self.assertIsInstance(captured["kwargs"]["sock"], TrickyStreamSocket)

    async def test_udp_resolver_uses_asyncquery_udp(self) -> None:
        query = _make_query()
        captured: dict[str, object] = {}
        original = dns.asyncquery.udp

        async def fake_udp(
            request: dns.message.Message, **kwargs: object
        ) -> dns.message.Message:
            captured["kwargs"] = kwargs
            return _build_response(request)

        dns.asyncquery.udp = fake_udp
        try:
            resolver = UdpUpstreamResolver(name="udp", address="1.1.1.1")
            answer = await resolver.resolve(query, timeout_s=0.5)
        finally:
            dns.asyncquery.udp = original

        self.assertEqual(answer.response.rcode(), dns.rcode.NOERROR)
        self.assertEqual(len(answer.response.answer), 1)
        self.assertEqual(captured["kwargs"]["where"], "1.1.1.1")
        self.assertEqual(captured["kwargs"]["port"], 53)

    async def test_udp_resolver_should_use_resolver_timeout_override(self) -> None:
        query = _make_query()
        captured: dict[str, object] = {}
        original = dns.asyncquery.udp

        async def fake_udp(
            request: dns.message.Message, **kwargs: object
        ) -> dns.message.Message:
            captured["kwargs"] = kwargs
            return _build_response(request)

        dns.asyncquery.udp = fake_udp
        try:
            resolver = UdpUpstreamResolver(
                name="udp-timeout",
                address="1.1.1.1",
                timeout=0.2,
            )
            await resolver.resolve(query, timeout_s=0.5)
        finally:
            dns.asyncquery.udp = original

        self.assertEqual(captured["kwargs"]["timeout"], 0.2)

    async def test_udp_resolver_should_override_or_add_ecs_option(self) -> None:
        request = dns.message.make_query("www.example.com.", "A", use_edns=True)
        original_ecs = dns.edns.ECSOption("198.51.100.12", 24)
        other_option = dns.edns.GenericOption(dns.edns.NSID, b"nsid")
        request.use_edns(options=[other_option, original_ecs])
        query = Query(
            client_addr=("127.0.0.1", 5335),
            qname=dns.name.from_text("www.example.com."),
            qtype=dns.rdatatype.A,
            txid=request.id,
            ecs=original_ecs,
            message=request,
        )
        captured: dict[str, object] = {}
        replacement_ecs = dns.edns.ECSOption("203.0.113.5", 20)
        original = dns.asyncquery.udp

        async def fake_udp(
            request: dns.message.Message, **kwargs: object
        ) -> dns.message.Message:
            captured["request"] = request
            return _build_response(request)

        dns.asyncquery.udp = fake_udp
        try:
            resolver = UdpUpstreamResolver(
                name="udp-ecs",
                address="1.1.1.1",
                ecs=replacement_ecs,
            )
            await resolver.resolve(query, timeout_s=0.5)
        finally:
            dns.asyncquery.udp = original

        sent_request = captured["request"]
        self.assertIsInstance(sent_request, dns.message.Message)
        ecs_options = [
            option
            for option in sent_request.options
            if isinstance(option, dns.edns.ECSOption)
        ]
        self.assertEqual(len(ecs_options), 1)
        self.assertEqual(ecs_options[0].address, replacement_ecs.address)
        self.assertEqual(ecs_options[0].srclen, replacement_ecs.srclen)
        self.assertTrue(
            any(option.otype == dns.edns.NSID for option in sent_request.options)
        )

    async def test_udp_resolver_should_use_tricky_socket_when_enabled(self) -> None:
        query = _make_query()
        captured: dict[str, object] = {}
        original = dns.asyncquery.udp

        async def fake_udp(
            request: dns.message.Message, **kwargs: object
        ) -> dns.message.Message:
            captured["kwargs"] = kwargs
            sock = kwargs.get("sock")
            if sock is not None:
                await sock.close()
            return _build_response(request)

        dns.asyncquery.udp = fake_udp
        try:
            resolver = UdpUpstreamResolver(
                name="udp-tricky",
                address="1.1.1.1",
                use_tricks=True,
            )
            answer = await resolver.resolve(query, timeout_s=0.5)
        finally:
            dns.asyncquery.udp = original

        self.assertEqual(answer.response.rcode(), dns.rcode.NOERROR)
        self.assertIsInstance(captured["kwargs"]["sock"], TrickyDatagramSocket)

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
        self.assertIn("client", captured["kwargs"])

    async def test_https_resolver_should_reuse_shared_client(self) -> None:
        query = _make_query()
        clients: list[object] = []
        original = dns.asyncquery.https

        async def fake_https(
            request: dns.message.Message, **kwargs: object
        ) -> dns.message.Message:
            clients.append(kwargs["client"])
            return _build_response(request)

        dns.asyncquery.https = fake_https
        try:
            resolver1 = HttpsUpstreamResolver(name="https1", address="dns.example")
            resolver2 = HttpsUpstreamResolver(name="https2", address="dns.example")
            await resolver1.resolve(query, timeout_s=0.5)
            await resolver2.resolve(query, timeout_s=0.5)
        finally:
            dns.asyncquery.https = original

        self.assertEqual(len(clients), 2)
        self.assertIs(clients[0], clients[1])

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
