"""Step 5: TCP 服务端到端集成测试。"""

from __future__ import annotations

import unittest

import dns.asyncquery
import dns.flags
import dns.message
import dns.name
import dns.opcode
import dns.rcode
import dns.rdataclass
import dns.rdatatype
import dns.rrset

from core.answer import Answer
from core.models import Query
from core.pipeline import Pipeline
from plugins.speedcheck import RewriteAnswerByRTTHook
from resolver.resolver import Resolver
from server.tcp_server import TCPDNSServer


class _StaticResolver(Resolver):
    name = "static"
    tags = {"default"}

    async def resolve(self, query: Query, timeout_s: float) -> Answer:
        _ = timeout_s
        if query.qtype == dns.rdatatype.A:
            cname = dns.rrset.from_text(
                query.qname.to_text(),
                30,
                "IN",
                "CNAME",
                "edge.example.com.",
            )
            a_rr = dns.rrset.from_text("edge.example.com.", 30, "IN", "A", "1.1.1.1")
            return Answer.from_query(
                query,
                rcode=dns.rcode.NOERROR,
                rrsets=[cname, a_rr],
            )
        return Answer.from_query(query, rcode=dns.rcode.NOERROR)


class TestTCPIntegrationStep5(unittest.IsolatedAsyncioTestCase):
    async def test_tcp_query_round_trip(self) -> None:
        pipeline = Pipeline(
            resolvers=[_StaticResolver()],
            response_hooks=[RewriteAnswerByRTTHook()],
        )
        server = TCPDNSServer(pipeline=pipeline, host="127.0.0.1", port=0)
        await server.start()
        try:
            query = dns.message.make_query(
                dns.name.from_text("www.example.com."),
                dns.rdatatype.A,
            )
            response = await dns.asyncquery.tcp(
                query,
                where="127.0.0.1",
                port=server.port,
                timeout=1.0,
            )
        finally:
            await server.stop()

        self.assertEqual(response.rcode(), dns.rcode.NOERROR)
        self.assertTrue(response.flags & dns.flags.QR)
        self.assertTrue(response.flags & dns.flags.RD)
        self.assertTrue(response.flags & dns.flags.RA)
        types = [rrset.rdtype for rrset in response.answer]
        self.assertIn(dns.rdatatype.CNAME, types)
        self.assertIn(dns.rdatatype.A, types)

    async def test_tcp_non_in_query_should_return_refused(self) -> None:
        pipeline = Pipeline(
            resolvers=[_StaticResolver()],
            response_hooks=[RewriteAnswerByRTTHook()],
        )
        server = TCPDNSServer(pipeline=pipeline, host="127.0.0.1", port=0)
        await server.start()
        try:
            query = dns.message.make_query(
                dns.name.from_text("www.example.com."),
                dns.rdatatype.A,
                dns.rdataclass.CH,
            )
            response = await dns.asyncquery.tcp(
                query,
                where="127.0.0.1",
                port=server.port,
                timeout=1.0,
            )
        finally:
            await server.stop()

        self.assertEqual(response.rcode(), dns.rcode.REFUSED)
        self.assertTrue(response.flags & dns.flags.QR)
        self.assertTrue(response.flags & dns.flags.RD)
        self.assertTrue(response.flags & dns.flags.RA)

    async def test_tcp_non_query_opcode_should_return_refused(self) -> None:
        pipeline = Pipeline(
            resolvers=[_StaticResolver()],
            response_hooks=[RewriteAnswerByRTTHook()],
        )
        server = TCPDNSServer(pipeline=pipeline, host="127.0.0.1", port=0)
        await server.start()
        try:
            query = dns.message.make_query(
                dns.name.from_text("www.example.com."),
                dns.rdatatype.A,
            )
            query.set_opcode(dns.opcode.STATUS)
            response = await dns.asyncquery.tcp(
                query,
                where="127.0.0.1",
                port=server.port,
                timeout=1.0,
            )
        finally:
            await server.stop()

        self.assertEqual(response.rcode(), dns.rcode.REFUSED)
        self.assertTrue(response.flags & dns.flags.QR)
        self.assertTrue(response.flags & dns.flags.RD)
        self.assertTrue(response.flags & dns.flags.RA)


if __name__ == "__main__":
    unittest.main()
