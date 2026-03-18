"""Step 5: UDP 服务端到端集成测试。"""

from __future__ import annotations

import unittest

import dns.asyncquery
import dns.message
import dns.name
import dns.rcode
import dns.rdatatype
import dns.rrset

from core.models import Answer, Query
from core.pipeline import Pipeline
from resolver.resolver import Resolver
from server.udp_server import UDPDNSServer


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
            return Answer(rcode=dns.rcode.NOERROR, rrsets=[cname, a_rr])
        return Answer(rcode=dns.rcode.NOERROR, rrsets=[])


class TestUDPIntegrationStep5(unittest.IsolatedAsyncioTestCase):
    async def test_udp_query_round_trip(self) -> None:
        pipeline = Pipeline(resolvers=[_StaticResolver()])
        server = UDPDNSServer(pipeline=pipeline, host="127.0.0.1", port=0)
        await server.start()
        try:
            query = dns.message.make_query(dns.name.from_text("www.example.com."), dns.rdatatype.A)
            response = await dns.asyncquery.udp(
                query,
                where="127.0.0.1",
                port=server.port,
                timeout=1.0,
            )
        finally:
            await server.stop()

        self.assertEqual(response.rcode(), dns.rcode.NOERROR)
        types = [rrset.rdtype for rrset in response.answer]
        self.assertIn(dns.rdatatype.CNAME, types)
        self.assertIn(dns.rdatatype.A, types)


if __name__ == "__main__":
    unittest.main()
