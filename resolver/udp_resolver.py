"""内置上游解析器实现。"""

from __future__ import annotations

import dns.asyncquery
import dns.message

from core.models import Answer, Query
from resolver.resolver import Resolver


class UdpUpstreamResolver(Resolver):
    """通过 UDP 向指定 DNS 上游发起查询。"""

    def __init__(
        self,
        *,
        name: str,
        address: str,
        port: int = 53,
        tags: set[str] | None = None,
    ) -> None:
        self.name = name
        self.address = address
        self.port = port
        self.tags = tags or {"default"}

    async def resolve(self, query: Query, timeout_s: float) -> Answer:
        request = dns.message.make_query(query.qname, query.qtype, use_edns=True)
        if query.ecs is not None:
            request.use_edns(options=[query.ecs])

        response = await dns.asyncquery.udp(
            request,
            where=self.address,
            port=self.port,
            timeout=timeout_s,
        )
        return Answer(
            rcode=response.rcode(),
            rrsets=list(response.answer),
        )
