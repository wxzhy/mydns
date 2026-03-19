"""内置上游解析器实现。"""

from __future__ import annotations

import dns.asyncquery
import dns.resolver

from core.answer import answer_from_response
from core.models import Query
from resolver.resolver import Resolver, build_request_message


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

    async def resolve(self, query: Query, timeout_s: float) -> dns.resolver.Answer:
        request = build_request_message(query, use_edns=True)

        response = await dns.asyncquery.udp(
            request,
            where=self.address,
            port=self.port,
            timeout=timeout_s,
        )
        return answer_from_response(
            query,
            response,
            nameserver=self.address,
            port=self.port,
        )
