"""DNS over QUIC 上游解析器。"""

from __future__ import annotations

import dns.asyncquery
import dns.resolver

from core.answer import answer_from_response
from core.models import Query
from resolver.resolver import Resolver, build_request_message


class QuicUpstreamResolver(Resolver):
    """通过 QUIC 向上游发起 DNS 查询。"""

    def __init__(
        self,
        *,
        name: str,
        address: str,
        port: int = 853,
        verify: bool | str = True,
        hostname: str | None = None,
        server_hostname: str | None = None,
        tags: set[str] | None = None,
    ) -> None:
        self.name = name
        self.address = address
        self.port = port
        self.verify = verify
        self.hostname = hostname
        self.server_hostname = server_hostname
        self.tags = tags or {"default"}

    async def resolve(self, query: Query, timeout_s: float) -> dns.resolver.Answer:
        request = build_request_message(query, use_edns=True)
        response = await dns.asyncquery.quic(
            request,
            where=self.address,
            timeout=timeout_s,
            port=self.port,
            verify=self.verify,
            hostname=self.hostname,
            server_hostname=self.server_hostname,
        )
        return answer_from_response(
            query,
            response,
            nameserver=self.address,
            port=self.port,
        )
