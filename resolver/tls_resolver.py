"""DNS over TLS 上游解析器。"""

from __future__ import annotations

import ssl

import dns.asyncquery

from core.models import Answer, Query
from resolver.resolver import Resolver, build_request_message


class TlsUpstreamResolver(Resolver):
    """通过 TLS 向上游发起 DNS 查询。"""

    def __init__(
        self,
        *,
        name: str,
        address: str,
        port: int = 853,
        server_hostname: str | None = None,
        verify: bool | str = True,
        ssl_context: ssl.SSLContext | None = None,
        source: str | None = None,
        source_port: int = 0,
        tags: set[str] | None = None,
    ) -> None:
        self.name = name
        self.address = address
        self.port = port
        self.server_hostname = server_hostname
        self.verify = verify
        self.ssl_context = ssl_context
        self.source = source
        self.source_port = source_port
        self.tags = tags or {"default"}

    async def resolve(self, query: Query, timeout_s: float) -> Answer:
        request = build_request_message(query, use_edns=True)
        response = await dns.asyncquery.tls(
            request,
            where=self.address,
            port=self.port,
            timeout=timeout_s,
            source=self.source,
            source_port=self.source_port,
            server_hostname=self.server_hostname,
            verify=self.verify,
            ssl_context=self.ssl_context,
        )
        return Answer(
            rcode=response.rcode(),
            rrsets=list(response.answer),
        )
