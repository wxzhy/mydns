"""DNS over HTTPS 上游解析器。"""

from __future__ import annotations

import ssl
from socket import AddressFamily

import dns.asyncquery
import dns.asyncresolver
import dns.query
import dns.resolver

from core.answer import answer_from_response
from core.models import Query
from resolver.resolver import Resolver, build_request_message


class HttpsUpstreamResolver(Resolver):
    """通过 HTTPS 向上游发起 DNS 查询。"""

    def __init__(
        self,
        *,
        name: str,
        address: str,
        port: int = 443,
        path: str = "/dns-query",
        post: bool = True,
        verify: bool | str | ssl.SSLContext = True,
        bootstrap_address: str | None = None,
        family: AddressFamily = AddressFamily.AF_UNSPEC,
        http_version: dns.query.HTTPVersion = dns.query.HTTPVersion.DEFAULT,
        source: str | None = None,
        source_port: int = 0,
        resolver: dns.asyncresolver.Resolver | None = None,
        tags: set[str] | None = None,
    ) -> None:
        self.name = name
        self.address = address
        self.port = port
        self.path = path
        self.post = post
        self.verify = verify
        self.bootstrap_address = bootstrap_address
        self.family = family
        self.http_version = http_version
        self.source = source
        self.source_port = source_port
        self.resolver = resolver
        self.tags = tags or {"default"}

    async def resolve(self, query: Query, timeout_s: float) -> dns.resolver.Answer:
        request = build_request_message(query, use_edns=True)
        response = await dns.asyncquery.https(
            request,
            where=self._build_where(),
            timeout=timeout_s,
            port=self.port,
            source=self.source,
            source_port=self.source_port,
            path=self.path,
            post=self.post,
            verify=self.verify,
            bootstrap_address=self.bootstrap_address,
            resolver=self.resolver,
            family=self.family,
            http_version=self.http_version,
        )
        return answer_from_response(
            query,
            response,
            nameserver=self.address,
            port=self.port,
        )

    def _build_where(self) -> str:
        if self.address.startswith(("https://", "http://")):
            return self.address
        return f"https://{self.address}"
