"""DNS over HTTPS 上游解析器。"""

from __future__ import annotations

import ssl

import dns.asyncquery
import dns.edns
import dns.asyncresolver

from core.answer import Answer
from core.models import Query
from resolver.resolver import Resolver

from httpx import AsyncClient, Limits

_limits = Limits(max_connections=100, max_keepalive_connections=20, keepalive_expiry=30)
# 共享 HTTPS client，复用连接池。
_shared_client = AsyncClient(http2=True, limits=_limits)


class HttpsUpstreamResolver(Resolver):
    """通过 HTTPS 向上游发起 DNS 查询。"""

    def __init__(
        self,
        *,
        name: str,
        address: str,
        port: int = 443,
        path: str = "/dns-query",
        verify: bool | str | ssl.SSLContext = True,
        bootstrap_address: str | None = None,
        resolver: dns.asyncresolver.Resolver | None = None,
        tags: set[str] | None = None,
        timeout: float | None = None,
        ecs: dns.edns.ECSOption | None = None,
    ) -> None:
        super().__init__(name=name, tags=tags, timeout=timeout, ecs=ecs)
        self.address = address
        self.port = port
        self.path = path
        self.verify = verify
        self.bootstrap_address = bootstrap_address
        self.resolver = resolver

    async def resolve(self, query: Query, timeout_s: float) -> Answer:
        timeout_s = self.effective_timeout(timeout_s)
        request = self.build_request_message(query, use_edns=True)
        response = await dns.asyncquery.https(
            request,
            where=self._build_where(),
            timeout=timeout_s,
            port=self.port,
            path=self.path,
            client=_shared_client,
            verify=self.verify,
            bootstrap_address=self.bootstrap_address,
            resolver=self.resolver,
            ignore_trailing=True,
        )
        return Answer.from_response(
            query,
            response,
            nameserver=self.address,
            port=self.port,
        )

    def _build_where(self) -> str:
        if self.address.startswith(("https://", "http://")):
            return self.address
        return f"https://{self.address}"
