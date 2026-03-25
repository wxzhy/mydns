"""DNS over TLS 上游解析器。"""

from __future__ import annotations

import dns.asyncquery
import dns.edns

from core.answer import Answer
from core.models import Query
from resolver.resolver import Resolver


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
        tags: set[str] | None = None,
        timeout: float | None = None,
        ecs: dns.edns.ECSOption | None = None,
    ) -> None:
        super().__init__(name=name, tags=tags, timeout=timeout, ecs=ecs)
        self.address = address
        self.port = port
        self.server_hostname = server_hostname
        self.verify = verify

    async def resolve(self, query: Query, timeout_s: float) -> Answer:
        timeout_s = self.effective_timeout(timeout_s)
        request = self.build_request_message(query, use_edns=True)
        response = await dns.asyncquery.tls(
            request,
            where=self.address,
            port=self.port,
            timeout=timeout_s,
            server_hostname=self.server_hostname,
            verify=self.verify,
        )
        return Answer.from_response(
            query,
            response,
            nameserver=self.address,
            port=self.port,
        )
