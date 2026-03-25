"""DNS over QUIC 上游解析器。"""

from __future__ import annotations

import dns.asyncquery
import dns.edns

from core.answer import Answer
from core.models import Query
from resolver.resolver import Resolver


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
        timeout: float | None = None,
        ecs: dns.edns.ECSOption | None = None,
    ) -> None:
        super().__init__(name=name, tags=tags, timeout=timeout, ecs=ecs)
        self.address = address
        self.port = port
        self.verify = verify
        self.hostname = hostname
        self.server_hostname = server_hostname

    async def resolve(self, query: Query, timeout_s: float) -> Answer:
        timeout_s = self.effective_timeout(timeout_s)
        request = self.build_request_message(query, use_edns=True)
        response = await dns.asyncquery.quic(
            request,
            where=self.address,
            timeout=timeout_s,
            port=self.port,
            verify=self.verify,
            hostname=self.hostname,
            server_hostname=self.server_hostname,
            ignore_trailing=True,
        )
        return Answer.from_response(
            query,
            response,
            nameserver=self.address,
            port=self.port,
        )
