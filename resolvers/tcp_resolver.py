from __future__ import annotations

import dns.asyncquery
import dns.message

from config import UpstreamConfig
from core.hooks import RequestHooks
from resolvers.resolver import BaseUpstreamResolver


class TcpUpstreamResolver(BaseUpstreamResolver):
    """强制使用 TCP 的上游 resolver。"""

    protocol = "tcp"

    def __init__(
        self,
        upstream: UpstreamConfig,
        hooks: RequestHooks | None = None,
    ) -> None:
        super().__init__(upstream=upstream, hooks=hooks)

    async def _perform_query(self, query: dns.message.Message) -> dns.message.Message:
        return await dns.asyncquery.tcp(
            q=query,
            where=self._upstream.host,
            port=self._upstream.port,
            timeout=self._upstream.timeout,
        )
