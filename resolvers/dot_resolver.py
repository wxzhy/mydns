from __future__ import annotations

import dns.asyncquery
import dns.message

from config import UpstreamConfig
from core.hooks import RequestHooks
from resolvers.resolver import BaseUpstreamResolver


class DotUpstreamResolver(BaseUpstreamResolver):
    """DNS-over-TLS 上游 resolver。"""

    protocol = "dot"

    def __init__(
        self,
        upstream: UpstreamConfig,
        hooks: RequestHooks | None = None,
    ) -> None:
        super().__init__(upstream=upstream, hooks=hooks)

    async def _perform_query(self, query: dns.message.Message) -> dns.message.Message:
        return await dns.asyncquery.tls(
            q=query,
            where=self._upstream.host,
            port=self._upstream.port,
            timeout=self._upstream.timeout,
            verify=self._upstream.verify,
            server_hostname=self._upstream.hostname,
        )
