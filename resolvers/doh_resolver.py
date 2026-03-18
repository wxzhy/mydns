from __future__ import annotations

import dns.asyncquery
import dns.message

from config import UpstreamConfig
from core.hooks import RequestHooks
from resolvers.resolver import BaseUpstreamResolver


class DohUpstreamResolver(BaseUpstreamResolver):
    """DNS-over-HTTPS 上游 resolver。"""

    protocol = "doh"

    def __init__(
        self,
        upstream: UpstreamConfig,
        hooks: RequestHooks | None = None,
    ) -> None:
        super().__init__(upstream=upstream, hooks=hooks)

    async def _perform_query(self, query: dns.message.Message) -> dns.message.Message:
        # DoH 请求目标主机名，host 仅作为可选 bootstrap 地址。
        request_host = (
            self._upstream.http_host
            or self._upstream.hostname
            or self._upstream.host
        )
        bootstrap_address = (
            self._upstream.host if request_host != self._upstream.host else None
        )
        return await dns.asyncquery.https(
            q=query,
            where=request_host,
            port=self._upstream.port,
            timeout=self._upstream.timeout,
            path=self._upstream.path,
            verify=self._upstream.verify,
            bootstrap_address=bootstrap_address,
        )
