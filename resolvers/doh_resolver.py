from __future__ import annotations

from ipaddress import ip_address

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
        # DoH 通过 http_host / hostname 指定主机名，host 作为 bootstrap 地址可选。
        request_host = (
            self._upstream.http_host
            or self._upstream.hostname
            or self._upstream.host
        )
        url = self._build_doh_url(
            host=request_host,
            port=self._upstream.port,
            path=self._upstream.path,
        )
        bootstrap_address = (
            self._upstream.host if request_host != self._upstream.host else None
        )
        return await dns.asyncquery.https(
            q=query,
            where=url,
            port=self._upstream.port,
            timeout=self._upstream.timeout,
            path=self._upstream.path,
            verify=self._upstream.verify,
            bootstrap_address=bootstrap_address,
        )

    @staticmethod
    def _build_doh_url(host: str, port: int, path: str) -> str:
        normalized_path = path if path.startswith("/") else f"/{path}"
        try:
            parsed_host = ip_address(host)
        except ValueError:
            return f"https://{host}:{port}{normalized_path}"
        if parsed_host.version == 6:
            return f"https://[{host}]:{port}{normalized_path}"
        return f"https://{host}:{port}{normalized_path}"
