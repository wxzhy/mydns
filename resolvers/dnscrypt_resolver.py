from __future__ import annotations

from dataclasses import replace

import dns.message

from config import UpstreamConfig
from core.hooks import RequestHooks
from resolvers.dnscrypt import (
    AsyncDnscryptClient,
    DnscryptError,
    normalize_provider_public_key,
    parse_dnscrypt_stamp,
)
from resolvers.resolver import BaseUpstreamResolver

DNSCRYPT_DEFAULT_PORT = 443


class DnscryptUpstreamResolver(BaseUpstreamResolver):
    """DNSCrypt 上游 resolver。"""

    protocol = "dnscrypt"

    def __init__(
        self,
        upstream: UpstreamConfig,
        hooks: RequestHooks | None = None,
    ) -> None:
        effective, provider_name, provider_public_key = _resolve_dnscrypt_upstream(upstream)
        super().__init__(upstream=effective, hooks=hooks)
        self._client = AsyncDnscryptClient(
            address=effective.host,
            port=effective.port,
            timeout=effective.timeout,
            provider_name=provider_name,
            provider_public_key=provider_public_key,
        )

    async def _perform_query(self, query: dns.message.Message) -> dns.message.Message:
        return await self._client.query(query)


def _resolve_dnscrypt_upstream(
    upstream: UpstreamConfig,
) -> tuple[UpstreamConfig, str, bytes]:
    if upstream.stamp:
        stamp_info = parse_dnscrypt_stamp(upstream.stamp)
        host = upstream.host or stamp_info.host
        port = (
            stamp_info.port
            if upstream.port == DNSCRYPT_DEFAULT_PORT
            else upstream.port
        )
        provider_name = upstream.provider_name or stamp_info.provider_name
        provider_public_key = normalize_provider_public_key(
            upstream.provider_pk or stamp_info.provider_public_key
        )
        effective = replace(
            upstream,
            host=host,
            port=port,
            provider_name=provider_name,
            provider_pk=provider_public_key.hex(),
        )
        return effective, provider_name, provider_public_key

    provider_name = (upstream.provider_name or "").strip()
    provider_pk = upstream.provider_pk
    if not provider_name or not provider_pk:
        raise DnscryptError(
            "dnscrypt 上游缺少 provider_name/provider_pk，或未提供可解析的 stamp。"
        )
    provider_public_key = normalize_provider_public_key(provider_pk)
    return upstream, provider_name, provider_public_key
