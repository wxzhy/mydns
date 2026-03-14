from __future__ import annotations

import asyncio

import dns.message

from config import UpstreamConfig
from core.hooks import RequestHooks
from resolvers.dnscrypt import (
    AsyncResolver,
    DnscryptError,
    async_query,
    normalize_provider_public_key,
)
from resolvers.resolver import BaseUpstreamResolver


class DnscryptUpstreamResolver(BaseUpstreamResolver):
    """DNSCrypt 上游 resolver。"""

    protocol = "dnscrypt"

    def __init__(
        self,
        upstream: UpstreamConfig,
        hooks: RequestHooks | None = None,
    ) -> None:
        provider_name, provider_public_key = _resolve_dnscrypt_credentials(upstream)
        super().__init__(upstream=upstream, hooks=hooks)
        self._provider_name = provider_name
        self._provider_public_key = provider_public_key
        self._client: AsyncResolver | None = None
        self._client_lock = asyncio.Lock()

    async def _perform_query(self, query: dns.message.Message) -> dns.message.Message:
        client = await self._get_client()
        return await async_query(client, query)

    async def _get_client(self) -> AsyncResolver:
        if self._client is not None:
            return self._client

        async with self._client_lock:
            if self._client is None:
                self._client = await AsyncResolver.create(
                    address=self._upstream.host,
                    port=self._upstream.port,
                    timeout=self._upstream.timeout,
                    provider_name=self._provider_name,
                    provider_pk=self._provider_public_key,
                )
        return self._client


def _resolve_dnscrypt_credentials(upstream: UpstreamConfig) -> tuple[str, bytes]:
    provider_name = (upstream.provider_name or "").strip()
    provider_pk = upstream.provider_pk
    if not provider_name or not provider_pk:
        raise DnscryptError(
            "dnscrypt 上游缺少 provider_name/provider_pk，请在配置解析阶段完成 stamp 展开。"
        )
    provider_public_key = normalize_provider_public_key(provider_pk)
    return provider_name, provider_public_key
