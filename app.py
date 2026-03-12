from __future__ import annotations

from config import AppConfig
from core.hooks import RequestHooks
from core.pipeline import RequestPipeline
from rules import build_default_hooks
from selector.resolver_manager import ResolverManager
from servers.udp_server import UdpDnsServer


class Application:
    def __init__(self, config: AppConfig) -> None:
        hooks = RequestHooks(build_default_hooks())
        resolver = ResolverManager.from_upstreams(config.upstreams, hooks=hooks)
        pipeline = RequestPipeline(resolver, hooks=hooks)
        self.config = config
        self.server = UdpDnsServer(
            host=config.server.host,
            port=config.server.port,
            pipeline=pipeline,
            max_packet_size=config.server.max_packet_size,
        )

    async def start(self) -> None:
        await self.server.start()

    def close(self) -> None:
        self.server.close()
