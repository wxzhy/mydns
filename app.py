from __future__ import annotations

from config import AppConfig
from core.pipeline import RequestPipeline
from resolvers.udp_resolver import UdpUpstreamResolver
from servers.udp_server import UdpDnsServer


class Application:
    def __init__(self, config: AppConfig) -> None:
        resolver = UdpUpstreamResolver(config.upstreams)
        pipeline = RequestPipeline(resolver)
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
