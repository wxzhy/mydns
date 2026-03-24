"""内置上游解析器实现。"""

from __future__ import annotations

import socket

import dns.asyncquery
import dns.inet

from core.answer import Answer
from core.models import Query
from resolver.resolver import Resolver, build_request_message
from resolver.tricks import TrickyDatagramSocket


class UdpUpstreamResolver(Resolver):
    """通过 UDP 向指定 DNS 上游发起查询。"""

    def __init__(
        self,
        *,
        name: str,
        address: str,
        port: int = 53,
        use_tricks: bool = False,
        tags: set[str] | None = None,
    ) -> None:
        self.name = name
        self.address = address
        self.port = port
        self.use_tricks = use_tricks
        self.tags = tags or {"default"}

    async def resolve(self, query: Query, timeout_s: float) -> Answer:
        request = build_request_message(query, use_edns=True)
        kwargs: dict[str, object] = {
            "where": self.address,
            "port": self.port,
            "timeout": timeout_s,
        }
        if self.use_tricks:
            af = dns.inet.af_for_address(self.address)
            kwargs["sock"] = TrickyDatagramSocket(af, socket.SOCK_DGRAM)

        response = await dns.asyncquery.udp(
            request,
            **kwargs,
        )
        return Answer.from_response(
            query,
            response,
            nameserver=self.address,
            port=self.port,
        )
