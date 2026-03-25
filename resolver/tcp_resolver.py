"""DNS over TCP 上游解析器。"""

from __future__ import annotations

import socket

import dns.asyncquery
import dns.edns
import dns.inet

from core.answer import Answer
from core.models import Query
from resolver.resolver import Resolver
from resolver.tricks import TrickyStreamSocket


class TcpUpstreamResolver(Resolver):
    """通过 TCP 向上游发起 DNS 查询。"""

    def __init__(
        self,
        *,
        name: str,
        address: str,
        port: int = 53,
        use_tricks: bool = False,
        tags: set[str] | None = None,
        timeout: float | None = None,
        ecs: dns.edns.ECSOption | None = None,
    ) -> None:
        super().__init__(name=name, tags=tags, timeout=timeout, ecs=ecs)
        self.address = address
        self.port = port
        self.use_tricks = use_tricks

    async def resolve(self, query: Query, timeout_s: float) -> Answer:
        timeout_s = self.effective_timeout(timeout_s)
        request = self.build_request_message(query, use_edns=True)
        kwargs: dict[str, object] = {
            "where": self.address,
            "port": self.port,
            "timeout": timeout_s,
        }
        if self.use_tricks:
            af = dns.inet.af_for_address(self.address)
            tricky_sock = TrickyStreamSocket(af, socket.SOCK_STREAM)
            await tricky_sock.connect((self.address, self.port), timeout_s)
            kwargs["sock"] = tricky_sock
        response = await dns.asyncquery.tcp(
            request,
            **kwargs,
        )
        return Answer.from_response(
            query,
            response,
            nameserver=self.address,
            port=self.port,
        )
