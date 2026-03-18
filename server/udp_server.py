"""最小 UDP DNS 服务。"""

from __future__ import annotations

import asyncio
from collections.abc import Awaitable, Callable

import dns.exception
import dns.rcode

from core.pipeline import Pipeline
from core.wire import build_error_response_wire, build_response_wire, parse_query_context


class _DNSDatagramProtocol(asyncio.DatagramProtocol):
    def __init__(
        self,
        handler: Callable[[bytes, tuple[str, int]], Awaitable[bytes]],
    ) -> None:
        self.handler = handler
        self.transport: asyncio.DatagramTransport | None = None
        self._tasks: set[asyncio.Task] = set()

    def connection_made(self, transport: asyncio.BaseTransport) -> None:
        self.transport = transport  # type: ignore[assignment]

    def datagram_received(self, data: bytes, addr: tuple[str, int]) -> None:
        task = asyncio.create_task(self._handle(data, addr))
        self._tasks.add(task)
        task.add_done_callback(self._tasks.discard)

    async def _handle(self, data: bytes, addr: tuple[str, int]) -> None:
        if self.transport is None:
            return
        response = await self.handler(data, addr)
        self.transport.sendto(response, addr)

    def connection_lost(self, exc: Exception | None) -> None:
        _ = exc
        for task in self._tasks:
            task.cancel()
        self._tasks.clear()
        self.transport = None


class UDPDNSServer:
    """把 UDP 报文接入 Pipeline 的服务对象。"""

    def __init__(self, pipeline: Pipeline, host: str = "127.0.0.1", port: int = 5353) -> None:
        self.pipeline = pipeline
        self.host = host
        self.port = port
        self._transport: asyncio.DatagramTransport | None = None
        self._protocol: _DNSDatagramProtocol | None = None
        self._closed = asyncio.Event()

    async def start(self) -> None:
        loop = asyncio.get_running_loop()
        transport, protocol = await loop.create_datagram_endpoint(
            lambda: _DNSDatagramProtocol(self._process_datagram),
            local_addr=(self.host, self.port),
        )
        self._transport = transport  # type: ignore[assignment]
        self._protocol = protocol  # type: ignore[assignment]
        sockname = transport.get_extra_info("sockname")
        if sockname is not None:
            self.port = sockname[1]
        self._closed.clear()

    async def stop(self) -> None:
        if self._transport is None:
            return
        self._transport.close()
        await asyncio.sleep(0)
        self._transport = None
        self._protocol = None
        self._closed.set()

    async def serve_forever(self) -> None:
        await self._closed.wait()

    async def _process_datagram(self, data: bytes, addr: tuple[str, int]) -> bytes:
        try:
            ctx = parse_query_context(data, client_addr=addr)
            answer = await self.pipeline.process(ctx)
            return build_response_wire(ctx, answer)
        except dns.exception.DNSException:
            return build_error_response_wire(data, rcode=dns.rcode.FORMERR)
        except Exception:
            return build_error_response_wire(data, rcode=dns.rcode.SERVFAIL)
