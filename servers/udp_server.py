from __future__ import annotations

import asyncio
from typing import Any, cast

from core.context import ClientAddress
from core.pipeline import RequestPipeline
from logger import get_logger

logger = get_logger(__name__)


class _DnsUdpProtocol(asyncio.DatagramProtocol):
    def __init__(self, pipeline: RequestPipeline, max_packet_size: int) -> None:
        self._pipeline = pipeline
        self._max_packet_size = max_packet_size
        self._transport: asyncio.DatagramTransport | None = None
        self._tasks: set[asyncio.Task[None]] = set()

    def connection_made(self, transport: asyncio.BaseTransport) -> None:
        self._transport = cast(asyncio.DatagramTransport, transport)
        sockname = self._transport.get_extra_info("sockname")
        logger.info("UDP DNS forwarder listening on %s", sockname)

    def datagram_received(self, data: bytes, addr: Any) -> None:
        client = self._coerce_addr(addr)
        if client is None:
            logger.warning("Ignoring datagram with unexpected client addr: %r", addr)
            return

        if len(data) > self._max_packet_size:
            logger.warning(
                "Drop oversized packet size=%s max=%s client=%s:%s",
                len(data),
                self._max_packet_size,
                client[0],
                client[1],
            )
            return

        task = asyncio.create_task(self._handle_packet(data, client))
        self._tasks.add(task)
        task.add_done_callback(self._tasks.discard)

    async def _handle_packet(self, data: bytes, client: ClientAddress) -> None:
        try:
            response = await self._pipeline.handle_datagram(data, client)
        except Exception:
            logger.exception("Unexpected packet handling error from %s:%s", *client)
            return

        if response and self._transport:
            self._transport.sendto(response, client)

    def error_received(self, exc: Exception) -> None:
        logger.warning("UDP server error: %s", exc)

    def connection_lost(self, exc: Exception | None) -> None:
        if exc:
            logger.error("UDP server connection lost: %s", exc)
        for task in tuple(self._tasks):
            task.cancel()
        self._tasks.clear()

    @staticmethod
    def _coerce_addr(addr: Any) -> ClientAddress | None:
        if not isinstance(addr, tuple) or len(addr) < 2:
            return None
        host, port = addr[0], addr[1]
        if not isinstance(host, str):
            return None
        try:
            return host, int(port)
        except (TypeError, ValueError):
            return None


class UdpDnsServer:
    def __init__(
        self,
        host: str,
        port: int,
        pipeline: RequestPipeline,
        max_packet_size: int = 4096,
    ) -> None:
        self._host = host
        self._port = port
        self._pipeline = pipeline
        self._max_packet_size = max_packet_size
        self._transport: asyncio.DatagramTransport | None = None

    async def start(self) -> None:
        if self._transport is not None:
            return

        loop = asyncio.get_running_loop()
        transport, _ = await loop.create_datagram_endpoint(
            lambda: _DnsUdpProtocol(
                pipeline=self._pipeline,
                max_packet_size=self._max_packet_size,
            ),
            local_addr=(self._host, self._port),
        )
        self._transport = cast(asyncio.DatagramTransport, transport)

    def close(self) -> None:
        if self._transport:
            self._transport.close()
            self._transport = None
