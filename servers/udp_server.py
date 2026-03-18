from __future__ import annotations

import asyncio
from typing import Any, cast

from core.context import ClientAddress
from core.pipeline import RequestPipeline
from logger import get_logger
from servers.server import BaseDnsServer

logger = get_logger(__name__)


class _DnsUdpProtocol(asyncio.DatagramProtocol):
    """UDP 协议适配层：收包后交由 UdpDnsServer 处理。"""

    def __init__(self, server: "UdpDnsServer") -> None:
        self._server = server
        self._transport: asyncio.DatagramTransport | None = None
        self._tasks: set[asyncio.Task[None]] = set()
        self._closed = False

    def connection_made(self, transport: asyncio.BaseTransport) -> None:
        """建立 UDP 监听连接。"""
        self._transport = cast(asyncio.DatagramTransport, transport)
        sockname = self._transport.get_extra_info("sockname")
        logger.info("UDP DNS 服务已监听：%s", sockname)

    def datagram_received(self, data: bytes, addr: Any) -> None:
        """接收单个 UDP 数据报并异步处理。"""
        if self._closed:
            return

        client = self._server.coerce_addr(addr)
        if client is None:
            logger.warning("忽略来源地址异常的数据报：%r", addr)
            return

        if self._server.is_oversized(data):
            logger.warning(
                "丢弃超大报文 size=%s max=%s client=%s:%s",
                len(data),
                self._server.max_packet_size,
                client[0],
                client[1],
            )
            return

        task = asyncio.create_task(self._handle_packet(data, client))
        self._tasks.add(task)
        task.add_done_callback(self._tasks.discard)

    async def _handle_packet(self, data: bytes, client: ClientAddress) -> None:
        """处理请求并回包。"""
        try:
            response_wire = await self._server.handle_wire_query(data, client)
        except Exception:
            logger.exception("处理数据报时发生异常，来源 %s:%s", *client)
            return

        if response_wire is not None and self._transport:
            try:
                self._transport.sendto(response_wire, client)
            except Exception:
                logger.exception("发送响应失败，目标 %s:%s", *client)

    def error_received(self, exc: Exception) -> None:
        logger.warning("UDP 服务错误：%s", exc)

    def connection_lost(self, exc: Exception | None) -> None:
        """连接断开时取消未完成任务。"""
        self._closed = True
        self._transport = None
        if exc:
            logger.error("UDP 服务连接中断：%s", exc)
        for task in tuple(self._tasks):
            task.cancel()
        self._tasks.clear()


class UdpDnsServer(BaseDnsServer):
    """基于 asyncio Datagram 的 UDP DNS 服务器。"""

    def __init__(
        self,
        host: str,
        port: int,
        pipeline: RequestPipeline,
        max_packet_size: int = 4096,
    ) -> None:
        super().__init__(
            host=host,
            port=port,
            pipeline=pipeline,
            max_packet_size=max_packet_size,
        )
        self._transport: asyncio.DatagramTransport | None = None

    async def start(self) -> None:
        """启动 UDP 监听。"""
        if self._transport is not None:
            return

        loop = asyncio.get_running_loop()
        transport, _ = await loop.create_datagram_endpoint(
            lambda: _DnsUdpProtocol(server=self),
            local_addr=(self.host, self.port),
        )
        self._transport = cast(asyncio.DatagramTransport, transport)

    def close(self) -> None:
        """关闭 UDP 监听。"""
        if self._transport:
            self._transport.close()
            self._transport = None

    @staticmethod
    def coerce_addr(addr: Any) -> ClientAddress | None:
        """将 asyncio 地址对象转换为标准 (host, port) 元组。"""
        if not isinstance(addr, tuple) or len(addr) < 2:
            return None
        host, port = addr[0], addr[1]
        if not isinstance(host, str):
            return None
        try:
            return host, int(port)
        except (TypeError, ValueError):
            return None
