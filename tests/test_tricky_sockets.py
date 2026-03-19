"""tricks 基础 socket 测试。"""

from __future__ import annotations

import asyncio
import socket
import unittest

from resolver.tricks.tcp_trick import TrickyStreamSocket
from resolver.tricks.udp_trick import TrickyDatagramSocket


class _UdpEchoProtocol(asyncio.DatagramProtocol):
    def __init__(self) -> None:
        self.transport: asyncio.DatagramTransport | None = None

    def connection_made(self, transport: asyncio.BaseTransport) -> None:
        self.transport = transport  # type: ignore[assignment]

    def datagram_received(self, data: bytes, addr: tuple[str, int]) -> None:
        if self.transport is None:
            return
        if data == b"ping":
            self.transport.sendto(b"pong", addr)


class TestTrickySockets(unittest.IsolatedAsyncioTestCase):
    async def test_tricky_stream_socket_basic_io(self) -> None:
        async def handle(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
            data = await reader.read(16)
            if data == b"ping":
                writer.write(b"pong")
                await writer.drain()
            writer.close()
            await writer.wait_closed()

        server = await asyncio.start_server(handle, "127.0.0.1", 0)
        self.addAsyncCleanup(server.wait_closed)
        self.addCleanup(server.close)
        port = server.sockets[0].getsockname()[1]

        sock = TrickyStreamSocket(socket.AF_INET, socket.SOCK_STREAM)
        self.addAsyncCleanup(sock.close)

        await sock.connect(("127.0.0.1", port), timeout=0.5)
        await sock.sendall(b"ping", timeout=0.5)
        data = await sock.recv(4, timeout=0.5)

        self.assertEqual(data, b"pong")
        self.assertIsNotNone(await sock.getpeername())
        self.assertGreater((await sock.getsockname())[1], 0)

    async def test_tricky_datagram_socket_basic_io(self) -> None:
        loop = asyncio.get_running_loop()
        transport, _ = await loop.create_datagram_endpoint(
            _UdpEchoProtocol,
            local_addr=("127.0.0.1", 0),
        )
        self.addCleanup(transport.close)
        server_port = transport.get_extra_info("sockname")[1]

        sock = TrickyDatagramSocket(socket.AF_INET, socket.SOCK_DGRAM)
        self.addAsyncCleanup(sock.close)

        sent = await sock.sendto(b"ping", ("127.0.0.1", server_port), timeout=0.5)
        data, remote = await sock.recvfrom(16, timeout=0.5)

        self.assertEqual(sent, 4)
        self.assertEqual(data, b"pong")
        self.assertEqual(remote[0], "127.0.0.1")
        self.assertEqual(remote[1], server_port)
        self.assertGreater((await sock.getsockname())[1], 0)


if __name__ == "__main__":
    unittest.main()
