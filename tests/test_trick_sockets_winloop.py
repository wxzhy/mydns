"""winloop 下的 trick socket 回归测试。"""

from __future__ import annotations

import asyncio
import socket
import unittest

import winloop

from resolver.tricks import TrickyDatagramSocket, TrickyStreamSocket


class TestTrickSocketsWinloop(unittest.TestCase):
    def test_tcp_trick_should_work_under_winloop(self) -> None:
        async def case() -> bytes:
            async def handler(
                reader: asyncio.StreamReader,
                writer: asyncio.StreamWriter,
            ) -> None:
                data = await reader.readexactly(5)
                writer.write(data[::-1])
                await writer.drain()
                writer.close()
                await writer.wait_closed()

            server = await asyncio.start_server(handler, "127.0.0.1", 0)
            host, port = server.sockets[0].getsockname()[:2]
            sock = TrickyStreamSocket(socket.AF_INET, socket.SOCK_STREAM)
            try:
                await sock.connect((host, port), 1.0)
                await sock.sendall(b"hello", 1.0)
                return await sock.recv(5, 1.0)
            finally:
                await sock.close()
                server.close()
                await server.wait_closed()

        data = winloop.run(case())
        self.assertEqual(data, b"olleh")

    def test_udp_trick_should_work_under_winloop(self) -> None:
        async def case() -> tuple[bytes, tuple[str, int]]:
            peer = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            peer.bind(("127.0.0.1", 0))
            sock = TrickyDatagramSocket(socket.AF_INET, socket.SOCK_DGRAM)
            sock._socket.bind(("127.0.0.1", 0))
            request = bytes(range(40))
            reply = bytearray(range(40))
            reply[10:12] = b"\x00\x01"
            reply_wire = bytes(reply)
            try:
                await sock.sendto(request, peer.getsockname(), 1.0)
                received, _ = await asyncio.to_thread(peer.recvfrom, 65535)
                self.assertEqual(received, request)

                peer.sendto(reply_wire, sock._socket.getsockname())
                return await sock.recvfrom(65535, 1.0)
            finally:
                await sock.close()
                peer.close()

        data, from_addr = winloop.run(case())
        self.assertEqual(data[10:12], b"\x00\x01")
        self.assertEqual(from_addr[0], "127.0.0.1")


if __name__ == "__main__":
    unittest.main()
