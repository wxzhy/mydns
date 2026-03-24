"""trick socket 运行时测试。"""

from __future__ import annotations

import asyncio
import socket
import unittest

from resolver.tricks import TrickyDatagramSocket, TrickyStreamSocket


def _raise_not_implemented(*args, **kwargs):
    _ = (args, kwargs)
    raise NotImplementedError


class TestTrickSocketsRuntime(unittest.IsolatedAsyncioTestCase):
    async def test_tcp_trick_should_not_depend_on_loop_sock_methods(self) -> None:
        async def handler(
            reader: asyncio.StreamReader,
            writer: asyncio.StreamWriter,
        ) -> None:
            data = await reader.readexactly(5)
            self.assertEqual(data, b"hello")
            writer.write(b"world")
            await writer.drain()
            writer.close()
            await writer.wait_closed()

        server = await asyncio.start_server(handler, "127.0.0.1", 0)
        loop = asyncio.get_running_loop()
        original_methods = (
            loop.sock_connect,
            loop.sock_sendall,
            loop.sock_recv,
        )
        loop.sock_connect = _raise_not_implemented
        loop.sock_sendall = _raise_not_implemented
        loop.sock_recv = _raise_not_implemented
        try:
            host, port = server.sockets[0].getsockname()[:2]
            sock = TrickyStreamSocket(socket.AF_INET, socket.SOCK_STREAM)
            try:
                await sock.connect((host, port), 1.0)
                await sock.sendall(b"hello", 1.0)
                received = await sock.recv(5, 1.0)
            finally:
                await sock.close()
        finally:
            loop.sock_connect, loop.sock_sendall, loop.sock_recv = original_methods
            server.close()
            await server.wait_closed()

        self.assertEqual(received, b"world")

    async def test_udp_trick_should_not_depend_on_loop_sock_methods(self) -> None:
        loop = asyncio.get_running_loop()
        original_methods = (
            loop.sock_sendto,
            loop.sock_recvfrom,
        )
        loop.sock_sendto = _raise_not_implemented
        loop.sock_recvfrom = _raise_not_implemented

        peer = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        peer.bind(("127.0.0.1", 0))
        sock = TrickyDatagramSocket(socket.AF_INET, socket.SOCK_DGRAM)
        sock._socket.bind(("127.0.0.1", 0))
        request = bytes(range(40))
        reply = bytearray(range(40))
        reply[10:12] = b"\x00\x01"
        reply_wire = bytes(reply)
        try:
            peer_addr = peer.getsockname()
            await sock.sendto(request, peer_addr, 1.0)
            received, source = await asyncio.to_thread(peer.recvfrom, 65535)
            self.assertEqual(received, request)
            self.assertIsInstance(source, tuple)

            peer.sendto(reply_wire, sock._socket.getsockname())
            data, from_addr = await sock.recvfrom(65535, 1.0)
        finally:
            loop.sock_sendto, loop.sock_recvfrom = original_methods
            await sock.close()
            peer.close()

        self.assertEqual(data, reply_wire)
        self.assertEqual(from_addr[0], "127.0.0.1")


if __name__ == "__main__":
    unittest.main()
