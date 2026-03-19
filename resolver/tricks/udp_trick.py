"""UDP 基础异步 socket。"""

from __future__ import annotations

import asyncio
import socket
from collections.abc import Awaitable
from typing import Any

import dns.asyncbackend


async def _wait_for(awaitable: Awaitable[Any], timeout: float | None) -> Any:
    """统一超时封装。"""
    if timeout is None:
        return await awaitable
    return await asyncio.wait_for(awaitable, timeout)


class TrickyDatagramSocket(dns.asyncbackend.DatagramSocket):
    """基础 UDP 异步 socket 封装。"""

    def __init__(self, family: int, sock_type: int) -> None:
        super().__init__(family, sock_type)
        self._socket = socket.socket(family, sock_type)
        self._socket.setblocking(False)
        self.closed = False

    async def sendto(
        self,
        what: bytes,
        where: tuple[str, int],
        timeout: float | None,
    ) -> int:
        loop = asyncio.get_running_loop()
        return await _wait_for(loop.sock_sendto(self._socket, what, where), timeout)

    async def recvfrom(
        self,
        size: int,
        timeout: float | None,
    ) -> tuple[bytes, tuple[str, int]]:
        loop = asyncio.get_running_loop()
        return await _wait_for(loop.sock_recvfrom(self._socket, size), timeout)

    async def close(self) -> None:
        if self.closed:
            return
        self.closed = True
        self._socket.close()

    async def getpeername(self) -> tuple[str, int] | None:
        try:
            return self._socket.getpeername()
        except OSError:
            return None

    async def getsockname(self) -> tuple[str, int]:
        return self._socket.getsockname()

    async def getpeercert(self, timeout: float | None) -> None:
        _ = timeout
        return None
