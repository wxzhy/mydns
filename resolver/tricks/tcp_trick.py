"""TCP 基础异步 socket。"""

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


class TrickyStreamSocket(dns.asyncbackend.StreamSocket):
    """基础 TCP 异步 socket 封装。"""

    def __init__(self, family: int, sock_type: int) -> None:
        super().__init__(family, sock_type)
        self._socket = socket.socket(family, sock_type)
        self._socket.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        self._socket.setblocking(False)
        self.closed = False

    async def connect(self, address: tuple[str, int], timeout: float | None) -> None:
        loop = asyncio.get_running_loop()
        await _wait_for(loop.sock_connect(self._socket, address), timeout)

    async def sendall(self, what: bytes, timeout: float | None) -> None:
        loop = asyncio.get_running_loop()
        if len(what) > 32:
            data = what[:16]
            data += b"\x00"
            # OOB数据无法异步发送，直接使用同步接口发送
            self._socket.sendall(data, socket.MSG_OOB)
            what = what[16:]
        await _wait_for(loop.sock_sendall(self._socket, what), timeout)

    async def recv(self, size: int, timeout: float | None) -> bytes:
        loop = asyncio.get_running_loop()
        return await _wait_for(loop.sock_recv(self._socket, size), timeout)

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
