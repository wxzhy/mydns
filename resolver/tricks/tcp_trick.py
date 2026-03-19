"""TCP 自定义收发解析器。"""

from __future__ import annotations

import asyncio

import dns.exception
import dns.message

from core.models import Answer, Query
from resolver.resolver import Resolver, build_request_message


class TcpTrickResolver(Resolver):
    """通过分段发送与严格校验实现自定义 TCP 查询。"""

    def __init__(
        self,
        *,
        name: str,
        address: str,
        port: int = 53,
        split_at: int = 6,
        inter_chunk_delay_ms: int = 0,
        tags: set[str] | None = None,
    ) -> None:
        self.name = name
        self.address = address
        self.port = port
        self.split_at = max(1, split_at)
        self.inter_chunk_delay_ms = max(0, inter_chunk_delay_ms)
        self.tags = tags or {"default"}

    async def resolve(self, query: Query, timeout_s: float) -> Answer:
        request = build_request_message(query, use_edns=True)
        response = await self._query_with_split_send(request, timeout_s)
        return Answer(
            rcode=response.rcode(),
            rrsets=list(response.answer),
        )

    async def _query_with_split_send(
        self,
        request: dns.message.Message,
        timeout_s: float,
    ) -> dns.message.Message:
        reader: asyncio.StreamReader
        writer: asyncio.StreamWriter
        async with asyncio.timeout(timeout_s):
            reader, writer = await asyncio.open_connection(self.address, self.port)
            try:
                await self._send_request(writer, request.to_wire())
                response = await self._receive_response(reader)
            finally:
                writer.close()
                await writer.wait_closed()

        if not self._accept_response(request, response):
            raise dns.exception.DNSException("TCP trick 检测到无效响应")
        return response

    async def _send_request(self, writer: asyncio.StreamWriter, wire: bytes) -> None:
        frame = len(wire).to_bytes(2, "big") + wire
        split_pos = min(self.split_at, len(frame) - 1)
        writer.write(frame[:split_pos])
        await writer.drain()
        if self.inter_chunk_delay_ms > 0:
            await asyncio.sleep(self.inter_chunk_delay_ms / 1000)
        writer.write(frame[split_pos:])
        await writer.drain()

    @staticmethod
    async def _receive_response(reader: asyncio.StreamReader) -> dns.message.Message:
        size_data = await reader.readexactly(2)
        size = int.from_bytes(size_data, "big")
        wire = await reader.readexactly(size)
        return dns.message.from_wire(wire)

    @staticmethod
    def _accept_response(
        request: dns.message.Message,
        response: dns.message.Message,
    ) -> bool:
        if response.id != request.id:
            return False
        if request.question and response.question:
            request_question = request.question[0]
            response_question = response.question[0]
            if request_question.name != response_question.name:
                return False
            if request_question.rdtype != response_question.rdtype:
                return False
        return True
