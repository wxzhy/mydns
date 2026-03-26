"""基于 asyncio Stream 的 TCP DNS 服务。"""

from __future__ import annotations

import asyncio

import dns.exception
import dns.rcode

from core.pipeline import Pipeline
from core.wire import (
    RefusedRequestError,
    build_error_response_wire,
    build_response_wire,
    parse_query_context,
)
from logger import get_logger


logger = get_logger("server.tcp")


class TCPDNSServer:
    """把 TCP DNS 报文接入 Pipeline 的服务对象。"""

    def __init__(
        self,
        pipeline: Pipeline,
        host: str = "127.0.0.1",
        port: int = 5335,
    ) -> None:
        self.pipeline = pipeline
        self.host = host
        self.port = port
        self._server: asyncio.AbstractServer | None = None
        self._closed = asyncio.Event()
        self._writers: set[asyncio.StreamWriter] = set()

    async def start(self) -> None:
        self._server = await asyncio.start_server(
            self._handle_client,
            host=self.host,
            port=self.port,
        )
        sockets = self._server.sockets or []
        if sockets:
            self.port = int(sockets[0].getsockname()[1])
        self._closed.clear()
        logger.info("TCP DNS 服务已启动 host=%s port=%s", self.host, self.port)

    async def stop(self) -> None:
        if self._server is None:
            return
        self._server.close()
        await self._server.wait_closed()
        self._server = None

        writers = list(self._writers)
        self._writers.clear()
        for writer in writers:
            writer.close()
        if writers:
            await asyncio.gather(
                *(writer.wait_closed() for writer in writers),
                return_exceptions=True,
            )

        self._closed.set()
        logger.info("TCP DNS 服务已停止 host=%s port=%s", self.host, self.port)

    async def serve_forever(self) -> None:
        await self._closed.wait()

    async def _handle_client(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
    ) -> None:
        self._writers.add(writer)
        addr = _normalize_peername(writer.get_extra_info("peername"))
        try:
            while True:
                try:
                    header = await reader.readexactly(2)
                except asyncio.IncompleteReadError:
                    break

                payload_len = int.from_bytes(header, "big")
                if payload_len <= 0:
                    logger.debug("TCP 请求长度非法 client=%s payload_len=%s", addr, payload_len)
                    break

                try:
                    request_wire = await reader.readexactly(payload_len)
                except asyncio.IncompleteReadError:
                    logger.debug(
                        "TCP 请求体不完整 client=%s expected=%s",
                        addr,
                        payload_len,
                    )
                    break

                response_wire = await self._process_request_wire(request_wire, addr)
                writer.write(len(response_wire).to_bytes(2, "big") + response_wire)
                await writer.drain()
        except ConnectionResetError:
            logger.debug("TCP 客户端已重置连接 client=%s", addr)
        finally:
            self._writers.discard(writer)
            writer.close()
            await writer.wait_closed()

    async def _process_request_wire(
        self,
        request_wire: bytes,
        addr: tuple[str, int],
    ) -> bytes:
        try:
            logger.debug("收到TCP请求 client=%s bytes=%s", addr, len(request_wire))
            ctx = parse_query_context(request_wire, client_addr=addr)
            logger.debug(
                "TCP请求详情 qname=%s qtype=%s ecs=%s",
                ctx.query.qname.to_text(),
                ctx.query.qtype,
                ctx.query.ecs,
            )
            answer = await self.pipeline.process(ctx)
            logger.debug(
                "TCP响应详情 qname=%s qtype=%s rcode=%s rrset_count=%s",
                ctx.query.qname.to_text(),
                ctx.query.qtype,
                answer.response.rcode(),
                len(answer.response.answer),
            )
            return build_response_wire(ctx, answer)
        except RefusedRequestError:
            logger.debug("TCP DNS 请求被拒绝 client=%s", addr)
            return build_error_response_wire(request_wire, rcode=dns.rcode.REFUSED)
        except dns.exception.DNSException:
            logger.exception("TCP DNS 请求解析失败 client=%s", addr)
            return build_error_response_wire(request_wire, rcode=dns.rcode.FORMERR)
        except Exception:
            logger.exception("TCP DNS 请求处理异常 client=%s", addr)
            return build_error_response_wire(request_wire, rcode=dns.rcode.SERVFAIL)


def _normalize_peername(peername: object) -> tuple[str, int]:
    if isinstance(peername, tuple) and len(peername) >= 2:
        host = str(peername[0])
        try:
            port = int(peername[1])
        except (TypeError, ValueError):
            return (host, 0)
        return (host, port)
    return ("0.0.0.0", 0)
