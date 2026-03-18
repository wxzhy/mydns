from __future__ import annotations

"""DNS 服务器基类。

封装各 server 共用逻辑：
- 最大包长校验
- 请求交给 pipeline 处理
- pipeline 统一输出 wire bytes
"""

from abc import ABC, abstractmethod

from core.context import ClientAddress
from core.pipeline import RequestPipeline


class BaseDnsServer(ABC):
    """传输层 DNS 服务器抽象基类。"""

    def __init__(
        self,
        *,
        host: str,
        port: int,
        pipeline: RequestPipeline,
        max_packet_size: int = 4096,
    ) -> None:
        self._host = host
        self._port = port
        self._pipeline = pipeline
        self._max_packet_size = max_packet_size

    @property
    def host(self) -> str:
        return self._host

    @property
    def port(self) -> int:
        return self._port

    @property
    def max_packet_size(self) -> int:
        return self._max_packet_size

    @abstractmethod
    async def start(self) -> None:
        """启动监听。"""

    @abstractmethod
    def close(self) -> None:
        """关闭监听并释放资源。"""

    def is_oversized(self, payload: bytes) -> bool:
        """判断请求是否超过服务端允许的最大报文大小。"""
        return len(payload) > self._max_packet_size

    async def handle_wire_query(
        self,
        payload: bytes,
        client: ClientAddress,
    ) -> bytes | None:
        """将 DNS 查询交由 pipeline 处理并返回 wire bytes。"""
        return await self._pipeline.handle_datagram(payload=payload, client=client)
