"""上游解析器抽象接口。"""

from __future__ import annotations

from abc import ABC, abstractmethod
import dns.message
from core.models import Answer, Query


class Resolver(ABC):
    """上游解析器接口。"""

    name: str
    tags: set[str]

    @abstractmethod
    async def resolve(self, query: Query, timeout_s: float) -> Answer:
        """对查询执行解析。"""
