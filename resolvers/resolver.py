from __future__ import annotations

from abc import ABC, abstractmethod

import dns.message

from core.context import QueryContext


class Resolver(ABC):
    @abstractmethod
    async def resolve(
        self,
        context: QueryContext,
        query: dns.message.Message,
        query_wire: bytes,
    ) -> bytes:
        """Resolve one DNS query and return a raw DNS response packet."""
