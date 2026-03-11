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
    ) -> dns.message.Message:
        """Resolve one DNS query and return DNS response message."""
