from __future__ import annotations

from dataclasses import dataclass, field
from time import monotonic
from typing import Any

ClientAddress = tuple[str, int]


@dataclass(slots=True)
class QueryContext:
    client: ClientAddress
    received_at: float = field(default_factory=monotonic)
    query_name: str | None = None
    query_type: str | None = None
    txid: int | None = None
    ecs: str | None = None
    tags: dict[str, Any] = field(default_factory=dict)

    @property
    def client_host(self) -> str:
        return self.client[0]

    @property
    def client_port(self) -> int:
        return self.client[1]
