"""请求上下文定义。"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

import dns.resolver

from core.models import IPList, Query, ResolverResult


@dataclass(slots=True)
class QueryContext:
    """DNS 查询在流水线中的运行态。"""

    query: Query
    final_answer: dns.resolver.Answer | None = None
    candidates: list[ResolverResult] = field(default_factory=list)
    ip_list: IPList = field(default_factory=IPList)
    tags: set[str] = field(default_factory=lambda: {"default"})
    state: dict[str, Any] = field(default_factory=dict)
    stop: bool = False
