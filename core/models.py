"""核心数据模型定义。"""

from __future__ import annotations

from dataclasses import dataclass, field
import dns.edns
import dns.message
import dns.name
import dns.rdatatype
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from core.answer import Answer


@dataclass(slots=True)
class Query:
    """DNS 请求抽象。"""

    client_addr: tuple[str, int] | None
    qname: dns.name.Name
    qtype: dns.rdatatype.RdataType
    txid: int = 0
    ecs: dns.edns.ECSOption | None = None
    message: dns.message.Message | None = None


@dataclass(slots=True)
class ResolverResult:
    """单个上游解析器的结果。"""

    resolver_name: str
    answer: Answer | None
    elapsed_ms: float | None
    error: Exception | None = None


@dataclass(slots=True)
class IPList:
    """IP 列表抽象。"""

    ips: set[str] = field(default_factory=set)
    results: dict[str, float | None] = field(default_factory=dict)
