"""核心数据模型定义。"""

from __future__ import annotations

from dataclasses import dataclass, field

import dns.edns
import dns.name
import dns.rdatatype
import dns.rrset
import dns.rcode


@dataclass(slots=True)
class Query:
    """DNS 请求抽象。"""

    client_addr: tuple[str, int] | None
    txid: int
    qname: dns.name.Name
    qtype: dns.rdatatype.RdataType
    ecs: dns.edns.ECSOption | None = None


@dataclass(slots=True)
class Answer:
    """DNS 响应抽象。"""

    rcode: dns.rcode.Rcode
    rrsets: list[dns.rrset.RRset] = field(default_factory=list)


@dataclass(slots=True)
class ResolverResult:
    """单个上游解析器的结果。"""

    resolver_name: str
    answer: Answer | None
    elapsed_ms: float | None
    error: Exception | None = None
