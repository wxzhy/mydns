from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

import dns.message
import dns.rcode
import dns.rrset
from time import monotonic

ClientAddress = tuple[str, int]


@dataclass(slots=True)
class QueryContext:
    client: ClientAddress
    received_at: float = field(default_factory=monotonic)
    # 解析后的 DNS Query 对象，便于后续调试和观测。
    raw_query: dns.message.Message | None = None
    query_name: str | None = None
    query_type: str | None = None
    txid: int | None = None
    ecs: str | None = None
    # 指定当前请求使用的服务器组，默认走 default。
    tag: str = "default"
    selected_resolver: str | None = None
    resolve_rtt_ms: float | None = None
    resolver_attempts: int = 0
    resolver_errors: list[str] = field(default_factory=list)
    selected_ip: str | None = None
    # A/AAAA 聚合选择出的候选 IP（按优先级排序）。
    selected_ips: list[str] = field(default_factory=list)
    selected_ip_rtt_ms: float | None = None
    # 当前请求下收集到的全部候选 IP（去重）。
    candidate_ips: set[str] = field(default_factory=set)
    # IP 测速结果（毫秒）；None 表示测速失败或不可达。
    ip_benchmark_results: dict[str, float | None] = field(default_factory=dict)
    tags: dict[str, Any] = field(default_factory=dict)
    # 响应结果：rcode + answer rrsets。
    rcode: dns.rcode.Rcode | None = None
    answer: list[dns.rrset.RRset] | None = None

    @property
    def has_answer(self) -> bool:
        return self.rcode is not None

    def set_answer(
        self,
        rcode: dns.rcode.Rcode,
        answer: list[dns.rrset.RRset] | None = None,
    ) -> None:
        self.rcode = rcode
        self.answer = answer if answer is not None else []

    @property
    def client_host(self) -> str:
        return self.client[0]

    @property
    def client_port(self) -> int:
        return self.client[1]
