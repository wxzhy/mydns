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


def build_request_message(query: Query, *, use_edns: bool = True) -> dns.message.Message:
    """基于 Query 构造 dnspython 请求对象。"""
    request = dns.message.make_query(query.qname, query.qtype, use_edns=use_edns)
    if query.ecs is not None:
        request.use_edns(options=[query.ecs])
    return request
