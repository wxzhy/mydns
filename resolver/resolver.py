"""上游解析器抽象接口。"""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import cast

import dns.message
import dns.edns

from core.answer import Answer
from core.models import Query


class Resolver(ABC):
    """上游解析器接口。"""

    name: str
    tags: set[str]
    timeout: float | None
    ecs: dns.edns.ECSOption | None = None

    def __init__(
        self,
        *,
        name: str | None = None,
        tags: set[str] | None = None,
        timeout: float | None = None,
        ecs: dns.edns.ECSOption | None = None,
    ) -> None:
        if name is not None:
            self.name = name
        elif not hasattr(self, "name"):
            self.name = self.__class__.__name__

        if tags is not None:
            self.tags = tags
        elif not hasattr(self, "tags"):
            self.tags = {"default"}

        if timeout is not None or not hasattr(self, "timeout"):
            self.timeout = timeout
        if ecs is not None or not hasattr(self, "ecs"):
            self.ecs = ecs

    @abstractmethod
    async def resolve(self, query: Query, timeout_s: float) -> Answer:
        """对查询执行解析。"""

    def effective_timeout(self, timeout_s: float) -> float:
        resolver_timeout = getattr(self, "timeout", None)
        if resolver_timeout is None:
            return timeout_s
        return resolver_timeout

    def build_request_message(
        self,
        query: Query,
        *,
        use_edns: bool = True,
    ) -> dns.message.QueryMessage:
        return build_request_message(query, use_edns=use_edns, ecs=self.ecs)


def build_request_message(
    query: Query,
    *,
    use_edns: bool = True,
    ecs: dns.edns.ECSOption | None = None,
) -> dns.message.QueryMessage:
    """基于 Query 构造 dnspython 请求对象。"""
    request = _copy_request_message(query, use_edns=use_edns)
    desired_ecs = ecs if ecs is not None else query.ecs
    if not use_edns and desired_ecs is None:
        request.use_edns(False)
        return request

    options = _replace_ecs_option(request.options, desired_ecs)
    request.use_edns(
        edns=request.edns if request.edns >= 0 else 0,
        ednsflags=request.ednsflags if request.edns >= 0 else 0,
        payload=request.payload if request.edns >= 0 else dns.message.DEFAULT_EDNS_PAYLOAD,
        request_payload=request.request_payload if request.edns >= 0 else None,
        options=options,
        pad=getattr(request, "pad", 0) if request.edns >= 0 else 0,
    )
    return request


def _copy_request_message(
    query: Query,
    *,
    use_edns: bool,
) -> dns.message.QueryMessage:
    if query.message is not None:
        request = cast(
            dns.message.QueryMessage,
            dns.message.from_wire(query.message.to_wire()),
        )
        request.id = query.txid
        return request

    request = dns.message.make_query(query.qname, query.qtype, use_edns=use_edns)
    request.id = query.txid
    return request


def _replace_ecs_option(
    options: tuple[dns.edns.Option, ...],
    ecs: dns.edns.ECSOption | None,
) -> list[dns.edns.Option]:
    merged = [
        option for option in options if not isinstance(option, dns.edns.ECSOption)
    ]
    if ecs is not None:
        merged.append(ecs)
    return merged
