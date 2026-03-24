"""dns.resolver.Answer 构造辅助。"""

from __future__ import annotations

from collections.abc import Iterable
from typing import Any, cast

import dns.message
import dns.rcode
import dns.rdataclass
import dns.resolver
import dns.rrset

from core.models import Query


def _invalidate_response_index(response: dns.message.Message) -> None:
    # 直接修改 section 后，message 内部索引需要失效，避免 resolve_chaining() 查旧索引。
    cast(Any, response).index = None


def answer_from_response(
    query: Query,
    response: dns.message.QueryMessage,
    *,
    nameserver: str | None = None,
    port: int | None = None,
) -> dns.resolver.Answer:
    """基于 Query 与 response 构造标准 Answer。"""
    return dns.resolver.Answer(
        query.qname,
        query.qtype,
        dns.rdataclass.IN,
        response,
        nameserver=nameserver,
        port=port,
    )


def make_resolver_answer(
    query: Query,
    *,
    rcode: dns.rcode.Rcode = dns.rcode.NOERROR,
    rrsets: Iterable[dns.rrset.RRset] | None = None,
    nameserver: str | None = None,
    port: int | None = None,
) -> dns.resolver.Answer:
    """构造一个可用于流程/测试的标准 dns.resolver.Answer。"""
    request = query.message
    if request is None:
        request = dns.message.make_query(query.qname, query.qtype, use_edns=True)
        request.id = query.txid
        if query.ecs is not None:
            request.use_edns(options=[query.ecs])

    response = dns.message.make_response(request)
    response.set_rcode(rcode)
    if rrsets is not None:
        response.answer.extend(rrsets)
        _invalidate_response_index(response)
    return answer_from_response(
        query,
        cast(dns.message.QueryMessage, response),
        nameserver=nameserver,
        port=port,
    )


def make_answer(
    query: Query,
    answer: dns.resolver.Answer | None = None,
    *,
    rcode: dns.rcode.Rcode | None = None,
    rrsets: Iterable[dns.rrset.RRset] | None = None,
    nameserver: str | None = None,
    port: int | None = None,
) -> dns.message.Message | dns.resolver.Answer:
    """构造响应对象。

    - 传入 `answer`（且不传 `rcode/rrsets`）时：返回 `dns.message.Message`。
    - 传入 `rcode/rrsets` 时：返回 `dns.resolver.Answer`。
    """
    if rcode is not None or rrsets is not None:
        return make_resolver_answer(
            query,
            rcode=rcode if rcode is not None else dns.rcode.NOERROR,
            rrsets=rrsets,
            nameserver=nameserver,
            port=port,
        )

    request = query.message
    if request is None:
        request = dns.message.make_query(query.qname, query.qtype, use_edns=True)
        request.id = query.txid
        if query.ecs is not None:
            request.use_edns(options=[query.ecs])
    response = dns.message.make_response(request)

    if answer is None:
        response.set_rcode(dns.rcode.SERVFAIL)
        return response

    response.set_rcode(answer.response.rcode())
    if answer.chaining_result.cnames:
        response.answer.extend(answer.chaining_result.cnames)
    if answer.rrset is not None:
        response.answer.append(answer.rrset)
    _invalidate_response_index(response)
    return response
