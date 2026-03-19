"""dns.resolver.Answer 构造辅助。"""

from __future__ import annotations

from collections.abc import Iterable

import dns.message
import dns.rcode
import dns.rdataclass
import dns.resolver
import dns.rrset

from core.models import Query


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


def make_answer(
    query: Query,
    *,
    rcode: dns.rcode.Rcode = dns.rcode.NOERROR,
    rrsets: Iterable[dns.rrset.RRset] | None = None,
    nameserver: str | None = None,
    port: int | None = None,
) -> dns.resolver.Answer:
    """构造一个可用于本地流程/测试的标准 Answer。"""
    request = dns.message.make_query(query.qname, query.qtype, use_edns=True)
    request.id = query.txid
    response = dns.message.make_response(request)
    response.set_rcode(rcode)
    if rrsets is not None:
        response.answer.extend(rrsets)
    return answer_from_response(
        query,
        response,
        nameserver=nameserver,
        port=port,
    )
