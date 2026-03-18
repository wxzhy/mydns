"""DNS 报文与抽象对象之间的转换。"""

from __future__ import annotations

from typing import Any

import dns.edns
import dns.exception
import dns.flags
import dns.message
import dns.rcode

from core.context import QueryContext
from core.models import Answer, Query


def parse_query_context(
    request_wire: bytes, client_addr: tuple[str, int]
) -> QueryContext:
    """把原始请求报文转换为 QueryContext。"""
    request = dns.message.from_wire(request_wire)
    if not request.question:
        raise dns.exception.DNSException("DNS 请求缺少 question")

    question = request.question[0]
    ecs = _find_ecs_option(request.options)
    query = Query(
        client_addr=client_addr,
        txid=request.id,
        qname=question.name,
        qtype=question.rdtype,
        ecs=ecs,
    )
    ctx = QueryContext(query=query)
    ctx.state["request_message"] = request
    return ctx


def build_response_wire(ctx: QueryContext, answer: Answer) -> bytes:
    """将抽象响应转换为 DNS wire。"""
    request: dns.message.Message = _require_state_value(ctx.state, "request_message")
    response = dns.message.make_response(request)
    response.set_rcode(answer.rcode)
    response.answer.extend(answer.rrsets)
    return response.to_wire()


def build_error_response_wire(request_wire: bytes, rcode: dns.rcode.Rcode) -> bytes:
    """在解析失败等场景下构造错误响应。"""
    try:
        request = dns.message.from_wire(request_wire, ignore_trailing=True)
        response = dns.message.make_response(request)
    except Exception:
        # 报文损坏时退化为最小响应，仅尽力回写事务 ID。
        txid = int.from_bytes(request_wire[:2], "big") if len(request_wire) >= 2 else 0
        response = dns.message.Message(id=txid)
        response.flags |= dns.flags.QR
    response.set_rcode(rcode)
    return response.to_wire()


def _find_ecs_option(options: list[dns.edns.Option]) -> dns.edns.ECSOption | None:
    for option in options:
        if isinstance(option, dns.edns.ECSOption):
            return option
    return None


def _require_state_value(state: dict[str, Any], key: str) -> Any:
    if key not in state:
        raise KeyError(f"缺少上下文状态字段: {key}")
    return state[key]
