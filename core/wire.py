"""DNS 报文与抽象对象之间的转换。"""

from __future__ import annotations

from typing import Any

import dns.edns
import dns.exception
import dns.flags
import dns.message
import dns.opcode
import dns.rcode
import dns.rdataclass
import dns.rrset

from core.answer import Answer, make_answer
from core.context import QueryContext
from core.models import Query


class RefusedRequestError(dns.exception.DNSException):
    """请求 opcode/qclass 不受支持时抛出，供 server 映射为 REFUSED。"""


def parse_query_context(
    request_wire: bytes, client_addr: tuple[str, int]
) -> QueryContext:
    """把原始请求报文转换为 QueryContext。"""
    request = dns.message.from_wire(request_wire)
    if not request.question:
        raise dns.exception.DNSException("DNS 请求缺少 question")

    question = request.question[0]
    _validate_request_message(request, question)
    ecs = _find_ecs_option(request.options)
    query = Query(
        client_addr=client_addr,
        txid=request.id,
        qname=question.name,
        qtype=question.rdtype,
        ecs=ecs,
        message=request,
    )
    ctx = QueryContext(query=query)
    ctx.state["request_message"] = request
    return ctx


def build_response_wire(ctx: QueryContext, answer: Answer) -> bytes:
    """将抽象响应转换为 DNS wire。"""
    request: dns.message.Message = _require_state_value(ctx.state, "request_message")
    if ctx.query.message is None:
        ctx.query.message = request
    response = make_answer(ctx.query, answer)
    return response.to_wire()


def build_error_response_wire(request_wire: bytes, rcode: dns.rcode.Rcode) -> bytes:
    """在解析失败等场景下构造错误响应。"""
    try:
        request = dns.message.from_wire(request_wire, ignore_trailing=True)
        response = Answer.ensure_response_flags(dns.message.make_response(request))
    except Exception:
        # 报文损坏时退化为最小响应，仅尽力回写事务 ID。
        txid = int.from_bytes(request_wire[:2], "big") if len(request_wire) >= 2 else 0
        response = dns.message.Message(id=txid)
        Answer.ensure_response_flags(response)
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


def _validate_request_message(
    request: dns.message.Message,
    question: dns.rrset.RRset,
) -> None:
    if request.opcode() != dns.opcode.QUERY:
        raise RefusedRequestError(
            f"不支持的 DNS opcode: {dns.opcode.to_text(request.opcode())}"
        )
    if question.rdclass != dns.rdataclass.IN:
        raise RefusedRequestError(
            f"不支持的 DNS qclass: {dns.rdataclass.to_text(question.rdclass)}"
        )
