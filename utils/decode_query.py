from __future__ import annotations

import dns.edns
import dns.message
import dns.rdatatype

from core.context import QueryContext
from logger import get_logger

logger = get_logger(__name__)


def decode_query(payload: bytes, context: QueryContext) -> dns.message.Message | None:
    """解码 DNS 查询并将核心字段写入 QueryContext。"""
    try:
        query = dns.message.from_wire(payload)
    except Exception:
        logger.warning(
            "丢弃非法 DNS 数据报，来源 %s:%s",
            context.client_host,
            context.client_port,
        )
        return None

    if query.question:
        first_q = query.question[0]
        context.query_name = first_q.name.to_text()
        context.query_type = dns.rdatatype.to_text(first_q.rdtype)

    context.txid = query.id
    context.ecs = _extract_ecs(query)
    return query


def _extract_ecs(query: dns.message.Message) -> str | None:
    """提取请求中的 ECS 字段（若存在）。"""
    for option in query.options:
        if isinstance(option, dns.edns.ECSOption):
            return f"{option.address}/{option.srclen}"
    return None
