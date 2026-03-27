"""DNS 响应前置校验辅助函数。"""

from __future__ import annotations

import dns.message
import dns.opcode
import dns.rcode
import dns.rdataclass


def response_guard_reason(
    response: dns.message.Message,
    *,
    noerror_reason: str = "non_noerror",
) -> str | None:
    if response.rcode() != dns.rcode.NOERROR:
        return noerror_reason
    if response.opcode() != dns.opcode.QUERY:
        return "invalid_opcode"
    if not response.question:
        return "missing_question"
    if response.question[0].rdclass != dns.rdataclass.IN:
        return "invalid_qclass"
    return None
