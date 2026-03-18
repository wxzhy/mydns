from __future__ import annotations

import dns.rcode
import dns.rdatatype
import dns.rrset


def summarize_dns_result(
    rcode: dns.rcode.Rcode,
    answer: list[dns.rrset.RRset],
    max_items: int = 6,
) -> str:
    """
    生成响应摘要，优先展示 IP 结果；
    若无 A/AAAA，则回退展示 answer 区记录。
    """
    rcode_text = dns.rcode.to_text(rcode)
    ip_answers = _collect_ip_answers(answer)
    if ip_answers:
        return f"rcode={rcode_text} ip=[{_join_items(ip_answers, max_items)}]"

    answer_items = _collect_answer_items(answer)
    if answer_items:
        return f"rcode={rcode_text} answer=[{_join_items(answer_items, max_items)}]"

    return f"rcode={rcode_text} answer=[]"


def _collect_ip_answers(answer: list[dns.rrset.RRset]) -> list[str]:
    items: list[str] = []
    for rrset in answer:
        if rrset.rdtype not in (dns.rdatatype.A, dns.rdatatype.AAAA):
            continue
        for record in rrset:
            items.append(record.to_text())
    return items


def _collect_answer_items(answer: list[dns.rrset.RRset]) -> list[str]:
    items: list[str] = []
    for rrset in answer:
        record_type = dns.rdatatype.to_text(rrset.rdtype)
        for record in rrset:
            items.append(f"{record_type}:{record.to_text()}")
    return items


def _join_items(items: list[str], max_items: int) -> str:
    if len(items) <= max_items:
        return ", ".join(items)
    shown = ", ".join(items[:max_items])
    return f"{shown}, ...(+{len(items) - max_items})"
