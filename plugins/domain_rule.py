"""domainset 规则插件。"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from ipaddress import ip_address

import dns.rcode
import dns.rdata
import dns.rdataclass
import dns.rdatatype
import dns.rrset

from core.answer import Answer
from core.context import QueryContext
from core.domainset import domainset
from core.hooks import RequestHook
from logger import get_logger


logger = get_logger("plugins.domain_rule")

_LOCALHOST_A = "127.0.0.1"
_LOCALHOST_AAAA = "::1"
_DEFAULT_TTL_S = 24 * 60 * 60


@dataclass(slots=True, frozen=True)
class _DomainRule:
    action: str
    ttl_s: int
    records: dict[dns.rdatatype.RdataType, tuple[str, ...]]


class DomainRuleRequestHook(RequestHook):
    """按 domainset tag 更新标签并执行本地域名规则。"""

    def __init__(
        self,
        *,
        rules: Mapping[str, str | Mapping[str, object]] | None = None,
    ) -> None:
        self.rules = _normalize_domain_rules(rules or {})
        self.domainset_by_tag: dict[str, list[str]] = {tag: [] for tag in domainset.tags}

    async def on_request(self, ctx: QueryContext) -> None:
        qname_text = ctx.query.qname.to_text().rstrip(".").lower()
        # 规则匹配只依赖 domainset，不考虑 client ip。
        matched_tags = domainset.match_tags(qname_text)
        if not matched_tags:
            return

        ctx.tags.discard("default")
        ctx.tags.update(matched_tags)

        selected = _select_domain_rule(matched_tags, self.rules)
        if selected is None:
            logger.debug(
                "域名标签命中 qname=%s tags=%s",
                qname_text,
                sorted(ctx.tags),
            )
            return

        tag, rule = selected
        answer = _build_domain_rule_answer(ctx, rule)
        if answer is None:
            logger.debug(
                "域名规则命中但继续转发 qname=%s qtype=%s tag=%s action=%s tags=%s",
                qname_text,
                ctx.query.qtype,
                tag,
                rule.action,
                sorted(ctx.tags),
            )
            return

        ctx.final_answer = answer
        ctx.stop = True
        logger.debug(
            "域名规则已短路 qname=%s qtype=%s tag=%s action=%s tags=%s",
            qname_text,
            ctx.query.qtype,
            tag,
            rule.action,
            sorted(ctx.tags),
        )


def _normalize_domain_rules(
    raw: Mapping[str, str | Mapping[str, object]],
) -> dict[str, _DomainRule]:
    normalized: dict[str, _DomainRule] = {}
    for raw_tag, raw_rule in raw.items():
        if not isinstance(raw_tag, str) or not raw_tag.strip():
            raise ValueError("domain_rules 的 tag 必须是非空字符串")
        tag = raw_tag.strip()
        normalized[tag] = _normalize_domain_rule(raw_rule, tag=tag)
    return normalized


def _normalize_domain_rule(
    raw_rule: str | Mapping[str, object],
    *,
    tag: str,
) -> _DomainRule:
    if isinstance(raw_rule, str):
        action = raw_rule.strip().lower()
        if action != "intercept":
            raise ValueError(f"domain_rules.{tag} 仅支持字符串动作 intercept")
        return _DomainRule(action="intercept", ttl_s=_DEFAULT_TTL_S, records={})

    if not isinstance(raw_rule, Mapping):
        raise ValueError(f"domain_rules.{tag} 必须是字符串或对象")

    raw_action = raw_rule.get("action", raw_rule.get("mode"))
    if not isinstance(raw_action, str) or not raw_action.strip():
        raise ValueError(f"domain_rules.{tag}.action 必须是非空字符串")
    action = raw_action.strip().lower()

    ttl_s = _normalize_positive_int(
        raw_rule.get("ttl_s", _DEFAULT_TTL_S),
        key=f"domain_rules.{tag}.ttl_s",
    )
    if action == "intercept":
        return _DomainRule(action="intercept", ttl_s=ttl_s, records={})
    if action == "hosts":
        records = _normalize_domain_host_records(raw_rule, tag=tag)
        if not records:
            raise ValueError(f"domain_rules.{tag} 的 hosts 规则至少需要一个 A/AAAA 记录")
        return _DomainRule(action="hosts", ttl_s=ttl_s, records=records)
    raise ValueError(f"domain_rules.{tag}.action 仅支持 intercept 或 hosts")


def _normalize_domain_host_records(
    raw_rule: Mapping[str, object],
    *,
    tag: str,
) -> dict[dns.rdatatype.RdataType, tuple[str, ...]]:
    records: dict[dns.rdatatype.RdataType, tuple[str, ...]] = {}
    for qtype_text, qtype in (("A", dns.rdatatype.A), ("AAAA", dns.rdatatype.AAAA)):
        if qtype_text not in raw_rule:
            continue
        records[qtype] = _normalize_ip_values(
            raw_rule[qtype_text],
            qtype=qtype,
            key=f"domain_rules.{tag}.{qtype_text}",
        )
    return records


def _normalize_ip_values(
    raw_value: object,
    *,
    qtype: dns.rdatatype.RdataType,
    key: str,
) -> tuple[str, ...]:
    if isinstance(raw_value, str):
        values = [raw_value]
    elif isinstance(raw_value, Sequence) and not isinstance(raw_value, (str, bytes, bytearray)):
        values = list(raw_value)
    else:
        raise ValueError(f"{key} 必须是字符串或字符串列表")

    normalized: list[str] = []
    seen: set[str] = set()
    for index, item in enumerate(values):
        if not isinstance(item, str) or not item.strip():
            raise ValueError(f"{key}[{index}] 必须是非空字符串 IP")
        text = item.strip()
        expected_qtype = _qtype_for_ip_text(text, key=f"{key}[{index}]")
        if expected_qtype != qtype:
            raise ValueError(f"{key}[{index}] 的 IP 版本与记录类型不匹配")
        if text not in seen:
            seen.add(text)
            normalized.append(text)
    return tuple(normalized)


def _normalize_positive_int(raw_value: object, *, key: str) -> int:
    try:
        value = int(raw_value)
    except (TypeError, ValueError) as exc:
        raise ValueError(f"{key} 必须是正整数") from exc
    if value <= 0:
        raise ValueError(f"{key} 必须是正整数")
    return value


def _qtype_for_ip_text(
    ip_text: str,
    *,
    key: str,
) -> dns.rdatatype.RdataType:
    try:
        parsed = ip_address(ip_text)
    except ValueError as exc:
        raise ValueError(f"{key} 不是合法 IP: {ip_text}") from exc
    return dns.rdatatype.A if parsed.version == 4 else dns.rdatatype.AAAA


def _select_domain_rule(
    matched_tags: set[str],
    rules: Mapping[str, _DomainRule],
) -> tuple[str, _DomainRule] | None:
    for tag, rule in rules.items():
        if tag in matched_tags:
            return tag, rule
    return None


def _build_domain_rule_answer(
    ctx: QueryContext,
    rule: _DomainRule,
) -> Answer | None:
    if rule.action == "intercept":
        return _build_intercept_answer(ctx, ttl_s=rule.ttl_s)
    if rule.action == "hosts":
        records = rule.records.get(ctx.query.qtype)
        if not records:
            return None
        rrset = _build_ip_rrset(
            owner_name=ctx.query.qname,
            rdclass=dns.rdataclass.IN,
            qtype=ctx.query.qtype,
            ips=list(records),
            ttl_s=rule.ttl_s,
        )
        return Answer.from_query(
            ctx.query,
            rcode=dns.rcode.NOERROR,
            rrsets=[rrset],
            tags=ctx.tags,
        )
    return None


def _build_intercept_answer(ctx: QueryContext, *, ttl_s: int) -> Answer:
    if ctx.query.qtype == dns.rdatatype.A:
        rrset = dns.rrset.from_text(
            ctx.query.qname.to_text(),
            ttl_s,
            "IN",
            "A",
            _LOCALHOST_A,
        )
        return Answer.from_query(
            ctx.query,
            rcode=dns.rcode.NOERROR,
            rrsets=[rrset],
            tags=ctx.tags,
        )
    if ctx.query.qtype == dns.rdatatype.AAAA:
        rrset = dns.rrset.from_text(
            ctx.query.qname.to_text(),
            ttl_s,
            "IN",
            "AAAA",
            _LOCALHOST_AAAA,
        )
        return Answer.from_query(
            ctx.query,
            rcode=dns.rcode.NOERROR,
            rrsets=[rrset],
            tags=ctx.tags,
        )
    return Answer.from_query(ctx.query, rcode=dns.rcode.NOERROR, tags=ctx.tags)


def _build_ip_rrset(
    *,
    owner_name: dns.name.Name,
    rdclass: dns.rdataclass.RdataClass,
    qtype: dns.rdatatype.RdataType,
    ips: list[str],
    ttl_s: int,
) -> dns.rrset.RRset:
    rrset = dns.rrset.RRset(owner_name, rdclass, qtype)
    rrset.ttl = ttl_s
    for ip_text in ips:
        rrset.add(dns.rdata.from_text(rdclass, qtype, ip_text), ttl_s)
    return rrset
