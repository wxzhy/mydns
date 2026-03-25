"""ipset 规则插件。"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from ipaddress import ip_address, ip_network

import dns.rdata
import dns.rdataclass
import dns.rdatatype
import dns.rrset

from core.hooks import ResolverHook
from core.ipset import ipset
from core.models import ResolverResult
from core.context import QueryContext
from logger import get_logger


logger = get_logger("plugins.ip_rule")


@dataclass(slots=True, frozen=True)
class _IPRule:
    action: str
    replacements: dict[dns.rdatatype.RdataType, str]
    prefixes: dict[dns.rdatatype.RdataType, object]


class IPRuleResolverHook(ResolverHook):
    """按 ipset tag 改写上游返回的 A/AAAA 记录。"""

    def __init__(
        self,
        *,
        rules: Mapping[str, str | Mapping[str, object]] | None = None,
    ) -> None:
        self.rules = _normalize_ip_rules(rules or {})

    async def on_resolver_result(
        self,
        ctx: QueryContext,
        result: ResolverResult,
    ) -> ResolverResult | None:
        if not self.rules:
            return result
        answer = result.answer
        if answer is None or result.error is not None:
            return result
        if ctx.query.qtype not in {dns.rdatatype.A, dns.rdatatype.AAAA}:
            return result
        if answer.response.rcode() != 0:
            return result
        rrset = answer.rrset
        if rrset is None or rrset.rdtype != ctx.query.qtype:
            return result

        rewritten_ips: list[str] = []
        seen: set[str] = set()
        changed = False
        action_logs: list[str] = []
        for rdata in rrset:
            source_ip = rdata.to_text()
            # 规则匹配只依赖应答中的 IP，不考虑 client_addr。
            applied = _apply_ip_rule(
                source_ip,
                qtype=ctx.query.qtype,
                rules=self.rules,
            )
            if applied is None:
                final_ip = source_ip
            else:
                tag, action, target = applied
                changed = True
                if action == "remove":
                    action_logs.append(f"{source_ip}->drop({tag})")
                    continue
                final_ip = target
                action_logs.append(f"{source_ip}->{final_ip}({tag}:{action})")

            if final_ip in seen:
                continue
            seen.add(final_ip)
            rewritten_ips.append(final_ip)

        if not changed:
            return result

        if rewritten_ips:
            rewritten = _build_ip_rrset(
                owner_name=rrset.name,
                rdclass=answer.rdclass,
                qtype=ctx.query.qtype,
                ips=rewritten_ips,
                ttl_s=rrset.ttl,
            )
            answer.replace_rrset(rewritten, preserve_expiration=answer.expiration)
        else:
            answer.replace_rrset(None, preserve_expiration=answer.expiration)
        logger.debug(
            "应答IP规则改写 resolver=%s qname=%s qtype=%s actions=%s result_ips=%s",
            result.resolver_name,
            ctx.query.qname.to_text(),
            ctx.query.qtype,
            action_logs,
            rewritten_ips,
        )
        return result


def _normalize_ip_rules(
    raw: Mapping[str, str | Mapping[str, object]],
) -> dict[str, _IPRule]:
    normalized: dict[str, _IPRule] = {}
    for raw_tag, raw_rule in raw.items():
        if not isinstance(raw_tag, str) or not raw_tag.strip():
            raise ValueError("ip_rules 的 tag 必须是非空字符串")
        tag = raw_tag.strip()
        normalized[tag] = _normalize_ip_rule(raw_rule, tag=tag)
    return normalized


def _normalize_ip_rule(
    raw_rule: str | Mapping[str, object],
    *,
    tag: str,
) -> _IPRule:
    if isinstance(raw_rule, str):
        action = raw_rule.strip().lower()
        if action != "remove":
            raise ValueError(f"ip_rules.{tag} 仅支持字符串动作 remove")
        return _IPRule(action="remove", replacements={}, prefixes={})

    if not isinstance(raw_rule, Mapping):
        raise ValueError(f"ip_rules.{tag} 必须是字符串或对象")

    raw_action = raw_rule.get("action", raw_rule.get("mode"))
    if not isinstance(raw_action, str) or not raw_action.strip():
        raise ValueError(f"ip_rules.{tag}.action 必须是非空字符串")
    action = raw_action.strip().lower()
    if action == "remove":
        return _IPRule(action="remove", replacements={}, prefixes={})
    if action == "replace":
        replacements = _normalize_exact_replacements(raw_rule, tag=tag)
        if not replacements:
            raise ValueError(f"ip_rules.{tag} 的 replace 规则至少需要一个 A/AAAA 值")
        return _IPRule(action="replace", replacements=replacements, prefixes={})
    if action == "replace_prefix":
        prefixes = _normalize_prefix_replacements(raw_rule, tag=tag)
        if not prefixes:
            raise ValueError(
                f"ip_rules.{tag} 的 replace_prefix 规则至少需要一个 A/AAAA 前缀"
            )
        return _IPRule(action="replace_prefix", replacements={}, prefixes=prefixes)
    raise ValueError(f"ip_rules.{tag}.action 仅支持 replace、replace_prefix 或 remove")


def _normalize_exact_replacements(
    raw_rule: Mapping[str, object],
    *,
    tag: str,
) -> dict[dns.rdatatype.RdataType, str]:
    replacements: dict[dns.rdatatype.RdataType, str] = {}
    for qtype_text, qtype in (("A", dns.rdatatype.A), ("AAAA", dns.rdatatype.AAAA)):
        if qtype_text not in raw_rule:
            continue
        raw_value = raw_rule[qtype_text]
        if not isinstance(raw_value, str) or not raw_value.strip():
            raise ValueError(f"ip_rules.{tag}.{qtype_text} 必须是非空字符串 IP")
        text = raw_value.strip()
        expected_qtype = _qtype_for_ip_text(text, key=f"ip_rules.{tag}.{qtype_text}")
        if expected_qtype != qtype:
            raise ValueError(f"ip_rules.{tag}.{qtype_text} 的 IP 版本与记录类型不匹配")
        replacements[qtype] = text
    return replacements


def _normalize_prefix_replacements(
    raw_rule: Mapping[str, object],
    *,
    tag: str,
) -> dict[dns.rdatatype.RdataType, object]:
    prefixes: dict[dns.rdatatype.RdataType, object] = {}
    for qtype_text, qtype in (("A", dns.rdatatype.A), ("AAAA", dns.rdatatype.AAAA)):
        if qtype_text not in raw_rule:
            continue
        raw_value = raw_rule[qtype_text]
        if not isinstance(raw_value, str) or not raw_value.strip():
            raise ValueError(f"ip_rules.{tag}.{qtype_text} 必须是非空字符串 CIDR")
        text = raw_value.strip()
        if "/" not in text:
            raise ValueError(f"ip_rules.{tag}.{qtype_text} 必须是 CIDR 前缀")
        try:
            network = ip_network(text, strict=False)
        except ValueError as exc:
            raise ValueError(f"ip_rules.{tag}.{qtype_text} 不是合法 CIDR: {text}") from exc
        expected_qtype = dns.rdatatype.A if network.version == 4 else dns.rdatatype.AAAA
        if expected_qtype != qtype:
            raise ValueError(f"ip_rules.{tag}.{qtype_text} 的前缀版本与记录类型不匹配")
        prefixes[qtype] = network
    return prefixes


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


def _apply_ip_rule(
    source_ip: str,
    *,
    qtype: dns.rdatatype.RdataType,
    rules: Mapping[str, _IPRule],
) -> tuple[str, str, str] | None:
    matched_tags = ipset.match_tags(source_ip)
    for tag, rule in rules.items():
        if tag not in matched_tags:
            continue
        if rule.action == "remove":
            return tag, "remove", ""
        if rule.action == "replace":
            target_ip = rule.replacements.get(qtype)
            if target_ip is not None:
                return tag, "replace", target_ip
            continue
        if rule.action == "replace_prefix":
            network = rule.prefixes.get(qtype)
            if network is not None:
                return tag, "replace_prefix", _rewrite_ip_prefix(source_ip, network)
    return None


def _rewrite_ip_prefix(source_ip: str, network: object) -> str:
    parsed = ip_address(source_ip)
    total_bits = parsed.max_prefixlen
    host_bits = total_bits - network.prefixlen
    host_mask = (1 << host_bits) - 1 if host_bits > 0 else 0
    new_value = int(network.network_address) | (int(parsed) & host_mask)
    return str(ip_address(new_value))


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
