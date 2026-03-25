"""按结果标签改写应答 IP 的 resolver hook。"""

from __future__ import annotations

from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass
from ipaddress import ip_address

import dns.rdata
import dns.rdatatype
import dns.rrset

from core.answer import Answer
from core.context import QueryContext
from core.hooks import ResolverHook
from core.ipset import ipset
from core.models import ResolverResult
from logger import get_logger


logger = get_logger("plugins.ip_rule")


@dataclass(slots=True, frozen=True)
class _FamilyRule:
    replacements: tuple["_ReplacementRule", ...]


@dataclass(slots=True, frozen=True)
class _ReplacementRule:
    tag: str
    ip: str
    preserve_prefix_len: int | None


@dataclass(slots=True, frozen=True)
class _IPRule:
    match_tags: frozenset[str]
    sections: dict[dns.rdatatype.RdataType, _FamilyRule]


class IPRuleResolverHook(ResolverHook):
    """按 answer.tags 改写上游返回的 A/AAAA 记录。"""

    def __init__(
        self,
        *,
        rules: Sequence[Mapping[str, object]] | None = None,
        skip_result_tags: Iterable[str] | None = None,
    ) -> None:
        self.rules = _normalize_ip_rules(rules or ())
        self.skip_result_tags = _normalize_tag_names(
            skip_result_tags,
            key="ip_rules.skip_result_tags",
            allow_none=True,
        )

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

        if answer.tags & self.skip_result_tags:
            logger.debug(
                "应答IP规则跳过 resolver=%s qname=%s qtype=%s reason=skip_result_tags tags=%s",
                result.resolver_name,
                ctx.query.qname.to_text(),
                ctx.query.qtype,
                sorted(answer.tags),
            )
            return result

        rule = _select_ip_rule(answer.tags, self.rules)
        if rule is None:
            return result

        section, source_ips = _select_ip_rule_inputs(
            answer=answer,
            qtype=ctx.query.qtype,
            rule=rule,
        )
        if section is None or not source_ips:
            return result

        rewritten_ips = _rewrite_ips(source_ips, section)
        if rewritten_ips == source_ips:
            return result

        rrset = answer.rrset
        assert rrset is not None
        rewritten = _build_ip_rrset(
            owner_name=rrset.name,
            rdclass=answer.rdclass,
            qtype=ctx.query.qtype,
            ips=rewritten_ips,
            ttl_s=rrset.ttl,
        )
        answer.replace_rrset(rewritten, preserve_expiration=answer.expiration)
        logger.debug(
            "应答IP规则改写 resolver=%s qname=%s qtype=%s match_tags=%s result_tags=%s result_ips=%s",
            result.resolver_name,
            ctx.query.qname.to_text(),
            ctx.query.qtype,
            sorted(rule.match_tags),
            sorted(answer.tags),
            rewritten_ips,
        )
        return result


def _select_ip_rule_inputs(
    *,
    answer: Answer,
    qtype: dns.rdatatype.RdataType,
    rule: _IPRule,
) -> tuple[_FamilyRule | None, list[str]]:
    """先按结果标签选规则，再按查询类型提取当前可改写的源 IP 列表。"""
    section = rule.sections.get(qtype)
    if section is None:
        return None, []

    rrset = answer.rrset
    if rrset is None or rrset.rdtype != qtype:
        return None, []

    source_ips = [rdata.to_text() for rdata in rrset]
    return section, source_ips


def _normalize_ip_rules(
    raw_rules: Sequence[Mapping[str, object]],
) -> tuple[_IPRule, ...]:
    if isinstance(raw_rules, (str, bytes, bytearray)) or not isinstance(raw_rules, Sequence):
        raise ValueError("ip_rules.rules 必须是列表")

    normalized: list[_IPRule] = []
    for index, raw_rule in enumerate(raw_rules):
        if not isinstance(raw_rule, Mapping):
            raise ValueError(f"ip_rules.rules[{index}] 必须是对象")
        normalized.append(_normalize_ip_rule(raw_rule, index=index))
    return tuple(normalized)


def _normalize_ip_rule(
    raw_rule: Mapping[str, object],
    *,
    index: int,
) -> _IPRule:
    unknown_keys = set(raw_rule) - {"match_tags", "A", "AAAA"}
    if unknown_keys:
        raise ValueError(
            f"ip_rules.rules[{index}] 包含未知字段: {', '.join(sorted(map(str, unknown_keys)))}"
        )

    match_tags = _normalize_tag_names(
        raw_rule.get("match_tags"),
        key=f"ip_rules.rules[{index}].match_tags",
    )
    sections: dict[dns.rdatatype.RdataType, _FamilyRule] = {}
    for qtype_text, qtype in (("A", dns.rdatatype.A), ("AAAA", dns.rdatatype.AAAA)):
        if qtype_text not in raw_rule:
            continue
        raw_section = raw_rule[qtype_text]
        if not isinstance(raw_section, Mapping):
            raise ValueError(f"ip_rules.rules[{index}].{qtype_text} 必须是对象")
        sections[qtype] = _normalize_family_rule(
            raw_section,
            qtype=qtype,
            key=f"ip_rules.rules[{index}].{qtype_text}",
        )

    if not sections:
        raise ValueError(f"ip_rules.rules[{index}] 至少需要一个 A/AAAA 配置")
    return _IPRule(match_tags=match_tags, sections=sections)


def _normalize_family_rule(
    raw_section: Mapping[str, object],
    *,
    qtype: dns.rdatatype.RdataType,
    key: str,
) -> _FamilyRule:
    unknown_keys = set(raw_section) - {"replacements"}
    if unknown_keys:
        raise ValueError(
            f"{key} 包含未知字段: {', '.join(sorted(map(str, unknown_keys)))}"
        )

    replacements = _normalize_replacements(
        raw_section.get("replacements"),
        qtype=qtype,
        key=f"{key}.replacements",
    )
    return _FamilyRule(replacements=replacements)


def _normalize_replacements(
    raw_value: object,
    *,
    qtype: dns.rdatatype.RdataType,
    key: str,
) -> tuple[_ReplacementRule, ...]:
    if isinstance(raw_value, Mapping):
        values = [raw_value]
    elif isinstance(raw_value, Sequence) and not isinstance(raw_value, (str, bytes, bytearray)):
        values = list(raw_value)
    else:
        raise ValueError(f"{key} 必须是对象或对象列表")

    if not values:
        raise ValueError(f"{key} 至少需要一个 replacement")

    normalized: list[_ReplacementRule] = []
    seen_tags: set[str] = set()
    for index, item in enumerate(values):
        if not isinstance(item, Mapping):
            raise ValueError(f"{key}[{index}] 必须是对象")
        replacement = _normalize_replacement(
            item,
            qtype=qtype,
            key=f"{key}[{index}]",
        )
        if replacement.tag in seen_tags:
            raise ValueError(f"{key}[{index}].tag 重复: {replacement.tag}")
        seen_tags.add(replacement.tag)
        normalized.append(replacement)
    return tuple(normalized)


def _normalize_replacement(
    raw_value: Mapping[str, object],
    *,
    qtype: dns.rdatatype.RdataType,
    key: str,
) -> _ReplacementRule:
    unknown_keys = set(raw_value) - {"tag", "ip", "preserve_prefix_len"}
    if unknown_keys:
        raise ValueError(
            f"{key} 包含未知字段: {', '.join(sorted(map(str, unknown_keys)))}"
        )

    raw_tag = raw_value.get("tag")
    if not isinstance(raw_tag, str) or not raw_tag.strip():
        raise ValueError(f"{key}.tag 必须是非空字符串")
    tag = raw_tag.strip()

    ip = _normalize_ip_value(raw_value.get("ip"), qtype=qtype, key=f"{key}.ip")
    preserve_prefix_len = _normalize_prefix_len(
        raw_value.get("preserve_prefix_len"),
        qtype=qtype,
        key=f"{key}.preserve_prefix_len",
    )
    return _ReplacementRule(tag=tag, ip=ip, preserve_prefix_len=preserve_prefix_len)


def _normalize_ip_value(
    raw_value: object,
    *,
    qtype: dns.rdatatype.RdataType,
    key: str,
) -> str:
    if not isinstance(raw_value, str) or not raw_value.strip():
        raise ValueError(f"{key} 必须是非空字符串 IP")

    text = raw_value.strip()
    expected_qtype = _qtype_for_ip_text(text, key=key)
    if expected_qtype != qtype:
        raise ValueError(f"{key} 的 IP 版本与记录类型不匹配")
    return text


def _normalize_prefix_len(
    raw_value: object,
    *,
    qtype: dns.rdatatype.RdataType,
    key: str,
) -> int | None:
    if raw_value is None:
        return None

    try:
        value = int(raw_value)
    except (TypeError, ValueError) as exc:
        raise ValueError(f"{key} 必须是整数") from exc

    max_bits = 32 if qtype == dns.rdatatype.A else 128
    if not 0 <= value <= max_bits:
        raise ValueError(f"{key} 必须在 0 到 {max_bits} 之间")
    return value


def _normalize_tag_names(
    raw_value: object,
    *,
    key: str,
    allow_none: bool = False,
) -> frozenset[str]:
    if raw_value is None and allow_none:
        return frozenset()
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
            raise ValueError(f"{key}[{index}] 必须是非空字符串")
        tag = item.strip()
        if tag not in seen:
            seen.add(tag)
            normalized.append(tag)
    if not allow_none and not normalized:
        raise ValueError(f"{key} 至少需要一个 tag")
    return frozenset(normalized)


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


def _select_ip_rule(
    answer_tags: set[str],
    rules: Sequence[_IPRule],
) -> _IPRule | None:
    # 第一层匹配看的是结果标签，例如 tagset/domain_rule 写入的逻辑标签。
    for rule in rules:
        if answer_tags & rule.match_tags:
            return rule
    return None


def _rewrite_ips(
    source_ips: Sequence[str],
    section: _FamilyRule,
) -> list[str]:
    rewritten: list[str] = []
    seen: set[str] = set()
    changed = False
    for source_ip in source_ips:
        final_ip = source_ip
        # 第二层匹配看的是单个返回 IP 命中的 ipset tag，用于区分不同 CDN 地址段。
        replacement = _select_replacement(
            ipset.match_tags(source_ip),
            section.replacements,
        )
        if replacement is not None:
            changed = True
            final_ip = replacement.ip
            if replacement.preserve_prefix_len is not None:
                final_ip = _rewrite_ip_prefix(
                    replacement.ip,
                    source_ip,
                    replacement.preserve_prefix_len,
                )
        if final_ip in seen:
            continue
        seen.add(final_ip)
        rewritten.append(final_ip)
    return rewritten if changed else list(source_ips)


def _select_replacement(
    source_tags: set[str],
    replacements: Sequence[_ReplacementRule],
) -> _ReplacementRule | None:
    # replacement 按配置顺序匹配第一条命中的 tag。
    for replacement in replacements:
        if replacement.tag in source_tags:
            return replacement
    return None


def _rewrite_ip_prefix(
    target_ip: str,
    source_ip: str,
    prefix_len: int,
) -> str:
    target = ip_address(target_ip)
    source = ip_address(source_ip)
    if target.version != source.version:
        raise ValueError("target_ip 与 source_ip 的 IP 版本不一致")

    total_bits = target.max_prefixlen
    suffix_bits = total_bits - prefix_len
    suffix_mask = (1 << suffix_bits) - 1 if suffix_bits > 0 else 0
    all_bits = (1 << total_bits) - 1
    prefix_mask = all_bits ^ suffix_mask
    new_value = (int(target) & prefix_mask) | (int(source) & suffix_mask)
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
