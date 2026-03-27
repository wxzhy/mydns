"""按结果标签改写应答 IP 的 resolver hook。"""

from __future__ import annotations

from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass
from ipaddress import IPv4Address, IPv6Address, ip_address
from typing import Annotated, Any, ClassVar

import dns.rdata
import dns.rdatatype
import dns.rrset
from pydantic import BeforeValidator, model_validator

from core.context import QueryContext
from core.hooks import ResolverHook
from core.ipset import ipset
from core.models import ResolverResult
from logger import get_logger
from plugins._config import (
    IPv4PrefixLen,
    IPv6PrefixLen,
    NonEmptyStr,
    NonEmptyStrSet,
    OptionalStrSet,
    PluginConfigModel,
    dump_model_compact,
)
from plugins.utils.dns_helpers import build_ip_rrset


logger = get_logger("plugins.ip_rule")


def _coerce_mapping_or_list(value: Any) -> Any:
    if isinstance(value, Mapping):
        return [value]
    return value


def _coerce_sequence_or_empty(value: Any) -> Any:
    if value is None:
        return ()
    return value


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


@dataclass(slots=True, frozen=True)
class _RewriteResult:
    ips: tuple[str, ...]
    changed: bool
    matched_tags: tuple[str, ...]


@dataclass(slots=True, frozen=True)
class _MatchedReplacement:
    tag: str
    ip: str


class _ReplacementConfigModel(PluginConfigModel):
    version: ClassVar[int]
    tag: NonEmptyStr
    ip: object


class _AReplacementConfigModel(_ReplacementConfigModel):
    version = 4
    ip: IPv4Address
    preserve_prefix_len: IPv4PrefixLen | None = None


class _AAAAReplacementConfigModel(_ReplacementConfigModel):
    version = 6
    ip: IPv6Address
    preserve_prefix_len: IPv6PrefixLen | None = None


class _FamilyConfigModel(PluginConfigModel):
    replacements: Annotated[
        tuple[_ReplacementConfigModel, ...],
        BeforeValidator(_coerce_mapping_or_list),
    ]

    @model_validator(mode="after")
    def _validate_unique_tags(self) -> "_FamilyConfigModel":
        seen_tags: set[str] = set()
        for replacement in self.replacements:
            if replacement.tag in seen_tags:
                raise ValueError("ip_rules.rules[*].*.replacements[*].tag 不能重复")
            seen_tags.add(replacement.tag)
        return self


class _AFamilyConfigModel(_FamilyConfigModel):
    replacements: tuple[_AReplacementConfigModel, ...]


class _AAAAFamilyConfigModel(_FamilyConfigModel):
    replacements: tuple[_AAAAReplacementConfigModel, ...]


class _IPRuleConfigModel(PluginConfigModel):
    match_tags: NonEmptyStrSet
    A: _AFamilyConfigModel | None = None
    AAAA: _AAAAFamilyConfigModel | None = None

    @model_validator(mode="after")
    def _validate_sections(self) -> "_IPRuleConfigModel":
        if self.A is None and self.AAAA is None:
            raise ValueError("ip_rules.rules[*] 至少需要一个 A/AAAA 配置")
        return self


class IPRuleHookConfigModel(PluginConfigModel):
    skip_result_tags: OptionalStrSet = set()
    rules: Annotated[
        tuple[_IPRuleConfigModel, ...],
        BeforeValidator(_coerce_sequence_or_empty),
    ] = ()


def normalize_ip_rules_config(raw_value: Any) -> dict[str, Any]:
    config = IPRuleHookConfigModel.model_validate(
        {} if raw_value is None else raw_value
    )
    return dump_model_compact(config)


def normalize_ip_rule_hook_kwargs(raw_kwargs: Any) -> dict[str, Any]:
    config = IPRuleHookConfigModel.model_validate(
        {} if raw_kwargs is None else raw_kwargs
    )
    return config.model_dump(mode="python", exclude_none=True)


def _build_ip_rules(
    config_rules: Sequence[_IPRuleConfigModel],
) -> tuple[_IPRule, ...]:
    normalized: list[_IPRule] = []
    for rule in config_rules:
        sections: dict[dns.rdatatype.RdataType, _FamilyRule] = {}
        if rule.A is not None:
            sections[dns.rdatatype.A] = _FamilyRule(
                replacements=tuple(
                    _ReplacementRule(
                        tag=replacement.tag,
                        ip=str(replacement.ip),
                        preserve_prefix_len=replacement.preserve_prefix_len,
                    )
                    for replacement in rule.A.replacements
                )
            )
        if rule.AAAA is not None:
            sections[dns.rdatatype.AAAA] = _FamilyRule(
                replacements=tuple(
                    _ReplacementRule(
                        tag=replacement.tag,
                        ip=str(replacement.ip),
                        preserve_prefix_len=replacement.preserve_prefix_len,
                    )
                    for replacement in rule.AAAA.replacements
                )
            )
        normalized.append(
            _IPRule(
                match_tags=frozenset(rule.match_tags),
                sections=sections,
            )
        )
    return tuple(normalized)


class IPRuleResolverHook(ResolverHook):
    """按 answer.tags 改写上游返回的 A/AAAA 记录。"""

    def __init__(
        self,
        *,
        rules: Sequence[Mapping[str, object]] | None = None,
        skip_result_tags: Iterable[str] | None = None,
    ) -> None:
        raw_config: dict[str, Any] = {}
        if rules is not None:
            raw_config["rules"] = rules
        if skip_result_tags is not None:
            raw_config["skip_result_tags"] = skip_result_tags
        config = IPRuleHookConfigModel.model_validate(raw_config)
        self.rules = _build_ip_rules(config.rules)
        self.skip_result_tags = frozenset(config.skip_result_tags)

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

        rrset = answer.rrset
        if rrset is None or rrset.rdtype not in {dns.rdatatype.A, dns.rdatatype.AAAA}:
            return result

        matched_sections = _match_rule_sections(
            answer.tags,
            rrset.rdtype,
            self.rules,
        )
        if not matched_sections:
            return result

        # 对 rrset 中的每条地址记录独立处理：命中则写入新 rrset，重复 tag 跳过。
        rewrite_result = _rewrite_rrset(rrset, matched_sections)
        if not rewrite_result.changed:
            return result

        rewritten = build_ip_rrset(
            owner_name=rrset.name,
            rdclass=answer.rdclass,
            qtype=rrset.rdtype,
            ips=list(rewrite_result.ips),
            ttl_s=rrset.ttl,
        )
        answer.replace_rrset(rewritten, preserve_expiration=answer.expiration)
        logger.debug(
            "应答IP规则改写 resolver=%s qname=%s qtype=%s matched_tags=%s result_tags=%s result_ips=%s",
            result.resolver_name,
            ctx.query.qname.to_text(),
            rrset.rdtype,
            list(rewrite_result.matched_tags),
            sorted(answer.tags),
            list(rewrite_result.ips),
        )
        return result


def _match_rule_sections(
    answer_tags: set[str],
    qtype: dns.rdatatype.RdataType,
    rules: Sequence[_IPRule],
) -> tuple[_FamilyRule, ...]:
    """先筛出当前结果上真正可能命中的规则，后续再按 rrset 逐条尝试。"""
    matched: list[_FamilyRule] = []
    for rule in rules:
        if not (answer_tags & rule.match_tags):
            continue
        section = rule.sections.get(qtype)
        if section is None:
            continue
        matched.append(section)
    return tuple(matched)


def _rewrite_rrset(
    rrset: dns.rrset.RRset,
    matched_sections: Sequence[_FamilyRule],
) -> _RewriteResult:
    # 新 rrset 只收集命中的结果；同一个 replacement.tag 只保留首个命中的条目。
    source_ips = tuple(rdata.to_text() for rdata in rrset)
    rewritten: list[str] = []
    matched_tags: list[str] = []
    seen_tags: set[str] = set()

    for source_ip in source_ips:
        matched = _rewrite_one_ip(source_ip, matched_sections, seen_tags)
        if matched is None:
            continue
        seen_tags.add(matched.tag)
        matched_tags.append(matched.tag)
        rewritten.append(matched.ip)

    if not matched_tags:
        return _RewriteResult(
            ips=source_ips,
            changed=False,
            matched_tags=(),
        )

    rewritten_ips = tuple(rewritten)
    return _RewriteResult(
        ips=rewritten_ips,
        changed=rewritten_ips != source_ips,
        matched_tags=tuple(matched_tags),
    )


def _rewrite_one_ip(
    source_ip: str,
    matched_sections: Sequence[_FamilyRule],
    seen_tags: set[str],
) -> _MatchedReplacement | None:
    # 对 rrset 的每条记录独立判断：先命中的 replacement tag 会占用该 tag。
    source_tags = ipset.match_tags(source_ip)
    for section in matched_sections:
        replacement = _select_replacement(source_tags, section.replacements)
        if replacement is None:
            continue
        if replacement.tag in seen_tags:
            return None
        return _MatchedReplacement(
            tag=replacement.tag,
            ip=_apply_replacement(source_ip, replacement),
        )
    return None


def _apply_replacement(
    source_ip: str,
    replacement: _ReplacementRule,
) -> str:
    if replacement.preserve_prefix_len is None:
        return replacement.ip
    return _rewrite_ip_prefix(
        replacement.ip,
        source_ip,
        replacement.preserve_prefix_len,
    )


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
