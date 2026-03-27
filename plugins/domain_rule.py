"""domainset 规则插件。"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from typing import Annotated, Any, Literal

import dns.rcode
import dns.rdata
import dns.rdataclass
import dns.rdatatype
import dns.rrset
from pydantic import BeforeValidator, Field, PositiveInt, model_validator

from core.answer import Answer
from core.context import QueryContext
from core.domainset import domainset
from core.hooks import RequestHook
from logger import get_logger
from plugins._config import (
    IPv4AddressList,
    IPv6AddressList,
    NonEmptyStr,
    PluginConfigModel,
    dump_model_compact,
)
from plugins.utils.dns_helpers import build_ip_rrset


logger = get_logger("plugins.domain_rule")

_LOCALHOST_A = "127.0.0.1"
_LOCALHOST_AAAA = "::1"
_DEFAULT_TTL_S = 24 * 60 * 60


def _normalize_domain_rule_action(value: Any) -> Any:
    if isinstance(value, str):
        return value.strip().lower()
    return value


DomainRuleAction = Annotated[
    Literal["intercept", "hosts"],
    BeforeValidator(_normalize_domain_rule_action),
]
DomainRuleConfigMap = Annotated[
    dict[NonEmptyStr, "_DomainRuleConfigModel"],
    BeforeValidator(lambda value: {} if value is None else value),
]


@dataclass(slots=True, frozen=True)
class _DomainRule:
    action: str
    ttl_s: int
    records: dict[dns.rdatatype.RdataType, tuple[str, ...]]


class _DomainRuleConfigModel(PluginConfigModel):
    action: DomainRuleAction
    ttl_s: PositiveInt = _DEFAULT_TTL_S
    A: IPv4AddressList = Field(default_factory=list)
    AAAA: IPv6AddressList = Field(default_factory=list)

    @model_validator(mode="before")
    @classmethod
    def _normalize_raw(cls, raw: Any) -> dict[str, Any]:
        if isinstance(raw, str):
            return {"action": raw}
        if not isinstance(raw, Mapping):
            raise ValueError("domain_rules.<tag> 必须是字符串或对象")

        data = dict(raw)
        if "action" not in data and "mode" in data:
            data["action"] = data["mode"]
        data.pop("mode", None)
        return data

    @model_validator(mode="after")
    def _validate_hosts_records(self) -> "_DomainRuleConfigModel":
        if self.action == "hosts" and not self.A and not self.AAAA:
            raise ValueError("domain_rules.<tag> 的 hosts 规则至少需要一个 A/AAAA 记录")
        return self


class DomainRuleHookConfigModel(PluginConfigModel):
    rules: DomainRuleConfigMap = Field(default_factory=dict)


class DomainRuleRequestHook(RequestHook):
    """按 domainset tag 更新标签并执行本地域名规则。"""

    def __init__(
        self,
        *,
        rules: Mapping[str, str | Mapping[str, object]] | None = None,
    ) -> None:
        config = DomainRuleHookConfigModel.model_validate(
            {} if rules is None else {"rules": rules}
        )
        self.rules = _build_domain_rules(config.rules)
        self.domainset_by_tag: dict[str, list[str]] = {
            tag: [] for tag in domainset.tags
        }

    async def on_request(self, ctx: QueryContext) -> None:
        qname_text = ctx.query.qname.to_text().rstrip(".").lower()
        matched_tags = domainset.match_tags(qname_text)
        if not matched_tags:
            return

        # 请求阶段只看域名命中的 domainset，不混入 client IP 等额外条件。
        _merge_request_tags(ctx, matched_tags)

        matched_rule = _select_domain_rule(matched_tags, self.rules)
        if matched_rule is None:
            logger.debug(
                "域名标签命中 qname=%s tags=%s",
                qname_text,
                sorted(ctx.tags),
            )
            return

        tag, rule = matched_rule
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


def _merge_request_tags(ctx: QueryContext, matched_tags: set[str]) -> None:
    """domain_rules 命中后，使用命中标签替换默认标签集合。"""
    ctx.tags.discard("default")
    ctx.tags.update(matched_tags)


def normalize_domain_rules_config(raw_value: Any) -> dict[str, Any]:
    config = DomainRuleHookConfigModel.model_validate(
        {} if raw_value is None else {"rules": raw_value}
    )
    return {tag: dump_model_compact(rule) for tag, rule in config.rules.items()}


def normalize_domain_rule_hook_kwargs(raw_kwargs: Any) -> dict[str, Any]:
    config = DomainRuleHookConfigModel.model_validate(
        {} if raw_kwargs is None else raw_kwargs
    )
    return config.model_dump(mode="python", exclude_none=True)


def _build_domain_rules(
    config_rules: Mapping[str, _DomainRuleConfigModel],
) -> dict[str, _DomainRule]:
    return {
        tag: _DomainRule(
            action=rule.action,
            ttl_s=rule.ttl_s,
            records=_build_domain_host_records(rule),
        )
        for tag, rule in config_rules.items()
    }


def _build_domain_host_records(
    rule: _DomainRuleConfigModel,
) -> dict[dns.rdatatype.RdataType, tuple[str, ...]]:
    records: dict[dns.rdatatype.RdataType, tuple[str, ...]] = {}
    if rule.A:
        records[dns.rdatatype.A] = tuple(str(ip) for ip in rule.A)
    if rule.AAAA:
        records[dns.rdatatype.AAAA] = tuple(str(ip) for ip in rule.AAAA)
    return records


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
        return _build_hosts_answer(ctx, rule)
    return None


def _build_intercept_answer(ctx: QueryContext, *, ttl_s: int) -> Answer:
    # intercept 只对 A/AAAA 回本地回环地址；其他类型返回空 NOERROR。
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


def _build_hosts_answer(ctx: QueryContext, rule: _DomainRule) -> Answer | None:
    records = rule.records.get(ctx.query.qtype)
    if not records:
        return None

    rrset = build_ip_rrset(
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
