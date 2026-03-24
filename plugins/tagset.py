"""domainset/ipset 相关插件。"""

from __future__ import annotations

from collections.abc import Mapping
from ipaddress import ip_address

import dns.rcode
import dns.rdata
import dns.rdataclass
import dns.rdatatype
import dns.rrset

from core.answer import Answer
from core.context import QueryContext
from core.domainset import domainset
from core.hooks import RequestHook, ResolverHook
from core.ipset import ipset
from core.models import ResolverResult
from logger import get_logger


logger = get_logger("plugins.tagset")

_ADS_TAG = "ads"
_ADS_TTL_S = 24 * 60 * 60
_ADS_A = "127.0.0.1"
_ADS_AAAA = "::1"


class TagSetRequestHook(RequestHook):
    """请求阶段为查询增加标签。"""

    def __init__(self) -> None:
        # 兼容已有测试：暴露 tag key 视图。
        self.domainset_by_tag: dict[str, list[str]] = {
            tag: [] for tag in domainset.tags
        }
        self.ipset_by_tag: dict[str, list[str]] = {tag: [] for tag in ipset.tags}

    async def on_request(self, ctx: QueryContext) -> None:
        qname_text = ctx.query.qname.to_text().rstrip(".").lower()
        matched_tags = domainset.match_tags(qname_text)

        if ctx.query.client_addr is not None:
            client_ip = ctx.query.client_addr[0]
            matched_tags.update(ipset.match_tags(client_ip))

        if not matched_tags:
            return

        # 一旦命中专用 tag，就替换默认 default tag。
        ctx.tags.discard("default")
        ctx.tags.update(matched_tags)
        if _ADS_TAG in matched_tags:
            ctx.final_answer = _build_ads_answer(ctx)
            ctx.stop = True
            logger.debug(
                "广告标签命中并短路 qname=%s qtype=%s tags=%s",
                qname_text,
                ctx.query.qtype,
                sorted(ctx.tags),
            )
            return

        logger.debug(
            "标签命中 qname=%s client=%s add=%s tags=%s",
            qname_text,
            ctx.query.client_addr,
            sorted(matched_tags),
            sorted(ctx.tags),
        )


class RewriteByIPTagResolverHook(ResolverHook):
    """按应答 IP 命中的 ipset tag 重写 A/AAAA 结果。"""

    def __init__(
        self,
        *,
        replacements: Mapping[str, str | Mapping[str, str]] | None = None,
    ) -> None:
        self.replacements = _normalize_ip_replacements(replacements or {})

    async def on_resolver_result(
        self,
        ctx: QueryContext,
        result: ResolverResult,
    ) -> ResolverResult | None:
        if not self.replacements:
            return result
        answer = result.answer
        if answer is None or result.error is not None:
            return result
        if answer.response.rcode() != dns.rcode.NOERROR:
            return result
        if ctx.query.qtype not in {dns.rdatatype.A, dns.rdatatype.AAAA}:
            return result
        rrset = answer.rrset
        if rrset is None or rrset.rdtype != ctx.query.qtype:
            return result

        rewritten_ips: list[str] = []
        seen: set[str] = set()
        changed = False
        replacements_log: list[str] = []
        for rdata in rrset:
            source_ip = rdata.to_text()
            matched_tag, target_ip = _resolve_replacement_ip(
                source_ip,
                qtype=ctx.query.qtype,
                replacements=self.replacements,
            )
            final_ip = target_ip or source_ip
            if final_ip != source_ip:
                changed = True
                replacements_log.append(f"{source_ip}->{final_ip}({matched_tag})")
            if final_ip in seen:
                continue
            seen.add(final_ip)
            rewritten_ips.append(final_ip)

        if not changed:
            return result

        rewritten = _build_ip_rrset(
            owner_name=rrset.name,
            rdclass=answer.rdclass,
            qtype=ctx.query.qtype,
            ips=rewritten_ips,
            ttl_s=rrset.ttl,
        )
        answer.replace_rrset(rewritten, preserve_expiration=answer.expiration)
        logger.debug(
            "应答IP标签改写 resolver=%s qname=%s qtype=%s replacements=%s result_ips=%s",
            result.resolver_name,
            ctx.query.qname.to_text(),
            ctx.query.qtype,
            replacements_log,
            rewritten_ips,
        )
        return result


def _build_ads_answer(ctx: QueryContext):
    if ctx.query.qtype == dns.rdatatype.A:
        rrset = dns.rrset.from_text(
            ctx.query.qname.to_text(),
            _ADS_TTL_S,
            "IN",
            "A",
            _ADS_A,
        )
        return Answer.from_query(
            ctx.query,
            rcode=dns.rcode.NOERROR,
            rrsets=[rrset],
        )
    if ctx.query.qtype == dns.rdatatype.AAAA:
        rrset = dns.rrset.from_text(
            ctx.query.qname.to_text(),
            _ADS_TTL_S,
            "IN",
            "AAAA",
            _ADS_AAAA,
        )
        return Answer.from_query(
            ctx.query,
            rcode=dns.rcode.NOERROR,
            rrsets=[rrset],
        )
    return Answer.from_query(ctx.query, rcode=dns.rcode.NOERROR)


def _normalize_ip_replacements(
    raw: Mapping[str, str | Mapping[str, str]],
) -> dict[str, dict[dns.rdatatype.RdataType, str]]:
    normalized: dict[str, dict[dns.rdatatype.RdataType, str]] = {}
    for raw_tag, raw_value in raw.items():
        tag = raw_tag.strip()
        if not tag:
            raise ValueError("replacements 的 tag 必须是非空字符串")
        normalized[tag] = _normalize_ip_replacement_entry(raw_value, tag=tag)
    return normalized


def _normalize_ip_replacement_entry(
    raw_value: str | Mapping[str, str],
    *,
    tag: str,
) -> dict[dns.rdatatype.RdataType, str]:
    if isinstance(raw_value, str):
        text = raw_value.strip()
        if not text:
            raise ValueError(f"replacements.{tag} 不能为空")
        return {_qtype_for_ip_text(text, key=f"replacements.{tag}"): text}
    if not isinstance(raw_value, Mapping):
        raise ValueError(f"replacements.{tag} 必须是字符串或对象")

    normalized: dict[dns.rdatatype.RdataType, str] = {}
    for raw_qtype, raw_ip in raw_value.items():
        if not isinstance(raw_qtype, str):
            raise ValueError(f"replacements.{tag} 的记录类型必须是字符串")
        if not isinstance(raw_ip, str) or not raw_ip.strip():
            raise ValueError(f"replacements.{tag}.{raw_qtype} 必须是非空字符串")
        qtype_text = raw_qtype.strip().upper()
        if qtype_text == "A":
            qtype = dns.rdatatype.A
        elif qtype_text == "AAAA":
            qtype = dns.rdatatype.AAAA
        else:
            raise ValueError(f"replacements.{tag}.{raw_qtype} 仅支持 A 或 AAAA")
        ip_text = raw_ip.strip()
        expected_qtype = _qtype_for_ip_text(
            ip_text,
            key=f"replacements.{tag}.{qtype_text}",
        )
        if expected_qtype != qtype:
            raise ValueError(
                f"replacements.{tag}.{qtype_text} 的 IP 版本与记录类型不匹配"
            )
        normalized[qtype] = ip_text
    return normalized


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


def _resolve_replacement_ip(
    source_ip: str,
    *,
    qtype: dns.rdatatype.RdataType,
    replacements: Mapping[str, Mapping[dns.rdatatype.RdataType, str]],
) -> tuple[str | None, str | None]:
    matched_tags = sorted(ipset.match_tags(source_ip))
    for tag in matched_tags:
        tag_replacements = replacements.get(tag)
        if tag_replacements is None:
            continue
        target_ip = tag_replacements.get(qtype)
        if target_ip is not None:
            return tag, target_ip
    return None, None


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
