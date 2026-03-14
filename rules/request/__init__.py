from __future__ import annotations

from collections.abc import Iterable, Mapping
from ipaddress import ip_address

import dns.message
import dns.opcode
import dns.rcode
import dns.rdataclass
import dns.rdatatype
import dns.rrset

from core.context import QueryContext
from core.hooks import RequestHook
from logger import get_logger
from utils.domainset import DomainSet
from utils.ipset import IPSet

DEFAULT_BLOCKED_DOMAINS: tuple[str, ...] = ()
DEFAULT_AD_BLOCK_TAGS: tuple[str, ...] = ()
DEFAULT_HOSTS: dict[str, str] = {}
logger = get_logger(__name__)


def _normalize_domain(name: str) -> str:
    normalized = name.strip().rstrip(".").lower()
    if not normalized:
        return ""
    return f"{normalized}."


def _normalize_tag_key(tag: str) -> str:
    return tag.strip().casefold()


def _make_empty_noerror_response(query: dns.message.Message) -> dns.message.Message:
    response = dns.message.make_response(query)
    response.set_rcode(dns.rcode.NOERROR)
    return response


class DomainSetRouteHook(RequestHook):
    """按域名集合匹配请求路由标签（最长后缀优先）。"""

    def __init__(self, domainset: DomainSet) -> None:
        self._domainset = domainset

    async def before_upstream(
        self,
        context: QueryContext,
        query: dns.message.Message,
    ) -> dns.message.Message | None:
        qname = context.query_name or (
            query.question[0].name.to_text() if query.question else ""
        )
        if not qname:
            return None

        matched_tag = self._domainset.match_best(qname)
        if matched_tag is None:
            return None

        context.tag = matched_tag
        context.tags["route_tag"] = matched_tag
        context.tags["route_tag_source"] = "domainset"
        return None


class ClientIPSetRouteHook(RequestHook):
    """按客户端来源 IP 匹配路由标签（最长前缀优先）。"""

    def __init__(self, ipset: IPSet) -> None:
        self._ipset = ipset

    async def before_upstream(
        self,
        context: QueryContext,
        query: dns.message.Message,
    ) -> dns.message.Message | None:
        del query
        # 已被 domainset 等规则设置过标签时，不再由 ipset 覆盖。
        if _normalize_tag_key(context.tag) != "default":
            return None

        matched_tag = self._ipset.match_best(context.client_host)
        if matched_tag is None:
            return None

        context.tag = matched_tag
        context.tags["route_tag"] = matched_tag
        context.tags["route_tag_source"] = "ipset"
        return None


class TagEmptyResponseHook(RequestHook):
    """命中指定 tag 时，直接返回 NOERROR 空应答。"""

    def __init__(self, blocked_tags: Iterable[str]) -> None:
        self._blocked_tags = {
            normalized
            for item in blocked_tags
            if (normalized := _normalize_tag_key(str(item)))
        }

    async def before_upstream(
        self,
        context: QueryContext,
        query: dns.message.Message,
    ) -> dns.message.Message | None:
        if _normalize_tag_key(context.tag) not in self._blocked_tags:
            return None
        context.tags["request_rule"] = "ad-block-tag-empty"
        context.tags["ad_block_tag"] = context.tag
        return _make_empty_noerror_response(query)


class DomainBlockHook(RequestHook):
    def __init__(
        self,
        blocked_domains: Iterable[str],
        rcode: int = dns.rcode.NXDOMAIN,
    ) -> None:
        self._exact: set[str] = set()
        self._suffixes: tuple[str, ...] = ()
        suffixes: list[str] = []

        for item in blocked_domains:
            domain = _normalize_domain(item)
            if not domain:
                continue
            if domain.startswith("*."):
                suffixes.append(domain[1:])
            else:
                self._exact.add(domain)
        self._suffixes = tuple(suffixes)
        self._rcode = rcode

    async def before_upstream(
        self,
        context: QueryContext,
        query: dns.message.Message,
    ) -> dns.message.Message | None:
        qname = context.query_name or (
            query.question[0].name.to_text() if query.question else ""
        )
        qname = _normalize_domain(qname)
        if not qname:
            return None

        if qname in self._exact or any(qname.endswith(suffix) for suffix in self._suffixes):
            context.tags["request_rule"] = "blocked-domain"
            response = dns.message.make_response(query)
            response.set_rcode(self._rcode)
            return response
        return None


class RequestDebugHook(RequestHook):
    """请求阶段调试日志。"""

    async def before_upstream(
        self,
        context: QueryContext,
        query: dns.message.Message,
    ) -> dns.message.Message | None:
        logger.debug(
            "收到请求 client=%s:%s txid=%s qtype=%s domain=%s ecs=%s",
            context.client_host,
            context.client_port,
            context.txid if context.txid is not None else "-",
            context.query_type or "-",
            context.query_name or "-",
            context.ecs or "-",
        )
        return None


class RequestSanityDropHook(RequestHook):
    """
    请求基础合法性校验：
    - 仅允许标准 QUERY opcode
    - 仅允许 IN qclass

    不满足时直接标记丢弃（不回包）。
    """

    async def before_upstream(
        self,
        context: QueryContext,
        query: dns.message.Message,
    ) -> dns.message.Message | None:
        if query.opcode() != dns.opcode.QUERY:
            context.tags["drop_request"] = True
            context.tags["drop_reason"] = "unsupported-opcode"
            return None

        for question in query.question:
            if question.rdclass != dns.rdataclass.IN:
                context.tags["drop_request"] = True
                context.tags["drop_reason"] = "unsupported-qclass"
                return None
        return None


class HostsHook(RequestHook):
    def __init__(self, hosts: Mapping[str, str], ttl: int = 60) -> None:
        self._ttl = ttl
        self._records_v4: dict[str, list[str]] = {}
        self._records_v6: dict[str, list[str]] = {}

        for domain, ip in hosts.items():
            normalized = _normalize_domain(domain)
            if not normalized:
                continue
            parsed = ip_address(ip)
            if parsed.version == 4:
                self._records_v4.setdefault(normalized, []).append(str(parsed))
            else:
                self._records_v6.setdefault(normalized, []).append(str(parsed))

    async def before_upstream(
        self,
        context: QueryContext,
        query: dns.message.Message,
    ) -> dns.message.Message | None:
        if not query.question:
            return None

        question = query.question[0]
        qname = _normalize_domain(question.name.to_text())
        if qname not in self._records_v4 and qname not in self._records_v6:
            return None

        response = dns.message.make_response(query)
        response.set_rcode(dns.rcode.NOERROR)

        if question.rdtype in (dns.rdatatype.A, dns.rdatatype.ANY):
            self._append_rrset(
                response=response,
                owner=question.name.to_text(),
                ttl=self._ttl,
                rdtype=dns.rdatatype.A,
                values=self._records_v4.get(qname, []),
            )
        if question.rdtype in (dns.rdatatype.AAAA, dns.rdatatype.ANY):
            self._append_rrset(
                response=response,
                owner=question.name.to_text(),
                ttl=self._ttl,
                rdtype=dns.rdatatype.AAAA,
                values=self._records_v6.get(qname, []),
            )

        context.tags["request_rule"] = "hosts"
        return response

    @staticmethod
    def _append_rrset(
        response: dns.message.Message,
        owner: str,
        ttl: int,
        rdtype: dns.rdatatype.RdataType,
        values: list[str],
    ) -> None:
        if not values:
            return
        rrset = dns.rrset.from_text(
            owner,
            ttl,
            dns.rdataclass.IN,
            rdtype,
            *values,
        )
        response.answer.append(rrset)


def build_request_hooks(
    blocked_domains: Iterable[str] | None = None,
    hosts: Mapping[str, str] | None = None,
    domainset: DomainSet | None = None,
    ipset: IPSet | None = None,
    ad_block_tags: Iterable[str] | None = None,
    enable_debug: bool = True,
) -> tuple[RequestHook, ...]:
    hooks: list[RequestHook] = []
    blocked = tuple(blocked_domains or ())
    hosts_map = dict(hosts or {})
    blocked_tags = tuple(ad_block_tags or ())

    if enable_debug:
        hooks.append(RequestDebugHook())
    hooks.append(RequestSanityDropHook())
    if domainset is not None:
        hooks.append(DomainSetRouteHook(domainset=domainset))
    if ipset is not None:
        hooks.append(ClientIPSetRouteHook(ipset=ipset))
    if blocked_tags:
        hooks.append(TagEmptyResponseHook(blocked_tags=blocked_tags))
    if blocked:
        hooks.append(DomainBlockHook(blocked_domains=blocked))
    if hosts_map:
        hooks.append(HostsHook(hosts=hosts_map))
    return tuple(hooks)


def build_default_request_hooks() -> tuple[RequestHook, ...]:
    return build_request_hooks(
        blocked_domains=DEFAULT_BLOCKED_DOMAINS,
        hosts=DEFAULT_HOSTS,
        ad_block_tags=DEFAULT_AD_BLOCK_TAGS,
    )


__all__ = [
    "ClientIPSetRouteHook",
    "DomainBlockHook",
    "DomainSetRouteHook",
    "HostsHook",
    "RequestSanityDropHook",
    "RequestDebugHook",
    "TagEmptyResponseHook",
    "build_request_hooks",
    "build_default_request_hooks",
]
