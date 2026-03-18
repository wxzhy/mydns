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


class DomainSetRouteHook(RequestHook):
    """按域名集合匹配请求路由标签（最长后缀优先）。"""

    def __init__(self, domainset: DomainSet) -> None:
        self._domainset = domainset

    async def before_upstream(self, context: QueryContext) -> None:
        qname = context.query_name or ""
        if not qname:
            return

        matched_tag = self._domainset.match_best(qname)
        if matched_tag is None:
            return

        context.tag = matched_tag
        context.tags["route_tag"] = matched_tag
        context.tags["route_tag_source"] = "domainset"


class ClientIPSetRouteHook(RequestHook):
    """按客户端来源 IP 匹配路由标签（最长前缀优先）。"""

    def __init__(self, ipset: IPSet) -> None:
        self._ipset = ipset

    async def before_upstream(self, context: QueryContext) -> None:
        # 已被 domainset 等规则设置过标签时，不再由 ipset 覆盖。
        if _normalize_tag_key(context.tag) != "default":
            return

        matched_tag = self._ipset.match_best(context.client_host)
        if matched_tag is None:
            return

        context.tag = matched_tag
        context.tags["route_tag"] = matched_tag
        context.tags["route_tag_source"] = "ipset"


class TagEmptyResponseHook(RequestHook):
    """命中指定 tag 时，直接返回 NOERROR 空应答。"""

    def __init__(self, blocked_tags: Iterable[str]) -> None:
        self._blocked_tags = {
            normalized
            for item in blocked_tags
            if (normalized := _normalize_tag_key(str(item)))
        }

    async def before_upstream(self, context: QueryContext) -> None:
        if _normalize_tag_key(context.tag) not in self._blocked_tags:
            return
        context.tags["request_rule"] = "ad-block-tag-empty"
        context.tags["ad_block_tag"] = context.tag
        context.set_answer(dns.rcode.NOERROR, [])


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

    async def before_upstream(self, context: QueryContext) -> None:
        qname = _normalize_domain(context.query_name or "")
        if not qname:
            return

        if qname in self._exact or any(
            qname.endswith(suffix) for suffix in self._suffixes
        ):
            context.tags["request_rule"] = "blocked-domain"
            context.set_answer(self._rcode, [])


class RequestDebugHook(RequestHook):
    """请求阶段调试日志。"""

    async def before_upstream(self, context: QueryContext) -> None:
        logger.debug(
            "收到请求 client=%s:%s txid=%s qtype=%s domain=%s ecs=%s",
            context.client_host,
            context.client_port,
            context.txid if context.txid is not None else "-",
            context.query_type or "-",
            context.query_name or "-",
            context.ecs or "-",
        )


class RequestSanityDropHook(RequestHook):
    """
    请求基础合法性校验：
    - 仅允许标准 QUERY opcode
    - 仅允许 IN qclass

    不满足时直接标记丢弃（不回包）。
    """

    async def before_upstream(self, context: QueryContext) -> None:
        raw = context.raw_query
        if raw is None:
            return
        if raw.opcode() != dns.opcode.QUERY:
            context.tags["drop_request"] = True
            context.tags["drop_reason"] = "unsupported-opcode"
            return

        for question in raw.question:
            if question.rdclass != dns.rdataclass.IN:
                context.tags["drop_request"] = True
                context.tags["drop_reason"] = "unsupported-qclass"
                return


class IpBenchmarkTopNHook(RequestHook):
    """为后续上游聚合阶段注入 A/AAAA 选取 IP 数量。"""

    def __init__(self, top_n: int = 3) -> None:
        self._top_n = max(1, int(top_n))

    async def before_upstream(self, context: QueryContext) -> None:
        # 允许前置自定义 Hook 通过 context.tags 显式覆盖。
        context.tags.setdefault("ip_benchmark_top_n", self._top_n)


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

    async def before_upstream(self, context: QueryContext) -> None:
        raw = context.raw_query
        if not raw or not raw.question:
            return

        question = raw.question[0]
        qname = _normalize_domain(question.name.to_text())
        if qname not in self._records_v4 and qname not in self._records_v6:
            return

        answer: list[dns.rrset.RRset] = []
        if question.rdtype in (dns.rdatatype.A, dns.rdatatype.ANY):
            rrset = _make_rrset(
                owner=question.name.to_text(),
                ttl=self._ttl,
                rdtype=dns.rdatatype.A,
                values=self._records_v4.get(qname, []),
            )
            if rrset is not None:
                answer.append(rrset)
        if question.rdtype in (dns.rdatatype.AAAA, dns.rdatatype.ANY):
            rrset = _make_rrset(
                owner=question.name.to_text(),
                ttl=self._ttl,
                rdtype=dns.rdatatype.AAAA,
                values=self._records_v6.get(qname, []),
            )
            if rrset is not None:
                answer.append(rrset)

        context.tags["request_rule"] = "hosts"
        context.set_answer(dns.rcode.NOERROR, answer)


def _make_rrset(
    owner: str,
    ttl: int,
    rdtype: dns.rdatatype.RdataType,
    values: list[str],
) -> dns.rrset.RRset | None:
    if not values:
        return None
    return dns.rrset.from_text(owner, ttl, dns.rdataclass.IN, rdtype, *values)


def build_request_hooks(
    blocked_domains: Iterable[str] | None = None,
    hosts: Mapping[str, str] | None = None,
    domainset: DomainSet | None = None,
    ipset: IPSet | None = None,
    ad_block_tags: Iterable[str] | None = None,
    ip_benchmark_top_n: int = 3,
    enable_debug: bool = True,
) -> tuple[RequestHook, ...]:
    hooks: list[RequestHook] = []
    blocked = tuple(blocked_domains or ())
    hosts_map = dict(hosts or {})
    blocked_tags = tuple(ad_block_tags or ())

    if enable_debug:
        hooks.append(RequestDebugHook())
    hooks.append(RequestSanityDropHook())
    hooks.append(IpBenchmarkTopNHook(top_n=ip_benchmark_top_n))
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
    "IpBenchmarkTopNHook",
    "RequestSanityDropHook",
    "RequestDebugHook",
    "TagEmptyResponseHook",
    "build_request_hooks",
    "build_default_request_hooks",
]
