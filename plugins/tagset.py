"""domainset/ipset 命中后打 tag 的请求插件。"""

from __future__ import annotations

import dns.rcode
import dns.rdatatype
import dns.rrset

from core.answer import Answer
from core.context import QueryContext
from core.domainset import domainset
from core.hooks import RequestHook
from core.ipset import ipset
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
