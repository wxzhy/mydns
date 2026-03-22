"""domainset/ipset 命中后打 tag 的请求插件。"""

from __future__ import annotations

from core.context import QueryContext
from core.domainset import domainset
from core.hooks import RequestHook
from core.ipset import ipset
from logger import get_logger


logger = get_logger("plugins.tagset")


class TagSetRequestHook(RequestHook):
    """请求阶段为查询增加标签。"""

    def __init__(self) -> None:
        # 兼容已有测试：暴露 tag key 视图。
        self.domainset_by_tag: dict[str, list[str]] = {
            tag: [] for tag in domainset.tags
        }

    async def on_request(self, ctx: QueryContext) -> None:
        qname_text = ctx.query.qname.to_text().rstrip(".").lower()
        matched_tags = domainset.match_tags(qname_text)

        if not matched_tags:
            return

        ctx.tags.update(matched_tags)
        logger.debug(
            "标签命中 qname=%s client=%s add=%s tags=%s",
            qname_text,
            ctx.query.client_addr,
            sorted(matched_tags),
            sorted(ctx.tags),
        )
