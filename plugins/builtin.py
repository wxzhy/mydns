"""内置 Hook 插件。"""

from __future__ import annotations

from core.context import QueryContext
from core.hooks import RequestHook, ResolverHook, ResponseHook
from core.models import ResolverResult
from logger import get_logger

logger = get_logger("core.plugins.builtin")


class NoopRequestHook(RequestHook):
    """请求阶段空操作插件。"""

    async def on_request(self, ctx: QueryContext) -> None:
        # 这里保留对上下文的日志观察，便于调试 hook 链顺序。
        logger.debug("请求: %s", ctx.query)


class NoopResolverHook(ResolverHook):
    """上游结果阶段空操作插件。"""

    async def on_resolver_result(
        self,
        ctx: QueryContext,
        result: ResolverResult,
    ) -> ResolverResult | None:
        # resolver hook 必须返回原结果，避免打断默认链路。
        _ = ctx
        logger.debug("上游结果: %s", result)
        return result


class NoopResponseHook(ResponseHook):
    """响应阶段空操作插件。"""

    async def on_response(self, ctx: QueryContext) -> None:
        # 响应阶段只观察最终答案，不参与修改。
        _ = ctx
        logger.debug("响应: %s", ctx.final_answer)
