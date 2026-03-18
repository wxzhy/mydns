"""扩展点接口定义。"""

from __future__ import annotations

from abc import ABC, abstractmethod

from core.context import QueryContext
from core.models import ResolverResult


class RequestHook(ABC):
    """请求阶段钩子，在流水线开头执行。"""

    @abstractmethod
    async def on_request(self, ctx: QueryContext) -> None:
        """处理请求。"""


class ResolverHook(ABC):
    """上游结果钩子，在每个解析器返回后执行。"""

    @abstractmethod
    async def on_resolver_result(
        self,
        ctx: QueryContext,
        result: ResolverResult,
    ) -> ResolverResult | None:
        """返回新的结果对象，或返回 None 丢弃该结果。"""


class ResponseHook(ABC):
    """响应阶段钩子，在流水线结束前执行。"""

    @abstractmethod
    async def on_response(self, ctx: QueryContext) -> None:
        """处理最终响应。"""
