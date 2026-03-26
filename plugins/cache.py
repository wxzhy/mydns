"""缓存插件。"""

from __future__ import annotations

from collections.abc import Iterable
from typing import Annotated, Any

import dns.rcode
from pydantic import BeforeValidator, PositiveInt, conset

from core.answer import Answer
from core.cache import AnswerLRUCache, build_cache_key
from core.context import QueryContext
from core.hooks import RequestHook, ResponseHook
from logger import get_logger
from plugins._config import (
    NonEmptyStr,
    PluginConfigModel,
)


logger = get_logger("plugins.cache")
_CACHE_REGISTRY: dict[str, AnswerLRUCache] = {}


def _coerce_cacheable_rcodes(value: Any) -> Any:
    if value is None:
        return (dns.rcode.NOERROR,)
    if isinstance(value, Iterable) and not isinstance(value, (str, bytes, bytearray)):
        return list(value)
    return value


CacheableRcodes = Annotated[
    conset(dns.rcode.Rcode),
    BeforeValidator(_coerce_cacheable_rcodes),
]


class CacheHookConfigModel(PluginConfigModel):
    cache: AnswerLRUCache | None = None
    cache_name: NonEmptyStr = "default"
    max_size: PositiveInt = 100000
    cacheable_rcodes: CacheableRcodes = {dns.rcode.NOERROR}


def get_shared_cache(
    *,
    cache_name: str = "default",
    max_size: int = 100000,
) -> AnswerLRUCache:
    cache = _CACHE_REGISTRY.get(cache_name)
    if cache is None:
        cache = AnswerLRUCache(max_size=max_size)
        _CACHE_REGISTRY[cache_name] = cache
    return cache


class CacheHook(RequestHook, ResponseHook):
    """请求阶段读缓存、响应阶段写缓存。"""

    def __init__(
        self,
        *,
        cache: AnswerLRUCache | None = None,
        cache_name: str = "default",
        max_size: int = 100000,
        cacheable_rcodes: Iterable[dns.rcode.Rcode] | None = None,
    ) -> None:
        raw_config: dict[str, Any] = {
            "cache": cache,
            "cache_name": cache_name,
            "max_size": max_size,
        }
        if cacheable_rcodes is not None:
            raw_config["cacheable_rcodes"] = cacheable_rcodes
        config = CacheHookConfigModel.model_validate(raw_config)
        self.cache = config.cache or get_shared_cache(
            cache_name=config.cache_name,
            max_size=config.max_size,
        )
        self.cacheable_rcodes = set(config.cacheable_rcodes)

    async def on_request(self, ctx: QueryContext) -> None:
        key = build_cache_key(ctx.query)
        ctx.state["cache_key"] = key
        answer = self.cache.get(key)
        if answer is None:
            await self._handle_cache_miss(ctx, key)
            return

        # 命中后直接复用缓存答案，不再进入后续转发。
        ctx.state["cache_hit"] = True
        ctx.final_answer = answer
        ctx.stop = True
        logger.debug(
            "缓存命中 qname=%s qtype=%s",
            ctx.query.qname.to_text(),
            ctx.query.qtype,
        )

    async def _handle_cache_miss(self, ctx: QueryContext, key: str) -> None:
        ctx.state["cache_hit"] = False
        pending, future = await self.cache.acquire_pending(key)
        ctx.state["cache_pending_request"] = pending
        if pending.owner:
            # owner 请求继续向后执行，由响应阶段负责写回缓存。
            return

        # 非 owner 请求等待共享结果，避免并发击穿同一个上游查询。
        waited = await future
        ctx.state["cache_wait"] = True
        ctx.final_answer = Answer.from_answer(waited)
        ctx.stop = True
        logger.debug(
            "等待同 key 请求完成 qname=%s qtype=%s",
            ctx.query.qname.to_text(),
            ctx.query.qtype,
        )

    async def on_response(self, ctx: QueryContext) -> None:
        if ctx.state.get("cache_hit") or ctx.state.get("cache_wait"):
            return
        answer = ctx.final_answer
        if answer is None:
            return
        rcode = answer.response.rcode()
        if rcode not in self.cacheable_rcodes:
            return

        key = ctx.state.get("cache_key")
        if key is None:
            key = build_cache_key(ctx.query)
        self.cache.put(key, answer)
        logger.debug(
            "缓存写入 qname=%s qtype=%s rcode=%s",
            ctx.query.qname.to_text(),
            ctx.query.qtype,
            rcode,
        )


def normalize_cache_hook_kwargs(raw_kwargs: Any) -> dict[str, Any]:
    config = CacheHookConfigModel.model_validate({} if raw_kwargs is None else raw_kwargs)
    return config.model_dump(mode="python", exclude_none=True)
