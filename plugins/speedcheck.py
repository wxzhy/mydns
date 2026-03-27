"""测速相关插件。"""

from __future__ import annotations

import asyncio
import time
from collections.abc import Awaitable, Callable
from typing import Any

import dns.rcode
import dns.name
import dns.rdata
import dns.rdataclass
import dns.rdatatype
import dns.rrset
from pydantic import PositiveFloat, PositiveInt, model_validator

from core.answer import Answer
from core.context import QueryContext
from core.hooks import ResolverHook, ResponseHook
from core.models import ResolverResult
from logger import get_logger
from plugins._config import (
    PluginConfigModel,
)
from plugins.utils.dns_helpers import build_ip_rrset
from plugins.utils.speedcheck import configure, probe_ips
from upstream.selector import select_best_answer


logger = get_logger("plugins.speedcheck")
ProbeIPsFunc = Callable[[list[str], float], Awaitable[dict[str, float | None]]]


class SpeedCheckResolverHookConfigModel(PluginConfigModel):
    timeout_s: PositiveFloat = 0.8
    max_size: PositiveInt | None = None
    ttl_s: PositiveFloat | None = None
    probe_func: ProbeIPsFunc | None = None


class RewriteAnswerByRTTHookConfigModel(PluginConfigModel):
    max_return_ips: PositiveInt = 2
    ttl_s: PositiveInt = 900

    @model_validator(mode="after")
    def _clamp_ttl_s(self) -> "RewriteAnswerByRTTHookConfigModel":
        self.ttl_s = max(600, min(900, self.ttl_s))
        return self


class SpeedCheckResolverHook(ResolverHook):
    """对 A/AAAA 候选 IP 执行测速，并写入上下文状态。"""

    def __init__(
        self,
        *,
        timeout_s: float = 0.8,
        max_size: int | None = None,
        ttl_s: float | None = None,
        probe_func: ProbeIPsFunc | None = None,
    ) -> None:
        raw_config: dict[str, Any] = {
            "timeout_s": timeout_s,
            "max_size": max_size,
            "ttl_s": ttl_s,
            "probe_func": probe_func,
        }
        config = SpeedCheckResolverHookConfigModel.model_validate(raw_config)
        configure(max_size=config.max_size, ttl_s=config.ttl_s)
        self.timeout_s = config.timeout_s
        self.probe_func = config.probe_func or probe_ips

    async def on_resolver_result(
        self,
        ctx: QueryContext,
        result: ResolverResult,
    ) -> ResolverResult | None:
        qname_text = ctx.query.qname.to_text()
        answer = result.answer
        if _should_skip_speedcheck(result):
            _log_skip_speedcheck(ctx, result, reason="answer_or_error")
            return result

        assert answer is not None
        if "ads" in answer.tags:
            logger.debug(
                "测速跳过 resolver=%s qname=%s reason=ads_tagged tags=%s",
                result.resolver_name,
                qname_text,
                sorted(answer.tags),
            )
            return result

        # 只测速最终可返回的 A/AAAA rrset，不扫描整个 response.answer。
        ips, pending = _extract_ips_and_pending(
            answer,
            existing_results=ctx.ip_list.results,
            known_ips=ctx.ip_list.ips,
        )
        if not ips:
            _log_skip_speedcheck(ctx, result, reason="no_ip_rrset")
            return result

        # 单个请求范围内做去重缓存，避免多个 resolver 对同一 IP 重复测速。
        logger.debug(
            "测速准备 resolver=%s qname=%s qtype=%s ips=%s pending=%s cached=%s",
            result.resolver_name,
            qname_text,
            ctx.query.qtype,
            ips,
            pending,
            ctx.ip_list.results,
        )
        tested = await self._probe_pending_ips(ctx, result, pending)
        for ip, rtt in tested.items():
            ctx.ip_list.results[ip] = rtt

        logger.debug(
            "测速完成 resolver=%s qname=%s qtype=%s ips=%s pending=%s rtt=%s cache=%s",
            result.resolver_name,
            qname_text,
            ctx.query.qtype,
            ips,
            pending,
            tested,
            ctx.ip_list.results,
        )
        return result

    async def _probe_pending_ips(
        self,
        ctx: QueryContext,
        result: ResolverResult,
        pending: list[str],
    ) -> dict[str, float | None]:
        if not pending:
            return {}

        try:
            return await asyncio.wait_for(
                self.probe_func(pending, self.timeout_s),
                timeout=self.timeout_s,
            )
        except TimeoutError:
            logger.debug(
                "测速超时 resolver=%s qname=%s qtype=%s pending=%s timeout=%.3fs",
                result.resolver_name,
                ctx.query.qname.to_text(),
                ctx.query.qtype,
                pending,
                self.timeout_s,
            )
        except Exception as exc:
            logger.debug(
                "测速异常 resolver=%s qname=%s qtype=%s pending=%s err=%r",
                result.resolver_name,
                ctx.query.qname.to_text(),
                ctx.query.qtype,
                pending,
                exc,
            )
        return {ip: None for ip in pending}


class RewriteAnswerByRTTHook(ResponseHook):
    """在响应阶段构造基础答案，并按 RTT 回填 A/AAAA RRSet。"""

    def __init__(
        self,
        max_return_ips: int = 2,
        ttl_s: int = 900,
    ) -> None:
        config = RewriteAnswerByRTTHookConfigModel.model_validate(
            {
                "max_return_ips": max_return_ips,
                "ttl_s": ttl_s,
            }
        )
        self.max_return_ips = config.max_return_ips
        self.ttl_s = config.ttl_s

    async def on_response(self, ctx: QueryContext) -> None:
        qname_text = ctx.query.qname.to_text()
        if ctx.final_answer is None:
            logger.debug(
                "响应基础构造 qname=%s qtype=%s candidates=%s",
                qname_text,
                ctx.query.qtype,
                len(ctx.candidates),
            )
            ctx.final_answer = select_best_answer(ctx)

        answer = ctx.final_answer
        if answer is None:
            _log_skip_rewrite(ctx, reason="no_final_answer")
            return
        assert isinstance(answer, Answer)
        if answer.response.rcode() != dns.rcode.NOERROR:
            _log_skip_rewrite(
                ctx,
                reason="rcode_not_noerror",
                extra=f"rcode={answer.response.rcode()}",
            )
            return
        if ctx.query.qtype not in {dns.rdatatype.A, dns.rdatatype.AAAA}:
            _log_skip_rewrite(ctx, reason="unsupported_qtype")
            return

        ip_rtt = {ip: rtt for ip, rtt in ctx.ip_list.results.items() if rtt is not None}
        if not ip_rtt:
            _log_skip_rewrite(ctx, reason="no_rtt_data")
            return

        ranked_ips = [ip for ip, _ in sorted(ip_rtt.items(), key=lambda item: item[1])]
        if not ranked_ips:
            return

        chain = answer.chaining_result
        owner_name = answer.chaining_result.canonical_name or answer.qname
        limit = min(self.max_return_ips, len(ranked_ips))
        selected_ips = ranked_ips[:limit]
        if not selected_ips:
            return

        # `Answer` 中的 CNAME 链与最终地址 rrset 分开存储，这里只替换地址部分。
        rewritten = build_ip_rrset(
            owner_name=owner_name,
            rdclass=answer.rdclass,
            qtype=answer.rdtype,
            ips=selected_ips,
            ttl_s=self.ttl_s,
        )
        answer.replace_rrset(
            rewritten,
            preserve_expiration=time.time() + self.ttl_s,
        )
        cname_count = len(chain.cnames)

        logger.debug(
            "响应IP改写 qname=%s qtype=%s cname_count=%s new_ips=%s ttl=%s rtt=%s",
            qname_text,
            ctx.query.qtype,
            cname_count,
            selected_ips,
            rewritten.ttl,
            ip_rtt,
        )


def normalize_speedcheck_resolver_hook_kwargs(raw_kwargs: Any) -> dict[str, Any]:
    config = SpeedCheckResolverHookConfigModel.model_validate(
        {} if raw_kwargs is None else raw_kwargs
    )
    return config.model_dump(mode="python", exclude_none=True)


def normalize_rewrite_answer_by_rtt_hook_kwargs(raw_kwargs: Any) -> dict[str, Any]:
    config = RewriteAnswerByRTTHookConfigModel.model_validate(
        {} if raw_kwargs is None else raw_kwargs
    )
    return config.model_dump(mode="python", exclude_none=True)


def _should_skip_speedcheck(result: ResolverResult) -> bool:
    return result.answer is None or result.error is not None


def _log_skip_speedcheck(
    ctx: QueryContext,
    result: ResolverResult,
    *,
    reason: str,
) -> None:
    logger.debug(
        "测速跳过 resolver=%s qname=%s qtype=%s reason=%s answer=%s error=%s",
        result.resolver_name,
        ctx.query.qname.to_text(),
        ctx.query.qtype,
        reason,
        result.answer is not None,
        repr(result.error) if result.error else None,
    )


def _log_skip_rewrite(
    ctx: QueryContext,
    *,
    reason: str,
    extra: str | None = None,
) -> None:
    message = "响应改写跳过 qname=%s qtype=%s reason=%s"
    args: list[object] = [ctx.query.qname.to_text(), ctx.query.qtype, reason]
    if extra is not None:
        message += " " + extra
    logger.debug(message, *args)


def _extract_ips_and_pending(
    answer: Answer,
    *,
    existing_results: dict[str, float | None],
    known_ips: set[str],
) -> tuple[list[str], list[str]]:
    """从 Answer.rrset 提取去重 IP，并同步返回尚未测速的地址列表。"""
    rrset = answer.rrset
    if rrset is None or rrset.rdtype not in {dns.rdatatype.A, dns.rdatatype.AAAA}:
        return ([], [])

    ips: list[str] = []
    pending: list[str] = []
    seen: set[str] = set()
    for rdata in rrset:
        ip_text = rdata.to_text()
        if ip_text in seen:
            continue
        seen.add(ip_text)
        ips.append(ip_text)
        known_ips.add(ip_text)
        if ip_text not in existing_results:
            pending.append(ip_text)
    return (ips, pending)
