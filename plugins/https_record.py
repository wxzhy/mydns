"""HTTPS 记录清洗与 ECH 注入。"""

from __future__ import annotations

import asyncio
from collections.abc import Iterable
from typing import TYPE_CHECKING, Any

import dns.name
import dns.opcode
import dns.rcode
import dns.rdataclass
import dns.rdatatype
import dns.rrset
from async_lru import alru_cache
from dns.rdtypes import svcbbase
from pydantic import field_validator

from core.answer import Answer
from core.context import QueryContext
from core.hooks import ResponseHook
from core.ipset import ipset
from core.models import Query
from logger import get_logger
from plugins._config import PluginConfigModel, normalize_string_tuple

if TYPE_CHECKING:
    from core.pipeline import Pipeline


logger = get_logger("plugins.https_record")

_ECH_SOURCE_DOMAIN = dns.name.from_text("cloudflare-ech.com.")
_ECH_CACHE_TTL_S = 300
_ECH_CACHE_MAX_SIZE = 16


class HttpsRecordResponseHookConfigModel(PluginConfigModel):
    skip_result_tags: tuple[str, ...] = ()
    cloudflare_tags: tuple[str, ...] = ("cloudflare",)

    @field_validator("skip_result_tags", mode="before")
    @classmethod
    def _normalize_skip_result_tags(cls, value: Any) -> tuple[str, ...]:
        return normalize_string_tuple(
            value,
            key="plugins.https_record.HttpsRecordResponseHook.skip_result_tags",
            allow_none=True,
        )

    @field_validator("cloudflare_tags", mode="before")
    @classmethod
    def _normalize_cloudflare_tags(cls, value: Any) -> tuple[str, ...]:
        return normalize_string_tuple(
            value,
            key="plugins.https_record.HttpsRecordResponseHook.cloudflare_tags",
            allow_none=True,
        )


class HttpsRecordResponseHook(ResponseHook):
    """清洗 HTTPS 记录中的 h3/hint，并按需补充 Cloudflare ECH。"""

    def __init__(
        self,
        *,
        skip_result_tags: Iterable[str] | None = None,
        cloudflare_tags: Iterable[str] | None = None,
    ) -> None:
        raw_config: dict[str, Any] = {}
        if skip_result_tags is not None:
            raw_config["skip_result_tags"] = skip_result_tags
        if cloudflare_tags is not None:
            raw_config["cloudflare_tags"] = cloudflare_tags
        config = HttpsRecordResponseHookConfigModel.model_validate(raw_config)
        self.skip_result_tags = set(config.skip_result_tags)
        self.cloudflare_tags = set(config.cloudflare_tags)

    async def on_response(self, ctx: QueryContext) -> None:
        answer = ctx.final_answer
        reason = _skip_reason(ctx, answer, skip_result_tags=self.skip_result_tags)
        if reason is not None:
            _log_skip(ctx, reason=reason, answer=answer)
            return

        assert answer is not None
        pipeline = ctx.state.get("pipeline")
        if not _is_pipeline_like(pipeline):
            _log_skip(ctx, reason="missing_pipeline", answer=answer)
            return

        rrset = answer.rrset
        assert rrset is not None

        rewritten_rrset, changed = await self._rewrite_rrset(
            pipeline,
            answer,
            rrset,
        )
        if not changed:
            return

        answer.replace_rrset(
            rewritten_rrset,
            preserve_expiration=answer.expiration,
        )
        logger.debug(
            "HTTPS记录已改写 qname=%s owner=%s tags=%s rr_count=%s",
            ctx.query.qname.to_text(),
            rrset.name.to_text(),
            sorted(answer.tags),
            len(rewritten_rrset),
        )

    async def _rewrite_rrset(
        self,
        pipeline: Pipeline,
        answer: Answer,
        rrset: dns.rrset.RRset,
    ) -> tuple[dns.rrset.RRset, bool]:
        rewritten_rrset = dns.rrset.RRset(rrset.name, rrset.rdclass, rrset.rdtype)
        rewritten_rrset.ttl = rrset.ttl

        changed = False
        for rdata in rrset:
            rewritten = await self._rewrite_rdata(
                pipeline,
                answer,
                rrset.name,
                rdata,
            )
            rewritten_rrset.add(rewritten, rrset.ttl)
            if rewritten.to_text() != rdata.to_text():
                changed = True
        return rewritten_rrset, changed

    async def _rewrite_rdata(
        self,
        pipeline: Pipeline,
        answer: Answer,
        owner_name: dns.name.Name,
        rdata: Any,
    ) -> Any:
        original_params = dict(rdata.params)
        rewritten_params = dict(original_params)

        original_ipv4hints = _hint_addresses(
            original_params.get(svcbbase.ParamKey.IPV4HINT)
        )
        original_ipv6hints = _hint_addresses(
            original_params.get(svcbbase.ParamKey.IPV6HINT)
        )

        changed = _remove_h3_from_alpn(rewritten_params)
        changed = _remove_both_hints(rewritten_params) or changed

        if svcbbase.ParamKey.ECH not in rewritten_params:
            should_inject = await self._should_inject_ech(
                pipeline,
                answer,
                owner_name,
                original_ipv4hints,
                original_ipv6hints,
            )
            if should_inject:
                ech_value = await _fetch_cached_ech_value(
                    pipeline,
                    _ECH_SOURCE_DOMAIN.to_text(),
                )
                if ech_value is not None:
                    rewritten_params[svcbbase.ParamKey.ECH] = svcbbase.ECHParam(
                        ech_value
                    )
                    changed = True

        if not changed:
            return rdata

        _sync_mandatory_param(rewritten_params)
        return type(rdata)(
            rdata.rdclass,
            rdata.rdtype,
            rdata.priority,
            rdata.target,
            rewritten_params,
        )

    async def _should_inject_ech(
        self,
        pipeline: Pipeline,
        answer: Answer,
        owner_name: dns.name.Name,
        ipv4hints: list[str],
        ipv6hints: list[str],
    ) -> bool:
        if not self.cloudflare_tags:
            return False
        if answer.tags & self.cloudflare_tags:
            return True
        if _ips_match_tags([*ipv4hints, *ipv6hints], self.cloudflare_tags):
            return True
        return await _subqueries_indicate_cloudflare(
            pipeline,
            owner_name,
            self.cloudflare_tags,
        )


def normalize_https_record_hook_kwargs(raw_kwargs: Any) -> dict[str, Any]:
    config = HttpsRecordResponseHookConfigModel.model_validate(
        {} if raw_kwargs is None else raw_kwargs
    )
    return config.model_dump(mode="python", exclude_none=True)


def _skip_reason(
    ctx: QueryContext,
    answer: Answer | None,
    *,
    skip_result_tags: set[str],
) -> str | None:
    if answer is None:
        return "no_final_answer"
    if ctx.query.qtype != dns.rdatatype.HTTPS:
        return "unsupported_qtype"

    response = answer.response
    if response.rcode() != dns.rcode.NOERROR:
        return "rcode_not_noerror"
    if response.opcode() != dns.opcode.QUERY:
        return "invalid_opcode"
    if not response.question:
        return "missing_question"
    if response.question[0].rdclass != dns.rdataclass.IN:
        return "invalid_qclass"
    if answer.tags & skip_result_tags:
        return "skip_result_tags"
    if _is_ech_source_answer(answer):
        return "ech_source_domain"

    rrset = answer.rrset
    if rrset is None or rrset.rdtype != dns.rdatatype.HTTPS:
        return "no_https_rrset"
    return None


def _is_pipeline_like(value: object) -> bool:
    return value is not None and callable(getattr(value, "resolve", None))


def _log_skip(
    ctx: QueryContext,
    *,
    reason: str,
    answer: Answer | None,
) -> None:
    logger.debug(
        "HTTPS记录处理跳过 qname=%s qtype=%s reason=%s tags=%s",
        ctx.query.qname.to_text(),
        ctx.query.qtype,
        reason,
        sorted(answer.tags) if answer is not None else [],
    )


def _remove_h3_from_alpn(params: dict[svcbbase.ParamKey, Any]) -> bool:
    """移除 ALPN 中的 h3；如果 ALPN 清空，连同 no-default-alpn 一并移除。"""
    alpn = params.get(svcbbase.ParamKey.ALPN)
    if not isinstance(alpn, svcbbase.ALPNParam):
        return False

    kept_ids = [item for item in alpn.ids if item != b"h3"]
    if len(kept_ids) == len(alpn.ids):
        return False

    if kept_ids:
        params[svcbbase.ParamKey.ALPN] = svcbbase.ALPNParam(kept_ids)
    else:
        params.pop(svcbbase.ParamKey.ALPN, None)
        params.pop(svcbbase.ParamKey.NO_DEFAULT_ALPN, None)
    return True


def _remove_both_hints(params: dict[svcbbase.ParamKey, Any]) -> bool:
    """只有同时出现 ipv4hint/ipv6hint 时，才一起删除。"""
    has_ipv4hint = svcbbase.ParamKey.IPV4HINT in params
    has_ipv6hint = svcbbase.ParamKey.IPV6HINT in params
    if not (has_ipv4hint and has_ipv6hint):
        return False
    params.pop(svcbbase.ParamKey.IPV4HINT, None)
    params.pop(svcbbase.ParamKey.IPV6HINT, None)
    return True


def _sync_mandatory_param(params: dict[svcbbase.ParamKey, Any]) -> None:
    """参数删改后同步 mandatory，避免引用已不存在的 key。"""
    mandatory = params.get(svcbbase.ParamKey.MANDATORY)
    if not isinstance(mandatory, svcbbase.MandatoryParam):
        return

    keys = [
        key
        for key in mandatory.keys
        if key != svcbbase.ParamKey.MANDATORY and key in params
    ]
    if keys:
        params[svcbbase.ParamKey.MANDATORY] = svcbbase.MandatoryParam(keys)
    else:
        params.pop(svcbbase.ParamKey.MANDATORY, None)


def _hint_addresses(param: Any) -> list[str]:
    if isinstance(param, svcbbase.IPv4HintParam):
        return list(param.addresses)
    if isinstance(param, svcbbase.IPv6HintParam):
        return list(param.addresses)
    return []


def _ips_match_tags(ips: Iterable[str], tags: set[str]) -> bool:
    for ip in ips:
        if ipset.match_tags(ip) & tags:
            return True
    return False


async def _subqueries_indicate_cloudflare(
    pipeline: Pipeline,
    owner_name: dns.name.Name,
    cloudflare_tags: set[str],
) -> bool:
    queries = [
        Query(client_addr=None, qname=owner_name, qtype=qtype)
        for qtype in (dns.rdatatype.A, dns.rdatatype.AAAA)
    ]
    results = await asyncio.gather(
        *(pipeline.resolve(query) for query in queries),
        return_exceptions=True,
    )
    for result in results:
        if isinstance(result, Exception):
            continue
        if _answer_indicates_cloudflare(result, cloudflare_tags):
            return True
    return False


def _answer_indicates_cloudflare(answer: Answer, cloudflare_tags: set[str]) -> bool:
    if answer.tags & cloudflare_tags:
        return True
    rrset = answer.rrset
    if rrset is None or rrset.rdtype not in {dns.rdatatype.A, dns.rdatatype.AAAA}:
        return False
    return _ips_match_tags((rdata.to_text() for rdata in rrset), cloudflare_tags)


@alru_cache(maxsize=_ECH_CACHE_MAX_SIZE, ttl=_ECH_CACHE_TTL_S)
async def _fetch_cached_ech_value(
    pipeline: Pipeline,
    source_domain_text: str,
) -> bytes | None:
    query = Query(
        client_addr=None,
        qname=dns.name.from_text(source_domain_text),
        qtype=dns.rdatatype.HTTPS,
    )
    try:
        answer = await pipeline.resolve(query)
    except Exception as exc:
        logger.debug(
            "ECH来源查询失败 domain=%s err=%r",
            source_domain_text,
            exc,
        )
        return None
    return _extract_first_ech_value(answer)


def _extract_first_ech_value(answer: Answer) -> bytes | None:
    rrset = answer.rrset
    if (
        answer.response.rcode() != dns.rcode.NOERROR
        or rrset is None
        or rrset.rdtype != dns.rdatatype.HTTPS
    ):
        return None
    for rdata in rrset:
        ech = rdata.params.get(svcbbase.ParamKey.ECH)
        if isinstance(ech, svcbbase.ECHParam):
            return bytes(ech.ech)
    return None


def _is_ech_source_answer(answer: Answer) -> bool:
    names = [answer.qname]
    rrset = answer.rrset
    if rrset is not None:
        names.append(rrset.name)
    canonical_name = getattr(answer, "canonical_name", None)
    if canonical_name is not None:
        names.append(canonical_name)
    return any(name == _ECH_SOURCE_DOMAIN for name in names)
