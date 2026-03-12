from __future__ import annotations

import asyncio
from dataclasses import dataclass

import dns.message
import dns.opcode
import dns.rdataclass
import dns.rdatatype
import dns.rrset

from core.context import QueryContext
from core.hooks import UpstreamHook
from logger import get_logger
from rules.upstream.benchmark.scorer import score_ip

logger = get_logger(__name__)

_BENCHMARK_STATE_TAG = "_a_aaaa_benchmark_state"
_SUPPORTED_TYPES = (dns.rdatatype.A, dns.rdatatype.AAAA)


@dataclass(slots=True, frozen=True)
class _IpCandidate:
    ip: str
    owner: str
    ttl: int
    source_response: dns.message.Message
    source_resolver: str


class _IpBenchmarkState:
    """单次请求内共享的 A/AAAA IP 测速状态。"""

    def __init__(
        self,
        context: QueryContext,
        query: dns.message.Message,
        rdtype: dns.rdatatype.RdataType,
        probe_timeout_ms: int,
        wait_timeout_ms: int,
        expected_upstreams: int,
    ) -> None:
        self._context = context
        self._query = query
        self._rdtype = rdtype
        self._probe_timeout_ms = probe_timeout_ms
        self._wait_timeout_ms = wait_timeout_ms
        self._expected_upstreams = max(1, expected_upstreams)
        self._submitted_upstreams = 0
        self._seen_ips: set[str] = set()
        self._probe_tasks: set[asyncio.Task[None]] = set()
        self._fallback_response: dns.message.Message | None = None
        self._timeout_task: asyncio.Task[None] | None = None
        self._lock = asyncio.Lock()
        self._result_future: asyncio.Future[dns.message.Message] = (
            asyncio.get_running_loop().create_future()
        )

    async def submit_response(
        self,
        response: dns.message.Message,
        resolver_name: str,
    ) -> None:
        new_candidates = _extract_ip_candidates(
            response=response,
            rdtype=self._rdtype,
            resolver_name=resolver_name,
        )

        async with self._lock:
            self._submitted_upstreams += 1
            if self._fallback_response is None:
                self._fallback_response = _clone_message(response)
            if self._timeout_task is None and not self._result_future.done():
                self._timeout_task = asyncio.create_task(self._resolve_after_timeout())

            accepted_candidates: list[_IpCandidate] = []
            for candidate in new_candidates:
                if candidate.ip in self._seen_ips:
                    continue
                self._seen_ips.add(candidate.ip)
                accepted_candidates.append(candidate)

                task = asyncio.create_task(self._probe_candidate(candidate))
                self._probe_tasks.add(task)
                task.add_done_callback(self._probe_tasks.discard)

            should_fallback_now = (
                not accepted_candidates
                and self._submitted_upstreams >= self._expected_upstreams
                and not self._has_pending_probes_locked()
            )
            if should_fallback_now:
                self._set_fallback_locked()

        if accepted_candidates:
            logger.debug(
                "上游候选IP resolver=%s txid=%s qtype=%s domain=%s ips=%s total_unique=%s",
                resolver_name,
                self._context.txid if self._context.txid is not None else "-",
                self._context.query_type or "-",
                self._context.query_name or "-",
                ", ".join(candidate.ip for candidate in accepted_candidates),
                len(self._seen_ips),
            )

    async def wait_result(self) -> dns.message.Message:
        return await asyncio.shield(self._result_future)

    async def _probe_candidate(self, candidate: _IpCandidate) -> None:
        score = await score_ip(candidate.ip, timeout_ms=self._probe_timeout_ms)

        async with self._lock:
            if self._result_future.done():
                return

            if score is not None:
                rewritten = _rewrite_response_with_selected_ip(
                    candidate=candidate,
                    rdtype=self._rdtype,
                )
                self._context.selected_ip = score.ip
                self._context.selected_ip_rtt_ms = score.best_ms
                self._context.tags["selected_ip_source_resolver"] = (
                    candidate.source_resolver
                )
                self._result_future.set_result(rewritten)
                if self._timeout_task is not None:
                    self._timeout_task.cancel()
                    self._timeout_task = None

                logger.debug(
                    "A/AAAA 选中最快IP resolver=%s txid=%s qtype=%s domain=%s ip=%s rtt=%.2fms",
                    candidate.source_resolver,
                    self._context.txid if self._context.txid is not None else "-",
                    self._context.query_type or "-",
                    self._context.query_name or "-",
                    score.ip,
                    score.best_ms,
                )
                return

            should_fallback_now = (
                self._submitted_upstreams >= self._expected_upstreams
                and not self._has_pending_probes_locked(exclude_current=True)
            )
            if should_fallback_now:
                self._set_fallback_locked()

    async def _resolve_after_timeout(self) -> None:
        try:
            await asyncio.sleep(self._wait_timeout_ms / 1000)
        except asyncio.CancelledError:  # pragma: no cover
            return

        async with self._lock:
            if self._result_future.done():
                return
            self._set_fallback_locked()
            logger.debug(
                "A/AAAA IP测速超时，回退首个上游响应 txid=%s qtype=%s domain=%s wait=%sms",
                self._context.txid if self._context.txid is not None else "-",
                self._context.query_type or "-",
                self._context.query_name or "-",
                self._wait_timeout_ms,
            )

    def _has_pending_probes_locked(self, exclude_current: bool = False) -> bool:
        current_task = asyncio.current_task()
        for task in self._probe_tasks:
            if task.done():
                continue
            if exclude_current and task is current_task:
                continue
            return True
        return False

    def _set_fallback_locked(self) -> None:
        if self._result_future.done():
            return
        fallback = self._fallback_response
        if fallback is None:
            fallback = dns.message.make_response(self._query)
        self._result_future.set_result(_clone_message(fallback))
        if self._timeout_task is not None:
            self._timeout_task.cancel()
            self._timeout_task = None


class FastestIpUpstreamHook(UpstreamHook):
    """A/AAAA 上游阶段 IP 测速与响应重写规则。"""

    def __init__(
        self,
        probe_timeout_ms: int = 1200,
        wait_timeout_ms: int = 1500,
    ) -> None:
        self._probe_timeout_ms = probe_timeout_ms
        self._wait_timeout_ms = wait_timeout_ms

    async def after_upstream(
        self,
        context: QueryContext,
        query: dns.message.Message,
        response: dns.message.Message,
        resolver_name: str,
    ) -> dns.message.Message | None:
        rdtype = _resolve_supported_rdtype(context, query)
        if rdtype is None:
            return None

        state = _get_or_create_state(
            context=context,
            query=query,
            rdtype=rdtype,
            probe_timeout_ms=self._probe_timeout_ms,
            wait_timeout_ms=self._wait_timeout_ms,
        )
        await state.submit_response(
            response=response,
            resolver_name=resolver_name,
        )
        return await state.wait_result()


def _get_or_create_state(
    context: QueryContext,
    query: dns.message.Message,
    rdtype: dns.rdatatype.RdataType,
    probe_timeout_ms: int,
    wait_timeout_ms: int,
) -> _IpBenchmarkState:
    state = context.tags.get(_BENCHMARK_STATE_TAG)
    if isinstance(state, _IpBenchmarkState):
        return state

    state = _IpBenchmarkState(
        context=context,
        query=query,
        rdtype=rdtype,
        probe_timeout_ms=probe_timeout_ms,
        wait_timeout_ms=max(wait_timeout_ms, probe_timeout_ms),
        expected_upstreams=context.resolver_attempts or 1,
    )
    context.tags[_BENCHMARK_STATE_TAG] = state
    return state


def _resolve_supported_rdtype(
    context: QueryContext,
    query: dns.message.Message,
) -> dns.rdatatype.RdataType | None:
    """仅对标准查询中的 A/AAAA 请求启用 IP 测速。"""
    if context.tags.get("enable_ip_benchmark") is False:
        return None

    context_qtype = (context.query_type or "").strip().upper()
    if context_qtype and context_qtype not in {"A", "AAAA"}:
        return None

    if query.opcode() != dns.opcode.QUERY:
        return None
    if len(query.question) != 1:
        return None

    rdtype = query.question[0].rdtype
    if rdtype not in _SUPPORTED_TYPES:
        return None

    if context_qtype:
        query_qtype = dns.rdatatype.to_text(rdtype).upper()
        if query_qtype != context_qtype:
            return None
    return rdtype


def _extract_ip_candidates(
    response: dns.message.Message,
    rdtype: dns.rdatatype.RdataType,
    resolver_name: str,
) -> list[_IpCandidate]:
    candidates: list[_IpCandidate] = []
    for rrset in response.answer:
        if rrset.rdtype != rdtype:
            continue
        owner = rrset.name.to_text()
        ttl = int(rrset.ttl)
        for rdata in rrset:
            ip_text = getattr(rdata, "address", None) or rdata.to_text()
            candidates.append(
                _IpCandidate(
                    ip=ip_text,
                    owner=owner,
                    ttl=ttl,
                    source_response=response,
                    source_resolver=resolver_name,
                )
            )
    return candidates


def _rewrite_response_with_selected_ip(
    candidate: _IpCandidate,
    rdtype: dns.rdatatype.RdataType,
) -> dns.message.Message:
    rewritten = _clone_message(candidate.source_response)
    filtered_answers = [
        rrset
        for rrset in rewritten.answer
        if rrset.rdtype not in (dns.rdatatype.A, dns.rdatatype.AAAA)
    ]
    selected_rrset = dns.rrset.from_text(
        candidate.owner,
        candidate.ttl,
        dns.rdataclass.IN,
        rdtype,
        candidate.ip,
    )
    filtered_answers.append(selected_rrset)
    rewritten.answer = filtered_answers
    return rewritten


def _clone_message(message: dns.message.Message) -> dns.message.Message:
    return dns.message.from_wire(message.to_wire())
