from __future__ import annotations

import asyncio
from dataclasses import dataclass
from typing import Iterable

from logger import get_logger
from rules.upstream.benchmark.ping import ping_once
from rules.upstream.benchmark.tcping import tcp_ping_once

logger = get_logger(__name__)


@dataclass(slots=True)
class IpScore:
    """单个 IP 的测速结果。"""

    ip: str
    best_ms: float
    ping_ms: float | None
    tcp_443_ms: float | None
    tcp_80_ms: float | None


async def score_ip(ip: str, timeout_ms: int = 1200) -> IpScore | None:
    """并发执行 ping / tcp443 / tcp80，首个成功结果返回。"""
    tasks_by_probe: dict[str, asyncio.Task[float | None]] = {
        "ping": asyncio.create_task(ping_once(ip, timeout_ms=timeout_ms)),
        "tcp443": asyncio.create_task(tcp_ping_once(ip, port=443, timeout_ms=timeout_ms)),
        "tcp80": asyncio.create_task(tcp_ping_once(ip, port=80, timeout_ms=timeout_ms)),
    }
    probe_by_task = {task: probe for probe, task in tasks_by_probe.items()}
    ping_ms: float | None = None
    tcp_443_ms: float | None = None
    tcp_80_ms: float | None = None

    pending: set[asyncio.Task[float | None]] = set(tasks_by_probe.values())
    try:
        while pending:
            done, pending = await asyncio.wait(
                pending,
                return_when=asyncio.FIRST_COMPLETED,
            )
            for task in done:
                probe = probe_by_task[task]
                try:
                    value = task.result()
                except Exception:  # pragma: no cover
                    value = None

                if probe == "ping":
                    ping_ms = value
                elif probe == "tcp443":
                    tcp_443_ms = value
                else:
                    tcp_80_ms = value

                if value is None:
                    continue

                for pending_task in pending:
                    pending_task.cancel()
                if pending:
                    await asyncio.gather(*pending, return_exceptions=True)

                score = IpScore(
                    ip=ip,
                    best_ms=value,
                    ping_ms=ping_ms,
                    tcp_443_ms=tcp_443_ms,
                    tcp_80_ms=tcp_80_ms,
                )
                logger.debug(
                    "测速结果 ip=%s selected=%s ping=%s tcp443=%s tcp80=%s best=%s",
                    ip,
                    probe,
                    _fmt_ms(score.ping_ms),
                    _fmt_ms(score.tcp_443_ms),
                    _fmt_ms(score.tcp_80_ms),
                    _fmt_ms(score.best_ms),
                )
                return score
    except asyncio.CancelledError:  # pragma: no cover
        for task in pending:
            task.cancel()
        if pending:
            await asyncio.gather(*pending, return_exceptions=True)
        raise

    logger.debug(
        "测速失败 ip=%s ping=%s tcp443=%s tcp80=%s",
        ip,
        _fmt_ms(ping_ms),
        _fmt_ms(tcp_443_ms),
        _fmt_ms(tcp_80_ms),
    )
    return None


async def choose_fastest_ip(
    ips: Iterable[str],
    timeout_ms: int = 1200,
) -> IpScore | None:
    """对 IP 集合并发测速，首个成功结果即返回。"""
    unique_ips = tuple(dict.fromkeys(ips))
    if not unique_ips:
        return None

    tasks_by_ip = {
        ip: asyncio.create_task(score_ip(ip, timeout_ms=timeout_ms))
        for ip in unique_ips
    }
    ip_by_task = {task: ip for ip, task in tasks_by_ip.items()}
    pending: set[asyncio.Task[IpScore | None]] = set(tasks_by_ip.values())
    errors: list[str] = []

    try:
        while pending:
            done, pending = await asyncio.wait(
                pending,
                return_when=asyncio.FIRST_COMPLETED,
            )
            for task in done:
                ip = ip_by_task[task]
                try:
                    score = task.result()
                except Exception as exc:  # pragma: no cover
                    errors.append(f"{ip}: {exc}")
                    continue

                if score is None:
                    continue

                for pending_task in pending:
                    pending_task.cancel()
                if pending:
                    await asyncio.gather(*pending, return_exceptions=True)

                logger.debug(
                    "选择最快 IP ip=%s rtt=%s",
                    score.ip,
                    _fmt_ms(score.best_ms),
                )
                return score
    except asyncio.CancelledError:  # pragma: no cover
        for task in pending:
            task.cancel()
        if pending:
            await asyncio.gather(*pending, return_exceptions=True)
        raise

    if errors:
        logger.debug(
            "IP 测速无可用结果 ips=%s errors=%s",
            ", ".join(unique_ips),
            "; ".join(errors),
        )
    else:
        logger.debug("IP 测速无可用结果，候选=%s", ", ".join(unique_ips))
    return None


def _fmt_ms(value: float | None) -> str:
    if value is None:
        return "-"
    return f"{value:.2f}ms"
