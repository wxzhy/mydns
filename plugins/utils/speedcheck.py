"""IP 测速能力。"""

from __future__ import annotations

import asyncio
import time
from collections.abc import Iterable

from icmplib import async_ping

from logger import get_logger

logger = get_logger("plugins.utils.speedcheck")


async def probe_ips(
    ips: Iterable[str],
    timeout_s: float,
) -> dict[str, float | None]:
    """并发测速多个 IP，返回每个 IP 的最佳 RTT（毫秒）。"""
    ip_list = list(dict.fromkeys(ips))
    probes = [probe_one_ip(ip, timeout_s=timeout_s) for ip in ip_list]
    raw_results = await asyncio.gather(*probes, return_exceptions=True)
    results: dict[str, float | None] = {}
    for ip, raw in zip(ip_list, raw_results, strict=True):
        if isinstance(raw, Exception):
            logger.debug("测速异常 ip=%s err=%r", ip, raw)
            results[ip] = None
        else:
            results[ip] = raw
    return results


async def probe_one_ip(ip: str, timeout_s: float) -> float | None:
    """针对单个 IP 并行测速，拿到首个成功 RTT 即返回。"""
    tasks = [
        asyncio.create_task(_probe_ping(ip, timeout_s)),
        asyncio.create_task(_probe_tcp(ip, 80, timeout_s)),
        asyncio.create_task(_probe_tcp(ip, 443, timeout_s)),
    ]

    try:
        for completed in asyncio.as_completed(tasks, timeout=timeout_s):
            rtt = await completed
            if rtt is not None:
                return rtt
        return None
    except TimeoutError:
        return None
    finally:
        for task in tasks:
            if not task.done():
                task.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)


async def _probe_ping(ip: str, timeout_s: float) -> float | None:
    try:
        host = await async_ping(
            ip,
            count=1,
            interval=0.2,
            timeout=timeout_s,
            privileged=False,
        )
    except Exception:
        return None
    if not host.is_alive:
        return None
    return float(host.min_rtt)


async def _probe_tcp(ip: str, port: int, timeout_s: float) -> float | None:
    start = time.perf_counter()
    try:
        connect = asyncio.open_connection(ip, port)
        reader, writer = await asyncio.wait_for(connect, timeout=timeout_s)
        _ = reader
        elapsed = (time.perf_counter() - start) * 1000
        writer.close()
        await writer.wait_closed()
        return elapsed
    except Exception:
        return None
