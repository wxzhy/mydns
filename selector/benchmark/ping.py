from __future__ import annotations

from typing import Final

try:
    from icmplib import async_ping as icmp_async_ping
except Exception:  # pragma: no cover
    icmp_async_ping = None

DEFAULT_MIN_TIMEOUT_SECONDS: Final[float] = 0.2


async def ping_once(ip: str, timeout_ms: int = 1200) -> float | None:
    """使用 icmplib.async_ping 执行一次 ping，返回 RTT（毫秒）。"""
    if icmp_async_ping is None:
        return None

    timeout_seconds = max(DEFAULT_MIN_TIMEOUT_SECONDS, timeout_ms / 1000)
    try:
        host = await icmp_async_ping(
            ip,
            count=1,
            interval=DEFAULT_MIN_TIMEOUT_SECONDS,
            timeout=timeout_seconds,
            privileged=False,
        )
    except Exception:  # pragma: no cover
        return None

    if not host.is_alive:
        return None
    if host.min_rtt is not None:
        return float(host.min_rtt)
    if host.avg_rtt is not None:
        return float(host.avg_rtt)
    if host.max_rtt is not None:
        return float(host.max_rtt)
    return None
