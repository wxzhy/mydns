"""IP 测速能力。"""

from __future__ import annotations

import asyncio
import time
from collections.abc import Iterable
from typing import Any

from async_lru import alru_cache
from icmplib import async_ping
from pydantic import PositiveFloat, PositiveInt

from logger import get_logger
from plugins._config import PluginConfigModel

logger = get_logger("plugins.utils.speedcheck")

DEFAULT_PROBE_CACHE_MAX_SIZE = 10000
DEFAULT_PROBE_CACHE_TTL_S = 3600.0

_probe_cache_max_size = DEFAULT_PROBE_CACHE_MAX_SIZE
_probe_cache_ttl_s = DEFAULT_PROBE_CACHE_TTL_S


class ProbeCacheConfigModel(PluginConfigModel):
    max_size: PositiveInt = DEFAULT_PROBE_CACHE_MAX_SIZE
    ttl_s: PositiveFloat = DEFAULT_PROBE_CACHE_TTL_S


async def probe_ips(
    ips: Iterable[str],
    timeout_s: float,
) -> dict[str, float | None]:
    """并发测速多个 IP，返回每个 IP 的最佳 RTT（毫秒）。"""
    # 同一轮测速里先按输入顺序去重，避免同一请求内重复发包。
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


def _decorate_probe_one_ip(func: Any) -> Any:
    # `async_lru` 直接装饰单 IP 探测函数，缓存粒度就是 (ip, timeout_s)。
    return alru_cache(maxsize=_probe_cache_max_size, ttl=_probe_cache_ttl_s)(func)


@_decorate_probe_one_ip
async def probe_one_ip(ip: str, timeout_s: float) -> float | None:
    """针对单个 IP 并行测速，拿到首个成功 RTT 即返回。"""
    tasks = _build_probe_tasks(ip, timeout_s)

    try:
        return await _wait_first_success(tasks, timeout_s=timeout_s)
    except TimeoutError:
        return None
    finally:
        await _close_probe_tasks(tasks)


_RAW_PROBE_ONE_IP = probe_one_ip.__wrapped__


def configure(
    *,
    max_size: int | None = None,
    ttl_s: float | None = None,
) -> tuple[int, float]:
    """配置全局单 IP 测速缓存。未传参数时回落默认值。"""
    global _probe_cache_max_size, _probe_cache_ttl_s

    raw_config: dict[str, Any] = {}
    if max_size is not None:
        raw_config["max_size"] = max_size
    if ttl_s is not None:
        raw_config["ttl_s"] = ttl_s
    config = ProbeCacheConfigModel.model_validate(raw_config)
    _probe_cache_max_size = config.max_size
    _probe_cache_ttl_s = config.ttl_s
    _reset_probe_one_ip_cache()
    logger.debug(
        "测速缓存配置更新 max_size=%s ttl_s=%.3fs",
        _probe_cache_max_size,
        _probe_cache_ttl_s,
    )
    return get_probe_cache_config()


def configure_probe_cache(
    *,
    max_size: int | None = None,
    ttl_s: float | None = None,
) -> tuple[int, float]:
    """兼容旧调用名。"""
    return configure(max_size=max_size, ttl_s=ttl_s)


def get_probe_cache_config() -> tuple[int, float]:
    return (_probe_cache_max_size, _probe_cache_ttl_s)


def clear_probe_cache() -> None:
    _reset_probe_one_ip_cache()


def _reset_probe_one_ip_cache() -> None:
    global probe_one_ip

    old_probe_one_ip = probe_one_ip
    # 重新装饰函数是为了让 async-lru 读取新的 maxsize/ttl 配置。
    probe_one_ip = _decorate_probe_one_ip(_RAW_PROBE_ONE_IP)
    cache_clear = getattr(old_probe_one_ip, "cache_clear", None)
    if callable(cache_clear):
        cache_clear()


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


def _build_probe_tasks(ip: str, timeout_s: float) -> list[asyncio.Task[float | None]]:
    # 同时发起 ICMP 和常见 TCP 端口探测，优先返回最早成功的一项。
    return [
        asyncio.create_task(_probe_ping(ip, timeout_s)),
        asyncio.create_task(_probe_tcp(ip, 80, timeout_s)),
        asyncio.create_task(_probe_tcp(ip, 443, timeout_s)),
    ]


async def _wait_first_success(
    tasks: list[asyncio.Task[float | None]],
    *,
    timeout_s: float,
) -> float | None:
    for completed in asyncio.as_completed(tasks, timeout=timeout_s):
        rtt = await completed
        if rtt is not None:
            return rtt
    return None


async def _close_probe_tasks(tasks: list[asyncio.Task[float | None]]) -> None:
    for task in tasks:
        if not task.done():
            task.cancel()
    await asyncio.gather(*tasks, return_exceptions=True)
