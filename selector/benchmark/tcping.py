from __future__ import annotations

import asyncio
from time import monotonic


async def tcp_ping_once(
    ip: str,
    port: int,
    timeout_ms: int = 1200,
) -> float | None:
    """执行一次 TCP 建连测速，返回耗时（毫秒）。失败返回 None。"""
    started_at = monotonic()
    writer: asyncio.StreamWriter | None = None
    try:
        _, writer = await asyncio.wait_for(
            asyncio.open_connection(host=ip, port=port),
            timeout=timeout_ms / 1000,
        )
    except Exception:  # pragma: no cover
        return None
    finally:
        if writer is not None:
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:  # pragma: no cover
                pass

    return (monotonic() - started_at) * 1000
