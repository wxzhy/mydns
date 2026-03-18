"""程序入口。"""

from __future__ import annotations

import argparse
import asyncio
import winuvloop

from app import build_pipeline
from logger import get_logger, setup_logging
from server.udp_server import UDPDNSServer

logger = get_logger("main")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="插件式流水线 DNS 服务器")
    parser.add_argument("--host", default="127.0.0.1", help="监听地址")
    parser.add_argument("--port", type=int, default=5335, help="监听端口")
    return parser.parse_args()


async def _run(host: str, port: int) -> None:
    server = UDPDNSServer(build_pipeline(), host=host, port=port)
    await server.start()
    logger.info("DNS 服务已启动地址 udp://%s:%s", host, server.port)
    try:
        await server.serve_forever()
    finally:
        await server.stop()


def main() -> None:
    setup_logging()
    args = parse_args()
    try:
        asyncio.run(_run(args.host, args.port))
    except KeyboardInterrupt:
        logger.info("收到中断信号，服务退出")


if __name__ == "__main__":
    winuvloop.install()
    main()
