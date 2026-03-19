"""程序入口。"""

from __future__ import annotations

import argparse
import asyncio
import winuvloop

from config import load_runtime_config
from core.pipeline import Pipeline
from logger import get_logger, setup_logging
from server.udp_server import UDPDNSServer

logger = get_logger("main")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="插件式流水线 DNS 服务器")
    parser.add_argument("--config", help="YAML 配置文件路径")
    parser.add_argument("--host", help="监听地址（可覆盖配置文件）")
    parser.add_argument("--port", type=int, help="监听端口（可覆盖配置文件）")
    return parser.parse_args()


async def _run(host: str, port: int, pipeline: Pipeline) -> None:
    server = UDPDNSServer(pipeline, host=host, port=port)
    await server.start()
    logger.info("DNS 服务已启动地址 udp://%s:%s", host, server.port)
    try:
        await server.serve_forever()
    finally:
        await server.stop()


def main() -> None:
    setup_logging()
    args = parse_args()
    host = args.host or "127.0.0.1"
    port = args.port if args.port is not None else 5335
    pipeline: Pipeline
    if args.config:
        runtime = load_runtime_config(args.config)
        pipeline = runtime.pipeline
        host = args.host or runtime.server.host
        port = args.port if args.port is not None else runtime.server.port
    else:
        from app import build_pipeline

        pipeline = build_pipeline()

    try:
        asyncio.run(_run(host, port, pipeline))
    except KeyboardInterrupt:
        logger.info("收到中断信号，服务退出")


if __name__ == "__main__":
    winuvloop.install()
    main()
