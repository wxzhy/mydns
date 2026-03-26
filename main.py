"""程序入口。"""

from __future__ import annotations

import argparse
import asyncio
from typing import Any
import winuvloop

from config import load_runtime_config
from core.pipeline import Pipeline
from logger import get_logger, setup_logging
from server.tcp_server import TCPDNSServer
from server.udp_server import UDPDNSServer

logger = get_logger("main")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="插件式流水线 DNS 服务器")
    parser.add_argument(
        "--config", help="YAML 配置文件路径", default="config/mydns.example.yaml"
    )
    parser.add_argument("--host", help="监听地址（可覆盖配置文件）")
    parser.add_argument("--port", type=int, help="监听端口（可覆盖配置文件）")
    return parser.parse_args()


async def _run(
    host: str,
    port: int,
    pipeline: Pipeline,
    *,
    enable_udp: bool,
    enable_tcp: bool,
) -> None:
    servers: list[Any] = []
    try:
        if enable_udp:
            udp_server = UDPDNSServer(pipeline, host=host, port=port)
            await udp_server.start()
            servers.append(udp_server)
            if port == 0 and enable_tcp:
                port = udp_server.port

        if enable_tcp:
            tcp_server = TCPDNSServer(pipeline, host=host, port=port)
            await tcp_server.start()
            servers.append(tcp_server)

        logger.info(
            "DNS 服务已启动 listeners=%s",
            [
                f"{'udp' if isinstance(server, UDPDNSServer) else 'tcp'}://{host}:{server.port}"
                for server in servers
            ],
        )
        await asyncio.gather(*(server.serve_forever() for server in servers))
    finally:
        for server in reversed(servers):
            await server.stop()


def main() -> None:
    setup_logging()
    args = parse_args()
    host = args.host or "127.0.0.1"
    port = args.port if args.port is not None else 5335
    enable_udp = True
    enable_tcp = False
    pipeline: Pipeline
    if args.config:
        runtime = load_runtime_config(args.config)
        pipeline = runtime.pipeline
        host = args.host or runtime.server.host
        port = args.port if args.port is not None else runtime.server.port
        enable_udp = runtime.server.udp
        enable_tcp = runtime.server.tcp
    else:
        from app import build_pipeline

        pipeline = build_pipeline()

    try:
        asyncio.run(
            _run(
                host,
                port,
                pipeline,
                enable_udp=enable_udp,
                enable_tcp=enable_tcp,
            )
        )
    except KeyboardInterrupt:
        logger.info("收到中断信号，服务退出")


if __name__ == "__main__":
    winuvloop.install()
    main()
