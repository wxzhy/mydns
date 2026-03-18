"""程序入口。"""

from __future__ import annotations

import argparse
import asyncio

from app import build_pipeline
from server.udp_server import UDPDNSServer


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="插件式流水线 DNS 服务器")
    parser.add_argument("--host", default="127.0.0.1", help="监听地址")
    parser.add_argument("--port", type=int, default=5353, help="监听端口")
    return parser.parse_args()


async def _run(host: str, port: int) -> None:
    server = UDPDNSServer(build_pipeline(), host=host, port=port)
    await server.start()
    print(f"DNS 服务已启动: udp://{host}:{server.port}")
    try:
        await server.serve_forever()
    finally:
        await server.stop()


def main() -> None:
    args = parse_args()
    try:
        asyncio.run(_run(args.host, args.port))
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
