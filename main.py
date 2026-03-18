from __future__ import annotations

import argparse
import asyncio
import signal

from app import Application
from config import load_config
from logger import get_logger, setup_logging

try:
    import winuvloop
except Exception:  # pragma: no cover
    winuvloop = None


def parse_args() -> argparse.Namespace:
    """解析命令行参数。"""
    parser = argparse.ArgumentParser(description="轻量级 UDP DNS 转发服务")
    parser.add_argument(
        "-c",
        "--config",
        default=None,
        help="YAML 配置文件路径（默认：./config.yaml）。",
    )
    return parser.parse_args()


async def run(config_path: str | None) -> None:
    """加载配置并运行应用主循环。"""
    config = load_config(config_path)
    setup_logging(config.logging.level)
    logger = get_logger(__name__)

    app = Application(config)
    await app.start()

    logger.info(
        "当前上游转发目标：%s",
        ", ".join(
            f"[{up.tag}] {up.protocol}://{up.host}:{up.port}"
            for up in config.upstreams
        ),
    )

    stop_event = asyncio.Event()
    loop = asyncio.get_running_loop()
    for signame in ("SIGINT", "SIGTERM"):
        sig = getattr(signal, signame, None)
        if sig is None:
            continue
        try:
            loop.add_signal_handler(sig, stop_event.set)
        except NotImplementedError:
            pass

    try:
        await stop_event.wait()
    finally:
        app.close()


def main() -> None:
    """程序入口。"""
    args = parse_args()
    if winuvloop is not None:
        try:
            winuvloop.install()
        except Exception:
            pass

    try:
        asyncio.run(run(args.config))
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
