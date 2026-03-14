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
    parser = argparse.ArgumentParser(description="Simple UDP DNS Forwarder")
    parser.add_argument(
        "-c",
        "--config",
        default=None,
        help="Path to YAML config file (default: ./config.yaml).",
    )
    return parser.parse_args()


async def run(config_path: str | None) -> None:
    config = load_config(config_path)
    setup_logging(config.logging.level)
    logger = get_logger(__name__)

    app = Application(config)
    await app.start()

    logger.info(
        "Forwarding to upstreams: %s",
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
