"""统一日志模块。"""

from __future__ import annotations

import logging
import os


_ROOT_LOGGER_NAME = "mydns"


def setup_logging(level: str | None = None) -> None:
    """初始化日志系统。"""
    root = logging.getLogger(_ROOT_LOGGER_NAME)
    if root.handlers:
        return

    handler = logging.StreamHandler()
    handler.setFormatter(
        logging.Formatter(
            fmt="%(asctime)s | %(levelname)s | %(name)s | %(message)s",
            datefmt="%Y-%m-%d %H:%M:%S",
        )
    )
    root.addHandler(handler)

    resolved_level = (level or os.getenv("MYDNS_LOG_LEVEL", "DEBUG")).upper()
    root.setLevel(getattr(logging, resolved_level, logging.DEBUG))


def get_logger(name: str | None = None) -> logging.Logger:
    """获取子 logger，首次调用时自动初始化。"""
    setup_logging()
    if not name:
        return logging.getLogger(_ROOT_LOGGER_NAME)
    return logging.getLogger(f"{_ROOT_LOGGER_NAME}.{name}")
