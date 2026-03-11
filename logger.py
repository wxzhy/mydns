from __future__ import annotations

import logging
from typing import Union

DEFAULT_LOG_FORMAT = "%(asctime)s %(levelname)s [%(name)s] %(message)s"
ROOT_LOGGER_NAME = "mydns"


def _normalize_log_level(level: Union[str, int]) -> int:
    """将字符串/整数日志级别统一转换为 logging 常量。"""
    if isinstance(level, int):
        return level
    return getattr(logging, level.upper(), logging.INFO)


def setup_logging(
    level: Union[str, int] = "INFO", fmt: str = DEFAULT_LOG_FORMAT
) -> None:
    """配置项目专用日志树。"""
    logger = logging.getLogger(ROOT_LOGGER_NAME)
    logger.setLevel(_normalize_log_level(level))
    logger.propagate = False

    if not logger.handlers:
        handler = logging.StreamHandler()
        handler.setFormatter(logging.Formatter(fmt))
        logger.addHandler(handler)

    # 允许重复调用 setup_logging 动态调整级别。
    for handler in logger.handlers:
        handler.setLevel(logger.level)


def get_logger(name: str) -> logging.Logger:
    """获取项目根 logger 下的子 logger。"""
    root_logger = logging.getLogger(ROOT_LOGGER_NAME)
    if not root_logger.handlers:
        setup_logging()
    return root_logger.getChild(name)
