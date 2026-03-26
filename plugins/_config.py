"""插件配置的共享 Pydantic 辅助。"""

from __future__ import annotations

from collections.abc import Iterable, Mapping, Sequence
from ipaddress import ip_address
from typing import Any

from pydantic import BaseModel, ConfigDict


class PluginConfigModel(BaseModel):
    """所有插件配置模型的统一基类。"""

    model_config = ConfigDict(
        extra="forbid",
        arbitrary_types_allowed=True,
    )


def dump_model_compact(model: BaseModel) -> dict[str, Any]:
    """导出适合运行时传递的紧凑配置。"""
    return model.model_dump(
        mode="python",
        exclude_none=True,
        exclude_defaults=True,
    )


def normalize_nonempty_string(raw_value: Any, *, key: str) -> str:
    if not isinstance(raw_value, str):
        raise ValueError(f"{key} 必须是非空字符串")
    value = raw_value.strip()
    if not value:
        raise ValueError(f"{key} 必须是非空字符串")
    return value


def normalize_string_tuple(
    raw_value: Any,
    *,
    key: str,
    allow_none: bool = False,
) -> tuple[str, ...]:
    if raw_value is None and allow_none:
        return ()
    if isinstance(raw_value, str):
        values = [raw_value]
    elif isinstance(raw_value, Iterable) and not isinstance(
        raw_value,
        (str, bytes, bytearray, Mapping),
    ):
        values = list(raw_value)
    else:
        raise ValueError(f"{key} 必须是字符串或字符串列表")

    normalized: list[str] = []
    seen: set[str] = set()
    for index, item in enumerate(values):
        value = normalize_nonempty_string(item, key=f"{key}[{index}]")
        if value in seen:
            continue
        seen.add(value)
        normalized.append(value)
    if not allow_none and not normalized:
        raise ValueError(f"{key} 至少需要一个值")
    return tuple(normalized)


def normalize_positive_int(raw_value: Any, *, key: str) -> int:
    try:
        value = int(raw_value)
    except (TypeError, ValueError) as exc:
        raise ValueError(f"{key} 必须是正整数") from exc
    if value <= 0:
        raise ValueError(f"{key} 必须是正整数")
    return value


def normalize_positive_float(raw_value: Any, *, key: str) -> float:
    try:
        value = float(raw_value)
    except (TypeError, ValueError) as exc:
        raise ValueError(f"{key} 必须是正数") from exc
    if value <= 0:
        raise ValueError(f"{key} 必须是正数")
    return value


def normalize_int_range(
    raw_value: Any,
    *,
    key: str,
    min_value: int,
    max_value: int,
) -> int:
    try:
        value = int(raw_value)
    except (TypeError, ValueError) as exc:
        raise ValueError(f"{key} 必须是整数") from exc
    if not min_value <= value <= max_value:
        raise ValueError(f"{key} 必须在 {min_value} 到 {max_value} 之间")
    return value


def normalize_ip_text(
    raw_value: Any,
    *,
    key: str,
    version: int,
) -> str:
    value = normalize_nonempty_string(raw_value, key=key)
    try:
        parsed = ip_address(value)
    except ValueError as exc:
        raise ValueError(f"{key} 不是合法 IP: {value}") from exc
    if parsed.version != version:
        raise ValueError(f"{key} 的 IP 版本与记录类型不匹配")
    return value


def normalize_ip_tuple(
    raw_value: Any,
    *,
    key: str,
    version: int,
) -> tuple[str, ...]:
    if isinstance(raw_value, str):
        values = [raw_value]
    elif isinstance(raw_value, Iterable) and not isinstance(
        raw_value,
        (str, bytes, bytearray, Mapping),
    ):
        values = list(raw_value)
    else:
        raise ValueError(f"{key} 必须是字符串或字符串列表")

    normalized: list[str] = []
    seen: set[str] = set()
    for index, item in enumerate(values):
        value = normalize_ip_text(item, key=f"{key}[{index}]", version=version)
        if value in seen:
            continue
        seen.add(value)
        normalized.append(value)
    return tuple(normalized)
