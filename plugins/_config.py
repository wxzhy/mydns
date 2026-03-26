"""插件配置的共享 Pydantic 类型别名。"""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from ipaddress import IPv4Address, IPv6Address
from typing import Annotated, Any

from pydantic import (
    AfterValidator,
    BaseModel,
    BeforeValidator,
    ConfigDict,
    StringConstraints,
    conint,
    conset,
)


def _coerce_multi_value(value: Any) -> Any:
    if isinstance(value, str):
        return [value]
    if isinstance(value, Iterable) and not isinstance(
        value,
        (str, bytes, bytearray, Mapping),
    ):
        return list(value)
    return value


def _coerce_multi_value_or_empty(value: Any) -> Any:
    if value is None:
        return ()
    return _coerce_multi_value(value)


def _dedupe_list(values: list[Any]) -> list[Any]:
    return list(dict.fromkeys(values))


NonEmptyStr = Annotated[str, StringConstraints(strip_whitespace=True, min_length=1)]
PortNumber = conint(ge=0, le=65535)
IPv4PrefixLen = conint(ge=0, le=32)
IPv6PrefixLen = conint(ge=0, le=128)

NonEmptyStrList = Annotated[list[NonEmptyStr], BeforeValidator(_coerce_multi_value)]
NonEmptyStrSet = Annotated[
    conset(NonEmptyStr, min_length=1),
    BeforeValidator(_coerce_multi_value),
]
OptionalStrSet = Annotated[
    conset(NonEmptyStr),
    BeforeValidator(_coerce_multi_value_or_empty),
]

IPv4AddressList = Annotated[
    list[IPv4Address],
    BeforeValidator(_coerce_multi_value),
    AfterValidator(_dedupe_list),
]
IPv6AddressList = Annotated[
    list[IPv6Address],
    BeforeValidator(_coerce_multi_value),
    AfterValidator(_dedupe_list),
]


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
