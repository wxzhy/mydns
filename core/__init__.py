from __future__ import annotations

from typing import TYPE_CHECKING

from core.context import ClientAddress, QueryContext
from core.hooks import PipelineHook, RequestHook, RequestHooks, ResponseHook, UpstreamHook

if TYPE_CHECKING:
    from core.pipeline import RequestPipeline


def __getattr__(name: str) -> object:
    if name == "RequestPipeline":
        from core.pipeline import RequestPipeline

        return RequestPipeline
    raise AttributeError(f"module 'core' has no attribute {name!r}")

__all__ = [
    "ClientAddress",
    "QueryContext",
    "PipelineHook",
    "RequestHook",
    "UpstreamHook",
    "ResponseHook",
    "RequestHooks",
    "RequestPipeline",
]
