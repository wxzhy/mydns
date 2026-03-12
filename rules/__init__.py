from __future__ import annotations

from collections.abc import Iterable, Mapping

from core.hooks import RequestHook, ResponseHook, UpstreamHook
from rules.request import build_request_hooks
from rules.response import build_response_hooks
from rules.upstream import build_upstream_hooks


def build_hooks(
    blocked_domains: Iterable[str] | None = None,
    hosts: Mapping[str, str] | None = None,
    enable_debug: bool = True,
) -> tuple[object, ...]:
    """按阶段构建 hook 列表，便于统一装配与扩展。"""
    request_hooks: tuple[RequestHook, ...] = build_request_hooks(
        blocked_domains=blocked_domains,
        hosts=hosts,
        enable_debug=enable_debug,
    )
    upstream_hooks: tuple[UpstreamHook, ...] = build_upstream_hooks(
        enable_debug=enable_debug,
    )
    response_hooks: tuple[ResponseHook, ...] = build_response_hooks(
        enable_debug=enable_debug,
    )
    return (*request_hooks, *upstream_hooks, *response_hooks)


def build_default_hooks() -> tuple[object, ...]:
    return build_hooks()


__all__ = ["build_hooks", "build_default_hooks"]
