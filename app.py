"""应用装配：通过代码注册表构建流水线。"""

from __future__ import annotations

from core.pipeline import Pipeline
from resolver.udp_resolver import UdpUpstreamResolver
from plugins.builtin import NoopRequestHook, NoopResolverHook, NoopResponseHook


def build_pipeline() -> Pipeline:
    """构建默认运行所需对象。"""
    request_hooks = [NoopRequestHook()]
    resolver_hooks = [NoopResolverHook()]
    response_hooks = [NoopResponseHook()]
    resolvers = [
        UdpUpstreamResolver(name="cloudflare", address="1.1.1.1"),
        UdpUpstreamResolver(name="google", address="8.8.8.8"),
    ]
    return Pipeline(
        resolvers=resolvers,
        resolver_hooks=resolver_hooks,
        request_hooks=request_hooks,
        response_hooks=response_hooks,
    )
