"""应用装配：通过代码注册表构建流水线。"""

from __future__ import annotations

from core.pipeline import Pipeline
from plugins.builtin import NoopRequestHook, NoopResolverHook, NoopResponseHook
from plugins.speedcheck import RewriteAnswerByRTTHook, SpeedCheckResolverHook
from resolver.udp_resolver import UdpUpstreamResolver


def build_pipeline() -> Pipeline:
    """构建默认运行所需对象。"""
    request_hooks = [NoopRequestHook()]
    # 测速插件要求放在其他 resolver hook 之后。
    resolver_hooks = [NoopResolverHook(), SpeedCheckResolverHook()]
    response_hooks = [
        NoopResponseHook(),
        RewriteAnswerByRTTHook(max_return_ips=2, ttl_s=900),
    ]
    resolvers = [
        UdpUpstreamResolver(name="alidns", address="223.5.5.5"),
        UdpUpstreamResolver(name="dnspod", address="119.29.29.29"),
        UdpUpstreamResolver(name="cloudflare", address="1.1.1.1"),
        UdpUpstreamResolver(name="google", address="8.8.8.8"),
    ]
    return Pipeline(
        resolvers=resolvers,
        resolver_hooks=resolver_hooks,
        request_hooks=request_hooks,
        response_hooks=response_hooks,
    )
