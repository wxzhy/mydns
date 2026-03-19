"""应用装配：通过代码注册表构建流水线。"""

from __future__ import annotations

from core.pipeline import Pipeline
from plugins.builtin import NoopRequestHook, NoopResolverHook, NoopResponseHook
from plugins.speedcheck import RewriteAnswerByRTTHook, SpeedCheckResolverHook
from resolver.https_resolver import HttpsUpstreamResolver
from resolver.quic_resolver import QuicUpstreamResolver
from resolver.tcp_resolver import TcpUpstreamResolver
from resolver.tls_resolver import TlsUpstreamResolver
from resolver.udp_resolver import UdpUpstreamResolver
from resolver.tricks import TcpTrickResolver, UdpTrickResolver


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
        TcpUpstreamResolver(name="tcp-cloudflare", address="1.1.1.1"),
        TcpUpstreamResolver(name="tcp-google", address="8.8.8.8"),
        TlsUpstreamResolver(
            name="tls-cloudflare",
            address="1.1.1.1",
            server_hostname="cloudflare-dns.com",
        ),
        TlsUpstreamResolver(
            name="tls-google",
            address="8.8.8.8",
            server_hostname="dns.google",
        ),
        QuicUpstreamResolver(
            name="doq-cloudflare",
            address="1.1.1.1",
            server_hostname="cloudflare-dns.com",
        ),
        QuicUpstreamResolver(
            name="doq-google",
            address="8.8.8.8",
            server_hostname="dns.google",
        ),
        HttpsUpstreamResolver(
            name="doh-cloudflare",
            address="cloudflare-dns.com",
            path="/dns-query",
            bootstrap_address="1.1.1.1",
        ),
        HttpsUpstreamResolver(
            name="doh-google",
            address="dns.google",
            path="/dns-query",
            bootstrap_address="8.8.8.8",
        ),
        UdpTrickResolver(
            name="udp-trick-alidns",
            address="223.5.5.5",
            padding_bytes=24,
            require_opt_response=True,
        ),
        TcpTrickResolver(
            name="tcp-trick-cloudflare",
            address="1.1.1.1",
            split_at=6,
            inter_chunk_delay_ms=5,
        ),
    ]
    return Pipeline(
        resolvers=resolvers,
        resolver_hooks=resolver_hooks,
        request_hooks=request_hooks,
        response_hooks=response_hooks,
    )
