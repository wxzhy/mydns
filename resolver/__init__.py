"""上游解析器实现。"""

from resolver.https_resolver import HttpsUpstreamResolver
from resolver.quic_resolver import QuicUpstreamResolver
from resolver.tcp_resolver import TcpUpstreamResolver
from resolver.tls_resolver import TlsUpstreamResolver
from resolver.udp_resolver import UdpUpstreamResolver

__all__ = [
    "UdpUpstreamResolver",
    "TcpUpstreamResolver",
    "TlsUpstreamResolver",
    "HttpsUpstreamResolver",
    "QuicUpstreamResolver",
]
