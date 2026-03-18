"""上游 resolver 实现集合。"""

from resolvers.doh_resolver import DohUpstreamResolver
from resolvers.doq_resolver import DoqUpstreamResolver
from resolvers.dnscrypt_resolver import DnscryptUpstreamResolver
from resolvers.dot_resolver import DotUpstreamResolver
from resolvers.resolver import BaseUpstreamResolver, DnsAnswer, ResolverProtocol
from resolvers.tcp_resolver import TcpUpstreamResolver
from resolvers.udp_resolver import UdpUpstreamResolver

__all__ = [
    "DnsAnswer",
    "ResolverProtocol",
    "BaseUpstreamResolver",
    "UdpUpstreamResolver",
    "TcpUpstreamResolver",
    "DotUpstreamResolver",
    "DohUpstreamResolver",
    "DoqUpstreamResolver",
    "DnscryptUpstreamResolver",
]
