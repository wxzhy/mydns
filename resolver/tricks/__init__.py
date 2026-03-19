"""自定义收发解析器集合。"""

from resolver.tricks.tcp_trick import TcpTrickResolver
from resolver.tricks.udp_trick import UdpTrickResolver

__all__ = [
    "TcpTrickResolver",
    "UdpTrickResolver",
]
