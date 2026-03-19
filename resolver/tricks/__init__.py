"""自定义 socket 工具集合。"""

from resolver.tricks.tcp_trick import TrickyStreamSocket
from resolver.tricks.udp_trick import TrickyDatagramSocket

__all__ = [
    "TrickyStreamSocket",
    "TrickyDatagramSocket",
]
