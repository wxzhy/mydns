class Pipeline:
    """请求处理管道，包含多个处理器"""

    def __init__(
        self,
        servers: list[server] | None,
        resolvers: list[resolver] | None,
        handlers: list[handler] | None,
        cache: Cache | None,
    ):
        self.handlers = handlers

    def _start_servers(self):

    def process_request(self, request: bytes) -> bytes | None:
        """处理请求"""
        return None

    def _parse_request(self, request: bytes) -> Context | None:
        """解析请求，构建上下文"""
        try:
            msg = dns.message.from_wire(request)
        except dns.exception.DNSException:
            return None
        return Context()
