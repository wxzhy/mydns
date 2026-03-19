"""UDP 自定义收发解析器。"""

from __future__ import annotations

import dns.asyncquery
import dns.edns
import dns.exception
import dns.message

from core.models import Answer, Query
from resolver.resolver import Resolver, build_request_message


class UdpTrickResolver(Resolver):
    """通过 EDNS 增强与响应校验实现更稳健的 UDP 解析。"""

    def __init__(
        self,
        *,
        name: str,
        address: str,
        port: int = 53,
        padding_bytes: int = 24,
        require_opt_response: bool = True,
        ignore_unexpected: bool = True,
        tags: set[str] | None = None,
    ) -> None:
        self.name = name
        self.address = address
        self.port = port
        self.padding_bytes = max(0, padding_bytes)
        self.require_opt_response = require_opt_response
        self.ignore_unexpected = ignore_unexpected
        self.tags = tags or {"default"}

    async def resolve(self, query: Query, timeout_s: float) -> Answer:
        request = self._build_request(query)
        response = await dns.asyncquery.udp(
            request,
            where=self.address,
            port=self.port,
            timeout=timeout_s,
            ignore_unexpected=self.ignore_unexpected,
        )
        if not self._accept_response(request, response):
            raise dns.exception.DNSException("UDP trick 检测到无效响应")
        return Answer(
            rcode=response.rcode(),
            rrsets=list(response.answer),
        )

    def _build_request(self, query: Query) -> dns.message.Message:
        request = build_request_message(query, use_edns=True)
        if self.padding_bytes <= 0:
            return request
        options = list(request.options)
        options.append(
            dns.edns.GenericOption(
                dns.edns.OptionType.PADDING,
                b"\x00" * self.padding_bytes,
            )
        )
        request.use_edns(
            edns=request.edns,
            ednsflags=request.ednsflags,
            payload=request.payload,
            options=options,
        )
        return request

    def _accept_response(
        self,
        request: dns.message.Message,
        response: dns.message.Message,
    ) -> bool:
        if response.id != request.id:
            return False
        if request.question and response.question:
            request_question = request.question[0]
            response_question = response.question[0]
            if request_question.name != response_question.name:
                return False
            if request_question.rdtype != response_question.rdtype:
                return False
        if self.require_opt_response and request.opt is not None and response.opt is None:
            return False
        return True
