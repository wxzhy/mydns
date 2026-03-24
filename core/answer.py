"""项目内统一使用的 DNS Answer 封装。"""

from __future__ import annotations

from collections.abc import Iterable
import time
from typing import Any, cast

import dns.message
import dns.rcode
import dns.rdataclass
import dns.resolver
import dns.rrset

from core.models import Query


class Answer(dns.resolver.Answer):
    """扩展 dnspython Answer，暴露显式 rcode 并提供状态同步方法。"""

    def __init__(
        self,
        qname: dns.name.Name,
        rdtype: dns.rdatatype.RdataType,
        rdclass: dns.rdataclass.RdataClass,
        response: dns.message.QueryMessage,
        nameserver: str | None = None,
        port: int | None = None,
        *,
        expiration: float | None = None,
    ) -> None:
        super().__init__(
            qname,
            rdtype,
            rdclass,
            response,
            nameserver=nameserver,
            port=port,
        )
        self._rcode = dns.rcode.Rcode(self.response.rcode())
        if expiration is not None:
            self.expiration = expiration

    @property
    def rcode(self) -> dns.rcode.Rcode:
        return self._rcode

    @rcode.setter
    def rcode(self, value: dns.rcode.Rcode) -> None:
        self._rcode = dns.rcode.Rcode(value)

    @staticmethod
    def _invalidate_response_index(response: dns.message.Message) -> None:
        # 直接修改 section 后，message 内部索引需要失效，避免 resolve_chaining() 命中旧索引。
        cast(Any, response).index = None

    @staticmethod
    def _clone_message(response: dns.message.Message) -> dns.message.QueryMessage:
        return cast(dns.message.QueryMessage, dns.message.from_wire(response.to_wire()))

    @staticmethod
    def _clone_rrset(rrset: dns.rrset.RRset) -> dns.rrset.RRset:
        return cast(dns.rrset.RRset, rrset._clone())

    @staticmethod
    def _copy_request_message(query: Query) -> dns.message.QueryMessage:
        request = query.message
        if request is None:
            request = dns.message.make_query(query.qname, query.qtype, use_edns=True)
            request.id = query.txid
            if query.ecs is not None:
                request.use_edns(options=[query.ecs])
        return Answer._clone_message(request)

    @staticmethod
    def _resolve_rdclass(
        query: Query,
        response: dns.message.Message | None = None,
    ) -> dns.rdataclass.RdataClass:
        if response is not None and response.question:
            return response.question[0].rdclass
        if query.message is not None and query.message.question:
            return query.message.question[0].rdclass
        return dns.rdataclass.IN

    @staticmethod
    def _answer_sections(answer: dns.resolver.Answer) -> list[dns.rrset.RRset]:
        sections: list[dns.rrset.RRset] = []
        chain = getattr(answer, "chaining_result", None)
        if chain is not None and chain.cnames:
            sections.extend(chain.cnames)
        rrset = getattr(answer, "rrset", None)
        if rrset is not None:
            sections.append(rrset)
        return sections

    @classmethod
    def _build_message_from_answer(
        cls,
        answer: dns.resolver.Answer,
    ) -> dns.message.QueryMessage:
        response = cls._clone_message(answer.response)
        response.set_rcode(
            dns.rcode.Rcode(getattr(answer, "rcode", answer.response.rcode()))
        )
        response.answer = [
            cls._clone_rrset(rrset) for rrset in cls._answer_sections(answer)
        ]
        cls._invalidate_response_index(response)
        return response

    @classmethod
    def from_answer(cls, answer: dns.resolver.Answer) -> "Answer":
        response = cls._build_message_from_answer(answer)
        cloned = cls(
            answer.qname,
            answer.rdtype,
            answer.rdclass,
            response,
            nameserver=answer.nameserver,
            port=answer.port,
            expiration=answer.expiration,
        )
        if hasattr(answer, "rcode"):
            cloned.rcode = dns.rcode.Rcode(getattr(answer, "rcode"))
        return cloned

    @classmethod
    def from_response(
        cls,
        query: Query,
        response: dns.message.QueryMessage,
        *,
        nameserver: str | None = None,
        port: int | None = None,
    ) -> "Answer":
        return cls(
            query.qname,
            query.qtype,
            cls._resolve_rdclass(query, response),
            response,
            nameserver=nameserver,
            port=port,
        )

    @classmethod
    def from_query(
        cls,
        query: Query,
        *,
        rcode: dns.rcode.Rcode = dns.rcode.NOERROR,
        rrsets: Iterable[dns.rrset.RRset] | None = None,
        nameserver: str | None = None,
        port: int | None = None,
    ) -> "Answer":
        request = cls._copy_request_message(query)
        response = dns.message.make_response(request)
        response.set_rcode(rcode)
        if rrsets is not None:
            response.answer.extend(rrsets)
            cls._invalidate_response_index(response)
        return cls(
            query.qname,
            query.qtype,
            cls._resolve_rdclass(query, response),
            cast(dns.message.QueryMessage, response),
            nameserver=nameserver,
            port=port,
        )

    def clone(self) -> "Answer":
        return type(self).from_answer(self)

    def refresh_from_response(
        self,
        *,
        preserve_expiration: float | None = None,
    ) -> "Answer":
        self.chaining_result = self.response.resolve_chaining()
        self.canonical_name = self.chaining_result.canonical_name
        self.rrset = self.chaining_result.answer
        self.rcode = dns.rcode.Rcode(self.response.rcode())
        if preserve_expiration is None:
            self.expiration = time.time() + self.chaining_result.minimum_ttl
        else:
            self.expiration = preserve_expiration
        return self

    def set_rcode(
        self,
        rcode: dns.rcode.Rcode,
        *,
        update_message: bool = True,
        preserve_expiration: float | None = None,
    ) -> "Answer":
        self.rcode = dns.rcode.Rcode(rcode)
        if update_message:
            self.update_message(preserve_expiration=preserve_expiration)
        return self

    def replace_rrset(
        self,
        rrset: dns.rrset.RRset | None,
        *,
        update_message: bool = True,
        preserve_expiration: float | None = None,
    ) -> "Answer":
        self.rrset = rrset
        if update_message:
            self.update_message(preserve_expiration=preserve_expiration)
        return self

    def update_message(
        self,
        *,
        preserve_expiration: float | None = None,
    ) -> dns.message.QueryMessage:
        self.response = self.to_message()
        self.refresh_from_response(preserve_expiration=preserve_expiration)
        return self.response

    def to_message(self) -> dns.message.QueryMessage:
        return type(self)._build_message_from_answer(self)


def make_answer(
    query: Query,
    answer: dns.resolver.Answer | None = None,
    *,
    rcode: dns.rcode.Rcode | None = None,
    rrsets: Iterable[dns.rrset.RRset] | None = None,
    nameserver: str | None = None,
    port: int | None = None,
) -> dns.message.Message:
    """构造响应 Message。"""
    request = Answer._copy_request_message(query)
    if answer is None and (rcode is not None or rrsets is not None):
        answer = Answer.from_query(
            query,
            rcode=rcode if rcode is not None else dns.rcode.NOERROR,
            rrsets=rrsets,
            nameserver=nameserver,
            port=port,
        )

    if answer is None:
        response = dns.message.make_response(request)
        response.set_rcode(dns.rcode.SERVFAIL)
        return response

    if isinstance(answer, Answer):
        response = answer.to_message()
    else:
        response = Answer.from_answer(answer).to_message()

    # 上游/缓存中的响应事务 ID 不一定等于当前客户端请求，回包前必须按当前请求重写。
    response.id = request.id
    return response
