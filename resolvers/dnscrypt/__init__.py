from __future__ import annotations

import asyncio
import binascii
import logging
import socket
import struct
from time import time
from typing import Optional, Union

import dns.message
import dns.name
import dns.query
import dns.rdataclass
import dns.rdatatype
import dns.resolver
from dns.exception import FormError, Timeout
from dns.flags import TC
from dns.inet import is_multicast
from dns.message import QueryMessage
from dns.rcode import NXDOMAIN, YXDOMAIN
from nacl.encoding import HexEncoder
from nacl.exceptions import BadSignatureError
from nacl.public import Box, PrivateKey, PublicKey
from nacl.signing import VerifyKey
from nacl.utils import random

DNSCRYPT_MINIMUM_SIZE = 256
DNSCRYPT_MODULO_SIZE = 64
DNSCRYPT_NONCE_SIZE = 12
DNSCRYPT_RESOLVER_MAGIC = b"r6fnvWj8"
DNSCRYPT_CERT_MAGIC = b"DNSC"


class DnscryptError(RuntimeError):
    """DNSCrypt 处理异常。"""


def normalize_provider_public_key(value: str | bytes) -> bytes:
    """标准化 provider 公钥到 32 字节原始数据。"""
    if isinstance(value, bytes):
        if len(value) == 32:
            return value
        try:
            text = value.decode("ascii", errors="strict")
        except UnicodeDecodeError as exc:
            raise DnscryptError("provider 公钥必须是 32 字节原始值或十六进制文本。") from exc
    else:
        text = value

    normalized = text.strip().replace(":", "").replace(" ", "")
    if not normalized:
        raise DnscryptError("provider 公钥为空。")
    try:
        decoded = binascii.unhexlify(normalized)
    except binascii.Error as exc:
        raise DnscryptError("provider 公钥十六进制格式不合法。") from exc
    if len(decoded) != 32:
        raise DnscryptError(f"provider 公钥长度错误: {len(decoded)}，期望 32 字节。")
    return decoded


class Resolver:
    """原始同步 DNSCrypt Resolver。"""

    def __init__(
        self,
        address: str,
        provider_name: str,
        provider_pk: str | bytes,
        private_key: Optional[str] = None,
        port: int = 53,
        timeout: float = 5,
    ) -> None:
        host, parsed_port = _split_host_port(address, default_port=port)
        self.address: str = host
        self.port: int = parsed_port
        self.publickey: Optional[PublicKey] = None
        self.client_magic: bytes = b""
        self.serial: Optional[int] = None
        self.tcp_only: bool = False
        self.timeout: float = timeout
        self._provider_name = provider_name

        if not private_key:
            self.private: PrivateKey = PrivateKey.generate()
            logging.info("Private Key: %s", self.private.encode(HexEncoder))
            logging.info("Public Key : %s", self.private.public_key.encode(HexEncoder))
        else:
            self.private = PrivateKey(private_key, HexEncoder)

        vk = self._build_verify_key(provider_name=provider_name, provider_pk=provider_pk)
        self._bootstrap(vk)
        self._secretbox: Box = Box(self.private, self.publickey)  # type: ignore[arg-type]

    def _build_verify_key(self, provider_name: str, provider_pk: str | bytes) -> VerifyKey:
        try:
            provider_public_key = normalize_provider_public_key(provider_pk)
            return VerifyKey(provider_public_key)
        except DnscryptError:
            # 兼容历史行为：provider_pk 也可作为 TXT 记录域名。
            try:
                answer = dns.resolver.resolve(str(provider_pk), rdtype=dns.rdatatype.TXT)
                fp = b"".join(answer.response.answer[0][0].strings)
                return VerifyKey(normalize_provider_public_key(fp))
            except Exception as exc:
                raise TypeError(f"No valid public key for {provider_name}") from exc

    def _bootstrap(self, verify_key: VerifyKey) -> None:
        question = dns.message.make_query(self._provider_name, rdtype=dns.rdatatype.TXT)
        try:
            answer = dns.query.udp(
                question,
                self.address,
                port=self.port,
                timeout=self.timeout,
            )
            if answer.flags & TC:
                answer = dns.query.tcp(
                    question,
                    self.address,
                    port=self.port,
                    timeout=self.timeout,
                )
        except Timeout:
            logging.debug("DNSCrypt certificate query failed over UDP, falling back to TCP")
            self.tcp_only = True
            answer = dns.query.tcp(
                question,
                self.address,
                port=self.port,
                timeout=self.timeout,
            )

        self._load_certificate(answer=answer, verify_key=verify_key)
        if not self.publickey:
            raise TypeError(
                "No valid certificate found for "
                f"{self.address}:{self.port} ({self._provider_name})"
            )
        logging.info("Selected certificate %s", self.serial)

    def _load_certificate(self, answer: dns.message.Message, verify_key: VerifyKey) -> None:
        now = time()
        for rrset in answer.answer:
            if rrset.rdtype != dns.rdatatype.TXT:
                continue
            for possible in rrset:
                cert_blob = b"".join(possible.strings)
                if len(cert_blob) <= 8:
                    continue

                logging.debug("Possible cert %s", cert_blob.hex())
                magic, es_version, _minor_version, signed = struct.unpack(
                    f"!4sHH{len(cert_blob) - 8}s",
                    cert_blob,
                )
                if magic != DNSCRYPT_CERT_MAGIC:
                    logging.warning("Bad certificate magic: %s", magic)
                    continue
                if es_version != 1:
                    logging.warning("Not using es_version 1")
                    continue

                try:
                    data = verify_key.verify(signed)
                except BadSignatureError:
                    logging.warning("Signature did not match")
                    continue

                if len(data) < 52:
                    continue
                pk, client_magic, serial, start, expire, _ = struct.unpack(
                    f"!32s8sIII{len(data) - 52}s",
                    data,
                )
                if start > now:
                    logging.warning("Certification not yet valid: %s", start)
                    continue
                if expire < now:
                    logging.warning("Certificate expired %s", expire)
                    continue
                if self.serial is None or serial > self.serial:
                    self.publickey = PublicKey(pk)
                    self.serial = serial
                    self.client_magic = client_magic

    def query(
        self,
        qname: Union[dns.name.Name, str],
        rdtype: Union[dns.rdatatype.RdataType, str] = dns.rdatatype.A,
        rdclass: Union[dns.rdataclass.RdataClass, str] = dns.rdataclass.IN,
        tcp: bool = False,
        source: Optional[str] = None,
        raise_on_no_answer: bool = True,
        source_port: int = 0,
    ) -> dns.resolver.Answer:
        qname, rdtype, rdclass, query = _build_query_message(
            qname=qname,
            rdtype=rdtype,
            rdclass=rdclass,
        )
        response = self.query_message(
            query=query,
            tcp=tcp,
            source=source,
            source_port=source_port,
        )
        _raise_for_response_code(response=response, qname=qname)
        return dns.resolver.Answer(
            qname,
            rdtype,
            rdclass,
            response,
            raise_on_no_answer,
        )

    def query_message(
        self,
        query: QueryMessage,
        tcp: bool = False,
        source: Optional[str] = None,
        source_port: int = 0,
    ) -> dns.message.Message:
        response: dns.message.Message | None = None
        try:
            tcp_attempt = False
            if tcp or self.tcp_only:
                tcp_attempt = True
                response = self.tcp(
                    query,
                    timeout=self.timeout,
                    source=source,
                    source_port=source_port,
                )
            else:
                response = self.udp(
                    query,
                    timeout=self.timeout,
                    source=source,
                    source_port=source_port,
                )
                if response.flags & TC:
                    tcp_attempt = True
                    response = self.tcp(
                        query,
                        timeout=self.timeout,
                        source=source,
                        source_port=source_port,
                    )
        except (
            socket.error,
            Timeout,
            FormError,
            dns.query.UnexpectedSource,
            EOFError,
        ) as ex:
            raise dns.resolver.NoNameservers(
                request=query,
                errors=[(self.address, tcp_attempt, self.port, ex, response)],
            ) from ex
        return response

    def _encrypt_query(self, query: QueryMessage) -> bytes:
        if not self.client_magic:
            raise DnscryptError("DNSCrypt client not initialized with certificate.")

        message = _pad_query(query.to_wire())
        nonce = random(DNSCRYPT_NONCE_SIZE)
        encrypted = self._secretbox.encrypt(message, nonce + b"\x00" * DNSCRYPT_NONCE_SIZE)
        # Remove the server nonce.
        encrypted = encrypted[0:12] + encrypted[24:]
        return self.client_magic + self.private.public_key.encode() + encrypted

    def _decrypt_response(self, wire: bytes, one_rr_per_rrset: bool) -> dns.message.Message:
        if len(wire) <= 32:
            raise TypeError("Invalid DNSCrypt response size")

        magic, nonce, data = struct.unpack(f"!8s24s{len(wire) - 32}s", wire)
        if magic != DNSCRYPT_RESOLVER_MAGIC:
            raise TypeError("This does not appear to be DNSCrypt")

        payload = self._secretbox.decrypt(data, nonce)
        return dns.message.from_wire(
            payload,
            ignore_trailing=True,
            one_rr_per_rrset=one_rr_per_rrset,
        )

    def tcp(
        self,
        query: QueryMessage,
        timeout: Optional[float] = None,
        af: Optional[int] = None,
        source: Optional[str] = None,
        source_port: int = 0,
        one_rr_per_rrset: bool = False,
    ) -> dns.message.Message:
        wire = self._encrypt_query(query)
        af, destination, source = dns.query._destination_and_source(
            self.address,
            self.port,
            source,
            source_port,
            where_must_be_address=False,
        )
        s = dns.query.socket_factory(af, socket.SOCK_STREAM)
        begin_time = None
        try:
            _, expiration = dns.query._compute_times(timeout)
            s.setblocking(False)
            if source is not None:
                s.bind(source)
            dns.query._connect(s, destination)
            tcpmsg = struct.pack("!H", len(wire)) + wire
            begin_time = time()
            dns.query._net_write(s, tcpmsg, expiration)
            ldata = dns.query._net_read(s, 2, expiration)
            (length,) = struct.unpack("!H", ldata)
            wire = dns.query._net_read(s, length, expiration)
        finally:
            response_time = 0 if begin_time is None else time() - begin_time
            s.close()

        response = self._decrypt_response(wire, one_rr_per_rrset)
        response.time = response_time
        if not query.is_response(response):
            raise dns.query.BadResponse
        return response

    def udp(
        self,
        query: QueryMessage,
        timeout: Optional[float] = None,
        af: Optional[int] = None,
        source: Optional[str] = None,
        source_port: int = 0,
        ignore_unexpected: bool = False,
        one_rr_per_rrset: bool = False,
    ) -> dns.message.Message:
        wire = self._encrypt_query(query)
        af, destination, source = dns.query._destination_and_source(
            self.address,
            self.port,
            source,
            source_port,
            where_must_be_address=False,
        )

        s = dns.query.socket_factory(af, socket.SOCK_DGRAM)
        begin_time = None
        try:
            _, expiration = dns.query._compute_times(timeout)
            s.setblocking(False)
            if source is not None:
                s.bind(source)
            dns.query._wait_for_writable(s, expiration)
            begin_time = time()
            s.sendto(wire, destination)
            while True:
                dns.query._wait_for_readable(s, expiration)
                wire, from_address = s.recvfrom(65535)
                if dns.query._addresses_equal(af, from_address, destination) or (
                    is_multicast(self.address) and from_address[1:] == destination[1:]
                ):
                    break
                if not ignore_unexpected:
                    raise dns.query.UnexpectedSource(
                        f"got a response from {from_address} instead of {destination}"
                    )
        finally:
            response_time = 0 if begin_time is None else time() - begin_time
            s.close()

        response = self._decrypt_response(wire, one_rr_per_rrset)
        response.time = response_time
        if not query.is_response(response):
            raise dns.query.BadResponse
        return response


class AsyncResolver(Resolver):
    """异步 DNSCrypt Resolver（基于同步实现包装，兼容 UDP/TCP）。"""

    @classmethod
    async def create(
        cls,
        address: str,
        provider_name: str,
        provider_pk: str | bytes,
        private_key: Optional[str] = None,
        port: int = 53,
        timeout: float = 5,
    ) -> "AsyncResolver":
        return await asyncio.to_thread(
            cls,
            address,
            provider_name,
            provider_pk,
            private_key,
            port,
            timeout,
        )

    async def query(
        self,
        qname: Union[dns.name.Name, str],
        rdtype: Union[dns.rdatatype.RdataType, str] = dns.rdatatype.A,
        rdclass: Union[dns.rdataclass.RdataClass, str] = dns.rdataclass.IN,
        tcp: bool = False,
        source: Optional[str] = None,
        raise_on_no_answer: bool = True,
        source_port: int = 0,
    ) -> dns.resolver.Answer:
        qname, rdtype, rdclass, query = _build_query_message(
            qname=qname,
            rdtype=rdtype,
            rdclass=rdclass,
        )
        response = await self.query_message(
            query=query,
            tcp=tcp,
            source=source,
            source_port=source_port,
        )
        _raise_for_response_code(response=response, qname=qname)
        return dns.resolver.Answer(
            qname,
            rdtype,
            rdclass,
            response,
            raise_on_no_answer,
        )

    async def query_message(
        self,
        query: QueryMessage,
        tcp: bool = False,
        source: Optional[str] = None,
        source_port: int = 0,
    ) -> dns.message.Message:
        response: dns.message.Message | None = None
        try:
            tcp_attempt = False
            if tcp or self.tcp_only:
                tcp_attempt = True
                response = await self.tcp(
                    query,
                    timeout=self.timeout,
                    source=source,
                    source_port=source_port,
                )
            else:
                response = await self.udp(
                    query,
                    timeout=self.timeout,
                    source=source,
                    source_port=source_port,
                )
                if response.flags & TC:
                    tcp_attempt = True
                    response = await self.tcp(
                        query,
                        timeout=self.timeout,
                        source=source,
                        source_port=source_port,
                    )
        except (
            socket.error,
            TimeoutError,
            Timeout,
            FormError,
            dns.query.UnexpectedSource,
            EOFError,
        ) as ex:
            raise dns.resolver.NoNameservers(
                request=query,
                errors=[(self.address, tcp_attempt, self.port, ex, response)],
            ) from ex
        return response

    async def tcp(
        self,
        query: QueryMessage,
        timeout: Optional[float] = None,
        af: Optional[int] = None,
        source: Optional[str] = None,
        source_port: int = 0,
        one_rr_per_rrset: bool = False,
    ) -> dns.message.Message:
        return await asyncio.to_thread(
            Resolver.tcp,
            self,
            query,
            timeout,
            af,
            source,
            source_port,
            one_rr_per_rrset,
        )

    async def udp(
        self,
        query: QueryMessage,
        timeout: Optional[float] = None,
        af: Optional[int] = None,
        source: Optional[str] = None,
        source_port: int = 0,
        ignore_unexpected: bool = False,
        one_rr_per_rrset: bool = False,
    ) -> dns.message.Message:
        return await asyncio.to_thread(
            Resolver.udp,
            self,
            query,
            timeout,
            af,
            source,
            source_port,
            ignore_unexpected,
            one_rr_per_rrset,
        )


async def async_query(
    resolver: AsyncResolver,
    query: QueryMessage,
    *,
    tcp: bool = False,
    source: Optional[str] = None,
    source_port: int = 0,
) -> dns.message.Message:
    """异步查询入口，自动处理 UDP/TCP。"""
    return await resolver.query_message(
        query=query,
        tcp=tcp,
        source=source,
        source_port=source_port,
    )


async def async_tcp(
    resolver: AsyncResolver,
    query: QueryMessage,
    *,
    timeout: Optional[float] = None,
    source: Optional[str] = None,
    source_port: int = 0,
    one_rr_per_rrset: bool = False,
) -> dns.message.Message:
    """强制使用 TCP 异步查询。"""
    return await resolver.tcp(
        query=query,
        timeout=timeout,
        source=source,
        source_port=source_port,
        one_rr_per_rrset=one_rr_per_rrset,
    )


async def async_udp(
    resolver: AsyncResolver,
    query: QueryMessage,
    *,
    timeout: Optional[float] = None,
    source: Optional[str] = None,
    source_port: int = 0,
    ignore_unexpected: bool = False,
    one_rr_per_rrset: bool = False,
) -> dns.message.Message:
    """强制使用 UDP 异步查询。"""
    return await resolver.udp(
        query=query,
        timeout=timeout,
        source=source,
        source_port=source_port,
        ignore_unexpected=ignore_unexpected,
        one_rr_per_rrset=one_rr_per_rrset,
    )


def _build_query_message(
    qname: Union[dns.name.Name, str],
    rdtype: Union[dns.rdatatype.RdataType, str],
    rdclass: Union[dns.rdataclass.RdataClass, str],
) -> tuple[dns.name.Name, dns.rdatatype.RdataType, dns.rdataclass.RdataClass, QueryMessage]:
    if isinstance(qname, str):
        qname = dns.name.from_text(qname, None)
    if isinstance(rdtype, str):
        rdtype = dns.rdatatype.from_text(rdtype)
    if dns.rdatatype.is_metatype(rdtype):
        raise dns.resolver.NoMetaqueries
    if isinstance(rdclass, str):
        rdclass = dns.rdataclass.from_text(rdclass)
    if dns.rdataclass.is_metaclass(rdclass):
        raise dns.resolver.NoMetaqueries
    if not qname.is_absolute():
        qname = qname.concatenate(dns.name.root)

    query = dns.message.make_query(qname, rdtype=rdtype, rdclass=rdclass)
    return qname, rdtype, rdclass, query


def _raise_for_response_code(response: dns.message.Message, qname: dns.name.Name) -> None:
    rcode = response.rcode()
    if rcode == YXDOMAIN:
        raise dns.resolver.YXDOMAIN()
    if rcode == NXDOMAIN:
        raise dns.resolver.NXDOMAIN(qnames=[qname], responses=[response])


def _pad_query(payload: bytes) -> bytes:
    base_len = max(DNSCRYPT_MINIMUM_SIZE, len(payload) + 1)
    target_len = (
        (base_len + DNSCRYPT_MODULO_SIZE - 1) // DNSCRYPT_MODULO_SIZE
    ) * DNSCRYPT_MODULO_SIZE
    pad_len = target_len - len(payload)
    return payload + b"\x80" + (b"\x00" * (pad_len - 1))


def _split_host_port(address: str, *, default_port: int) -> tuple[str, int]:
    text = address.strip()
    if not text:
        return "", default_port

    if text.startswith("["):
        right = text.find("]")
        if right <= 1:
            raise DnscryptError(f"非法 IPv6 address: {address}")
        host = text[1:right]
        rest = text[right + 1 :]
        if not rest:
            return host, default_port
        if not rest.startswith(":"):
            raise DnscryptError(f"非法 address 端口格式: {address}")
        return host, _parse_port(rest[1:], default_port=default_port)

    if text.count(":") == 1:
        host_part, port_part = text.rsplit(":", 1)
        if port_part.isdigit():
            return host_part, _parse_port(port_part, default_port=default_port)

    return text, default_port


def _parse_port(value: str, *, default_port: int) -> int:
    if not value:
        return default_port
    port = int(value)
    if not (1 <= port <= 65535):
        raise DnscryptError(f"端口超出范围: {port}")
    return port


__all__ = [
    "Resolver",
    "AsyncResolver",
    "DnscryptError",
    "normalize_provider_public_key",
    "async_query",
    "async_tcp",
    "async_udp",
]
