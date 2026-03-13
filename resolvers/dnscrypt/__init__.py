from __future__ import annotations

import asyncio
import binascii
import socket
import struct
from dataclasses import dataclass
from time import time
from typing import Final

import dns.asyncquery
import dns.flags
import dns.message
import dns.rdatatype
import dnsstamps
from dnsstamps import Protocol as StampProtocol

from Crypto.Cipher import ChaCha20_Poly1305
from Crypto.Cipher import Salsa20
from Crypto.Hash import Poly1305
from Crypto.PublicKey import ECC
from Crypto.Protocol import DH
from Crypto.Random import get_random_bytes
from Crypto.Signature import eddsa

DNSCRYPT_CERT_MAGIC: Final[bytes] = b"DNSC"
DNSCRYPT_RESOLVER_MAGIC: Final[bytes] = b"r6fnvWj8"
DNSCRYPT_ES_VERSION_V1: Final[int] = 0x0001
DNSCRYPT_ES_VERSION_V2: Final[int] = 0x0002

DNSCRYPT_CLIENT_NONCE_SIZE: Final[int] = 12
DNSCRYPT_NONCE_SIZE: Final[int] = 24
DNSCRYPT_QUERY_MIN_SIZE: Final[int] = 256
DNSCRYPT_QUERY_BLOCK_SIZE: Final[int] = 64
DNSCRYPT_TAG_SIZE: Final[int] = 16

DNSCRYPT_DEFAULT_PORT: Final[int] = 443
DNSCRYPT_CERT_REFRESH_SECONDS: Final[int] = 3600


class DnscryptError(RuntimeError):
    """DNSCrypt 处理异常。"""


@dataclass(slots=True, frozen=True)
class DnscryptStampInfo:
    host: str
    port: int
    provider_name: str
    provider_public_key: bytes


@dataclass(slots=True, frozen=True)
class _DnscryptCertificate:
    es_version: int
    resolver_public_key: bytes
    client_magic: bytes
    serial: int
    ts_start: int
    ts_end: int


def parse_dnscrypt_stamp(stamp: str) -> DnscryptStampInfo:
    """
    解析 DNS stamp，仅接受 DNSCrypt 协议。
    """
    parameter = dnsstamps.parse(stamp)
    if parameter.protocol != StampProtocol.DNSCRYPT:
        raise DnscryptError(f"不支持的 stamp 协议: {parameter.protocol}")

    host, port = _split_host_port(
        _normalize_text(parameter.address),
        default_port=DNSCRYPT_DEFAULT_PORT,
    )
    provider_name = _normalize_text(parameter.provider_name)
    provider_public_key = normalize_provider_public_key(parameter.public_key)

    if not provider_name:
        raise DnscryptError("stamp 中缺少 provider_name。")
    return DnscryptStampInfo(
        host=host,
        port=port,
        provider_name=provider_name,
        provider_public_key=provider_public_key,
    )


def normalize_provider_public_key(value: str | bytes) -> bytes:
    """
    标准化 provider 公钥到 32 字节原始数据。
    """
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


class AsyncDnscryptClient:
    """
    基于 DNSCrypt（v1/v2）的异步客户端。
    """

    def __init__(
        self,
        address: str,
        provider_name: str,
        provider_public_key: str | bytes,
        *,
        port: int = DNSCRYPT_DEFAULT_PORT,
        timeout: float = 5.0,
        tcp_only: bool = False,
    ) -> None:
        self._address = address.strip()
        self._provider_name = provider_name.strip()
        self._port = int(port)
        self._timeout = float(timeout)
        self._tcp_only = tcp_only

        if not self._address:
            raise DnscryptError("DNSCrypt address 不能为空。")
        if not self._provider_name:
            raise DnscryptError("DNSCrypt provider_name 不能为空。")
        if self._timeout <= 0:
            raise DnscryptError("DNSCrypt timeout 必须为正数。")

        provider_pk = normalize_provider_public_key(provider_public_key)
        self._provider_verifier = eddsa.new(
            eddsa.import_public_key(provider_pk),
            mode="rfc8032",
        )

        self._client_private_key = ECC.generate(curve="curve25519")
        self._client_public_key = self._client_private_key.public_key().export_key(
            format="raw"
        )

        self._certificate: _DnscryptCertificate | None = None
        self._shared_key: bytes | None = None
        self._next_refresh_at: float = 0.0
        self._cert_lock = asyncio.Lock()

    async def query(
        self,
        query: dns.message.Message,
        *,
        force_tcp: bool = False,
    ) -> dns.message.Message:
        await self._ensure_ready()
        use_tcp = force_tcp or self._tcp_only
        if use_tcp:
            return await self._query_tcp(query)

        try:
            response = await self._query_udp(query)
        except (OSError, TimeoutError, DnscryptError):
            return await self._query_tcp(query)

        if response.flags & dns.flags.TC:
            return await self._query_tcp(query)
        return response

    async def _ensure_ready(self) -> None:
        if self._is_certificate_fresh():
            return

        async with self._cert_lock:
            if self._is_certificate_fresh():
                return
            await self._refresh_certificate()

    def _is_certificate_fresh(self) -> bool:
        cert = self._certificate
        now = time()
        if cert is None:
            return False
        if not (cert.ts_start <= now <= cert.ts_end):
            return False
        return now < self._next_refresh_at and self._shared_key is not None

    async def _refresh_certificate(self) -> None:
        now = int(time())
        certificates = await self._fetch_certificates()
        candidates = [
            cert for cert in certificates if cert.ts_start <= now <= cert.ts_end
        ]
        if not candidates:
            raise DnscryptError("未找到有效的 DNSCrypt 证书。")

        selected = max(candidates, key=lambda cert: cert.serial)
        resolver_pub = DH.import_x25519_public_key(selected.resolver_public_key)
        shared_key = DH.key_agreement(
            static_priv=self._client_private_key,
            static_pub=resolver_pub,
            kdf=lambda x: x,
        )

        self._certificate = selected
        self._shared_key = self._derive_session_key(shared_key, selected.es_version)

        refresh_at = min(
            float(selected.ts_end - 60),
            time() + DNSCRYPT_CERT_REFRESH_SECONDS,
        )
        if refresh_at <= time():
            refresh_at = time() + 30
        self._next_refresh_at = refresh_at

    async def _fetch_certificates(self) -> list[_DnscryptCertificate]:
        question = dns.message.make_query(self._provider_name, dns.rdatatype.TXT)
        response: dns.message.Message | None = None

        try:
            response = await dns.asyncquery.udp(
                q=question,
                where=self._address,
                port=self._port,
                timeout=self._timeout,
                ignore_unexpected=True,
            )
            if response.flags & dns.flags.TC:
                response = await dns.asyncquery.tcp(
                    q=question,
                    where=self._address,
                    port=self._port,
                    timeout=self._timeout,
                )
        except Exception:
            response = await dns.asyncquery.tcp(
                q=question,
                where=self._address,
                port=self._port,
                timeout=self._timeout,
            )

        certs: list[_DnscryptCertificate] = []
        for rrset in response.answer:
            if rrset.rdtype != dns.rdatatype.TXT:
                continue
            for item in rrset:
                candidate = self._parse_certificate(b"".join(item.strings))
                if candidate is not None:
                    certs.append(candidate)
        if not certs:
            raise DnscryptError(
                f"{self._address}:{self._port} 未返回可用 DNSCrypt 证书。"
            )
        return certs

    def _parse_certificate(self, cert_bytes: bytes) -> _DnscryptCertificate | None:
        if len(cert_bytes) < 8 + 64 + 52:
            return None

        magic, es_version, _minor_version = struct.unpack("!4sHH", cert_bytes[:8])
        if magic != DNSCRYPT_CERT_MAGIC:
            return None
        if es_version not in (DNSCRYPT_ES_VERSION_V1, DNSCRYPT_ES_VERSION_V2):
            return None

        signed = cert_bytes[8:]
        signature = signed[:64]
        payload = signed[64:]
        if len(payload) < 52:
            return None

        try:
            self._provider_verifier.verify(payload, signature)
        except ValueError:
            return None

        resolver_pk, client_magic, serial, ts_start, ts_end = struct.unpack(
            "!32s8sIII",
            payload[:52],
        )
        return _DnscryptCertificate(
            es_version=es_version,
            resolver_public_key=resolver_pk,
            client_magic=client_magic,
            serial=serial,
            ts_start=ts_start,
            ts_end=ts_end,
        )

    async def _query_udp(self, query: dns.message.Message) -> dns.message.Message:
        packet, client_nonce = self._build_encrypted_query_packet(query)
        wire = await self._exchange_udp(packet)
        return self._decrypt_response(query, client_nonce, wire)

    async def _query_tcp(self, query: dns.message.Message) -> dns.message.Message:
        packet, client_nonce = self._build_encrypted_query_packet(query)
        wire = await self._exchange_tcp(packet)
        return self._decrypt_response(query, client_nonce, wire)

    def _build_encrypted_query_packet(
        self,
        query: dns.message.Message,
    ) -> tuple[bytes, bytes]:
        cert = self._certificate
        shared_key = self._shared_key
        if cert is None or shared_key is None:
            raise DnscryptError("DNSCrypt 客户端尚未初始化证书。")

        payload = _apply_query_padding(query.to_wire())
        client_nonce = get_random_bytes(DNSCRYPT_CLIENT_NONCE_SIZE)
        full_nonce = client_nonce + (b"\x00" * DNSCRYPT_CLIENT_NONCE_SIZE)

        encrypted_payload = _encrypt_payload(
            es_version=cert.es_version,
            key=shared_key,
            nonce=full_nonce,
            payload=payload,
        )

        packet = (
            cert.client_magic
            + self._client_public_key
            + client_nonce
            + encrypted_payload
        )
        return packet, client_nonce

    async def _exchange_udp(self, packet: bytes) -> bytes:
        loop = asyncio.get_running_loop()
        addrinfo = await loop.getaddrinfo(
            self._address,
            self._port,
            type=socket.SOCK_DGRAM,
        )
        if not addrinfo:
            raise DnscryptError("无法解析 DNSCrypt 上游地址。")

        family, socktype, proto, _, sockaddr = addrinfo[0]
        sock = socket.socket(family, socktype, proto)
        sock.setblocking(False)
        try:
            await asyncio.wait_for(
                loop.sock_sendto(sock, packet, sockaddr),
                timeout=self._timeout,
            )
            wire, _ = await asyncio.wait_for(
                loop.sock_recvfrom(sock, 65535),
                timeout=self._timeout,
            )
            return wire
        finally:
            sock.close()

    async def _exchange_tcp(self, packet: bytes) -> bytes:
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(self._address, self._port),
                timeout=self._timeout,
            )
        except Exception as exc:
            raise DnscryptError(f"DNSCrypt TCP 连接失败: {exc}") from exc

        try:
            frame = struct.pack("!H", len(packet)) + packet
            writer.write(frame)
            await asyncio.wait_for(writer.drain(), timeout=self._timeout)

            length_data = await asyncio.wait_for(
                reader.readexactly(2),
                timeout=self._timeout,
            )
            (length,) = struct.unpack("!H", length_data)
            if length <= 0:
                raise DnscryptError("DNSCrypt TCP 响应长度非法。")
            return await asyncio.wait_for(
                reader.readexactly(length),
                timeout=self._timeout,
            )
        except asyncio.IncompleteReadError as exc:
            raise DnscryptError("DNSCrypt TCP 响应不完整。") from exc
        finally:
            writer.close()
            await writer.wait_closed()

    def _decrypt_response(
        self,
        query: dns.message.Message,
        client_nonce: bytes,
        wire: bytes,
    ) -> dns.message.Message:
        shared_key = self._shared_key
        if shared_key is None:
            raise DnscryptError("DNSCrypt 会话密钥不存在。")
        if len(wire) < 8 + DNSCRYPT_NONCE_SIZE + DNSCRYPT_TAG_SIZE:
            raise DnscryptError("DNSCrypt 响应长度不足。")

        magic = wire[:8]
        if magic != DNSCRYPT_RESOLVER_MAGIC:
            raise DnscryptError("DNSCrypt 响应 magic 不匹配。")

        nonce = wire[8 : 8 + DNSCRYPT_NONCE_SIZE]
        if nonce[:DNSCRYPT_CLIENT_NONCE_SIZE] != client_nonce:
            raise DnscryptError("DNSCrypt 响应 nonce 与请求不匹配。")

        encrypted = wire[8 + DNSCRYPT_NONCE_SIZE :]
        cert = self._certificate
        if cert is None:
            raise DnscryptError("DNSCrypt 证书状态丢失。")

        try:
            plaintext = _decrypt_payload(
                es_version=cert.es_version,
                key=shared_key,
                nonce=nonce,
                payload=encrypted,
            )
        except ValueError as exc:
            raise DnscryptError("DNSCrypt 响应认证失败。") from exc

        response = dns.message.from_wire(
            _remove_query_padding(plaintext),
            ignore_trailing=True,
        )
        if not query.is_response(response):
            raise DnscryptError("DNSCrypt 响应与请求不匹配。")
        return response

    @staticmethod
    def _derive_session_key(shared_key: bytes, es_version: int) -> bytes:
        if es_version == DNSCRYPT_ES_VERSION_V1:
            return _hsalsa20(
                key=shared_key,
                nonce16=(b"\x00" * 16),
            )
        return shared_key


def _normalize_text(value: str | bytes) -> str:
    if isinstance(value, bytes):
        return value.decode("utf-8", errors="ignore").strip()
    return value.strip()


def _split_host_port(
    address: str,
    *,
    default_port: int,
) -> tuple[str, int]:
    text = address.strip()
    if not text:
        raise DnscryptError("address 不能为空。")

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


def _apply_query_padding(payload: bytes) -> bytes:
    base_len = max(DNSCRYPT_QUERY_MIN_SIZE, len(payload) + 1)
    target_len = (
        (base_len + DNSCRYPT_QUERY_BLOCK_SIZE - 1) // DNSCRYPT_QUERY_BLOCK_SIZE
    ) * DNSCRYPT_QUERY_BLOCK_SIZE
    pad_len = target_len - len(payload)
    if pad_len <= 0:
        pad_len = 1
    return payload + b"\x80" + (b"\x00" * (pad_len - 1))


def _remove_query_padding(payload: bytes) -> bytes:
    index = len(payload) - 1
    while index >= 0 and payload[index] == 0:
        index -= 1
    if index >= 0 and payload[index] == 0x80:
        return payload[:index]
    return payload


def _encrypt_payload(
    *,
    es_version: int,
    key: bytes,
    nonce: bytes,
    payload: bytes,
) -> bytes:
    if es_version == DNSCRYPT_ES_VERSION_V1:
        return _xsalsa20poly1305_encrypt(key=key, nonce=nonce, plaintext=payload)
    if es_version == DNSCRYPT_ES_VERSION_V2:
        cipher = ChaCha20_Poly1305.new(key=key, nonce=nonce)
        ciphertext, tag = cipher.encrypt_and_digest(payload)
        return tag + ciphertext
    raise DnscryptError(f"不支持的 DNSCrypt 证书版本: {es_version}")


def _decrypt_payload(
    *,
    es_version: int,
    key: bytes,
    nonce: bytes,
    payload: bytes,
) -> bytes:
    if len(payload) < DNSCRYPT_TAG_SIZE:
        raise ValueError("payload too short")
    if es_version == DNSCRYPT_ES_VERSION_V1:
        return _xsalsa20poly1305_decrypt(key=key, nonce=nonce, payload=payload)
    if es_version == DNSCRYPT_ES_VERSION_V2:
        tag = payload[:DNSCRYPT_TAG_SIZE]
        ciphertext = payload[DNSCRYPT_TAG_SIZE:]
        cipher = ChaCha20_Poly1305.new(key=key, nonce=nonce)
        return cipher.decrypt_and_verify(ciphertext, tag)
    raise DnscryptError(f"不支持的 DNSCrypt 证书版本: {es_version}")


def _xsalsa20poly1305_encrypt(
    *,
    key: bytes,
    nonce: bytes,
    plaintext: bytes,
) -> bytes:
    stream = Salsa20.new(
        key=_hsalsa20(key=key, nonce16=nonce[:16]),
        nonce=nonce[16:],
    )
    poly_key = stream.encrypt(b"\x00" * 32)
    ciphertext = stream.encrypt(plaintext)
    mac = Poly1305.Poly1305_MAC(poly_key[:16], poly_key[16:], ciphertext)
    return mac.digest() + ciphertext


def _xsalsa20poly1305_decrypt(
    *,
    key: bytes,
    nonce: bytes,
    payload: bytes,
) -> bytes:
    tag = payload[:DNSCRYPT_TAG_SIZE]
    ciphertext = payload[DNSCRYPT_TAG_SIZE:]

    stream = Salsa20.new(
        key=_hsalsa20(key=key, nonce16=nonce[:16]),
        nonce=nonce[16:],
    )
    poly_key = stream.encrypt(b"\x00" * 32)
    mac = Poly1305.Poly1305_MAC(poly_key[:16], poly_key[16:], ciphertext)
    mac.verify(tag)
    return stream.encrypt(ciphertext)


def _hsalsa20(*, key: bytes, nonce16: bytes) -> bytes:
    if len(key) != 32:
        raise ValueError("HSalsa20 key must be 32 bytes")
    if len(nonce16) != 16:
        raise ValueError("HSalsa20 nonce must be 16 bytes")

    sigma = b"expand 32-byte k"
    k = struct.unpack("<8I", key)
    n = struct.unpack("<4I", nonce16)
    c = struct.unpack("<4I", sigma)
    state = [
        c[0],
        k[0],
        k[1],
        k[2],
        k[3],
        c[1],
        n[0],
        n[1],
        n[2],
        n[3],
        c[2],
        k[4],
        k[5],
        k[6],
        k[7],
        c[3],
    ]
    working = state[:]

    for _ in range(10):
        _salsa20_rounds(working)

    output = (
        working[0],
        working[5],
        working[10],
        working[15],
        working[6],
        working[7],
        working[8],
        working[9],
    )
    return struct.pack("<8I", *output)


def _salsa20_rounds(x: list[int]) -> None:
    x[4] ^= _rol32((x[0] + x[12]) & 0xFFFFFFFF, 7)
    x[8] ^= _rol32((x[4] + x[0]) & 0xFFFFFFFF, 9)
    x[12] ^= _rol32((x[8] + x[4]) & 0xFFFFFFFF, 13)
    x[0] ^= _rol32((x[12] + x[8]) & 0xFFFFFFFF, 18)

    x[9] ^= _rol32((x[5] + x[1]) & 0xFFFFFFFF, 7)
    x[13] ^= _rol32((x[9] + x[5]) & 0xFFFFFFFF, 9)
    x[1] ^= _rol32((x[13] + x[9]) & 0xFFFFFFFF, 13)
    x[5] ^= _rol32((x[1] + x[13]) & 0xFFFFFFFF, 18)

    x[14] ^= _rol32((x[10] + x[6]) & 0xFFFFFFFF, 7)
    x[2] ^= _rol32((x[14] + x[10]) & 0xFFFFFFFF, 9)
    x[6] ^= _rol32((x[2] + x[14]) & 0xFFFFFFFF, 13)
    x[10] ^= _rol32((x[6] + x[2]) & 0xFFFFFFFF, 18)

    x[3] ^= _rol32((x[15] + x[11]) & 0xFFFFFFFF, 7)
    x[7] ^= _rol32((x[3] + x[15]) & 0xFFFFFFFF, 9)
    x[11] ^= _rol32((x[7] + x[3]) & 0xFFFFFFFF, 13)
    x[15] ^= _rol32((x[11] + x[7]) & 0xFFFFFFFF, 18)

    x[1] ^= _rol32((x[0] + x[3]) & 0xFFFFFFFF, 7)
    x[2] ^= _rol32((x[1] + x[0]) & 0xFFFFFFFF, 9)
    x[3] ^= _rol32((x[2] + x[1]) & 0xFFFFFFFF, 13)
    x[0] ^= _rol32((x[3] + x[2]) & 0xFFFFFFFF, 18)

    x[6] ^= _rol32((x[5] + x[4]) & 0xFFFFFFFF, 7)
    x[7] ^= _rol32((x[6] + x[5]) & 0xFFFFFFFF, 9)
    x[4] ^= _rol32((x[7] + x[6]) & 0xFFFFFFFF, 13)
    x[5] ^= _rol32((x[4] + x[7]) & 0xFFFFFFFF, 18)

    x[11] ^= _rol32((x[10] + x[9]) & 0xFFFFFFFF, 7)
    x[8] ^= _rol32((x[11] + x[10]) & 0xFFFFFFFF, 9)
    x[9] ^= _rol32((x[8] + x[11]) & 0xFFFFFFFF, 13)
    x[10] ^= _rol32((x[9] + x[8]) & 0xFFFFFFFF, 18)

    x[12] ^= _rol32((x[15] + x[14]) & 0xFFFFFFFF, 7)
    x[13] ^= _rol32((x[12] + x[15]) & 0xFFFFFFFF, 9)
    x[14] ^= _rol32((x[13] + x[12]) & 0xFFFFFFFF, 13)
    x[15] ^= _rol32((x[14] + x[13]) & 0xFFFFFFFF, 18)


def _rol32(value: int, shift: int) -> int:
    value &= 0xFFFFFFFF
    return ((value << shift) | (value >> (32 - shift))) & 0xFFFFFFFF


__all__ = [
    "AsyncDnscryptClient",
    "DnscryptError",
    "DnscryptStampInfo",
    "normalize_provider_public_key",
    "parse_dnscrypt_stamp",
]
