from __future__ import annotations

from dataclasses import dataclass, field
from ipaddress import ip_network
from pathlib import Path
from typing import Any, Mapping
import os
from collections.abc import Sequence

try:
    import yaml
except Exception:  # pragma: no cover
    yaml = None

DEFAULT_CONFIG_PATH = "config.yaml"


@dataclass(frozen=True, slots=True)
class ServerConfig:
    host: str = "127.0.0.1"
    port: int = 5353
    max_packet_size: int = 4096


@dataclass(frozen=True, slots=True)
class UpstreamConfig:
    host: str
    protocol: str = "udp"
    port: int = 53
    timeout: float = 2.0
    ecs: str | None = None
    verify: bool | str = True
    hostname: str | None = None
    http_host: str | None = None
    path: str = "/dns-query"


@dataclass(frozen=True, slots=True)
class LoggingConfig:
    level: str = "INFO"


@dataclass(frozen=True, slots=True)
class CacheConfig:
    enabled: bool = True
    max_size: int = 10000


def _default_upstreams() -> tuple[UpstreamConfig, ...]:
    return (
        UpstreamConfig(host="223.5.5.5", protocol="udp", port=53, timeout=2.0),
        UpstreamConfig(host="8.8.8.8", protocol="udp", port=53, timeout=2.0),
    )


@dataclass(frozen=True, slots=True)
class AppConfig:
    server: ServerConfig = field(default_factory=ServerConfig)
    upstreams: tuple[UpstreamConfig, ...] = field(default_factory=_default_upstreams)
    logging: LoggingConfig = field(default_factory=LoggingConfig)
    cache: CacheConfig = field(default_factory=CacheConfig)


def load_config(path: str | Path | None = None) -> AppConfig:
    config_path = Path(path or os.getenv("MYDNS_CONFIG", DEFAULT_CONFIG_PATH))
    if not config_path.exists():
        return AppConfig()

    if yaml is None:
        raise RuntimeError(
            "检测到 YAML 配置文件，但缺少依赖 `PyYAML`。请先安装：`pip install pyyaml`。"
        )

    with config_path.open("r", encoding="utf-8") as f:
        raw = yaml.safe_load(f) or {}

    if not isinstance(raw, Mapping):
        raise ValueError("Config root must be a mapping.")

    config = AppConfig(
        server=_parse_server(raw.get("server")),
        upstreams=_parse_upstreams(raw.get("upstreams")),
        logging=_parse_logging(raw.get("logging")),
        cache=_parse_cache(raw.get("cache")),
    )
    _validate_config(config)
    return config


def _parse_server(raw: Any) -> ServerConfig:
    if not isinstance(raw, Mapping):
        return ServerConfig()
    return ServerConfig(
        host=str(raw.get("host", "127.0.0.1")),
        port=int(raw.get("port", 5353)),
        max_packet_size=int(raw.get("max_packet_size", 4096)),
    )


def _parse_upstreams(raw: Any) -> tuple[UpstreamConfig, ...]:
    if raw is None:
        return _default_upstreams()
    if not isinstance(raw, Sequence) or isinstance(raw, (str, bytes)):
        raise ValueError("`upstreams` must be a list.")

    upstreams: list[UpstreamConfig] = []
    for index, item in enumerate(raw):
        if not isinstance(item, Mapping):
            raise ValueError(f"`upstreams[{index}]` must be a mapping.")
        host = str(item.get("host", item.get("address", ""))).strip()
        if not host:
            raise ValueError(f"`upstreams[{index}].host` (or `address`) is required.")
        protocol = str(item.get("protocol", "udp")).strip().lower()
        default_port = _default_port_for_protocol(protocol)
        raw_hostname = item.get("hostname", item.get("sni"))
        raw_http_host = item.get("http_host", item.get("httpHost"))
        raw_path = item.get("path")
        raw_ecs = item.get("ecs", item.get("client_subnet"))
        try:
            parsed_ecs = _parse_ecs(raw_ecs)
        except ValueError as exc:
            raise ValueError(
                f"`upstreams[{index}].ecs` is invalid: {raw_ecs}"
            ) from exc
        upstreams.append(
            UpstreamConfig(
                host=host,
                protocol=protocol,
                port=int(item.get("port", default_port)),
                timeout=float(item.get("timeout", 2.0)),
                ecs=parsed_ecs,
                verify=_parse_verify(item.get("verify", True)),
                hostname=(
                    str(raw_hostname).strip()
                    if raw_hostname is not None and str(raw_hostname).strip()
                    else None
                ),
                http_host=(
                    str(raw_http_host).strip()
                    if raw_http_host is not None and str(raw_http_host).strip()
                    else None
                ),
                path=_normalize_doh_path(raw_path),
            )
        )

    if not upstreams:
        raise ValueError("At least one upstream DNS server is required.")
    return tuple(upstreams)


def _parse_logging(raw: Any) -> LoggingConfig:
    if not isinstance(raw, Mapping):
        return LoggingConfig()
    return LoggingConfig(level=str(raw.get("level", "INFO")))


def _parse_cache(raw: Any) -> CacheConfig:
    if not isinstance(raw, Mapping):
        return CacheConfig()
    return CacheConfig(
        enabled=_as_bool(raw.get("enabled", True)),
        max_size=int(raw.get("max_size", 10000)),
    )


def _as_bool(value: Any) -> bool:
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        return value.strip().lower() in {"1", "true", "yes", "on"}
    return bool(value)


def _parse_verify(value: Any) -> bool | str:
    if isinstance(value, bool):
        return value
    if value is None:
        return True
    if isinstance(value, str):
        normalized = value.strip()
        lowered = normalized.lower()
        if lowered in {"1", "true", "yes", "on"}:
            return True
        if lowered in {"0", "false", "no", "off"}:
            return False
        if not normalized:
            return True
        return normalized
    return bool(value)


def _default_port_for_protocol(protocol: str) -> int:
    if protocol == "dot" or protocol == "doq":
        return 853
    if protocol == "doh":
        return 443
    if protocol == "tcp":
        return 53
    return 53


def _normalize_doh_path(raw_path: Any) -> str:
    if raw_path is None:
        return "/dns-query"
    path = str(raw_path).strip()
    if not path:
        return "/dns-query"
    if path.startswith("/"):
        return path
    return f"/{path}"


def _parse_ecs(value: Any) -> str | None:
    if value is None:
        return None
    ecs = str(value).strip()
    if not ecs:
        return None
    network = ip_network(ecs, strict=False)
    return network.with_prefixlen


def _validate_config(config: AppConfig) -> None:
    if not (1 <= config.server.port <= 65535):
        raise ValueError("`server.port` must be in 1..65535.")
    if not (12 <= config.server.max_packet_size <= 65535):
        raise ValueError("`server.max_packet_size` must be in 12..65535.")
    if config.cache.max_size <= 0:
        raise ValueError("`cache.max_size` must be greater than 0.")

    for upstream in config.upstreams:
        if upstream.protocol not in {"udp", "tcp", "dot", "doh", "doq"}:
            raise ValueError(
                f"Unsupported upstream protocol `{upstream.protocol}` for {upstream.host}."
            )
        if not (1 <= upstream.port <= 65535):
            raise ValueError(
                f"Invalid upstream port for {upstream.protocol}://{upstream.host}."
            )
        if upstream.timeout <= 0:
            raise ValueError(f"Timeout must be positive for {upstream.host}.")
        if upstream.ecs is not None:
            try:
                ip_network(upstream.ecs, strict=False)
            except ValueError as exc:
                raise ValueError(
                    f"Invalid ECS subnet for {upstream.host}: {upstream.ecs}"
                ) from exc
        if upstream.protocol == "doh" and not upstream.path.startswith("/"):
            raise ValueError(f"Invalid DoH path for {upstream.host}: {upstream.path}")
