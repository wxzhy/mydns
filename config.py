from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Mapping
import os
import tomllib

DEFAULT_CONFIG_PATH = "config.toml"


@dataclass(frozen=True, slots=True)
class ServerConfig:
    host: str = "127.0.0.1"
    port: int = 5353
    max_packet_size: int = 4096


@dataclass(frozen=True, slots=True)
class UpstreamConfig:
    host: str
    port: int = 53
    timeout: float = 2.0


@dataclass(frozen=True, slots=True)
class LoggingConfig:
    level: str = "INFO"


def _default_upstreams() -> tuple[UpstreamConfig, ...]:
    return (
        UpstreamConfig(host="223.5.5.5", port=53, timeout=2.0),
        UpstreamConfig(host="8.8.8.8", port=53, timeout=2.0),
    )


@dataclass(frozen=True, slots=True)
class AppConfig:
    server: ServerConfig = field(default_factory=ServerConfig)
    upstreams: tuple[UpstreamConfig, ...] = field(default_factory=_default_upstreams)
    logging: LoggingConfig = field(default_factory=LoggingConfig)


def load_config(path: str | Path | None = None) -> AppConfig:
    config_path = Path(path or os.getenv("MYDNS_CONFIG", DEFAULT_CONFIG_PATH))
    if not config_path.exists():
        return AppConfig()

    with config_path.open("rb") as f:
        raw = tomllib.load(f)

    if not isinstance(raw, Mapping):
        raise ValueError("Config root must be a mapping.")

    config = AppConfig(
        server=_parse_server(raw.get("server")),
        upstreams=_parse_upstreams(raw.get("upstreams")),
        logging=_parse_logging(raw.get("logging")),
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
    if not isinstance(raw, list):
        raise ValueError("`upstreams` must be a list.")

    upstreams: list[UpstreamConfig] = []
    for index, item in enumerate(raw):
        if not isinstance(item, Mapping):
            raise ValueError(f"`upstreams[{index}]` must be a mapping.")
        host = str(item.get("host", "")).strip()
        if not host:
            raise ValueError(f"`upstreams[{index}].host` is required.")
        upstreams.append(
            UpstreamConfig(
                host=host,
                port=int(item.get("port", 53)),
                timeout=float(item.get("timeout", 2.0)),
            )
        )

    if not upstreams:
        raise ValueError("At least one upstream DNS server is required.")
    return tuple(upstreams)


def _parse_logging(raw: Any) -> LoggingConfig:
    if not isinstance(raw, Mapping):
        return LoggingConfig()
    return LoggingConfig(level=str(raw.get("level", "INFO")))


def _validate_config(config: AppConfig) -> None:
    if not (1 <= config.server.port <= 65535):
        raise ValueError("`server.port` must be in 1..65535.")
    if not (12 <= config.server.max_packet_size <= 65535):
        raise ValueError("`server.max_packet_size` must be in 12..65535.")

    for upstream in config.upstreams:
        if not (1 <= upstream.port <= 65535):
            raise ValueError(f"Invalid upstream port for {upstream.host}.")
        if upstream.timeout <= 0:
            raise ValueError(f"Timeout must be positive for {upstream.host}.")
