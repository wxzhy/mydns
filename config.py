from __future__ import annotations

from dataclasses import dataclass, field
from ipaddress import ip_address, ip_network
from pathlib import Path
from typing import Any, Mapping
import os
from collections.abc import Sequence
from yarl import URL

try:
    import dnsstamps
    from dnsstamps import Protocol as StampProtocol
except Exception:  # pragma: no cover
    dnsstamps = None
    StampProtocol = None  # type: ignore[assignment]

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
    tag: str = "default"
    ecs: str | None = None
    verify: bool | str = True
    hostname: str | None = None
    http_host: str | None = None
    path: str = "/dns-query"
    stamp: str | None = None
    provider_name: str | None = None
    provider_pk: str | None = None


@dataclass(frozen=True, slots=True)
class LoggingConfig:
    level: str = "INFO"


@dataclass(frozen=True, slots=True)
class CacheConfig:
    enabled: bool = True
    max_size: int = 10000


@dataclass(frozen=True, slots=True)
class RuleConfig:
    domainset_dirs: tuple[str, ...] = ()
    ipset_dirs: tuple[str, ...] = ()
    ad_block_tags: tuple[str, ...] = ()


def _default_upstreams() -> tuple[UpstreamConfig, ...]:
    return (
        UpstreamConfig(
            host="223.5.5.5",
            protocol="udp",
            port=53,
            timeout=2.0,
            tag="default",
        ),
        UpstreamConfig(
            host="8.8.8.8",
            protocol="udp",
            port=53,
            timeout=2.0,
            tag="default",
        ),
    )


@dataclass(frozen=True, slots=True)
class AppConfig:
    server: ServerConfig = field(default_factory=ServerConfig)
    upstreams: tuple[UpstreamConfig, ...] = field(default_factory=_default_upstreams)
    logging: LoggingConfig = field(default_factory=LoggingConfig)
    cache: CacheConfig = field(default_factory=CacheConfig)
    rules: RuleConfig = field(default_factory=RuleConfig)


def load_config(path: str | Path | None = None) -> AppConfig:
    config_path = Path(path or os.getenv("MYDNS_CONFIG", DEFAULT_CONFIG_PATH))
    if not config_path.exists():
        return AppConfig()
    config_base_dir = config_path.resolve(strict=False).parent

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
        rules=_parse_rules(raw.get("rules"), root=raw, base_dir=config_base_dir),
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
        upstreams.append(_parse_upstream_item(index=index, item=item))

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


def _parse_rules(
    raw: Any,
    *,
    root: Mapping[str, Any],
    base_dir: Path,
) -> RuleConfig:
    rules = raw if isinstance(raw, Mapping) else {}

    domainset_value = _first_non_none(
        rules.get("domainset_dirs"),
        rules.get("domainset_dir"),
        rules.get("domainset"),
        root.get("domainset_dirs"),
        root.get("domainset_dir"),
        root.get("domainset"),
    )
    ipset_value = _first_non_none(
        rules.get("ipset_dirs"),
        rules.get("ipset_dir"),
        rules.get("ipset"),
        root.get("ipset_dirs"),
        root.get("ipset_dir"),
        root.get("ipset"),
    )
    ad_block_value = _first_non_none(
        rules.get("ad_block_tags"),
        rules.get("ad_block_tag"),
        rules.get("ad_block"),
        root.get("ad_block_tags"),
        root.get("ad_block_tag"),
        root.get("ad_block"),
    )

    return RuleConfig(
        domainset_dirs=_parse_rule_directories(
            domainset_value,
            field_name="rules.domainset_dirs",
            base_dir=base_dir,
        ),
        ipset_dirs=_parse_rule_directories(
            ipset_value,
            field_name="rules.ipset_dirs",
            base_dir=base_dir,
        ),
        ad_block_tags=_parse_rule_tags(
            ad_block_value,
            field_name="rules.ad_block_tags",
        ),
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


def _parse_upstream_item(index: int, item: Any) -> UpstreamConfig:
    if isinstance(item, str):
        raw_text = item.strip()
        if not raw_text:
            raise ValueError(f"`upstreams[{index}]` is empty.")
        if raw_text.startswith("sdns://") or "://" in raw_text:
            mapping: Mapping[str, Any] = {"target": raw_text}
        else:
            mapping = {"host": raw_text}
    elif isinstance(item, Mapping):
        mapping = item
    else:
        raise ValueError(
            f"`upstreams[{index}]` must be a mapping or a string (URL/stamp/host)."
        )

    return _build_upstream_config(index=index, item=mapping)


def _build_upstream_config(index: int, item: Mapping[str, Any]) -> UpstreamConfig:
    base = _parse_base_upstream(index=index, item=item)

    raw_host = _normalize_optional_text(item.get("host", item.get("address")))
    if raw_host and (raw_host.startswith("sdns://") or "://" in raw_host):
        raw_host = None
    host = raw_host or str(base.get("host", "")).strip()
    protocol = _normalize_protocol(
        str(item.get("protocol", base.get("protocol", "udp")))
    )
    default_port = _default_port_for_protocol(protocol)
    port = int(item.get("port", base.get("port", default_port)))
    timeout = float(item.get("timeout", base.get("timeout", 2.0)))
    tag = _normalize_tag(item.get("tag", base.get("tag")))

    raw_ecs = item.get("ecs", item.get("client_subnet", base.get("ecs")))
    try:
        parsed_ecs = _parse_ecs(raw_ecs)
    except ValueError as exc:
        raise ValueError(f"`upstreams[{index}].ecs` is invalid: {raw_ecs}") from exc

    raw_hostname = item.get("hostname", item.get("sni", base.get("hostname")))
    raw_http_host = item.get(
        "http_host",
        item.get("httpHost", base.get("http_host")),
    )
    hostname = _normalize_optional_text(raw_hostname)
    http_host = _normalize_optional_text(raw_http_host)

    if protocol in {"dot", "doq"} and hostname is None and _is_hostname(host):
        hostname = host

    if protocol == "doh":
        if hostname is None and _is_hostname(host):
            hostname = host
        if http_host is None and hostname is not None:
            http_host = hostname
    else:
        http_host = None

    raw_path = item.get("path", base.get("path"))
    raw_stamp = _normalize_optional_text(item.get("stamp")) or _normalize_optional_text(
        base.get("stamp")
    )
    raw_provider_name = _normalize_optional_text(
        item.get("provider_name", item.get("providerName", base.get("provider_name")))
    )
    raw_provider_pk = _normalize_optional_text(
        item.get(
            "provider_pk",
            item.get("providerPk", item.get("public_key", base.get("provider_pk"))),
        )
    )

    if not host:
        raise ValueError(f"`upstreams[{index}].host` (or `address`) is required.")

    return UpstreamConfig(
        host=host,
        protocol=protocol,
        port=port,
        timeout=timeout,
        tag=tag,
        ecs=parsed_ecs,
        verify=_parse_verify(item.get("verify", base.get("verify", True))),
        hostname=hostname,
        http_host=http_host,
        path=_normalize_doh_path(raw_path),
        stamp=raw_stamp,
        provider_name=raw_provider_name,
        provider_pk=raw_provider_pk,
    )


def _parse_base_upstream(index: int, item: Mapping[str, Any]) -> dict[str, Any]:
    raw_stamp = _normalize_optional_text(item.get("stamp"))
    raw_target = _normalize_optional_text(
        item.get(
            "url",
            item.get(
                "resolver",
                item.get(
                    "upstream",
                    item.get("target"),
                ),
            ),
        )
    )

    host_or_address = _normalize_optional_text(item.get("host", item.get("address")))
    if raw_stamp is None and raw_target is None and host_or_address:
        if host_or_address.startswith("sdns://") or "://" in host_or_address:
            raw_target = host_or_address

    if raw_stamp is None and raw_target and raw_target.startswith("sdns://"):
        raw_stamp = raw_target
        raw_target = None

    if raw_stamp is not None:
        return _parse_stamp_to_base(index=index, stamp=raw_stamp)
    if raw_target is not None:
        return _parse_url_to_base(index=index, target=raw_target)
    return {}


def _parse_stamp_to_base(index: int, stamp: str) -> dict[str, Any]:
    if dnsstamps is None or StampProtocol is None:
        raise RuntimeError(
            "使用 dnsstamp 配置需要安装依赖 `dnsstamps`。"
        )
    try:
        parameter = dnsstamps.parse(stamp)
    except Exception as exc:  # pragma: no cover
        raise ValueError(f"`upstreams[{index}].stamp` parse failed: {exc}") from exc

    protocol = parameter.protocol
    if protocol == StampProtocol.PLAIN:
        host, port = _split_host_port(
            _normalize_optional_text(parameter.address) or "",
            default_port=_default_port_for_protocol("udp"),
        )
        return {
            "protocol": "udp",
            "host": host,
            "port": port,
            "stamp": stamp,
        }

    if protocol == StampProtocol.DOT:
        host, port, hostname = _parse_stamp_endpoint(
            parameter=parameter,
            default_port=_default_port_for_protocol("dot"),
        )
        return {
            "protocol": "dot",
            "host": host,
            "port": port,
            "hostname": hostname,
            "stamp": stamp,
        }

    if protocol == StampProtocol.DOH:
        host, port, hostname = _parse_stamp_endpoint(
            parameter=parameter,
            default_port=_default_port_for_protocol("doh"),
        )
        path = _normalize_doh_path(parameter.path)
        return {
            "protocol": "doh",
            "host": host,
            "port": port,
            "hostname": hostname,
            "http_host": hostname,
            "path": path,
            "stamp": stamp,
        }

    if protocol == StampProtocol.DOQ:
        host, port, hostname = _parse_stamp_endpoint(
            parameter=parameter,
            default_port=_default_port_for_protocol("doq"),
        )
        return {
            "protocol": "doq",
            "host": host,
            "port": port,
            "hostname": hostname,
            "stamp": stamp,
        }

    if protocol == StampProtocol.DNSCRYPT:
        host, port = _split_host_port(
            _normalize_optional_text(parameter.address) or "",
            default_port=_default_port_for_protocol("dnscrypt"),
        )
        provider_name = _normalize_optional_text(parameter.provider_name)
        provider_pk = _normalize_optional_text(parameter.public_key)
        if not host:
            raise ValueError(
                f"`upstreams[{index}].stamp` dnscrypt address is empty."
            )
        if not provider_name or not provider_pk:
            raise ValueError(
                f"`upstreams[{index}].stamp` dnscrypt provider fields are incomplete."
            )
        return {
            "protocol": "dnscrypt",
            "host": host,
            "port": port,
            "provider_name": provider_name,
            "provider_pk": provider_pk,
            "stamp": stamp,
        }

    raise ValueError(
        f"`upstreams[{index}].stamp` contains unsupported protocol: {protocol}"
    )


def _parse_stamp_endpoint(
    parameter: Any,
    default_port: int,
) -> tuple[str, int, str | None]:
    host = ""
    port = default_port
    address = _normalize_optional_text(parameter.address)
    if address:
        host, port = _split_host_port(address, default_port=default_port)

    hostname = _normalize_optional_text(parameter.hostname)
    bootstrap_ips = _normalize_text_sequence(getattr(parameter, "bootstrap_ips", ()))
    if not host and bootstrap_ips:
        host = bootstrap_ips[0]
    if not host and hostname:
        host = hostname
    return host, port, hostname


def _parse_url_to_base(index: int, target: str) -> dict[str, Any]:
    try:
        parsed = URL(target)
    except Exception as exc:  # pragma: no cover
        raise ValueError(f"`upstreams[{index}]` URL parse failed: {exc}") from exc

    scheme = _normalize_optional_text(parsed.scheme)
    protocol = _protocol_from_scheme(scheme or "")
    if protocol is None:
        raise ValueError(
            f"`upstreams[{index}]` URL scheme `{scheme}` is not supported."
        )

    host = _normalize_optional_text(parsed.host)
    if host is None:
        raise ValueError(f"`upstreams[{index}]` URL must include host: {target}")

    port = parsed.port or _default_port_for_protocol(protocol)
    base: dict[str, Any] = {
        "protocol": protocol,
        "host": host,
        "port": port,
    }

    if protocol in {"dot", "doq"} and _is_hostname(host):
        base["hostname"] = host
    if protocol == "doh":
        doh_path = parsed.path_qs if parsed.path_qs else parsed.path
        base["path"] = _normalize_doh_path(doh_path)
        if _is_hostname(host):
            base["hostname"] = host
            base["http_host"] = host

    return base


def _normalize_protocol(protocol: str) -> str:
    normalized = protocol.strip().lower()
    aliases = {
        "tls": "dot",
        "https": "doh",
        "quic": "doq",
    }
    return aliases.get(normalized, normalized)


def _protocol_from_scheme(scheme: str) -> str | None:
    mapping = {
        "udp": "udp",
        "tcp": "tcp",
        "tls": "dot",
        "https": "doh",
        "quic": "doq",
    }
    return mapping.get(scheme.strip().lower())


def _default_port_for_protocol(protocol: str) -> int:
    normalized = _normalize_protocol(protocol)
    if normalized == "dot" or normalized == "doq":
        return 853
    if normalized == "doh":
        return 443
    if normalized == "dnscrypt":
        return 443
    if normalized == "tcp":
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


def _split_host_port(address: str, *, default_port: int) -> tuple[str, int]:
    text = address.strip()
    if not text:
        return "", default_port

    if text.startswith("["):
        right = text.find("]")
        if right <= 1:
            raise ValueError(f"Invalid IPv6 address: {address}")
        host = text[1:right]
        rest = text[right + 1 :]
        if not rest:
            return host, default_port
        if not rest.startswith(":"):
            raise ValueError(f"Invalid address format: {address}")
        return host, _parse_port(rest[1:], default_port=default_port)

    if text.count(":") == 1:
        host_part, port_part = text.rsplit(":", 1)
        if port_part.isdigit():
            return host_part.strip(), _parse_port(port_part, default_port=default_port)

    return text, default_port


def _parse_port(value: str, *, default_port: int) -> int:
    if not value:
        return default_port
    port = int(value)
    if not (1 <= port <= 65535):
        raise ValueError(f"Invalid port: {port}")
    return port


def _parse_ecs(value: Any) -> str | None:
    if value is None:
        return None
    ecs = str(value).strip()
    if not ecs:
        return None
    network = ip_network(ecs, strict=False)
    return network.with_prefixlen


def _normalize_optional_text(value: Any) -> str | None:
    if value is None:
        return None
    if isinstance(value, bytes):
        try:
            text = value.decode("utf-8", errors="strict").strip()
        except UnicodeDecodeError:
            text = value.hex()
    else:
        text = str(value).strip()
    if not text:
        return None
    return text


def _normalize_tag(value: Any) -> str:
    tag = _normalize_optional_text(value)
    return tag or "default"


def _normalize_text_sequence(values: Any) -> tuple[str, ...]:
    if not isinstance(values, Sequence) or isinstance(values, (str, bytes)):
        return ()
    results: list[str] = []
    for value in values:
        text = _normalize_optional_text(value)
        if text is not None:
            results.append(text)
    return tuple(results)


def _parse_rule_directories(
    value: Any,
    *,
    field_name: str,
    base_dir: Path,
) -> tuple[str, ...]:
    raw_value = value
    if isinstance(raw_value, Mapping):
        raw_value = _first_non_none(
            raw_value.get("dirs"),
            raw_value.get("dir"),
            raw_value.get("directory"),
            raw_value.get("path"),
        )
    items = _parse_text_items(raw_value, field_name=field_name)
    if not items:
        return ()
    return _resolve_paths(items, base_dir=base_dir)


def _parse_rule_tags(
    value: Any,
    *,
    field_name: str,
) -> tuple[str, ...]:
    raw_value = value
    if isinstance(raw_value, Mapping):
        raw_value = _first_non_none(raw_value.get("tags"), raw_value.get("tag"))
    return _parse_text_items(raw_value, field_name=field_name)


def _parse_text_items(
    value: Any,
    *,
    field_name: str,
) -> tuple[str, ...]:
    if value is None:
        return ()
    if isinstance(value, (str, bytes, Path)):
        raw_items: tuple[Any, ...] = (value,)
    elif isinstance(value, Sequence):
        raw_items = tuple(value)
    else:
        raise ValueError(f"`{field_name}` must be a string or a list of strings.")

    items: list[str] = []
    seen: set[str] = set()
    for raw_item in raw_items:
        text = _normalize_optional_text(raw_item)
        if text is None or text in seen:
            continue
        seen.add(text)
        items.append(text)
    return tuple(items)


def _resolve_paths(
    items: tuple[str, ...],
    *,
    base_dir: Path,
) -> tuple[str, ...]:
    resolved_items: list[str] = []
    seen: set[str] = set()
    for item in items:
        path = Path(item).expanduser()
        if not path.is_absolute():
            path = base_dir / path
        resolved = str(path.resolve(strict=False))
        if resolved in seen:
            continue
        seen.add(resolved)
        resolved_items.append(resolved)
    return tuple(resolved_items)


def _first_non_none(*values: Any) -> Any:
    for value in values:
        if value is not None:
            return value
    return None


def _is_hostname(host: str) -> bool:
    try:
        ip_address(host)
    except ValueError:
        return True
    return False


def _validate_config(config: AppConfig) -> None:
    if not (1 <= config.server.port <= 65535):
        raise ValueError("`server.port` must be in 1..65535.")
    if not (12 <= config.server.max_packet_size <= 65535):
        raise ValueError("`server.max_packet_size` must be in 12..65535.")
    if config.cache.max_size <= 0:
        raise ValueError("`cache.max_size` must be greater than 0.")
    _validate_directory_config(
        directories=config.rules.domainset_dirs,
        field_name="rules.domainset_dirs",
    )
    _validate_directory_config(
        directories=config.rules.ipset_dirs,
        field_name="rules.ipset_dirs",
    )

    for upstream in config.upstreams:
        if upstream.protocol not in {"udp", "tcp", "dot", "doh", "doq", "dnscrypt"}:
            raise ValueError(
                f"Unsupported upstream protocol `{upstream.protocol}` for {upstream.host}."
            )
        if not upstream.host:
            raise ValueError(f"Upstream host is required for protocol {upstream.protocol}.")
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
        if not upstream.tag.strip():
            raise ValueError(
                f"Invalid upstream tag for {upstream.protocol}://{upstream.host}."
            )
        if upstream.protocol == "dnscrypt":
            if not upstream.provider_name or not upstream.provider_pk:
                raise ValueError(
                    "dnscrypt upstream requires parsed `provider_name` and "
                    "`provider_pk` in final config."
                )


def _validate_directory_config(
    directories: tuple[str, ...],
    *,
    field_name: str,
) -> None:
    for directory in directories:
        path = Path(directory)
        if not path.exists():
            raise ValueError(f"`{field_name}` directory does not exist: {directory}")
        if not path.is_dir():
            raise ValueError(f"`{field_name}` must contain directory paths: {directory}")
