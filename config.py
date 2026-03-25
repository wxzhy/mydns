"""YAML 配置解析与运行时对象构建。"""

from __future__ import annotations

from dataclasses import dataclass
from collections.abc import Callable
from importlib import import_module
from pathlib import Path
from typing import Any

import dns.edns
import yaml

from core.domainset import domainset, init_domainset
from core.hooks import RequestHook, ResolverHook, ResponseHook
from core.ipset import init_ipset, ipset
from core.pipeline import Pipeline
from plugins.builtin import NoopRequestHook, NoopResolverHook, NoopResponseHook
from plugins.cache import CacheHook
from plugins.domain_rule import DomainRuleRequestHook
from plugins.ip_rule import IPRuleResolverHook
from plugins.speedcheck import RewriteAnswerByRTTHook, SpeedCheckResolverHook
from plugins.tagset import TagSetResolverHook
from resolver.resolver import Resolver


@dataclass(slots=True)
class ServerConfig:
    """服务监听配置。"""

    host: str = "127.0.0.1"
    port: int = 5335


@dataclass(slots=True)
class RuntimeConfig:
    """运行时装配结果。"""

    server: ServerConfig
    pipeline: Pipeline


_RESOLVER_TYPES: dict[str, str] = {
    "udp": "resolver.udp_resolver.UdpUpstreamResolver",
    "tcp": "resolver.tcp_resolver.TcpUpstreamResolver",
    "tls": "resolver.tls_resolver.TlsUpstreamResolver",
    "https": "resolver.https_resolver.HttpsUpstreamResolver",
    "quic": "resolver.quic_resolver.QuicUpstreamResolver",
}

_REMOVED_RESOLVER_OPTIONS: dict[str, set[str]] = {
    "tcp": {"source", "source_port"},
    "tls": {"source", "source_port", "ssl_context"},
    "quic": {"source", "source_port"},
    "https": {"source", "source_port", "http_version", "family", "post"},
}


def load_runtime_config(path: str | Path) -> RuntimeConfig:
    """从 YAML 文件加载运行配置。"""
    config_path = Path(path)
    if not config_path.exists():
        raise FileNotFoundError(f"配置文件不存在: {config_path}")
    raw = _load_yaml_mapping(config_path)
    return build_runtime_config(raw, base_dir=config_path.parent)


def build_runtime_config(
    raw: dict[str, Any],
    *,
    base_dir: Path | None = None,
) -> RuntimeConfig:
    """从字典构建运行配置。"""
    server_section = _ensure_mapping(raw.get("server"), key="server", allow_none=True)
    pipeline_section = _ensure_mapping(
        raw.get("pipeline"), key="pipeline", allow_none=True
    )
    hooks_section = _ensure_mapping(raw.get("hooks"), key="hooks", allow_none=True)
    domainset_section = _ensure_mapping(
        raw.get("domainset"), key="domainset", allow_none=True
    )
    domain_rules_section = _ensure_mapping(
        raw.get("domain_rules"), key="domain_rules", allow_none=True
    )
    ipset_section = _ensure_mapping(raw.get("ipset"), key="ipset", allow_none=True)
    ip_rules_section = _ensure_mapping(
        raw.get("ip_rules"), key="ip_rules", allow_none=True
    )
    domainset_cache_file = _normalize_optional_path(
        raw.get("domainset_cache_file"),
        key="domainset_cache_file",
    )

    server = ServerConfig(
        host=str(server_section.get("host", "127.0.0.1")),
        port=int(server_section.get("port", 5335)),
    )
    upstream_timeout_s = float(pipeline_section.get("upstream_timeout_s", 0.8))

    resolvers_raw = raw.get("resolvers")
    if resolvers_raw is None:
        resolvers = _default_resolvers()
    else:
        resolvers = _build_resolvers(resolvers_raw)

    request_hooks = _build_hooks(
        hooks_section.get("request"),
        stage="request",
        expected_base=RequestHook,
        default_factory=_default_request_hooks,
    )
    resolver_hooks = _build_hooks(
        hooks_section.get("resolver"),
        stage="resolver",
        expected_base=ResolverHook,
        default_factory=_default_resolver_hooks,
    )
    response_hooks = _build_hooks(
        hooks_section.get("response"),
        stage="response",
        expected_base=ResponseHook,
        default_factory=_default_response_hooks,
    )
    _init_rule_sets(
        domainset_section=domainset_section,
        ipset_section=ipset_section,
        base_dir=base_dir,
        domainset_cache_file=domainset_cache_file,
    )
    request_hooks = _configure_request_hooks(
        request_hooks,
        domain_rules_section=domain_rules_section,
    )
    resolver_hooks = _configure_resolver_hooks(
        resolver_hooks,
        ip_rules_section=ip_rules_section,
    )

    _validate_resolver_hook_configs(resolver_hooks)
    _validate_request_hook_order(request_hooks)
    _validate_resolver_hook_order(resolver_hooks)

    pipeline = Pipeline(
        resolvers=resolvers,
        resolver_hooks=resolver_hooks,
        request_hooks=request_hooks,
        response_hooks=response_hooks,
        upstream_timeout_s=upstream_timeout_s,
    )
    return RuntimeConfig(server=server, pipeline=pipeline)


def _load_yaml_mapping(path: Path) -> dict[str, Any]:
    with path.open("r", encoding="utf-8") as fh:
        loaded = yaml.safe_load(fh)
    if loaded is None:
        return {}
    if not isinstance(loaded, dict):
        raise ValueError("配置根节点必须是映射对象")
    return loaded


def _build_resolvers(raw: Any) -> list[Resolver]:
    if not isinstance(raw, list):
        raise ValueError("resolvers 必须是列表")
    resolvers: list[Resolver] = []
    for index, item in enumerate(raw):
        if not isinstance(item, dict):
            raise ValueError(f"resolvers[{index}] 必须是对象")
        resolvers.append(_build_resolver(item, index=index))
    return resolvers


def _build_resolver(raw: dict[str, Any], *, index: int) -> Resolver:
    if "class" in raw:
        class_path = raw.get("class")
        kwargs = _ensure_mapping(
            raw.get("kwargs"), key=f"resolvers[{index}].kwargs", allow_none=True
        )
        resolver_cls = _load_class(class_path, expected_base=Resolver)
    else:
        resolver_type = raw.get("type")
        if not isinstance(resolver_type, str):
            raise ValueError(f"resolvers[{index}].type 必须是字符串")
        resolver_class_path = _RESOLVER_TYPES.get(resolver_type)
        if resolver_class_path is None:
            raise ValueError(f"不支持的 resolver 类型: {resolver_type}")
        resolver_cls = _load_class(resolver_class_path, expected_base=Resolver)
        kwargs = {k: v for k, v in raw.items() if k != "type"}
        _validate_removed_resolver_options(
            resolver_type,
            kwargs,
            index=index,
        )

    _normalize_tags(kwargs, key=f"resolvers[{index}].tags")
    _normalize_resolver_timeout(kwargs, key=f"resolvers[{index}].timeout")
    _normalize_resolver_ecs(kwargs, key=f"resolvers[{index}].ecs")
    try:
        return resolver_cls(**kwargs)
    except TypeError as exc:
        raise ValueError(f"resolvers[{index}] 参数不合法: {exc}") from exc


def _build_hooks(
    raw: Any,
    *,
    stage: str,
    expected_base: type[Any],
    default_factory: Callable[[], list[Any]],
) -> list[Any]:
    if raw is None:
        return default_factory()
    if not isinstance(raw, list):
        raise ValueError(f"hooks.{stage} 必须是列表")

    hooks: list[Any] = []
    for index, item in enumerate(raw):
        class_path: Any
        kwargs: dict[str, Any]
        if isinstance(item, str):
            class_path = item
            kwargs = {}
        elif isinstance(item, dict):
            class_path = item.get("class")
            kwargs = _ensure_mapping(
                item.get("kwargs"),
                key=f"hooks.{stage}[{index}].kwargs",
                allow_none=True,
            )
        else:
            raise ValueError(f"hooks.{stage}[{index}] 必须是字符串或对象")

        hook_cls = _load_class(class_path, expected_base=expected_base)
        try:
            hooks.append(hook_cls(**kwargs))
        except TypeError as exc:
            raise ValueError(f"hooks.{stage}[{index}] 参数不合法: {exc}") from exc
    return hooks


def _load_class(class_path: Any, *, expected_base: type[Any]) -> type[Any]:
    if not isinstance(class_path, str) or "." not in class_path:
        raise ValueError(f"非法类路径: {class_path!r}")
    module_name, class_name = class_path.rsplit(".", 1)
    try:
        module = import_module(module_name)
    except Exception as exc:
        raise ValueError(f"模块加载失败: {module_name}: {exc}") from exc
    cls = getattr(module, class_name, None)
    if not isinstance(cls, type):
        raise ValueError(f"类不存在: {class_path}")
    if not issubclass(cls, expected_base):
        raise ValueError(f"{class_path} 不是 {expected_base.__name__} 子类")
    return cls


def _normalize_tags(kwargs: dict[str, Any], *, key: str) -> None:
    tags = kwargs.get("tags")
    if tags is None:
        return
    if isinstance(tags, set):
        kwargs["tags"] = {str(x) for x in tags}
        return
    if isinstance(tags, (list, tuple)):
        kwargs["tags"] = {str(x) for x in tags}
        return
    raise ValueError(f"{key} 必须是列表或集合")


def _validate_removed_resolver_options(
    resolver_type: str,
    kwargs: dict[str, Any],
    *,
    index: int,
) -> None:
    removed_options = _REMOVED_RESOLVER_OPTIONS.get(resolver_type, set())
    for option in removed_options:
        if option in kwargs:
            raise ValueError(
                f"resolvers[{index}].{option} 已移除，请从 {resolver_type} 配置中删除"
            )


def _normalize_resolver_timeout(kwargs: dict[str, Any], *, key: str) -> None:
    if "timeout" not in kwargs or kwargs["timeout"] is None:
        return
    try:
        timeout = float(kwargs["timeout"])
    except (TypeError, ValueError) as exc:
        raise ValueError(f"{key} 必须是正数") from exc
    if timeout <= 0:
        raise ValueError(f"{key} 必须是正数")
    kwargs["timeout"] = timeout


def _normalize_resolver_ecs(kwargs: dict[str, Any], *, key: str) -> None:
    if "ecs" not in kwargs or kwargs["ecs"] is None:
        return
    kwargs["ecs"] = _parse_ecs_option(kwargs["ecs"], key=key)


def _parse_ecs_option(raw_value: Any, *, key: str) -> dns.edns.ECSOption:
    if isinstance(raw_value, str):
        value = raw_value.strip()
        if not value:
            raise ValueError(f"{key} 不能为空")
        try:
            return dns.edns.ECSOption.from_text(value)
        except ValueError:
            try:
                return dns.edns.ECSOption(value)
            except Exception as exc:
                raise ValueError(f"{key} 不是合法的 ECS 配置") from exc

    if isinstance(raw_value, dict):
        address = raw_value.get("address")
        if not isinstance(address, str) or not address.strip():
            raise ValueError(f"{key}.address 必须是非空字符串")
        srclen = raw_value.get("srclen")
        scopelen = raw_value.get("scopelen", 0)
        try:
            parsed_srclen = None if srclen is None else int(srclen)
            parsed_scopelen = int(scopelen)
            return dns.edns.ECSOption(
                address.strip(),
                srclen=parsed_srclen,
                scopelen=parsed_scopelen,
            )
        except Exception as exc:
            raise ValueError(f"{key} 不是合法的 ECS 配置") from exc

    raise ValueError(f"{key} 必须是字符串或对象")


def _ensure_mapping(
    value: Any, *, key: str, allow_none: bool = False
) -> dict[str, Any]:
    if value is None and allow_none:
        return {}
    if not isinstance(value, dict):
        raise ValueError(f"{key} 必须是对象")
    return dict(value)


def _init_rule_sets(
    *,
    domainset_section: dict[str, Any],
    ipset_section: dict[str, Any],
    base_dir: Path | None,
    domainset_cache_file: str | None,
) -> None:
    domainset_mapping = _normalize_tag_to_files(
        domainset_section,
        key="domainset",
    )
    ipset_mapping = _normalize_tag_to_files(
        ipset_section,
        key="ipset",
    )
    init_domainset(
        domainset_mapping,
        base_dir=base_dir,
        cache_file=domainset_cache_file,
    )
    init_ipset(ipset_mapping, base_dir=base_dir)


def _build_domain_rule_hook(
    raw_rules: dict[str, Any],
) -> DomainRuleRequestHook | None:
    if raw_rules:
        _validate_rule_tags(
            raw_rules,
            available_tags=domainset.tags,
            key="domain_rules",
        )
    if not domainset.tags and not raw_rules:
        return None
    return DomainRuleRequestHook(rules=raw_rules)


def _build_ip_rule_hook(
    raw_rules: dict[str, Any],
) -> IPRuleResolverHook | None:
    if not raw_rules:
        return None
    unknown_keys = set(raw_rules) - {"skip_result_tags", "rules"}
    if unknown_keys:
        raise ValueError(
            "ip_rules 包含未知字段: "
            + ", ".join(sorted(map(str, unknown_keys)))
        )
    hook = IPRuleResolverHook(
        rules=raw_rules.get("rules"),
        skip_result_tags=raw_rules.get("skip_result_tags"),
    )
    _validate_ip_rule_tags(
        hook,
        result_tags=domainset.tags | {"default"},
        ip_tags=ipset.tags,
        key="ip_rules",
    )
    if not hook.rules:
        return None
    return hook


def _build_tagset_hook() -> TagSetResolverHook | None:
    if not domainset.tags:
        return None
    return TagSetResolverHook()


def _configure_request_hooks(
    hooks: list[RequestHook],
    *,
    domain_rules_section: dict[str, Any],
) -> list[RequestHook]:
    if not domain_rules_section:
        return hooks
    configured = _build_domain_rule_hook(domain_rules_section)
    if configured is None:
        return hooks

    indexes = [
        index
        for index, hook in enumerate(hooks)
        if isinstance(hook, DomainRuleRequestHook)
    ]
    if not indexes:
        raise ValueError(
            "配置了 domain_rules，但 hooks.request 中未声明 "
            "plugins.domain_rule.DomainRuleRequestHook"
        )
    if len(indexes) > 1:
        raise ValueError(
            "配置了 domain_rules 时，hooks.request 中只能声明一个 "
            "plugins.domain_rule.DomainRuleRequestHook"
        )

    index = indexes[0]
    existing = hooks[index]
    if isinstance(existing, DomainRuleRequestHook) and existing.rules:
        raise ValueError(
            "domain_rules 与 hooks.request 中 "
            "plugins.domain_rule.DomainRuleRequestHook.kwargs.rules "
            "不能同时配置"
        )
    return [*hooks[:index], configured, *hooks[index + 1 :]]


def _configure_resolver_hooks(
    hooks: list[ResolverHook],
    *,
    ip_rules_section: dict[str, Any],
) -> list[ResolverHook]:
    if not ip_rules_section:
        return hooks
    configured = _build_ip_rule_hook(ip_rules_section)
    if configured is None:
        return hooks

    indexes = [
        index
        for index, hook in enumerate(hooks)
        if isinstance(hook, IPRuleResolverHook)
    ]
    if not indexes:
        raise ValueError(
            "配置了 ip_rules，但 hooks.resolver 中未声明 "
            "plugins.ip_rule.IPRuleResolverHook"
        )
    if len(indexes) > 1:
        raise ValueError(
            "配置了 ip_rules 时，hooks.resolver 中只能声明一个 "
            "plugins.ip_rule.IPRuleResolverHook"
        )

    index = indexes[0]
    existing = hooks[index]
    if isinstance(existing, IPRuleResolverHook) and (
        existing.rules or existing.skip_result_tags
    ):
        raise ValueError(
            "ip_rules 与 hooks.resolver 中 "
            "plugins.ip_rule.IPRuleResolverHook.kwargs.rules/"
            "skip_result_tags 不能同时配置"
        )
    return [*hooks[:index], configured, *hooks[index + 1 :]]


def _normalize_tag_to_files(
    raw: dict[str, Any], *, key: str
) -> dict[str, list[str | Path]]:
    output: dict[str, list[str | Path]] = {}
    for raw_tag, raw_value in raw.items():
        if not isinstance(raw_tag, str) or not raw_tag.strip():
            raise ValueError(f"{key} 的 tag 必须是非空字符串")
        tag = raw_tag.strip()
        values = _normalize_file_list(raw_value, key=f"{key}.{tag}")
        output[tag] = values
    return output


def _normalize_file_list(raw_value: Any, *, key: str) -> list[str | Path]:
    if isinstance(raw_value, str):
        value = raw_value.strip()
        if not value:
            raise ValueError(f"{key} 路径不能为空")
        return [value]
    if isinstance(raw_value, (list, tuple)):
        values: list[str | Path] = []
        for index, item in enumerate(raw_value):
            if not isinstance(item, str) or not item.strip():
                raise ValueError(f"{key}[{index}] 必须是非空字符串路径")
            values.append(item.strip())
        return values
    raise ValueError(f"{key} 必须是字符串或字符串列表")


def _normalize_optional_path(raw_value: Any, *, key: str) -> str | None:
    if raw_value is None:
        return None
    if not isinstance(raw_value, str):
        raise ValueError(f"{key} 必须是字符串路径")
    value = raw_value.strip()
    if not value:
        return None
    return value


def _validate_rule_tags(
    raw_rules: dict[str, Any],
    *,
    available_tags: set[str],
    key: str,
) -> None:
    unknown = [tag for tag in raw_rules if tag not in available_tags]
    if unknown:
        raise ValueError(
            f"{key} 引用了未定义的 tag: {', '.join(sorted(unknown))}"
        )


def _insert_domain_rule_hook(
    hooks: list[RequestHook],
    hook: DomainRuleRequestHook,
) -> list[RequestHook]:
    insert_at = 0
    for index, existing in enumerate(hooks):
        if isinstance(existing, CacheHook):
            insert_at = index + 1
    return [*hooks[:insert_at], hook, *hooks[insert_at:]]


def _insert_ip_rule_hook(
    hooks: list[ResolverHook],
    hook: IPRuleResolverHook,
) -> list[ResolverHook]:
    speedcheck_indexes = [
        index for index, existing in enumerate(hooks) if isinstance(existing, SpeedCheckResolverHook)
    ]
    tagset_indexes = [
        index for index, existing in enumerate(hooks) if isinstance(existing, TagSetResolverHook)
    ]

    insert_at = min(speedcheck_indexes) if speedcheck_indexes else len(hooks)
    if tagset_indexes:
        after_tagset = max(tagset_indexes) + 1
        insert_at = after_tagset if not speedcheck_indexes else max(insert_at, after_tagset)
    return [*hooks[:insert_at], hook, *hooks[insert_at:]]


def _insert_tagset_hook(
    hooks: list[ResolverHook],
    hook: TagSetResolverHook,
) -> list[ResolverHook]:
    if any(isinstance(existing, TagSetResolverHook) for existing in hooks):
        return hooks
    ip_rule_indexes = [
        index for index, existing in enumerate(hooks) if isinstance(existing, IPRuleResolverHook)
    ]
    speedcheck_indexes = [
        index for index, existing in enumerate(hooks) if isinstance(existing, SpeedCheckResolverHook)
    ]
    if ip_rule_indexes:
        insert_at = min(ip_rule_indexes)
        return [*hooks[:insert_at], hook, *hooks[insert_at:]]
    if speedcheck_indexes:
        insert_at = min(speedcheck_indexes)
        return [*hooks[:insert_at], hook, *hooks[insert_at:]]
    return [*hooks, hook]


def _default_request_hooks() -> list[RequestHook]:
    return [NoopRequestHook()]


def _default_resolver_hooks() -> list[ResolverHook]:
    return [NoopResolverHook(), SpeedCheckResolverHook()]


def _validate_request_hook_order(hooks: list[RequestHook]) -> None:
    cache_indexes = [
        index for index, hook in enumerate(hooks) if isinstance(hook, CacheHook)
    ]
    if not cache_indexes:
        return
    last_cache = max(cache_indexes)
    for index, hook in enumerate(hooks):
        if isinstance(hook, DomainRuleRequestHook) and index < last_cache:
            raise ValueError(
                "plugins.domain_rule.DomainRuleRequestHook 必须位于 "
                "plugins.cache.CacheHook 之后"
            )


def _validate_resolver_hook_order(hooks: list[ResolverHook]) -> None:
    tagset_indexes = [
        index for index, hook in enumerate(hooks) if isinstance(hook, TagSetResolverHook)
    ]
    ip_rule_indexes = [
        index for index, hook in enumerate(hooks) if isinstance(hook, IPRuleResolverHook)
    ]
    speedcheck_indexes = [
        index for index, hook in enumerate(hooks) if isinstance(hook, SpeedCheckResolverHook)
    ]
    if tagset_indexes and ip_rule_indexes and min(tagset_indexes) > min(ip_rule_indexes):
        raise ValueError(
            "plugins.tagset.TagSetResolverHook 必须位于 "
            "plugins.ip_rule.IPRuleResolverHook 之前"
        )
    if not speedcheck_indexes:
        return
    first_speedcheck = min(speedcheck_indexes)
    if tagset_indexes and min(tagset_indexes) > first_speedcheck:
        raise ValueError(
            "plugins.tagset.TagSetResolverHook 必须位于 "
            "plugins.speedcheck.SpeedCheckResolverHook 之前"
        )
    if ip_rule_indexes and min(ip_rule_indexes) > first_speedcheck:
        raise ValueError(
            "plugins.ip_rule.IPRuleResolverHook 必须位于 "
            "plugins.speedcheck.SpeedCheckResolverHook 之前"
        )


def _default_response_hooks() -> list[ResponseHook]:
    return [NoopResponseHook(), RewriteAnswerByRTTHook(max_return_ips=2, ttl_s=900)]


def _validate_ip_rule_tags(
    hook: IPRuleResolverHook,
    *,
    result_tags: set[str],
    ip_tags: set[str],
    key: str,
) -> None:
    referenced_result_tags = set(hook.skip_result_tags)
    referenced_ip_tags: set[str] = set()
    for rule in hook.rules:
        referenced_result_tags.update(rule.match_tags)
        for section in rule.sections.values():
            for replacement in section.replacements:
                referenced_ip_tags.add(replacement.tag)

    unknown_result_tags = [
        tag for tag in referenced_result_tags if tag not in result_tags
    ]
    if unknown_result_tags:
        raise ValueError(
            f"{key} 引用了未定义的结果 tag: {', '.join(sorted(unknown_result_tags))}"
        )

    unknown_ip_tags = [tag for tag in referenced_ip_tags if tag not in ip_tags]
    if unknown_ip_tags:
        raise ValueError(
            f"{key} 引用了未定义的 IP tag: {', '.join(sorted(unknown_ip_tags))}"
        )


def _validate_resolver_hook_configs(hooks: list[ResolverHook]) -> None:
    for hook in hooks:
        if isinstance(hook, IPRuleResolverHook):
            _validate_ip_rule_tags(
                hook,
                result_tags=domainset.tags | {"default"},
                ip_tags=ipset.tags,
                key="plugins.ip_rule.IPRuleResolverHook",
            )


def _default_resolvers() -> list[Resolver]:
    return _build_resolvers(
        [
            {"type": "udp", "name": "alidns", "address": "223.5.5.5"},
            {"type": "udp", "name": "dnspod", "address": "119.29.29.29"},
            {"type": "udp", "name": "cloudflare", "address": "1.1.1.1"},
            {"type": "udp", "name": "google", "address": "8.8.8.8"},
            {"type": "tcp", "name": "tcp-cloudflare", "address": "1.1.1.1"},
            {"type": "tcp", "name": "tcp-google", "address": "8.8.8.8"},
            {
                "type": "tls",
                "name": "tls-cloudflare",
                "address": "1.1.1.1",
                "server_hostname": "cloudflare-dns.com",
            },
            {
                "type": "tls",
                "name": "tls-google",
                "address": "8.8.8.8",
                "server_hostname": "dns.google",
            },
            {
                "type": "quic",
                "name": "doq-cloudflare",
                "address": "1.1.1.1",
                "server_hostname": "cloudflare-dns.com",
            },
            {
                "type": "quic",
                "name": "doq-google",
                "address": "8.8.8.8",
                "server_hostname": "dns.google",
            },
            {
                "type": "https",
                "name": "doh-cloudflare",
                "address": "cloudflare-dns.com",
                "path": "/dns-query",
                "bootstrap_address": "1.1.1.1",
            },
            {
                "type": "https",
                "name": "doh-google",
                "address": "dns.google",
                "path": "/dns-query",
                "bootstrap_address": "8.8.8.8",
            },
        ]
    )
