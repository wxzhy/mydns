"""YAML 配置解析与运行时对象构建。"""

from __future__ import annotations

from dataclasses import dataclass
from importlib import import_module
from pathlib import Path
from typing import Any

from collections.abc import Mapping, Sequence

import dns.edns
import yaml
from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    StrictBool,
    ValidationInfo,
    field_validator,
    model_validator,
)

from core.domainset import domainset, init_domainset
from core.hooks import RequestHook, ResolverHook, ResponseHook
from core.ipset import init_ipset, ipset
from core.pipeline import Pipeline
from plugins.cache import normalize_cache_hook_kwargs
from plugins.domain_rule import (
    normalize_domain_rule_hook_kwargs,
    normalize_domain_rules_config,
)
from plugins.https_record import normalize_https_record_hook_kwargs
from plugins.ip_rule import normalize_ip_rule_hook_kwargs, normalize_ip_rules_config
from plugins.speedcheck import (
    normalize_rewrite_answer_by_rtt_hook_kwargs,
    normalize_speedcheck_resolver_hook_kwargs,
)
from resolver.resolver import Resolver


_DOMAIN_RULE_REQUEST_HOOK = "plugins.domain_rule.DomainRuleRequestHook"
_CACHE_HOOK = "plugins.cache.CacheHook"
_TAGSET_RESOLVER_HOOK = "plugins.tagset.TagSetResolverHook"
_IP_RULE_RESOLVER_HOOK = "plugins.ip_rule.IPRuleResolverHook"
_SPEEDCHECK_RESOLVER_HOOK = "plugins.speedcheck.SpeedCheckResolverHook"
_HTTPS_RECORD_RESPONSE_HOOK = "plugins.https_record.HttpsRecordResponseHook"
_REWRITE_ANSWER_BY_RTT_RESPONSE_HOOK = "plugins.speedcheck.RewriteAnswerByRTTHook"

_HOOK_KWARG_NORMALIZERS: dict[str, Any] = {
    _CACHE_HOOK: normalize_cache_hook_kwargs,
    _DOMAIN_RULE_REQUEST_HOOK: normalize_domain_rule_hook_kwargs,
    _IP_RULE_RESOLVER_HOOK: normalize_ip_rule_hook_kwargs,
    _SPEEDCHECK_RESOLVER_HOOK: normalize_speedcheck_resolver_hook_kwargs,
    _REWRITE_ANSWER_BY_RTT_RESPONSE_HOOK: normalize_rewrite_answer_by_rtt_hook_kwargs,
    _HTTPS_RECORD_RESPONSE_HOOK: normalize_https_record_hook_kwargs,
}

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

_DEFAULT_REQUEST_HOOKS = [
    "plugins.builtin.NoopRequestHook",
]

_DEFAULT_RESOLVER_HOOKS = [
    "plugins.builtin.NoopResolverHook",
    "plugins.speedcheck.SpeedCheckResolverHook",
]

_DEFAULT_RESPONSE_HOOKS = [
    "plugins.builtin.NoopResponseHook",
    {
        "class": "plugins.speedcheck.RewriteAnswerByRTTHook",
        "kwargs": {
            "max_return_ips": 2,
            "ttl_s": 900,
        },
    },
]

_DEFAULT_RESOLVERS = [
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


class ServerConfig(BaseModel):
    """服务监听配置。"""

    model_config = ConfigDict(extra="ignore")

    host: str = "127.0.0.1"
    port: int = 5335
    udp: StrictBool = True
    tcp: StrictBool = False

    @field_validator("host", mode="before")
    @classmethod
    def _normalize_host(cls, value: Any) -> str:
        return _normalize_nonempty_string(value, key="server.host")

    @field_validator("port", mode="before")
    @classmethod
    def _normalize_port(cls, value: Any) -> int:
        try:
            return int(value)
        except (TypeError, ValueError) as exc:
            raise ValueError("server.port 必须是整数") from exc

    @model_validator(mode="after")
    def _validate_protocols(self) -> "ServerConfig":
        if not self.udp and not self.tcp:
            raise ValueError("server.udp 与 server.tcp 不能同时为 false")
        return self


class PipelineConfigModel(BaseModel):
    model_config = ConfigDict(extra="ignore")

    upstream_timeout_s: float = 0.8

    @field_validator("upstream_timeout_s", mode="before")
    @classmethod
    def _normalize_timeout(cls, value: Any) -> float:
        try:
            timeout = float(value)
        except (TypeError, ValueError) as exc:
            raise ValueError("pipeline.upstream_timeout_s 必须是正数") from exc
        if timeout <= 0:
            raise ValueError("pipeline.upstream_timeout_s 必须是正数")
        return timeout


class HookSpecModel(BaseModel):
    """标准化后的 hook 配置项。"""

    model_config = ConfigDict(populate_by_name=True, extra="ignore")

    class_path: str = Field(alias="class")
    kwargs: dict[str, Any] = Field(default_factory=dict)

    @model_validator(mode="before")
    @classmethod
    def _normalize_hook_item(cls, raw: Any) -> dict[str, Any]:
        if isinstance(raw, str):
            return {"class": raw, "kwargs": {}}
        if not isinstance(raw, Mapping):
            raise ValueError("hook 配置必须是字符串或对象")
        data = dict(raw)
        kwargs = data.get("kwargs")
        if kwargs is None:
            data["kwargs"] = {}
        elif isinstance(kwargs, Mapping):
            data["kwargs"] = dict(kwargs)
        else:
            raise ValueError("hook.kwargs 必须是对象")
        return data

    @field_validator("class_path", mode="before")
    @classmethod
    def _normalize_class_path(cls, value: Any) -> str:
        return _normalize_nonempty_string(value, key="hook.class")


class HooksConfigModel(BaseModel):
    model_config = ConfigDict(extra="ignore")

    request: list[HookSpecModel] | None = None
    resolver: list[HookSpecModel] | None = None
    response: list[HookSpecModel] | None = None


class ResolverSpecModel(BaseModel):
    """标准化后的 resolver 配置项。"""

    model_config = ConfigDict(
        populate_by_name=True,
        extra="allow",
        arbitrary_types_allowed=True,
    )

    type: str | None = None
    class_path: str | None = Field(default=None, alias="class")
    kwargs: dict[str, Any] = Field(default_factory=dict)
    name: str | None = None
    tags: set[str] | None = None
    timeout: float | None = None
    ecs: dns.edns.ECSOption | None = None

    @model_validator(mode="before")
    @classmethod
    def _normalize_resolver_item(cls, raw: Any) -> Any:
        if not isinstance(raw, Mapping):
            raise ValueError("resolver 配置必须是对象")
        data = dict(raw)
        if "class" in data:
            kwargs = data.get("kwargs")
            if kwargs is None:
                data["kwargs"] = {}
            elif isinstance(kwargs, Mapping):
                data["kwargs"] = dict(kwargs)
            else:
                raise ValueError("resolvers[*].kwargs 必须是对象")
        return data

    @field_validator("type", mode="before")
    @classmethod
    def _normalize_type(cls, value: Any) -> str | None:
        if value is None:
            return None
        return _normalize_nonempty_string(value, key="resolvers[*].type")

    @field_validator("class_path", mode="before")
    @classmethod
    def _normalize_class_path(cls, value: Any) -> str | None:
        if value is None:
            return None
        return _normalize_nonempty_string(value, key="resolvers[*].class")

    @field_validator("name", mode="before")
    @classmethod
    def _normalize_name(cls, value: Any) -> str | None:
        if value is None:
            return None
        return _normalize_nonempty_string(value, key="resolvers[*].name")

    @field_validator("tags", mode="before")
    @classmethod
    def _normalize_tags(cls, value: Any) -> set[str] | None:
        if value is None:
            return None
        return set(_normalize_string_list(value, key="resolvers[*].tags"))

    @field_validator("timeout", mode="before")
    @classmethod
    def _normalize_timeout(cls, value: Any) -> float | None:
        if value is None:
            return None
        try:
            timeout = float(value)
        except (TypeError, ValueError) as exc:
            raise ValueError("resolvers[*].timeout 必须是正数") from exc
        if timeout <= 0:
            raise ValueError("resolvers[*].timeout 必须是正数")
        return timeout

    @field_validator("ecs", mode="before")
    @classmethod
    def _normalize_ecs(cls, value: Any) -> dns.edns.ECSOption | None:
        if value is None:
            return None
        return _parse_ecs_option(value, key="resolvers[*].ecs")

    @model_validator(mode="after")
    def _validate_form(self) -> "ResolverSpecModel":
        if self.class_path is not None:
            return self
        if self.type is None:
            raise ValueError("resolvers[*] 必须声明 type 或 class")
        if self.type not in _RESOLVER_TYPES:
            raise ValueError(f"不支持的 resolver 类型: {self.type}")
        for option in _REMOVED_RESOLVER_OPTIONS.get(self.type, set()):
            if option in (self.model_extra or {}):
                raise ValueError(
                    f"resolvers[*].{option} 已移除，请从 {self.type} 配置中删除"
                )
        return self

    def build_resolver(self) -> Resolver:
        if self.class_path is not None:
            resolver_cls = _load_class(self.class_path, expected_base=Resolver)
            kwargs = dict(self.kwargs)
        else:
            assert self.type is not None
            resolver_cls = _load_class(_RESOLVER_TYPES[self.type], expected_base=Resolver)
            kwargs = dict(self.model_extra or {})
            if self.name is not None:
                kwargs["name"] = self.name
            if self.tags is not None:
                kwargs["tags"] = set(self.tags)
            if self.timeout is not None:
                kwargs["timeout"] = self.timeout
            if self.ecs is not None:
                kwargs["ecs"] = self.ecs
        try:
            return resolver_cls(**kwargs)
        except TypeError as exc:
            raise ValueError(f"resolver 参数不合法: {exc}") from exc


class RawRuntimeConfigModel(BaseModel):
    """原始 YAML 配置的 pydantic 解析模型。"""

    model_config = ConfigDict(extra="ignore", arbitrary_types_allowed=True)

    server: ServerConfig = Field(default_factory=ServerConfig)
    pipeline: PipelineConfigModel = Field(default_factory=PipelineConfigModel)
    resolvers: list[ResolverSpecModel] | None = None
    hooks: HooksConfigModel = Field(default_factory=HooksConfigModel)
    domainset: dict[str, list[str]] = Field(default_factory=dict)
    domain_rules: dict[str, Any] = Field(default_factory=dict)
    ipset: dict[str, list[str]] = Field(default_factory=dict)
    ip_rules: dict[str, Any] = Field(default_factory=dict)
    domainset_cache_file: str | None = None

    @field_validator("domainset", "ipset", mode="before")
    @classmethod
    def _normalize_tagged_paths(
        cls,
        value: Any,
        info: ValidationInfo,
    ) -> dict[str, list[str]]:
        return _normalize_tagged_path_mapping(value, key=info.field_name)

    @field_validator("domain_rules", mode="before")
    @classmethod
    def _normalize_domain_rules(cls, value: Any) -> dict[str, Any]:
        return normalize_domain_rules_config(value)

    @field_validator("ip_rules", mode="before")
    @classmethod
    def _normalize_ip_rules(cls, value: Any) -> dict[str, Any]:
        return normalize_ip_rules_config(value)

    @field_validator("domainset_cache_file", mode="before")
    @classmethod
    def _normalize_cache_file(cls, value: Any) -> str | None:
        if value is None:
            return None
        if not isinstance(value, str):
            raise ValueError("domainset_cache_file 必须是字符串路径")
        normalized = value.strip()
        return normalized or None

    def effective_resolver_specs(self) -> list[ResolverSpecModel]:
        if self.resolvers is not None:
            return [spec.model_copy(deep=True) for spec in self.resolvers]
        return [ResolverSpecModel.model_validate(item) for item in _DEFAULT_RESOLVERS]

    def effective_request_hook_specs(self) -> list[HookSpecModel]:
        if self.hooks.request is not None:
            return [spec.model_copy(deep=True) for spec in self.hooks.request]
        return [HookSpecModel.model_validate(item) for item in _DEFAULT_REQUEST_HOOKS]

    def effective_resolver_hook_specs(self) -> list[HookSpecModel]:
        if self.hooks.resolver is not None:
            return [spec.model_copy(deep=True) for spec in self.hooks.resolver]
        return [HookSpecModel.model_validate(item) for item in _DEFAULT_RESOLVER_HOOKS]

    def effective_response_hook_specs(self) -> list[HookSpecModel]:
        if self.hooks.response is not None:
            return [spec.model_copy(deep=True) for spec in self.hooks.response]
        return [HookSpecModel.model_validate(item) for item in _DEFAULT_RESPONSE_HOOKS]


@dataclass(slots=True)
class RuntimeConfig:
    """运行时装配结果。"""

    server: ServerConfig
    pipeline: Pipeline


class RuntimeSemanticConfigModel(BaseModel):
    """依赖已加载 rule sets 的运行时语义校验模型。"""

    model_config = ConfigDict(arbitrary_types_allowed=True)

    request_hooks: list[HookSpecModel]
    resolver_hooks: list[HookSpecModel]
    response_hooks: list[HookSpecModel]
    domain_rules: dict[str, Any] = Field(default_factory=dict)
    ip_rules: dict[str, Any] = Field(default_factory=dict)
    domainset_tags: set[str] = Field(default_factory=set)
    ipset_tags: set[str] = Field(default_factory=set)

    @model_validator(mode="after")
    def _validate_runtime(self) -> "RuntimeSemanticConfigModel":
        _validate_request_hook_order(self.request_hooks)
        _validate_resolver_hook_order(self.resolver_hooks)

        if self.domain_rules:
            _validate_domain_rule_tags(
                self.domain_rules,
                available_tags=self.domainset_tags,
                key="domain_rules",
            )
            domain_rule_hooks = _find_hooks(
                self.request_hooks,
                class_path=_DOMAIN_RULE_REQUEST_HOOK,
            )
            if not domain_rule_hooks:
                raise ValueError(
                    "配置了 domain_rules，但 hooks.request 中未声明 "
                    "plugins.domain_rule.DomainRuleRequestHook"
                )
            if len(domain_rule_hooks) > 1:
                raise ValueError(
                    "配置了 domain_rules 时，hooks.request 中只能声明一个 "
                    "plugins.domain_rule.DomainRuleRequestHook"
                )
            if _extract_domain_rule_hook_rules(domain_rule_hooks[0]):
                raise ValueError(
                    "domain_rules 与 hooks.request 中 "
                    "plugins.domain_rule.DomainRuleRequestHook.kwargs.rules "
                    "不能同时配置"
                )

        for hook in _find_hooks(self.request_hooks, class_path=_DOMAIN_RULE_REQUEST_HOOK):
            manual_rules = _extract_domain_rule_hook_rules(hook)
            if manual_rules:
                _validate_domain_rule_tags(
                    manual_rules,
                    available_tags=self.domainset_tags,
                    key=_DOMAIN_RULE_REQUEST_HOOK,
                )

        if self.ip_rules:
            _validate_ip_rule_tags(
                self.ip_rules,
                result_tags=self.domainset_tags | {"default"},
                ip_tags=self.ipset_tags,
                key="ip_rules",
            )
            if self.ip_rules.get("rules"):
                ip_rule_hooks = _find_hooks(
                    self.resolver_hooks,
                    class_path=_IP_RULE_RESOLVER_HOOK,
                )
                if not ip_rule_hooks:
                    raise ValueError(
                        "配置了 ip_rules，但 hooks.resolver 中未声明 "
                        "plugins.ip_rule.IPRuleResolverHook"
                    )
                if len(ip_rule_hooks) > 1:
                    raise ValueError(
                        "配置了 ip_rules 时，hooks.resolver 中只能声明一个 "
                        "plugins.ip_rule.IPRuleResolverHook"
                    )
                if _hook_has_effective_ip_rules(ip_rule_hooks[0]):
                    raise ValueError(
                        "ip_rules 与 hooks.resolver 中 "
                        "plugins.ip_rule.IPRuleResolverHook.kwargs.rules/"
                        "skip_result_tags 不能同时配置"
                    )

        for hook in _find_hooks(self.resolver_hooks, class_path=_IP_RULE_RESOLVER_HOOK):
            hook_ip_rules = normalize_ip_rule_hook_kwargs(hook.kwargs)
            if hook_ip_rules:
                _validate_ip_rule_tags(
                    hook_ip_rules,
                    result_tags=self.domainset_tags | {"default"},
                    ip_tags=self.ipset_tags,
                    key=_IP_RULE_RESOLVER_HOOK,
                )

        for hook in _find_hooks(self.response_hooks, class_path=_HTTPS_RECORD_RESPONSE_HOOK):
            kwargs = normalize_https_record_hook_kwargs(hook.kwargs)
            _validate_tag_membership(
                kwargs["skip_result_tags"],
                available_tags=self.domainset_tags | {"default"},
                key="plugins.https_record.HttpsRecordResponseHook.skip_result_tags",
                label="结果 tag",
            )
            _validate_tag_membership(
                kwargs["cloudflare_tags"],
                available_tags=self.domainset_tags | self.ipset_tags,
                key="plugins.https_record.HttpsRecordResponseHook.cloudflare_tags",
                label="Cloudflare tag",
            )
        return self


def load_runtime_config(path: str | Path) -> RuntimeConfig:
    """从 YAML 文件加载运行配置。"""
    config_path = Path(path)
    if not config_path.exists():
        raise FileNotFoundError(f"配置文件不存在: {config_path}")
    with config_path.open("r", encoding="utf-8") as fh:
        loaded = yaml.safe_load(fh)
    raw = {} if loaded is None else loaded
    return build_runtime_config(raw, base_dir=config_path.parent)


def build_runtime_config(
    raw: dict[str, Any],
    *,
    base_dir: Path | None = None,
) -> RuntimeConfig:
    """从字典构建运行配置。"""
    parsed = RawRuntimeConfigModel.model_validate(raw)

    init_domainset(
        parsed.domainset,
        base_dir=base_dir,
        cache_file=parsed.domainset_cache_file,
    )
    init_ipset(parsed.ipset, base_dir=base_dir)

    request_hook_specs = parsed.effective_request_hook_specs()
    resolver_hook_specs = parsed.effective_resolver_hook_specs()
    response_hook_specs = parsed.effective_response_hook_specs()

    RuntimeSemanticConfigModel.model_validate(
        {
            "request_hooks": request_hook_specs,
            "resolver_hooks": resolver_hook_specs,
            "response_hooks": response_hook_specs,
            "domain_rules": parsed.domain_rules,
            "ip_rules": parsed.ip_rules,
            "domainset_tags": domainset.tags,
            "ipset_tags": ipset.tags,
        }
    )

    request_hook_specs = _apply_top_level_domain_rules(
        request_hook_specs,
        parsed.domain_rules,
    )
    resolver_hook_specs = _apply_top_level_ip_rules(
        resolver_hook_specs,
        parsed.ip_rules,
    )

    pipeline = Pipeline(
        resolvers=[spec.build_resolver() for spec in parsed.effective_resolver_specs()],
        request_hooks=_build_hook_objects(request_hook_specs, expected_base=RequestHook),
        resolver_hooks=_build_hook_objects(
            resolver_hook_specs,
            expected_base=ResolverHook,
        ),
        response_hooks=_build_hook_objects(
            response_hook_specs,
            expected_base=ResponseHook,
        ),
        upstream_timeout_s=parsed.pipeline.upstream_timeout_s,
    )
    return RuntimeConfig(server=parsed.server, pipeline=pipeline)


def _build_hook_objects(
    specs: list[HookSpecModel],
    *,
    expected_base: type[Any],
) -> list[Any]:
    hooks: list[Any] = []
    for spec in specs:
        hook_cls = _load_class(spec.class_path, expected_base=expected_base)
        kwargs = _normalize_hook_kwargs(spec.class_path, spec.kwargs)
        try:
            hooks.append(hook_cls(**kwargs))
        except TypeError as exc:
            raise ValueError(f"{spec.class_path} 参数不合法: {exc}") from exc
    return hooks


def _load_class(class_path: str, *, expected_base: type[Any]) -> type[Any]:
    if "." not in class_path:
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


def _apply_top_level_domain_rules(
    specs: list[HookSpecModel],
    domain_rules: dict[str, Any],
) -> list[HookSpecModel]:
    if not domain_rules:
        return [spec.model_copy(deep=True) for spec in specs]
    updated: list[HookSpecModel] = []
    for spec in specs:
        if spec.class_path == _DOMAIN_RULE_REQUEST_HOOK:
            kwargs = dict(spec.kwargs)
            kwargs["rules"] = domain_rules
            updated.append(spec.model_copy(update={"kwargs": kwargs}, deep=True))
        else:
            updated.append(spec.model_copy(deep=True))
    return updated


def _apply_top_level_ip_rules(
    specs: list[HookSpecModel],
    ip_rules: dict[str, Any],
) -> list[HookSpecModel]:
    if not ip_rules or not ip_rules.get("rules"):
        return [spec.model_copy(deep=True) for spec in specs]
    updated: list[HookSpecModel] = []
    for spec in specs:
        if spec.class_path == _IP_RULE_RESOLVER_HOOK:
            kwargs = dict(spec.kwargs)
            if "rules" in ip_rules:
                kwargs["rules"] = ip_rules["rules"]
            if "skip_result_tags" in ip_rules:
                kwargs["skip_result_tags"] = ip_rules["skip_result_tags"]
            updated.append(spec.model_copy(update={"kwargs": kwargs}, deep=True))
        else:
            updated.append(spec.model_copy(deep=True))
    return updated


def _normalize_hook_kwargs(class_path: str, raw_kwargs: dict[str, Any]) -> dict[str, Any]:
    normalizer = _HOOK_KWARG_NORMALIZERS.get(class_path)
    kwargs = dict(raw_kwargs)
    if normalizer is None:
        return kwargs
    return normalizer(kwargs)


def _normalize_tagged_path_mapping(raw_value: Any, *, key: str) -> dict[str, list[str]]:
    if raw_value is None:
        return {}
    if not isinstance(raw_value, Mapping):
        raise ValueError(f"{key} 必须是对象")

    normalized: dict[str, list[str]] = {}
    for raw_tag, raw_paths in raw_value.items():
        tag = _normalize_nonempty_string(raw_tag, key=f"{key}.<tag>")
        normalized[tag] = _normalize_path_list(raw_paths, key=f"{key}.{tag}")
    return normalized


def _normalize_nonempty_string(raw_value: Any, *, key: str) -> str:
    if not isinstance(raw_value, str):
        raise ValueError(f"{key} 必须是非空字符串")
    value = raw_value.strip()
    if not value:
        raise ValueError(f"{key} 必须是非空字符串")
    return value


def _normalize_string_list(
    raw_value: Any,
    *,
    key: str,
    allow_none: bool = False,
) -> list[str]:
    if raw_value is None and allow_none:
        return []
    if isinstance(raw_value, str):
        values = [raw_value]
    elif isinstance(raw_value, Sequence) and not isinstance(raw_value, (str, bytes, bytearray)):
        values = list(raw_value)
    else:
        raise ValueError(f"{key} 必须是字符串或字符串列表")

    normalized: list[str] = []
    seen: set[str] = set()
    for index, item in enumerate(values):
        tag = _normalize_nonempty_string(item, key=f"{key}[{index}]")
        if tag not in seen:
            seen.add(tag)
            normalized.append(tag)
    if not allow_none and not normalized:
        raise ValueError(f"{key} 至少需要一个 tag")
    return normalized


def _normalize_path_list(raw_value: Any, *, key: str) -> list[str]:
    if isinstance(raw_value, str):
        values = [raw_value]
    elif isinstance(raw_value, Sequence) and not isinstance(raw_value, (str, bytes, bytearray)):
        values = list(raw_value)
    else:
        raise ValueError(f"{key} 必须是字符串或字符串列表")

    normalized: list[str] = []
    for index, item in enumerate(values):
        normalized.append(_normalize_nonempty_string(item, key=f"{key}[{index}]"))
    return normalized


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

    if isinstance(raw_value, Mapping):
        address = _normalize_nonempty_string(raw_value.get("address"), key=f"{key}.address")
        srclen = raw_value.get("srclen")
        scopelen = raw_value.get("scopelen", 0)
        try:
            parsed_srclen = None if srclen is None else int(srclen)
            parsed_scopelen = int(scopelen)
            return dns.edns.ECSOption(
                address,
                srclen=parsed_srclen,
                scopelen=parsed_scopelen,
            )
        except Exception as exc:
            raise ValueError(f"{key} 不是合法的 ECS 配置") from exc

    raise ValueError(f"{key} 必须是字符串或对象")


def _find_hooks(specs: Sequence[HookSpecModel], *, class_path: str) -> list[HookSpecModel]:
    return [spec for spec in specs if spec.class_path == class_path]


def _extract_domain_rule_hook_rules(spec: HookSpecModel) -> dict[str, Any]:
    return normalize_domain_rule_hook_kwargs(spec.kwargs).get("rules", {})


def _hook_has_effective_ip_rules(spec: HookSpecModel) -> bool:
    raw_rules = normalize_ip_rule_hook_kwargs(spec.kwargs)
    return bool(raw_rules.get("rules")) or bool(raw_rules.get("skip_result_tags"))


def _validate_request_hook_order(hooks: Sequence[HookSpecModel]) -> None:
    cache_indexes = [
        index for index, hook in enumerate(hooks) if hook.class_path == _CACHE_HOOK
    ]
    if not cache_indexes:
        return
    last_cache = max(cache_indexes)
    for index, hook in enumerate(hooks):
        if hook.class_path == _DOMAIN_RULE_REQUEST_HOOK and index < last_cache:
            raise ValueError(
                "plugins.domain_rule.DomainRuleRequestHook 必须位于 "
                "plugins.cache.CacheHook 之后"
            )


def _validate_resolver_hook_order(hooks: Sequence[HookSpecModel]) -> None:
    tagset_indexes = [
        index for index, hook in enumerate(hooks) if hook.class_path == _TAGSET_RESOLVER_HOOK
    ]
    ip_rule_indexes = [
        index for index, hook in enumerate(hooks) if hook.class_path == _IP_RULE_RESOLVER_HOOK
    ]
    speedcheck_indexes = [
        index
        for index, hook in enumerate(hooks)
        if hook.class_path == _SPEEDCHECK_RESOLVER_HOOK
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


def _validate_domain_rule_tags(
    rules: dict[str, Any],
    *,
    available_tags: set[str],
    key: str,
) -> None:
    unknown = [tag for tag in rules if tag not in available_tags]
    if unknown:
        raise ValueError(f"{key} 引用了未定义的 tag: {', '.join(sorted(unknown))}")


def _validate_ip_rule_tags(
    ip_rules: dict[str, Any],
    *,
    result_tags: set[str],
    ip_tags: set[str],
    key: str,
) -> None:
    referenced_result_tags = set(ip_rules.get("skip_result_tags", []))
    referenced_ip_tags: set[str] = set()
    for rule in ip_rules.get("rules", []):
        referenced_result_tags.update(rule.get("match_tags", []))
        for section_name in ("A", "AAAA"):
            section = rule.get(section_name)
            if not section:
                continue
            for replacement in section.get("replacements", []):
                referenced_ip_tags.add(replacement["tag"])

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


def _validate_tag_membership(
    referenced_tags: Sequence[str],
    *,
    available_tags: set[str],
    key: str,
    label: str,
) -> None:
    unknown_tags = [tag for tag in referenced_tags if tag not in available_tags]
    if unknown_tags:
        raise ValueError(
            f"{key} 引用了未定义的{label}: {', '.join(sorted(unknown_tags))}"
        )
