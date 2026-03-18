from __future__ import annotations

from cache.dns_cache import DnsLruCache
from config import AppConfig
from core.hooks import RequestHooks
from core.pipeline import RequestPipeline
from logger import get_logger
from rules import build_hooks
from selector.resolver_manager import ResolverManager
from servers.udp_server import UdpDnsServer
from utils.domainset import DomainSet
from utils.ipset import IPSet

logger = get_logger(__name__)


class Application:
    """应用装配入口：负责串联配置、规则、解析器与服务器。"""

    def __init__(self, config: AppConfig) -> None:
        """根据配置构建运行时组件。"""
        domainset = _load_domainset(config)
        ipset = _load_ipset(config)
        hooks = RequestHooks(
            build_hooks(
                domainset=domainset,
                ipset=ipset,
                ad_block_tags=config.rules.ad_block_tags,
                ip_benchmark_top_n=config.rules.ip_benchmark_top_n,
            )
        )
        resolver = ResolverManager.from_upstreams(config.upstreams, hooks=hooks)
        dns_cache = (
            DnsLruCache(max_size=config.cache.max_size)
            if config.cache.enabled
            else None
        )
        pipeline = RequestPipeline(
            resolver,
            hooks=hooks,
            dns_cache=dns_cache,
        )
        self.config = config
        self.server = UdpDnsServer(
            host=config.server.host,
            port=config.server.port,
            pipeline=pipeline,
            max_packet_size=config.server.max_packet_size,
        )

    async def start(self) -> None:
        """启动网络服务。"""
        await self.server.start()

    def close(self) -> None:
        """关闭网络服务。"""
        self.server.close()


def _load_domainset(config: AppConfig) -> DomainSet | None:
    """按配置加载域名规则集。"""
    if not config.rules.domainset_dirs:
        return None
    domainset = DomainSet()
    for directory in config.rules.domainset_dirs:
        domainset.update_directory(directory)
    logger.info(
        "已加载 domainset：目录数=%s 标识=%s",
        len(config.rules.domainset_dirs),
        ", ".join(domainset.identifiers) or "-",
    )
    return domainset


def _load_ipset(config: AppConfig) -> IPSet | None:
    """按配置加载客户端 IP 规则集。"""
    if not config.rules.ipset_dirs:
        return None
    ipset = IPSet()
    for directory in config.rules.ipset_dirs:
        ipset.update_directory(directory)
    logger.info(
        "已加载 ipset：目录数=%s 标识=%s",
        len(config.rules.ipset_dirs),
        ", ".join(ipset.identifiers) or "-",
    )
    return ipset
