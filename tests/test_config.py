"""配置解析测试。"""

from __future__ import annotations

import os
import tempfile
import textwrap
import unittest
from pathlib import Path

import dns.edns

from config import build_runtime_config, load_runtime_config
from core.domainset import domainset
from plugins.builtin import NoopRequestHook
from plugins.cache import CacheHook
from plugins.domain_rule import DomainRuleRequestHook
from plugins.https_record import HttpsRecordResponseHook
from plugins.ip_rule import IPRuleResolverHook
from plugins.speedcheck import SpeedCheckResolverHook
from plugins.tagset import TagSetResolverHook
from plugins.utils.speedcheck import configure_probe_cache, get_probe_cache_config
from resolver.quic_resolver import QuicUpstreamResolver
from resolver.udp_resolver import UdpUpstreamResolver


class TestConfig(unittest.TestCase):
    def test_load_runtime_config_defaults(self) -> None:
        config_path = self._write_temp_yaml("{}")
        runtime = load_runtime_config(config_path)

        self.assertEqual(runtime.server.host, "127.0.0.1")
        self.assertEqual(runtime.server.port, 5335)
        self.assertTrue(runtime.server.udp)
        self.assertFalse(runtime.server.tcp)
        self.assertAlmostEqual(runtime.pipeline.upstream_timeout_s, 0.8)
        self.assertGreaterEqual(len(runtime.pipeline.resolver_manager.resolvers), 1)
        self.assertIsInstance(runtime.pipeline.request_hooks[0], NoopRequestHook)

    def test_load_runtime_config_custom(self) -> None:
        content = """
        server:
          host: 0.0.0.0
          port: 1053
          udp: false
          tcp: true
        pipeline:
          upstream_timeout_s: 1.2
        resolvers:
          - type: udp
            name: cf
            address: 1.1.1.1
            tags: [default, oversea]
          - type: quic
            name: doq
            address: 8.8.8.8
            server_hostname: dns.google
        hooks:
          request:
            - plugins.builtin.NoopRequestHook
          resolver:
            - class: plugins.speedcheck.SpeedCheckResolverHook
              kwargs:
                timeout_s: 0.3
          response:
            - class: plugins.speedcheck.RewriteAnswerByRTTHook
              kwargs:
                max_return_ips: 1
                ttl_s: 700
        """
        runtime = load_runtime_config(self._write_temp_yaml(content))

        self.assertEqual(runtime.server.host, "0.0.0.0")
        self.assertEqual(runtime.server.port, 1053)
        self.assertFalse(runtime.server.udp)
        self.assertTrue(runtime.server.tcp)
        self.assertAlmostEqual(runtime.pipeline.upstream_timeout_s, 1.2)
        self.assertEqual(len(runtime.pipeline.resolver_manager.resolvers), 2)
        self.assertIsInstance(runtime.pipeline.resolver_manager.resolvers[0], UdpUpstreamResolver)
        self.assertEqual(runtime.pipeline.resolver_manager.resolvers[0].tags, {"default", "oversea"})
        self.assertIsInstance(runtime.pipeline.resolver_manager.resolvers[1], QuicUpstreamResolver)
        self.assertIsInstance(runtime.pipeline.resolver_manager.resolver_hooks[0], SpeedCheckResolverHook)
        self.assertAlmostEqual(runtime.pipeline.resolver_manager.resolver_hooks[0].timeout_s, 0.3)
        self.assertEqual(runtime.pipeline.response_hooks[0].max_return_ips, 1)

    def test_speedcheck_hook_cache_config_should_load(self) -> None:
        original_cache_config = get_probe_cache_config()
        self.addCleanup(
            lambda: configure_probe_cache(
                max_size=original_cache_config[0],
                ttl_s=original_cache_config[1],
            )
        )
        raw = {
            "hooks": {
                "resolver": [
                    {
                        "class": "plugins.speedcheck.SpeedCheckResolverHook",
                        "kwargs": {
                            "timeout_s": 0.3,
                            "max_size": 10000,
                            "ttl_s": 3600,
                        },
                    }
                ]
            }
        }

        runtime = build_runtime_config(raw)
        hook = runtime.pipeline.resolver_manager.resolver_hooks[0]

        self.assertIsInstance(hook, SpeedCheckResolverHook)
        self.assertAlmostEqual(hook.timeout_s, 0.3)
        self.assertEqual(get_probe_cache_config(), (10000, 3600.0))

    def test_server_udp_and_tcp_cannot_both_be_disabled(self) -> None:
        raw = {
            "server": {
                "udp": False,
                "tcp": False,
            }
        }

        with self.assertRaisesRegex(ValueError, "不能同时为 false"):
            build_runtime_config(raw)

    def test_https_record_response_hook_should_load_with_defaults(self) -> None:
        content = """
        ipset:
          cloudflare:
            - cloudflare.txt
        hooks:
          response:
            - class: plugins.https_record.HttpsRecordResponseHook
        """
        with tempfile.TemporaryDirectory(prefix="mydns-https-response-hook-") as td:
            base = Path(td)
            (base / "cloudflare.txt").write_text("1.1.1.0/24\n", encoding="utf-8")
            path = base / "mydns.yaml"
            path.write_text(textwrap.dedent(content), encoding="utf-8")
            runtime = load_runtime_config(path)

        self.assertIsInstance(runtime.pipeline.response_hooks[0], HttpsRecordResponseHook)
        self.assertEqual(runtime.pipeline.response_hooks[0].cloudflare_tags, {"cloudflare"})

    def test_https_record_response_hook_should_validate_skip_tags(self) -> None:
        raw = {
            "ipset": {
                "cloudflare": ["cloudflare.txt"],
            },
            "hooks": {
                "response": [
                    {
                        "class": "plugins.https_record.HttpsRecordResponseHook",
                        "kwargs": {
                            "skip_result_tags": ["missing"],
                        },
                    }
                ]
            },
        }
        with tempfile.TemporaryDirectory(prefix="mydns-https-response-hook-skip-") as td:
            base = Path(td)
            (base / "cloudflare.txt").write_text("1.1.1.0/24\n", encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "未定义的结果 tag"):
                build_runtime_config(raw, base_dir=base)

    def test_https_record_response_hook_should_validate_cloudflare_tags(self) -> None:
        raw = {
            "hooks": {
                "response": [
                    {
                        "class": "plugins.https_record.HttpsRecordResponseHook",
                        "kwargs": {
                            "cloudflare_tags": ["missing"],
                        },
                    }
                ]
            },
        }
        with self.assertRaisesRegex(ValueError, "未定义的Cloudflare tag"):
            build_runtime_config(raw)

    def test_tagset_hook_should_load_when_declared_manually(self) -> None:
        content = """
        domainset:
          ads:
            - ads.txt
        hooks:
          resolver:
            - class: plugins.tagset.TagSetResolverHook
            - class: plugins.speedcheck.SpeedCheckResolverHook
        """
        with tempfile.TemporaryDirectory(prefix="mydns-tagset-order-") as td:
            base = Path(td)
            (base / "ads.txt").write_text("ads.example.com\n", encoding="utf-8")
            path = base / "mydns.yaml"
            path.write_text(textwrap.dedent(content), encoding="utf-8")
            runtime = load_runtime_config(path)

        self.assertIsInstance(
            runtime.pipeline.resolver_manager.resolver_hooks[0],
            TagSetResolverHook,
        )
        self.assertIsInstance(
            runtime.pipeline.resolver_manager.resolver_hooks[1],
            SpeedCheckResolverHook,
        )

    def test_tagset_hook_after_speedcheck_should_raise(self) -> None:
        raw = {
            "domainset": {
                "ads": ["ads.txt"],
            },
            "hooks": {
                "resolver": [
                    "plugins.speedcheck.SpeedCheckResolverHook",
                    "plugins.tagset.TagSetResolverHook",
                ]
            },
        }

        with tempfile.TemporaryDirectory(prefix="mydns-tagset-order-") as td:
            base = Path(td)
            (base / "ads.txt").write_text("ads.example.com\n", encoding="utf-8")
            with self.assertRaisesRegex(
                ValueError,
                "TagSetResolverHook 必须位于 .*SpeedCheckResolverHook 之前",
            ):
                build_runtime_config(raw, base_dir=base)

    def test_domain_rule_hook_before_cache_should_raise(self) -> None:
        raw = {
            "domainset": {
                "cn": ["domains.txt"],
            },
            "domain_rules": {
                "cn": "intercept",
            },
            "hooks": {
                "request": [
                    "plugins.domain_rule.DomainRuleRequestHook",
                    "plugins.cache.CacheHook",
                ]
            },
        }

        with tempfile.TemporaryDirectory(prefix="mydns-domain-rule-before-cache-") as td:
            base = Path(td)
            (base / "domains.txt").write_text("example.cn\n", encoding="utf-8")
            with self.assertRaisesRegex(
                ValueError,
                "DomainRuleRequestHook 必须位于 .*CacheHook 之后",
            ):
                build_runtime_config(raw, base_dir=base)

    def test_resolver_timeout_and_ecs_should_load_from_config(self) -> None:
        raw = {
            "resolvers": [
                {
                    "type": "udp",
                    "name": "cf",
                    "address": "1.1.1.1",
                    "timeout": 0.25,
                    "ecs": "203.0.113.0/24",
                },
                {
                    "type": "udp",
                    "name": "v6",
                    "address": "2001:4860:4860::8888",
                    "ecs": {
                        "address": "2001:db8::",
                        "srclen": 48,
                        "scopelen": 0,
                    },
                },
            ]
        }

        runtime = build_runtime_config(raw)
        resolver1 = runtime.pipeline.resolver_manager.resolvers[0]
        resolver2 = runtime.pipeline.resolver_manager.resolvers[1]

        self.assertAlmostEqual(resolver1.timeout, 0.25)
        self.assertIsInstance(resolver1.ecs, dns.edns.ECSOption)
        self.assertEqual(resolver1.ecs.address, "203.0.113.0")
        self.assertEqual(resolver1.ecs.srclen, 24)
        self.assertIsInstance(resolver2.ecs, dns.edns.ECSOption)
        self.assertEqual(resolver2.ecs.address, "2001:db8::")
        self.assertEqual(resolver2.ecs.srclen, 48)

    def test_unknown_resolver_type_should_raise(self) -> None:
        raw = {
            "resolvers": [
                {
                    "type": "unknown",
                    "name": "bad",
                    "address": "1.1.1.1",
                }
            ]
        }
        with self.assertRaises(ValueError):
            build_runtime_config(raw)

    def test_wrong_hook_type_should_raise(self) -> None:
        raw = {
            "hooks": {
                "request": [
                    "resolver.udp_resolver.UdpUpstreamResolver",
                ]
            }
        }
        with self.assertRaises(ValueError):
            build_runtime_config(raw)

    def test_removed_resolver_options_should_raise(self) -> None:
        cases = [
            ("tcp", "source", "127.0.0.1"),
            ("tls", "ssl_context", object()),
            ("quic", "source_port", 1053),
            ("https", "post", True),
        ]
        for resolver_type, key, value in cases:
            raw = {
                "resolvers": [
                    {
                        "type": resolver_type,
                        "name": "x",
                        "address": "dns.example"
                        if resolver_type == "https"
                        else "1.1.1.1",
                        key: value,
                    }
                ]
            }
            with self.assertRaises(ValueError):
                build_runtime_config(raw)

    def test_load_runtime_config_with_domainset_and_ipset(self) -> None:
        with tempfile.TemporaryDirectory(prefix="mydns-tagsets-") as td:
            base = Path(td)
            (base / "domains.txt").write_text("example.cn\n", encoding="utf-8")
            (base / "ips.txt").write_text("10.0.0.0/8\n", encoding="utf-8")
            (base / "mydns.yaml").write_text(
                textwrap.dedent(
                    """
                    domainset:
                      cn:
                        - domains.txt
                    domain_rules:
                      cn: intercept
                    ipset:
                      office:
                        - ips.txt
                    ip_rules:
                      rules:
                        - match_tags: [cn]
                          A:
                            replacements:
                              - tag: office
                                ip: 203.0.113.10
                    hooks:
                      request:
                        - class: plugins.domain_rule.DomainRuleRequestHook
                      resolver:
                        - class: plugins.tagset.TagSetResolverHook
                        - class: plugins.ip_rule.IPRuleResolverHook
                    """
                ),
                encoding="utf-8",
            )

            runtime = load_runtime_config(base / "mydns.yaml")
            self.assertIsInstance(runtime.pipeline.request_hooks[0], DomainRuleRequestHook)
            hook = runtime.pipeline.request_hooks[0]
            self.assertIn("cn", hook.domainset_by_tag)
            self.assertTrue(hook.rules)
            self.assertTrue(
                any(
                    isinstance(item, IPRuleResolverHook)
                    for item in runtime.pipeline.resolver_manager.resolver_hooks
                )
            )

    def test_domain_rule_hook_should_load_after_cache_when_declared_manually(self) -> None:
        with tempfile.TemporaryDirectory(prefix="mydns-domain-rule-order-") as td:
            base = Path(td)
            (base / "domains.txt").write_text("example.cn\n", encoding="utf-8")
            path = base / "mydns.yaml"
            path.write_text(
                textwrap.dedent(
                    """
                    domainset:
                      cn:
                        - domains.txt
                    domain_rules:
                      cn: intercept
                    hooks:
                      request:
                        - class: plugins.cache.CacheHook
                        - class: plugins.domain_rule.DomainRuleRequestHook
                        - plugins.builtin.NoopRequestHook
                    """
                ),
                encoding="utf-8",
            )

            runtime = load_runtime_config(path)

        self.assertIsInstance(runtime.pipeline.request_hooks[0], CacheHook)
        self.assertIsInstance(runtime.pipeline.request_hooks[1], DomainRuleRequestHook)
        self.assertIsInstance(runtime.pipeline.request_hooks[2], NoopRequestHook)

    def test_ip_rule_hook_should_load_after_tagset_and_before_speedcheck(self) -> None:
        content = """
        domainset:
          cn:
            - domains.txt
        ipset:
          office:
            - ips.txt
        ip_rules:
          rules:
            - match_tags: [cn]
              A:
                replacements:
                  - tag: office
                    ip: 203.0.113.10
        hooks:
          resolver:
            - class: plugins.tagset.TagSetResolverHook
            - class: plugins.ip_rule.IPRuleResolverHook
            - class: plugins.speedcheck.SpeedCheckResolverHook
        """
        with tempfile.TemporaryDirectory(prefix="mydns-ip-rule-") as td:
            base = Path(td)
            (base / "domains.txt").write_text("example.cn\n", encoding="utf-8")
            (base / "ips.txt").write_text("10.0.0.0/8\n", encoding="utf-8")
            path = base / "mydns.yaml"
            path.write_text(textwrap.dedent(content), encoding="utf-8")
            runtime = load_runtime_config(path)

        self.assertIsInstance(
            runtime.pipeline.resolver_manager.resolver_hooks[0],
            TagSetResolverHook,
        )
        self.assertIsInstance(
            runtime.pipeline.resolver_manager.resolver_hooks[1],
            IPRuleResolverHook,
        )
        self.assertIsInstance(
            runtime.pipeline.resolver_manager.resolver_hooks[2],
            SpeedCheckResolverHook,
        )

    def test_domain_rule_should_require_manual_hook(self) -> None:
        raw = {
            "domainset": {
                "cn": ["domains.txt"],
            },
            "domain_rules": {
                "cn": "intercept",
            },
        }

        with tempfile.TemporaryDirectory(prefix="mydns-domain-rule-required-") as td:
            base = Path(td)
            (base / "domains.txt").write_text("example.cn\n", encoding="utf-8")
            with self.assertRaises(ValueError):
                build_runtime_config(raw, base_dir=base)

    def test_ip_rule_should_require_manual_hook(self) -> None:
        raw = {
            "domainset": {
                "cn": ["domains.txt"],
            },
            "ipset": {
                "office": ["ips.txt"],
            },
            "ip_rules": {
                "rules": [
                    {
                        "match_tags": ["cn"],
                        "A": {
                            "replacements": [
                                {
                                    "tag": "office",
                                    "ip": "203.0.113.10",
                                }
                            ]
                        },
                    }
                ]
            },
            "hooks": {
                "resolver": [
                    "plugins.tagset.TagSetResolverHook",
                ]
            },
        }

        with tempfile.TemporaryDirectory(prefix="mydns-ip-rule-required-") as td:
            base = Path(td)
            (base / "domains.txt").write_text("example.cn\n", encoding="utf-8")
            (base / "ips.txt").write_text("10.0.0.0/8\n", encoding="utf-8")
            with self.assertRaises(ValueError):
                build_runtime_config(raw, base_dir=base)

    def test_ip_rule_hook_after_speedcheck_should_raise(self) -> None:
        raw = {
            "domainset": {
                "cn": ["domains.txt"],
            },
            "ipset": {
                "office": ["ips.txt"],
            },
            "hooks": {
                "resolver": [
                    "plugins.speedcheck.SpeedCheckResolverHook",
                    {
                        "class": "plugins.ip_rule.IPRuleResolverHook",
                        "kwargs": {
                            "rules": [
                                {
                                    "match_tags": ["cn"],
                                    "A": {
                                        "replacements": [
                                            {
                                                "tag": "office",
                                                "ip": "203.0.113.10",
                                            }
                                        ]
                                    },
                                }
                            ]
                        },
                    },
                ]
            }
        }

        with tempfile.TemporaryDirectory(prefix="mydns-ip-rule-speedcheck-order-") as td:
            base = Path(td)
            (base / "domains.txt").write_text("example.cn\n", encoding="utf-8")
            (base / "ips.txt").write_text("10.0.0.0/8\n", encoding="utf-8")
            with self.assertRaisesRegex(
                ValueError,
                "IPRuleResolverHook 必须位于 .*SpeedCheckResolverHook 之前",
            ):
                build_runtime_config(raw, base_dir=base)

    def test_ip_rule_should_validate_replacement_ip_tags(self) -> None:
        raw = {
            "domainset": {
                "cn": ["domains.txt"],
            },
            "ipset": {
                "office": ["ips.txt"],
            },
            "ip_rules": {
                "rules": [
                    {
                        "match_tags": ["cn"],
                        "A": {
                            "replacements": [
                                {
                                    "tag": "telegram",
                                    "ip": "203.0.113.10",
                                }
                            ]
                        },
                    }
                ]
            },
            "hooks": {
                "resolver": [
                    "plugins.tagset.TagSetResolverHook",
                    "plugins.ip_rule.IPRuleResolverHook",
                ]
            },
        }

        with tempfile.TemporaryDirectory(prefix="mydns-ip-rule-iptag-") as td:
            base = Path(td)
            (base / "domains.txt").write_text("example.cn\n", encoding="utf-8")
            (base / "ips.txt").write_text("10.0.0.0/8\n", encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "未定义的 IP tag"):
                build_runtime_config(raw, base_dir=base)

    def test_ip_rule_hook_before_tagset_should_raise(self) -> None:
        raw = {
            "domainset": {
                "cn": ["domains.txt"],
            },
            "ipset": {
                "office": ["ips.txt"],
            },
            "hooks": {
                "resolver": [
                    {
                        "class": "plugins.ip_rule.IPRuleResolverHook",
                        "kwargs": {
                            "rules": [
                                {
                                    "match_tags": ["cn"],
                                    "A": {
                                        "replacements": [
                                            {
                                                "tag": "office",
                                                "ip": "203.0.113.10",
                                            }
                                        ]
                                    },
                                }
                            ]
                        },
                    },
                    "plugins.tagset.TagSetResolverHook",
                ]
            },
        }

        with tempfile.TemporaryDirectory(prefix="mydns-ip-rule-tagset-order-") as td:
            base = Path(td)
            (base / "domains.txt").write_text("example.cn\n", encoding="utf-8")
            (base / "ips.txt").write_text("10.0.0.0/8\n", encoding="utf-8")
            with self.assertRaisesRegex(
                ValueError,
                "TagSetResolverHook 必须位于 .*IPRuleResolverHook 之前",
            ):
                build_runtime_config(raw, base_dir=base)

    def test_domainset_cache_file_should_prefer_cache(self) -> None:
        with tempfile.TemporaryDirectory(prefix="mydns-domainset-cache-") as td:
            base = Path(td)
            domains_file = base / "domains.txt"
            config_file = base / "mydns.yaml"
            cache_file = base / "domainset.cache"
            domains_file.write_text("example.cn\n", encoding="utf-8")
            config_file.write_text(
                textwrap.dedent(
                    """
                    domainset_cache_file: domainset.cache
                    domainset:
                      cn:
                        - domains.txt
                    """
                ),
                encoding="utf-8",
            )

            load_runtime_config(config_file)
            self.assertTrue(cache_file.exists())
            self.assertTrue(domainset.match("www.example.cn", "cn"))

            domains_file.write_text("changed.cn\n", encoding="utf-8")
            load_runtime_config(config_file)
            # 缓存命中时优先使用缓存文件而不是重读规则文本。
            self.assertTrue(domainset.match("www.example.cn", "cn"))
            self.assertFalse(domainset.match("www.changed.cn", "cn"))

    def test_domainset_empty_cache_file_should_skip_cache(self) -> None:
        with tempfile.TemporaryDirectory(prefix="mydns-domainset-no-cache-") as td:
            base = Path(td)
            domains_file = base / "domains.txt"
            config_file = base / "mydns.yaml"
            domains_file.write_text("example.cn\n", encoding="utf-8")
            config_file.write_text(
                textwrap.dedent(
                    """
                    domainset_cache_file: ""
                    domainset:
                      cn:
                        - domains.txt
                    """
                ),
                encoding="utf-8",
            )

            load_runtime_config(config_file)
            self.assertTrue(domainset.match("www.example.cn", "cn"))

            domains_file.write_text("changed.cn\n", encoding="utf-8")
            load_runtime_config(config_file)
            # cache_file 为空应跳过缓存读写，按最新文本规则重建。
            self.assertFalse(domainset.match("www.example.cn", "cn"))
            self.assertTrue(domainset.match("www.changed.cn", "cn"))

    def _write_temp_yaml(self, content: str) -> Path:
        fd, raw_path = tempfile.mkstemp(prefix="mydns-config-", suffix=".yaml")
        os.close(fd)
        path = Path(raw_path)
        path.write_text(textwrap.dedent(content), encoding="utf-8")
        self.addCleanup(lambda: path.unlink(missing_ok=True))
        return path


if __name__ == "__main__":
    unittest.main()
