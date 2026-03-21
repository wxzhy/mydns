"""配置解析测试。"""

from __future__ import annotations

import os
import tempfile
import textwrap
import unittest
from pathlib import Path

from config import build_runtime_config, load_runtime_config
from plugins.builtin import NoopRequestHook
from plugins.tagset import TagSetRequestHook
from plugins.speedcheck import SpeedCheckResolverHook
from resolver.quic_resolver import QuicUpstreamResolver
from resolver.udp_resolver import UdpUpstreamResolver


class TestConfig(unittest.TestCase):
    def test_load_runtime_config_defaults(self) -> None:
        config_path = self._write_temp_yaml("{}")
        runtime = load_runtime_config(config_path)

        self.assertEqual(runtime.server.host, "127.0.0.1")
        self.assertEqual(runtime.server.port, 5335)
        self.assertAlmostEqual(runtime.pipeline.upstream_timeout_s, 0.8)
        self.assertGreaterEqual(len(runtime.pipeline.resolver_manager.resolvers), 1)
        self.assertIsInstance(runtime.pipeline.request_hooks[0], NoopRequestHook)

    def test_load_runtime_config_custom(self) -> None:
        content = """
        server:
          host: 0.0.0.0
          port: 1053
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
        self.assertAlmostEqual(runtime.pipeline.upstream_timeout_s, 1.2)
        self.assertEqual(len(runtime.pipeline.resolver_manager.resolvers), 2)
        self.assertIsInstance(runtime.pipeline.resolver_manager.resolvers[0], UdpUpstreamResolver)
        self.assertEqual(runtime.pipeline.resolver_manager.resolvers[0].tags, {"default", "oversea"})
        self.assertIsInstance(runtime.pipeline.resolver_manager.resolvers[1], QuicUpstreamResolver)
        self.assertIsInstance(runtime.pipeline.resolver_manager.resolver_hooks[0], SpeedCheckResolverHook)
        self.assertEqual(runtime.pipeline.response_hooks[0].max_return_ips, 1)

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

    def test_load_runtime_config_with_domainset_and_ipset(self) -> None:
        with tempfile.TemporaryDirectory(prefix="mydns-tagsets-") as td:
            base = Path(td)
            (base / "domains.txt").write_text("example.cn\n", encoding="utf-8")
            (base / "ips.txt").write_text("10.0.0.0/8\n", encoding="utf-8")
            (base / "mydns.yaml").write_text(
                textwrap.dedent(
                    """
                    domainset:
                      cn: domains.txt
                    ipset:
                      office: ips.txt
                    """
                ),
                encoding="utf-8",
            )

            runtime = load_runtime_config(base / "mydns.yaml")
            self.assertIsInstance(runtime.pipeline.request_hooks[0], TagSetRequestHook)
            hook = runtime.pipeline.request_hooks[0]
            self.assertIn("cn", hook.domainset_by_tag)
            self.assertIn("office", hook.ipset_by_tag)

    def _write_temp_yaml(self, content: str) -> Path:
        fd, raw_path = tempfile.mkstemp(prefix="mydns-config-", suffix=".yaml")
        os.close(fd)
        path = Path(raw_path)
        path.write_text(textwrap.dedent(content), encoding="utf-8")
        self.addCleanup(lambda: path.unlink(missing_ok=True))
        return path


if __name__ == "__main__":
    unittest.main()
