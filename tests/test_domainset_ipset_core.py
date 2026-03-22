"""core.domainset / core.ipset 测试。"""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

import dns.name
import dns.rdatatype

from core.context import QueryContext
from core.domainset import DomainSet, init_domainset
from core.ipset import IPSet, init_ipset
from core.models import Query
from plugins.tagset import TagSetRequestHook


class TestDomainSet(unittest.TestCase):
    def test_load_from_files_and_match(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            base = Path(td)
            p1 = base / "domains1.txt"
            p2 = base / "domains2.txt"
            p1.write_text("example.cn\n", encoding="utf-8")
            p2.write_text("qq.com\n", encoding="utf-8")

            domainset = DomainSet()
            domainset.load_from_file(p1, tag="cn")
            domainset.load_from_file(p2, tag="office")
            # load 后不自动重建，手动 rebuild 前不会命中新增规则。
            self.assertFalse(domainset.match("www.example.cn", "cn"))
            domainset.rebuild_tree()

            self.assertTrue(domainset.match("www.example.cn", "cn"))
            self.assertTrue(domainset.match("im.qq.com", "office"))
            self.assertFalse(domainset.match("www.example.cn", "office"))
            self.assertFalse(domainset.match("example.com", "cn"))
            self.assertEqual(domainset.match_tags("a.example.cn"), {"cn"})
            self.assertEqual(domainset.match_tags("im.qq.com"), {"office"})

    def test_save_and_load_cache(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            base = Path(td)
            rules = base / "domains.txt"
            cache = base / "domainset.cache"
            rules.write_text("example.cn\n", encoding="utf-8")

            domainset = DomainSet()
            domainset.load_from_file(rules, tag="cn")
            domainset.rebuild_tree()
            domainset.save(cache)

            loaded = DomainSet()
            loaded.load(cache)
            self.assertTrue(loaded.match("www.example.cn", "cn"))


class TestIPSet(unittest.TestCase):
    def test_load_from_files_and_match(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            base = Path(td)
            p1 = base / "ips1.txt"
            p2 = base / "ips2.txt"
            p1.write_text("10.0.0.0/8\n", encoding="utf-8")
            p2.write_text("240e::/20\n", encoding="utf-8")

            ipset = IPSet()
            ipset.load_from_file(p1, tag="cn")
            ipset.load_from_file(p2, tag="office")

            self.assertTrue(ipset.match("10.12.0.1", "cn"))
            self.assertTrue(ipset.match("240e::1", "office"))
            self.assertFalse(ipset.match("10.12.0.1", "office"))
            self.assertFalse(ipset.match("8.8.8.8", "cn"))
            self.assertEqual(ipset.match_tags("10.2.3.4"), {"cn"})
            self.assertEqual(ipset.match_tags("240e::9"), {"office"})


class TestTagSetHook(unittest.IsolatedAsyncioTestCase):
    async def test_tagset_hook_should_add_tags(self) -> None:
        try:
            with tempfile.TemporaryDirectory() as td:
                base = Path(td)
                (base / "domains.txt").write_text("example.cn\n", encoding="utf-8")
                (base / "ips.txt").write_text("10.0.0.0/8\n", encoding="utf-8")
                init_domainset({"cn": ["domains.txt"]}, base_dir=base)
                init_ipset({"office": ["ips.txt"]}, base_dir=base)

                hook = TagSetRequestHook()
                ctx = QueryContext(
                    query=Query(
                        client_addr=("10.8.0.1", 5335),
                        qname=dns.name.from_text("www.example.cn."),
                        qtype=dns.rdatatype.A,
                    )
                )

            await hook.on_request(ctx)
            self.assertEqual(ctx.tags, {"cn", "office"})
        finally:
            init_domainset({})
            init_ipset({})


if __name__ == "__main__":
    unittest.main()
