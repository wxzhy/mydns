"""core.domainset / core.ipset 测试。"""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

import dns.name
import dns.rcode
import dns.rdatatype
import dns.rrset

from core.answer import Answer
from core.context import QueryContext
from core.domainset import DomainSet, init_domainset
from core.ipset import IPSet, init_ipset
from core.models import Query, ResolverResult
from plugins.domain_rule import DomainRuleRequestHook
from plugins.ip_rule import IPRuleResolverHook
from plugins.speedcheck import SpeedCheckResolverHook


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
            p3 = base / "ips3.txt"
            p1.write_text("10.0.0.0/8\n", encoding="utf-8")
            p2.write_text("240e::/20\n", encoding="utf-8")
            p3.write_text("10.2.0.0/16\n", encoding="utf-8")

            ipset = IPSet()
            ipset.load_from_file(p1, tag="cn")
            ipset.load_from_file(p2, tag="office")
            ipset.load_from_file(p3, tag="telegram")

            self.assertTrue(ipset.match("10.12.0.1", "cn"))
            self.assertTrue(ipset.match("240e::1", "office"))
            self.assertTrue(ipset.match("10.2.3.4", "cn"))
            self.assertTrue(ipset.match("10.2.3.4", "telegram"))
            self.assertFalse(ipset.match("10.12.0.1", "office"))
            self.assertFalse(ipset.match("8.8.8.8", "cn"))
            self.assertEqual(ipset.match_tags("10.2.3.4"), {"cn", "telegram"})
            self.assertEqual(ipset.match_tags("240e::9"), {"office"})


class TestDomainRuleHook(unittest.IsolatedAsyncioTestCase):
    async def test_domain_rule_should_add_tags(self) -> None:
        try:
            with tempfile.TemporaryDirectory() as td:
                base = Path(td)
                (base / "domains.txt").write_text("example.cn\n", encoding="utf-8")
                init_domainset({"cn": ["domains.txt"]}, base_dir=base)

                hook = DomainRuleRequestHook()
                ctx = QueryContext(
                    query=Query(
                        client_addr=("127.0.0.1", 5335),
                        qname=dns.name.from_text("www.example.cn."),
                        qtype=dns.rdatatype.A,
                    )
                )

            await hook.on_request(ctx)
            self.assertEqual(ctx.tags, {"cn"})
        finally:
            init_domainset({})

    async def test_domain_rule_should_ignore_client_ip(self) -> None:
        try:
            with tempfile.TemporaryDirectory() as td:
                base = Path(td)
                (base / "domains.txt").write_text("example.cn\n", encoding="utf-8")
                (base / "ips.txt").write_text("10.0.0.0/8\n", encoding="utf-8")
                init_domainset({"cn": ["domains.txt"]}, base_dir=base)
                init_ipset({"private": ["ips.txt"]}, base_dir=base)

                hook = DomainRuleRequestHook()
                ctx = QueryContext(
                    query=Query(
                        client_addr=("10.1.2.3", 5335),
                        qname=dns.name.from_text("www.example.cn."),
                        qtype=dns.rdatatype.A,
                    )
                )

            await hook.on_request(ctx)
            self.assertEqual(ctx.tags, {"cn"})
        finally:
            init_domainset({})
            init_ipset({})

    async def test_domain_rule_should_intercept_a_query(self) -> None:
        try:
            with tempfile.TemporaryDirectory() as td:
                base = Path(td)
                (base / "ads.txt").write_text("ads.example.com\n", encoding="utf-8")
                init_domainset({"ads": ["ads.txt"]}, base_dir=base)

                hook = DomainRuleRequestHook(rules={"ads": "intercept"})
                ctx = QueryContext(
                    query=Query(
                        client_addr=("127.0.0.1", 5335),
                        qname=dns.name.from_text("ads.example.com."),
                        qtype=dns.rdatatype.A,
                    )
                )

            await hook.on_request(ctx)

            self.assertTrue(ctx.stop)
            self.assertEqual(ctx.tags, {"ads"})
            self.assertIsNotNone(ctx.final_answer)
            assert ctx.final_answer is not None
            self.assertEqual(ctx.final_answer.response.rcode(), dns.rcode.NOERROR)
            self.assertEqual(len(ctx.final_answer.response.answer), 1)
            rrset = ctx.final_answer.response.answer[0]
            self.assertEqual(rrset.rdtype, dns.rdatatype.A)
            self.assertEqual(rrset.ttl, 86400)
            self.assertEqual(rrset[0].to_text(), "127.0.0.1")
        finally:
            init_domainset({})

    async def test_domain_rule_should_intercept_aaaa_query(self) -> None:
        try:
            with tempfile.TemporaryDirectory() as td:
                base = Path(td)
                (base / "ads.txt").write_text("ads.example.com\n", encoding="utf-8")
                init_domainset({"ads": ["ads.txt"]}, base_dir=base)

                hook = DomainRuleRequestHook(rules={"ads": "intercept"})
                ctx = QueryContext(
                    query=Query(
                        client_addr=("127.0.0.1", 5335),
                        qname=dns.name.from_text("ads.example.com."),
                        qtype=dns.rdatatype.AAAA,
                    )
                )

            await hook.on_request(ctx)

            self.assertTrue(ctx.stop)
            self.assertEqual(ctx.tags, {"ads"})
            self.assertIsNotNone(ctx.final_answer)
            assert ctx.final_answer is not None
            self.assertEqual(ctx.final_answer.response.rcode(), dns.rcode.NOERROR)
            self.assertEqual(len(ctx.final_answer.response.answer), 1)
            rrset = ctx.final_answer.response.answer[0]
            self.assertEqual(rrset.rdtype, dns.rdatatype.AAAA)
            self.assertEqual(rrset.ttl, 86400)
            self.assertEqual(rrset[0].to_text(), "::1")
        finally:
            init_domainset({})

    async def test_domain_rule_should_return_empty_noerror_for_non_address_intercept(
        self,
    ) -> None:
        try:
            with tempfile.TemporaryDirectory() as td:
                base = Path(td)
                (base / "ads.txt").write_text("ads.example.com\n", encoding="utf-8")
                init_domainset({"ads": ["ads.txt"]}, base_dir=base)

                hook = DomainRuleRequestHook(rules={"ads": "intercept"})
                ctx = QueryContext(
                    query=Query(
                        client_addr=("127.0.0.1", 5335),
                        qname=dns.name.from_text("ads.example.com."),
                        qtype=dns.rdatatype.TXT,
                    )
                )

            await hook.on_request(ctx)

            self.assertTrue(ctx.stop)
            self.assertEqual(ctx.tags, {"ads"})
            self.assertIsNotNone(ctx.final_answer)
            assert ctx.final_answer is not None
            self.assertEqual(ctx.final_answer.response.rcode(), dns.rcode.NOERROR)
            self.assertEqual(ctx.final_answer.response.answer, [])
        finally:
            init_domainset({})

    async def test_domain_rule_hosts_should_short_circuit_a_query(self) -> None:
        try:
            with tempfile.TemporaryDirectory() as td:
                base = Path(td)
                (base / "private.txt").write_text("router.lan\n", encoding="utf-8")
                init_domainset({"private": ["private.txt"]}, base_dir=base)

                hook = DomainRuleRequestHook(
                    rules={
                        "private": {
                            "action": "hosts",
                            "A": "192.0.2.10",
                            "AAAA": "2001:db8::10",
                        }
                    }
                )
                ctx = QueryContext(
                    query=Query(
                        client_addr=("127.0.0.1", 5335),
                        qname=dns.name.from_text("router.lan."),
                        qtype=dns.rdatatype.A,
                    )
                )

            await hook.on_request(ctx)

            self.assertTrue(ctx.stop)
            self.assertEqual(ctx.tags, {"private"})
            assert ctx.final_answer is not None
            self.assertEqual(ctx.final_answer.response.rcode(), dns.rcode.NOERROR)
            self.assertEqual(
                [rdata.to_text() for rdata in ctx.final_answer.rrset],
                ["192.0.2.10"],
            )
            self.assertEqual(ctx.final_answer.rrset.ttl, 86400)
        finally:
            init_domainset({})

    async def test_domain_rule_hosts_should_forward_non_address_query(self) -> None:
        try:
            with tempfile.TemporaryDirectory() as td:
                base = Path(td)
                (base / "private.txt").write_text("router.lan\n", encoding="utf-8")
                init_domainset({"private": ["private.txt"]}, base_dir=base)

                hook = DomainRuleRequestHook(
                    rules={
                        "private": {
                            "action": "hosts",
                            "A": "192.0.2.10",
                        }
                    }
                )
                ctx = QueryContext(
                    query=Query(
                        client_addr=("127.0.0.1", 5335),
                        qname=dns.name.from_text("router.lan."),
                        qtype=dns.rdatatype.TXT,
                    )
                )

            await hook.on_request(ctx)

            self.assertFalse(ctx.stop)
            self.assertEqual(ctx.tags, {"private"})
            self.assertIsNone(ctx.final_answer)
        finally:
            init_domainset({})


class TestIPRuleResolverHook(unittest.IsolatedAsyncioTestCase):
    async def test_ip_rule_should_replace_a_answer(self) -> None:
        try:
            with tempfile.TemporaryDirectory() as td:
                base = Path(td)
                (base / "telegram.txt").write_text("1.1.1.0/24\n", encoding="utf-8")
                init_ipset({"telegram": ["telegram.txt"]}, base_dir=base)

                hook = IPRuleResolverHook(
                    rules={
                        "telegram": {
                            "action": "replace",
                            "A": "203.0.113.10",
                        }
                    }
                )
                ctx = QueryContext(
                    query=Query(
                        client_addr=("127.0.0.1", 5335),
                        qname=dns.name.from_text("www.example.com."),
                        qtype=dns.rdatatype.A,
                    )
                )
                rrset = dns.rrset.from_text(
                    "www.example.com.",
                    60,
                    "IN",
                    "A",
                    "1.1.1.1",
                    "8.8.8.8",
                )
                result = ResolverResult(
                    resolver_name="upstream",
                    answer=Answer.from_query(
                        ctx.query,
                        rcode=dns.rcode.NOERROR,
                        rrsets=[rrset],
                    ),
                    elapsed_ms=1.0,
                    error=None,
                )

            rewritten = await hook.on_resolver_result(ctx, result)

            assert rewritten is not None
            assert rewritten.answer is not None
            self.assertEqual(
                [rdata.to_text() for rdata in rewritten.answer.rrset],
                ["203.0.113.10", "8.8.8.8"],
            )
            self.assertEqual(rewritten.answer.rrset.ttl, 60)
        finally:
            init_ipset({})

    async def test_ip_rule_should_ignore_client_ip(self) -> None:
        try:
            with tempfile.TemporaryDirectory() as td:
                base = Path(td)
                (base / "private.txt").write_text("10.0.0.0/8\n", encoding="utf-8")
                init_ipset({"private": ["private.txt"]}, base_dir=base)

                hook = IPRuleResolverHook(
                    rules={
                        "private": {
                            "action": "remove",
                        }
                    }
                )
                ctx = QueryContext(
                    query=Query(
                        client_addr=("10.1.1.1", 5335),
                        qname=dns.name.from_text("www.example.com."),
                        qtype=dns.rdatatype.A,
                    )
                )
                rrset = dns.rrset.from_text(
                    "www.example.com.",
                    60,
                    "IN",
                    "A",
                    "8.8.8.8",
                )
                result = ResolverResult(
                    resolver_name="upstream",
                    answer=Answer.from_query(
                        ctx.query,
                        rcode=dns.rcode.NOERROR,
                        rrsets=[rrset],
                    ),
                    elapsed_ms=1.0,
                    error=None,
                )

            rewritten = await hook.on_resolver_result(ctx, result)

            assert rewritten is not None
            assert rewritten.answer is not None
            self.assertEqual(
                [rdata.to_text() for rdata in rewritten.answer.rrset],
                ["8.8.8.8"],
            )
        finally:
            init_ipset({})

    async def test_ip_rule_should_replace_prefix(self) -> None:
        try:
            with tempfile.TemporaryDirectory() as td:
                base = Path(td)
                (base / "cn.txt").write_text("1.1.0.0/16\n", encoding="utf-8")
                init_ipset({"cn": ["cn.txt"]}, base_dir=base)

                hook = IPRuleResolverHook(
                    rules={
                        "cn": {
                            "action": "replace_prefix",
                            "A": "203.0.113.0/24",
                        }
                    }
                )
                ctx = QueryContext(
                    query=Query(
                        client_addr=("127.0.0.1", 5335),
                        qname=dns.name.from_text("www.example.com."),
                        qtype=dns.rdatatype.A,
                    )
                )
                rrset = dns.rrset.from_text(
                    "www.example.com.",
                    60,
                    "IN",
                    "A",
                    "1.1.2.3",
                )
                result = ResolverResult(
                    resolver_name="upstream",
                    answer=Answer.from_query(
                        ctx.query,
                        rcode=dns.rcode.NOERROR,
                        rrsets=[rrset],
                    ),
                    elapsed_ms=1.0,
                    error=None,
                )

            rewritten = await hook.on_resolver_result(ctx, result)

            assert rewritten is not None
            assert rewritten.answer is not None
            self.assertEqual(
                [rdata.to_text() for rdata in rewritten.answer.rrset],
                ["203.0.113.3"],
            )
            self.assertEqual(rewritten.answer.rrset.ttl, 60)
        finally:
            init_ipset({})

    async def test_ip_rule_should_remove_ip(self) -> None:
        try:
            with tempfile.TemporaryDirectory() as td:
                base = Path(td)
                (base / "private.txt").write_text("10.0.0.0/8\n", encoding="utf-8")
                init_ipset({"private": ["private.txt"]}, base_dir=base)

                hook = IPRuleResolverHook(
                    rules={
                        "private": {
                            "action": "remove",
                        }
                    }
                )
                ctx = QueryContext(
                    query=Query(
                        client_addr=("127.0.0.1", 5335),
                        qname=dns.name.from_text("www.example.com."),
                        qtype=dns.rdatatype.A,
                    )
                )
                rrset = dns.rrset.from_text(
                    "www.example.com.",
                    60,
                    "IN",
                    "A",
                    "10.1.1.1",
                    "8.8.8.8",
                )
                result = ResolverResult(
                    resolver_name="upstream",
                    answer=Answer.from_query(
                        ctx.query,
                        rcode=dns.rcode.NOERROR,
                        rrsets=[rrset],
                    ),
                    elapsed_ms=1.0,
                    error=None,
                )

            rewritten = await hook.on_resolver_result(ctx, result)

            assert rewritten is not None
            assert rewritten.answer is not None
            self.assertEqual(
                [rdata.to_text() for rdata in rewritten.answer.rrset],
                ["8.8.8.8"],
            )
        finally:
            init_ipset({})

    async def test_ip_rule_should_replace_aaaa_answer(self) -> None:
        try:
            with tempfile.TemporaryDirectory() as td:
                base = Path(td)
                (base / "private6.txt").write_text("fd00::/8\n", encoding="utf-8")
                init_ipset({"private": ["private6.txt"]}, base_dir=base)

                hook = IPRuleResolverHook(
                    rules={
                        "private": {
                            "action": "replace",
                            "AAAA": "2001:db8::10",
                        }
                    }
                )
                ctx = QueryContext(
                    query=Query(
                        client_addr=("127.0.0.1", 5335),
                        qname=dns.name.from_text("ipv6.example.com."),
                        qtype=dns.rdatatype.AAAA,
                    )
                )
                rrset = dns.rrset.from_text(
                    "ipv6.example.com.",
                    120,
                    "IN",
                    "AAAA",
                    "fd00::1",
                )
                result = ResolverResult(
                    resolver_name="upstream",
                    answer=Answer.from_query(
                        ctx.query,
                        rcode=dns.rcode.NOERROR,
                        rrsets=[rrset],
                    ),
                    elapsed_ms=1.0,
                    error=None,
                )

            rewritten = await hook.on_resolver_result(ctx, result)

            assert rewritten is not None
            assert rewritten.answer is not None
            self.assertEqual(
                [rdata.to_text() for rdata in rewritten.answer.rrset],
                ["2001:db8::10"],
            )
            self.assertEqual(rewritten.answer.rrset.ttl, 120)
        finally:
            init_ipset({})

    async def test_ip_rule_should_run_before_speedcheck(self) -> None:
        captured: list[list[str]] = []

        async def fake_probe(
            ips: list[str],
            timeout_s: float,
        ) -> dict[str, float | None]:
            _ = timeout_s
            captured.append(list(ips))
            return {ip: 1.0 for ip in ips}

        try:
            with tempfile.TemporaryDirectory() as td:
                base = Path(td)
                (base / "telegram.txt").write_text("1.1.1.0/24\n", encoding="utf-8")
                init_ipset({"telegram": ["telegram.txt"]}, base_dir=base)

                rewrite_hook = IPRuleResolverHook(
                    rules={
                        "telegram": {
                            "action": "replace",
                            "A": "203.0.113.20",
                        }
                    }
                )
                speedcheck_hook = SpeedCheckResolverHook(probe_func=fake_probe)
                ctx = QueryContext(
                    query=Query(
                        client_addr=("127.0.0.1", 5335),
                        qname=dns.name.from_text("www.example.com."),
                        qtype=dns.rdatatype.A,
                    )
                )
                rrset = dns.rrset.from_text(
                    "www.example.com.",
                    60,
                    "IN",
                    "A",
                    "1.1.1.1",
                )
                result = ResolverResult(
                    resolver_name="upstream",
                    answer=Answer.from_query(
                        ctx.query,
                        rcode=dns.rcode.NOERROR,
                        rrsets=[rrset],
                    ),
                    elapsed_ms=1.0,
                    error=None,
                )

            result = await rewrite_hook.on_resolver_result(ctx, result)
            assert result is not None
            await speedcheck_hook.on_resolver_result(ctx, result)

            self.assertEqual(captured, [["203.0.113.20"]])
            self.assertEqual(ctx.ip_list.ips, {"203.0.113.20"})
        finally:
            init_ipset({})


if __name__ == "__main__":
    unittest.main()
