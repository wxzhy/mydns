"""core.domainset / core.ipset 测试。"""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

import dns.message
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
    def setUp(self) -> None:
        init_ipset({})

    def tearDown(self) -> None:
        init_ipset({})

    @staticmethod
    def _new_ctx(
        qtype: dns.rdatatype.RdataType,
        *,
        message: dns.message.Message | None = None,
    ) -> QueryContext:
        return QueryContext(
            query=Query(
                client_addr=("127.0.0.1", 5335),
                qname=dns.name.from_text("www.example.com."),
                qtype=qtype,
                message=message,
            )
        )

    @staticmethod
    def _make_result(
        ctx: QueryContext,
        *records: str,
        rcode: dns.rcode.Rcode = dns.rcode.NOERROR,
        tags: set[str] | None = None,
    ) -> ResolverResult:
        rrsets = None
        if records:
            rrsets = [
                dns.rrset.from_text(
                    ctx.query.qname.to_text(),
                    60,
                    "IN",
                    dns.rdatatype.to_text(ctx.query.qtype),
                    *records,
                )
            ]
        return ResolverResult(
            resolver_name="upstream",
            answer=Answer.from_query(
                ctx.query,
                rcode=rcode,
                rrsets=rrsets,
                tags=tags,
            ),
            elapsed_ms=1.0,
            error=None,
        )

    @staticmethod
    def _init_ipset_for_test(base: Path, mapping: dict[str, str]) -> None:
        files: dict[str, list[str]] = {}
        for tag, content in mapping.items():
            filename = f"{tag}.txt"
            (base / filename).write_text(content, encoding="utf-8")
            files[tag] = [filename]
        init_ipset(files, base_dir=base)

    async def test_ip_rule_should_match_source_ip_tags_and_keep_unmatched_ip(self) -> None:
        with tempfile.TemporaryDirectory(prefix="mydns-ip-rule-tags-") as td:
            base = Path(td)
            self._init_ipset_for_test(
                base,
                {
                    "office": "1.1.1.0/24\n",
                },
            )

            hook = IPRuleResolverHook(
                rules=[
                    {
                        "match_tags": ["cn"],
                        "A": {
                            "replacements": [
                                {
                                    "tag": "office",
                                    "ip": "203.0.113.10",
                                }
                            ],
                        },
                    }
                ]
            )
            ctx = self._new_ctx(dns.rdatatype.A)
            result = self._make_result(ctx, "1.1.1.1", "8.8.8.8", tags={"cn"})

            rewritten = await hook.on_resolver_result(ctx, result)

        assert rewritten is not None
        assert rewritten.answer is not None
        self.assertEqual(
            [rdata.to_text() for rdata in rewritten.answer.rrset],
            ["203.0.113.10", "8.8.8.8"],
        )
        self.assertEqual(rewritten.answer.rrset.ttl, 60)

    async def test_ip_rule_should_skip_when_result_has_skip_tag(self) -> None:
        hook = IPRuleResolverHook(
            skip_result_tags=["ads"],
            rules=[
                {
                    "match_tags": ["cn"],
                    "A": {
                        "replacements": [
                            {
                                "tag": "office",
                                "ip": "203.0.113.10",
                            }
                        ],
                    },
                }
            ],
        )
        ctx = self._new_ctx(dns.rdatatype.A)
        result = self._make_result(ctx, "1.1.1.1", tags={"cn", "ads"})

        rewritten = await hook.on_resolver_result(ctx, result)

        assert rewritten is not None
        assert rewritten.answer is not None
        self.assertEqual(
            [rdata.to_text() for rdata in rewritten.answer.rrset],
            ["1.1.1.1"],
        )

    async def test_ip_rule_should_use_first_matching_rule(self) -> None:
        with tempfile.TemporaryDirectory(prefix="mydns-ip-rule-first-") as td:
            base = Path(td)
            self._init_ipset_for_test(
                base,
                {
                    "office": "1.1.1.0/24\n",
                },
            )

            hook = IPRuleResolverHook(
                rules=[
                    {
                        "match_tags": ["cn"],
                        "A": {
                            "replacements": [
                                {
                                    "tag": "office",
                                    "ip": "203.0.113.10",
                                }
                            ],
                        },
                    },
                    {
                        "match_tags": ["cn", "private"],
                        "A": {
                            "replacements": [
                                {
                                    "tag": "office",
                                    "ip": "203.0.113.20",
                                }
                            ],
                        },
                    },
                ]
            )
            ctx = self._new_ctx(dns.rdatatype.A)
            result = self._make_result(ctx, "1.1.1.1", tags={"cn", "private"})

            rewritten = await hook.on_resolver_result(ctx, result)

        assert rewritten is not None
        assert rewritten.answer is not None
        self.assertEqual(
            [rdata.to_text() for rdata in rewritten.answer.rrset],
            ["203.0.113.10"],
        )

    async def test_ip_rule_should_rewrite_each_source_ip_by_its_own_tag(self) -> None:
        with tempfile.TemporaryDirectory(prefix="mydns-ip-rule-per-ip-") as td:
            base = Path(td)
            self._init_ipset_for_test(
                base,
                {
                    "office": "1.2.3.0/24\n",
                    "cn": "5.6.7.0/24\n",
                },
            )

            hook = IPRuleResolverHook(
                rules=[
                    {
                        "match_tags": ["cn"],
                        "A": {
                            "replacements": [
                                {
                                    "tag": "office",
                                    "ip": "203.0.113.10",
                                    "preserve_prefix_len": 24,
                                },
                                {
                                    "tag": "cn",
                                    "ip": "198.18.0.20",
                                    "preserve_prefix_len": 24,
                                },
                            ],
                        },
                    }
                ]
            )
            ctx = self._new_ctx(dns.rdatatype.A)
            result = self._make_result(ctx, "1.2.3.4", "5.6.7.8", tags={"cn"})

            rewritten = await hook.on_resolver_result(ctx, result)

        assert rewritten is not None
        assert rewritten.answer is not None
        self.assertEqual(
            [rdata.to_text() for rdata in rewritten.answer.rrset],
            ["203.0.113.4", "198.18.0.8"],
        )

    async def test_ip_rule_should_dedupe_rewritten_ips(self) -> None:
        with tempfile.TemporaryDirectory(prefix="mydns-ip-rule-dedupe-") as td:
            base = Path(td)
            self._init_ipset_for_test(
                base,
                {
                    "office": "1.2.3.0/24\n5.6.7.0/24\n",
                },
            )

            hook = IPRuleResolverHook(
                rules=[
                    {
                        "match_tags": ["cn"],
                        "A": {
                            "replacements": [
                                {
                                    "tag": "office",
                                    "ip": "203.0.113.10",
                                    "preserve_prefix_len": 24,
                                }
                            ],
                        },
                    }
                ]
            )
            ctx = self._new_ctx(dns.rdatatype.A)
            result = self._make_result(ctx, "1.2.3.4", "5.6.7.4", tags={"cn"})

            rewritten = await hook.on_resolver_result(ctx, result)

        assert rewritten is not None
        assert rewritten.answer is not None
        self.assertEqual(
            [rdata.to_text() for rdata in rewritten.answer.rrset],
            ["203.0.113.4"],
        )

    async def test_ip_rule_should_rewrite_aaaa_independently(self) -> None:
        with tempfile.TemporaryDirectory(prefix="mydns-ip-rule-aaaa-") as td:
            base = Path(td)
            self._init_ipset_for_test(
                base,
                {
                    "office": "240e:1::/32\n",
                },
            )

            hook = IPRuleResolverHook(
                rules=[
                    {
                        "match_tags": ["cn"],
                        "AAAA": {
                            "replacements": [
                                {
                                    "tag": "office",
                                    "ip": "2001:db8:100::10",
                                    "preserve_prefix_len": 64,
                                }
                            ],
                        },
                    }
                ]
            )
            ctx = self._new_ctx(dns.rdatatype.AAAA)
            result = self._make_result(ctx, "240e:1::1234", tags={"cn"})

            rewritten = await hook.on_resolver_result(ctx, result)

        assert rewritten is not None
        assert rewritten.answer is not None
        self.assertEqual(
            [rdata.to_text() for rdata in rewritten.answer.rrset],
            ["2001:db8:100::1234"],
        )

    async def test_invalid_ip_rule_config_should_raise(self) -> None:
        with self.assertRaises(ValueError):
            IPRuleResolverHook(
                rules=[
                    {
                        "match_tags": ["cn"],
                        "A": {
                            "replacements": [
                                {
                                    "tag": "office",
                                    "ip": "2001:db8::10",
                                }
                            ],
                        },
                    }
                ]
            )
        with self.assertRaises(ValueError):
            IPRuleResolverHook(
                rules=[
                    {
                        "match_tags": ["cn"],
                        "AAAA": {
                            "replacements": [
                                {
                                    "tag": "office",
                                    "ip": "2001:db8::10",
                                    "preserve_prefix_len": 129,
                                }
                            ],
                        },
                    }
                ]
            )
        with self.assertRaises(ValueError):
            IPRuleResolverHook(
                rules=[
                    {
                        "match_tags": ["cn"],
                        "A": {
                            "replacements": [
                                {
                                    "tag": "office",
                                    "ip": "203.0.113.10",
                                },
                                {
                                    "tag": "office",
                                    "ip": "203.0.113.20",
                                },
                            ],
                        },
                    }
                ]
            )

    async def test_ip_rule_should_run_before_speedcheck(self) -> None:
        captured: list[list[str]] = []

        async def fake_probe(
            ips: list[str],
            timeout_s: float,
        ) -> dict[str, float | None]:
            _ = timeout_s
            captured.append(list(ips))
            return {ip: 1.0 for ip in ips}

        with tempfile.TemporaryDirectory(prefix="mydns-ip-rule-speedcheck-") as td:
            base = Path(td)
            self._init_ipset_for_test(
                base,
                {
                    "office": "1.1.1.0/24\n",
                },
            )

            rewrite_hook = IPRuleResolverHook(
                rules=[
                    {
                        "match_tags": ["cn"],
                        "A": {
                            "replacements": [
                                {
                                    "tag": "office",
                                    "ip": "203.0.113.20",
                                }
                            ],
                        },
                    }
                ]
            )
            speedcheck_hook = SpeedCheckResolverHook(probe_func=fake_probe)
            ctx = self._new_ctx(dns.rdatatype.A)
            result = self._make_result(ctx, "1.1.1.1", tags={"cn"})

            result = await rewrite_hook.on_resolver_result(ctx, result)
            assert result is not None
            await speedcheck_hook.on_resolver_result(ctx, result)

        self.assertEqual(captured, [["203.0.113.20"]])
        self.assertEqual(ctx.ip_list.ips, {"203.0.113.20"})


if __name__ == "__main__":
    unittest.main()
