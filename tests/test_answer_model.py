"""Answer 模型测试。"""

from __future__ import annotations

import time
import unittest

import dns.message
import dns.name
import dns.rcode
import dns.rdatatype
import dns.rrset

from core.answer import Answer, make_answer
from core.models import Query


def _make_query(qtype: dns.rdatatype.RdataType = dns.rdatatype.A) -> Query:
    return Query(
        client_addr=("127.0.0.1", 5335),
        qname=dns.name.from_text("www.example.com."),
        qtype=qtype,
    )


class TestAnswerModel(unittest.TestCase):
    def test_make_answer_should_only_return_message(self) -> None:
        message = make_answer(_make_query(), rcode=dns.rcode.NXDOMAIN)

        self.assertIsInstance(message, dns.message.Message)
        self.assertEqual(message.rcode(), dns.rcode.NXDOMAIN)

    def test_make_answer_should_use_current_query_txid(self) -> None:
        cached_query = _make_query()
        cached_query.txid = 100
        cached_answer = Answer.from_query(cached_query, rcode=dns.rcode.NOERROR)

        current_query = _make_query()
        current_query.txid = 200

        message = make_answer(current_query, cached_answer)

        self.assertEqual(cached_answer.response.id, 100)
        self.assertEqual(message.id, 200)

    def test_replace_rrset_should_sync_response_and_to_message(self) -> None:
        query = _make_query()
        cname = dns.rrset.from_text(
            "www.example.com.",
            30,
            "IN",
            "CNAME",
            "edge.example.com.",
        )
        rrset = dns.rrset.from_text("edge.example.com.", 30, "IN", "A", "1.1.1.1")
        answer = Answer.from_query(query, rcode=dns.rcode.NOERROR, rrsets=[cname, rrset])

        rewritten = dns.rrset.from_text("edge.example.com.", 900, "IN", "A", "2.2.2.2")
        answer.replace_rrset(
            rewritten,
            preserve_expiration=time.time() + 900,
        )

        self.assertEqual(answer.response.answer[-1][0].to_text(), "2.2.2.2")
        self.assertEqual(answer.response.answer[-1].ttl, 900)
        message = answer.to_message()
        self.assertEqual(message.answer[-1][0].to_text(), "2.2.2.2")
        self.assertEqual(message.answer[-1].ttl, 900)

    def test_from_answer_should_use_current_state_not_stale_response(self) -> None:
        query = _make_query()
        rrset = dns.rrset.from_text("www.example.com.", 30, "IN", "A", "1.1.1.1")
        answer = Answer.from_query(query, rcode=dns.rcode.NOERROR, rrsets=[rrset])

        rewritten = dns.rrset.from_text("www.example.com.", 120, "IN", "A", "3.3.3.3")
        answer.replace_rrset(rewritten, update_message=False)

        cloned = Answer.from_answer(answer)

        self.assertEqual(answer.response.answer[-1][0].to_text(), "1.1.1.1")
        self.assertEqual(cloned.response.answer[-1][0].to_text(), "3.3.3.3")
        self.assertEqual(cloned.rrset[0].to_text(), "3.3.3.3")

    def test_refresh_from_response_should_sync_external_message_change(self) -> None:
        answer = Answer.from_query(_make_query(), rcode=dns.rcode.NOERROR)

        answer.response.set_rcode(dns.rcode.SERVFAIL)
        answer.refresh_from_response()

        self.assertEqual(answer.rcode, dns.rcode.SERVFAIL)
        self.assertEqual(answer.response.rcode(), dns.rcode.SERVFAIL)

    def test_from_answer_should_copy_tags(self) -> None:
        answer = Answer.from_query(
            _make_query(),
            rcode=dns.rcode.NOERROR,
            tags={"default", "ads"},
        )

        cloned = Answer.from_answer(answer)
        answer.tags.add("cn")

        self.assertEqual(cloned.tags, {"default", "ads"})
        self.assertEqual(answer.tags, {"default", "ads", "cn"})


if __name__ == "__main__":
    unittest.main()
