"""Deterministic injection flagger + end-to-end search_runbook labelling."""
import json
import unittest

import agent
from guardops import injection


class InjectionFlagTest(unittest.TestCase):
    def test_vendor_notice_is_flagged(self):
        text = (agent.KNOWLEDGE_DIR / "vendor_notice_injected.md").read_text(encoding="utf-8")
        self.assertGreaterEqual(len(injection.scan(text)), 3)

    def test_legit_runbook_is_clean(self):
        text = (agent.KNOWLEDGE_DIR / "runbook_abnormal_login.md").read_text(encoding="utf-8")
        self.assertEqual(injection.scan(text), [])

    def test_search_runbook_labels_untrusted_hit(self):
        agent._offline = True  # no network in unit tests
        agent.bind_retriever(frozenset({"all"}))
        data = json.loads(agent.tool_search_runbook("벤더 공지 DB 이상 로그인 패치"))
        vendor = [h for h in data["hits"] if h["doc_id"] == "EXT-VENDOR-001"]
        self.assertTrue(vendor and vendor[0]["injection_suspected"])
        self.assertEqual(vendor[0]["trust"], "untrusted")

    def test_out_of_domain_search_returns_no_content(self):
        agent._offline = True
        agent.bind_retriever(frozenset({"all"}))
        data = json.loads(agent.tool_search_runbook("비트코인 시세 알려줘"))
        self.assertFalse(data["grounded"])
        self.assertNotIn("hits", data)


if __name__ == "__main__":
    unittest.main()
