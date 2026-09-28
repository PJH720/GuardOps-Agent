"""Deterministic injection flagger + end-to-end search_runbook labelling."""
import json
import unittest
from unittest import mock

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
        p = mock.patch.object(agent, "GUARD_MODEL", "")  # no network in unit tests
        p.start()
        self.addCleanup(p.stop)
        agent.bind_retriever(frozenset({"all"}))
        data = json.loads(agent.tool_search_runbook("벤더 공지 DB 이상 로그인 패치"))
        vendor = [h for h in data["hits"] if h["doc_id"] == "EXT-VENDOR-001"]
        self.assertTrue(vendor and vendor[0]["injection_suspected"])
        self.assertEqual(vendor[0]["trust"], "untrusted")

    def test_out_of_domain_search_returns_no_content(self):
        p = mock.patch.object(agent, "GUARD_MODEL", "")
        p.start()
        self.addCleanup(p.stop)
        agent.bind_retriever(frozenset({"all"}))
        data = json.loads(agent.tool_search_runbook("비트코인 시세 알려줘"))
        self.assertFalse(data["grounded"])
        self.assertNotIn("hits", data)

class QuarantineTest(unittest.TestCase):
    """Self-assessment gap #3: raw attack text must not reach the LLM when both detectors agree."""

    QUERY = "벤더 공지 DB 이상 로그인 패치"

    def search_vendor(self, guard_ok, mode="dual"):
        agent.bind_retriever(frozenset({"all"}))
        with mock.patch.object(agent, "GUARD_MODEL", "stub-guard"), \
             mock.patch.object(agent, "QUARANTINE_MODE", mode), mock.patch.object(agent, "audit"), \
             mock.patch.object(agent, "guard_input", return_value=(guard_ok, "stub")):
            data = json.loads(agent.tool_search_runbook(self.QUERY))
        return next(h for h in data["hits"] if h["doc_id"] == "EXT-VENDOR-001")

    def test_decision_table(self):
        q = agent.should_quarantine
        self.assertTrue(q(True, True, "dual"))
        self.assertFalse(q(True, False, "dual"))
        self.assertFalse(q(False, True, "dual"))
        self.assertTrue(q(True, False, "any"))
        self.assertTrue(q(False, True, "any"))
        self.assertFalse(q(True, True, "off"))

    def test_dual_flag_withholds_attack_payload(self):
        hit = self.search_vendor(guard_ok=False)
        self.assertTrue(hit["quarantined"])
        self.assertNotIn("attacker.example", json.dumps(hit, ensure_ascii=False))
        self.assertIn("content_safety:unsafe", hit["reasons"])

    def test_regex_only_flags_but_delivers(self):
        hit = self.search_vendor(guard_ok=True)
        self.assertNotIn("quarantined", hit)
        self.assertTrue(hit["injection_suspected"])

    def test_off_mode_never_quarantines(self):
        hit = self.search_vendor(guard_ok=False, mode="off")
        self.assertNotIn("quarantined", hit)

    def test_trusted_internal_runbook_is_never_quarantined(self):
        agent.bind_retriever(frozenset({"all"}))
        with mock.patch.object(agent, "GUARD_MODEL", "stub-guard"), \
             mock.patch.object(agent, "QUARANTINE_MODE", "any"), mock.patch.object(agent, "audit"), \
             mock.patch.object(agent, "guard_input", return_value=(False, "stub")):
            data = json.loads(agent.tool_search_runbook("운영 DB 이상 로그인 대응 런북"))
        runbook = next(h for h in data["hits"] if h["doc_id"] == "RB-DB-001")
        self.assertNotIn("quarantined", runbook)


class GuardFailModeTest(unittest.TestCase):
    def guard_with_error(self, fail_open):
        with mock.patch.object(agent, "GUARD_MODEL", "stub-guard"), \
             mock.patch.object(agent, "GUARD_FAIL_OPEN", fail_open), \
             mock.patch.object(agent, "chat", side_effect=agent.requests.Timeout("stub timeout")), \
             mock.patch.object(agent, "audit") as audit:
            ok, detail = agent.guard_input("hello")
        return ok, detail, audit.call_args

    def test_fail_open_proceeds_and_is_audited(self):
        ok, detail, call = self.guard_with_error(fail_open=True)
        self.assertTrue(ok)
        self.assertEqual(call.args[0], "guard_error")
        self.assertEqual(call.kwargs["fail_mode"], "fail-open")

    def test_fail_closed_rejects_and_is_audited(self):
        ok, detail, call = self.guard_with_error(fail_open=False)
        self.assertFalse(ok)
        self.assertEqual(call.kwargs["fail_mode"], "fail-closed")


if __name__ == "__main__":
    unittest.main()
