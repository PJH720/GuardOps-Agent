"""Headless engine contract: typed events, the send() HITL protocol, and gate-before-human ordering.

Offline: tests/fakes.FooledModel replays a model that falls for the injected vendor notice (test-only double);
the network guard is disabled and audit goes to a temp OUT_DIR.
"""
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import agent
from guardops.engine import AgentEvent, cite_rule, run_agent
from tests.fakes import FINAL_TEXT, FooledModel

REQUIRED_KEYS = {"id", "type", "layer", "status", "stage", "step", "payload", "timestamp"}
STAGES = {"goal", "screening", "grounding", "reasoning", "enforcement", "action"}


class EngineTest(unittest.TestCase):
    def setUp(self):
        tmpdir = tempfile.TemporaryDirectory()  # addCleanup keeps Python 3.10 support
        self.addCleanup(tmpdir.cleanup)
        saved = (agent._backend, agent._retriever)
        self.addCleanup(lambda: (setattr(agent, "_backend", saved[0]), setattr(agent, "_retriever", saved[1])))
        for patch in (mock.patch.object(agent, "OUT_DIR", Path(tmpdir.name)),
                      mock.patch.object(agent, "GUARD_MODEL", ""),  # 네트워크 가드 없이 하네스만 검증
                      mock.patch.object(agent, "chat", side_effect=AssertionError("network LLM called"))):
            patch.start()
            self.addCleanup(patch.stop)

    def drive(self, role: str, auto_approve: bool, decision: bool = True) -> tuple[list[AgentEvent], str]:
        gen = run_agent(agent.build_context(role, auto_approve, llm=FooledModel()), "prod-db 이상 로그인 대응")
        events, reply = [], None
        try:
            while True:
                e = gen.send(reply)
                events.append(e)
                reply = decision if e.type == "approval_required" else None
        except StopIteration as done:
            return events, done.value

    @staticmethod
    def of(events, kind, tool=None):
        return [e for e in events if e.type == kind and (tool is None or e.payload.get("tool") == tool)]

    def test_every_event_is_typed_and_ordered(self):
        events, final = self.drive("analyst", auto_approve=True)
        self.assertEqual([e.id for e in events], list(range(1, len(events) + 1)))
        self.assertEqual(events[0].type, "session_started")
        self.assertEqual(events[1].type, "input_screened")
        self.assertEqual(events[-1].type, "final_report")
        for e in events:
            self.assertEqual(set(e.to_dict()), REQUIRED_KEYS)
            self.assertIn(e.stage, STAGES)
            self.assertIn(e.layer, {"L1", "L2", "L3", "agent", "system"})
        self.assertEqual(final, FINAL_TEXT)

    def test_policy_decision_precedes_every_tool_result(self):
        events, _ = self.drive("analyst", auto_approve=True)
        for i, e in enumerate(events):
            if e.type == "tool_result":
                prior = [x for x in events[:i] if x.type == "policy_decision" and x.payload["tool"] == e.payload["tool"]]
                self.assertTrue(prior, e.payload["tool"])

    def test_hitl_approve_and_reject_via_send(self):
        approved, _ = self.drive("analyst", auto_approve=False, decision=True)
        self.assertEqual(len(self.of(approved, "approval_required")), 1)
        self.assertTrue(self.of(approved, "policy_decision", "create_incident_ticket")[0].payload["allowed"])
        self.assertEqual(len(self.of(approved, "ticket_created")), 1)

        rejected, _ = self.drive("analyst", auto_approve=False, decision=False)
        decision = self.of(rejected, "policy_decision", "create_incident_ticket")[0].payload
        self.assertFalse(decision["allowed"])
        self.assertEqual(decision["reason"], "human approver rejected")
        self.assertEqual(self.of(rejected, "ticket_created"), [])

    def test_viewer_never_reaches_human_approval(self):
        events, _ = self.drive("viewer", auto_approve=False)
        self.assertEqual(self.of(events, "approval_required"), [])
        for tool in ("check_permission", "create_incident_ticket", "fetch_url"):
            self.assertFalse(self.of(events, "policy_decision", tool)[0].payload["allowed"], tool)
        start = events[0].payload
        self.assertIn("HR-012", start["excluded_docs"])
        self.assertNotIn("HR-012", start["reachable_docs"])

    def test_injection_and_egress_events_and_risk(self):
        events, _ = self.drive("analyst", auto_approve=True)
        flag = self.of(events, "injection_flagged")[0]
        self.assertEqual(flag.payload["doc_id"], "EXT-VENDOR-001")
        self.assertEqual(flag.layer, "L1")
        self.assertTrue(flag.payload["patterns"])
        egress = self.of(events, "egress_decision")[0]
        self.assertEqual((egress.status, egress.layer), ("blocked", "L2"))
        self.assertEqual(egress.payload["rule"], "app_policy.yaml › egress_allowlist")
        report = events[-1].payload
        self.assertEqual(report["risk"], "critical")
        self.assertTrue(any(b["what"] == "fetch_url" for b in report["blocked_attempts"]))

    def test_injected_llm_never_touches_the_network(self):
        # setUp 이 agent.chat 을 AssertionError 로 막아 두었다: 주입된 더블만 쓰이고 실제 백엔드는 호출되지 않는다
        events, _ = self.drive("analyst", auto_approve=True)
        self.assertEqual(events[1].payload["model"], "disabled")
        self.assertEqual(events[0].payload["model"], agent.MODEL)

    def test_cite_rule(self):
        self.assertEqual(cite_rule("role 'viewer' is not allowed to call 'fetch_url'", "viewer", "fetch_url"),
                         "app_policy.yaml › roles.viewer.tools")
        self.assertIn("egress_url_rules", cite_rule("query parameter 'q' not permitted by egress URL policy", "a", "t"))


if __name__ == "__main__":
    unittest.main()
