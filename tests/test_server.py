"""Web SOC Dashboard wiring: the WebSocket loop must run the same harness as agent.run().

MockLLM replays a model that falls for the injected vendor notice. Every run is offline (mock=True) and writes to a
temp OUT_DIR. The key regression: the HITL modal must never let a role skip PolicyGate (RBAC before human approval).
"""
import json
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from fastapi.testclient import TestClient
from starlette.websockets import WebSocketDisconnect

import agent
import server

GOAL = "prod-db 이상 로그인 알림 대응"


class DashboardWebSocketTest(unittest.TestCase):
    def setUp(self):
        tmpdir = tempfile.TemporaryDirectory()  # addCleanup keeps Python 3.10 support
        self.addCleanup(tmpdir.cleanup)
        self.out = Path(tmpdir.name)
        saved = (agent._offline, agent._retriever)
        self.addCleanup(lambda: (setattr(agent, "_offline", saved[0]), setattr(agent, "_retriever", saved[1])))
        for patch in (mock.patch.object(agent, "OUT_DIR", self.out),
                      # mock 실행은 네트워크 가드를 절대 호출하면 안 된다
                      mock.patch.object(agent, "guard_input", side_effect=AssertionError("network guard called"))):
            patch.start()
            self.addCleanup(patch.stop)
        self.client = TestClient(server.app)

    def run_ws(self, role: str, auto_approve: bool, approve: bool = True) -> list[dict]:
        msgs = []
        with self.client.websocket_connect("/ws/agent") as ws:
            ws.send_json({"goal": GOAL, "role": role, "auto_approve": auto_approve, "mock": True})
            while True:
                m = ws.receive_json()
                msgs.append(m)
                if m["type"] == "approval_required":
                    ws.send_json({"type": "hitl_response", "approved": approve})
                if m["type"] == "done":
                    self.assertEqual(self.of(msgs, "error"), [], "run must end cleanly")
                    return msgs

    def audit_events(self) -> list[dict]:
        return [json.loads(x) for x in (self.out / "audit.jsonl").read_text(encoding="utf-8").splitlines()]

    @staticmethod
    def of(msgs: list[dict], kind: str, tool: str | None = None) -> list[dict]:
        return [m for m in msgs if m["type"] == kind and (tool is None or m.get("payload", {}).get("tool") == tool)]

    @staticmethod
    def p(msgs: list[dict], kind: str, tool: str | None = None) -> dict:
        return DashboardWebSocketTest.of(msgs, kind, tool)[0]["payload"]

    def tickets(self) -> list[Path]:
        return list((self.out / "tickets").glob("*.json")) if (self.out / "tickets").exists() else []

    def test_analyst_hitl_approve_writes_ticket_and_audit(self):
        msgs = self.run_ws("analyst", auto_approve=False, approve=True)
        self.assertEqual(len(self.of(msgs, "approval_required")), 1)
        check = self.p(msgs, "policy_decision", "create_incident_ticket")
        self.assertTrue(check["allowed"])
        self.assertEqual(check["reason"], "approved by human")
        self.assertEqual(len(self.tickets()), 1)
        events = self.audit_events()
        tool = [e for e in events if e["event"] == "tool" and e["tool"] == "create_incident_ticket"]
        self.assertTrue(tool and tool[0]["allowed"] and tool[0]["channel"] == "web")
        self.assertTrue(any(e["event"] == "hitl_decision" and e["approved"] for e in events))
        report = self.p(msgs, "final_report")
        self.assertEqual(report["tickets"][0]["severity"], "high")
        self.assertEqual(report["risk"], "critical")  # 속은 모델의 외부 전송 시도가 차단된 실행
        self.assertTrue(self.of(msgs, "ticket_created"))
        for m in msgs:  # 모든 스트림 메시지는 타입이 지정된 구조화 이벤트
            if m["type"] not in {"done", "error"}:
                self.assertTrue({"type", "layer", "status", "stage", "payload", "timestamp"} <= set(m), m["type"])

    def test_analyst_hitl_reject_creates_no_ticket(self):
        msgs = self.run_ws("analyst", auto_approve=False, approve=False)
        check = self.p(msgs, "policy_decision", "create_incident_ticket")
        self.assertFalse(check["allowed"])
        self.assertEqual(check["reason"], "human approver rejected")
        self.assertEqual(self.tickets(), [])

    def test_viewer_is_denied_before_any_human_approval(self):
        # 회귀 테스트: HITL 경로가 PolicyGate 를 건너뛰면 viewer 가 승인만으로 티켓을 발행할 수 있었다
        msgs = self.run_ws("viewer", auto_approve=False, approve=True)
        self.assertEqual(self.of(msgs, "approval_required"), [])
        for tool in ("create_incident_ticket", "check_permission", "fetch_url"):
            check = self.p(msgs, "policy_decision", tool)
            self.assertFalse(check["allowed"], tool)
        self.assertIn("not allowed", self.p(msgs, "policy_decision", "create_incident_ticket")["reason"])
        self.assertIn("roles.viewer.tools", self.p(msgs, "policy_decision", "create_incident_ticket")["rule"])
        self.assertEqual(self.tickets(), [])
        start = self.p(msgs, "session_started")
        self.assertEqual(start["doc_clearance"], ["all"])
        self.assertNotIn("HR-012", start["reachable_docs"])
        self.assertIn("HR-012", start["excluded_docs"])

    def test_injection_flag_and_egress_deny_are_streamed(self):
        msgs = self.run_ws("analyst", auto_approve=True)
        egress = self.p(msgs, "egress_decision")
        self.assertIn("attacker.example", egress["url"])
        self.assertFalse(egress["allowed"])
        self.assertIn("not in allowlist", egress["reason"])
        flagged = {m["payload"]["doc_id"] for m in self.of(msgs, "injection_flagged")} | \
                  {m["payload"]["doc_id"] for m in self.of(msgs, "doc_quarantined")}
        self.assertIn("EXT-VENDOR-001", flagged)

    def test_unknown_role_is_rejected_cleanly(self):
        with self.client.websocket_connect("/ws/agent") as ws:
            ws.send_json({"goal": GOAL, "role": "root", "mock": True})
            self.assertEqual(ws.receive_json()["type"], "error")
            self.assertEqual(ws.receive_json()["type"], "done")

    def test_cross_origin_websocket_is_refused(self):
        with self.assertRaises(WebSocketDisconnect):
            with self.client.websocket_connect("/ws/agent", headers={"origin": "https://evil.example"}) as ws:
                ws.receive_json()

    def test_evidence_endpoint_serves_real_artifacts(self):
        ev = self.client.get("/api/evidence").json()
        self.assertIn("HR-012", ev["rbac_retrieval"])
        self.assertIn("DENIED", ev["kernel_deny"])
        self.assertTrue(any(e["verdict"] == "DENIED" and "attacker.example" in e["detail"] for e in ev["kernel_events"]))
        self.assertEqual([p["id"] for p in ev["kernel_probes"]], [f"P{i}" for i in range(1, 9)])
        self.assertTrue(ev["policy_audit_live"]["pass"])
        self.assertEqual(ev["policy_audit_live"]["blocking"], 0)
        self.assertTrue(ev["skill"]["present"])
        status = self.client.get("/api/status").json()
        self.assertNotIn("api_key_masked", status)
        self.assertTrue(status["openshell"]["policy_audit_pass"])


if __name__ == "__main__":
    unittest.main()
