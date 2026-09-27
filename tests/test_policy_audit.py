"""OpenShell policy auditor (official NVIDIA generate-sandbox-policy skill, Step 6 checklist) + cross-layer check."""
import unittest
from pathlib import Path

import yaml

from guardops.policy_audit import audit_policy

ROOT = Path(__file__).resolve().parents[1]
APP = yaml.safe_load((ROOT / "policy" / "app_policy.yaml").read_text(encoding="utf-8"))
NVIDIA = frozenset({"integrate.api.nvidia.com"})


def messages(rep, level):
    return " | ".join(f.message for f in rep.of(level))


class ShippedPolicyTest(unittest.TestCase):
    def test_committed_policy_has_no_blocking_findings(self):
        policy = yaml.safe_load((ROOT / "policy" / "openshell-policy.yaml").read_text(encoding="utf-8"))
        rep = audit_policy(policy, APP["egress_allowlist"], NVIDIA)
        self.assertEqual(rep.blocking, [], rep.findings)
        self.assertEqual(rep.of("breadth_warning"), [])

    def test_official_skill_is_vendored_unmodified_with_notice(self):
        skill = ROOT / "skills" / "generate-sandbox-policy"
        self.assertTrue((skill / "SKILL.md").read_text(encoding="utf-8").startswith("---\nname: generate-sandbox-policy"))
        self.assertIn("Apache License 2.0", (skill / "NOTICE.md").read_text(encoding="utf-8"))


class BadPolicyTest(unittest.TestCase):
    BAD = {"network_policies": {
        "k1": {"name": "other", "binaries": [{"path": "/usr/bin/*"}], "endpoints": [
            {"host": "integrate.api.nvidia.com", "port": 443},                       # L4-only + credentialed
            {"host": "a.example", "port": 443, "protocol": "rest", "access": "full", "enforcement": "audit",
             "rules": [{"allow": {"method": "GET", "path": "/**"}}]},                  # rules+access, full+audit
            {"host": "b.example", "port": 443, "protocol": "rest"},                   # L7 without rules/access
            {"host": "10.0.0.1", "port": 22, "protocol": "tcp"},                      # tcp to IP literal
            {"host": "c.example", "port": 443, "protocol": "rest", "tls": "terminate", "rules": []},
        ]},
        "k2": {"endpoints": [{"host": "d.example"}]},                                  # missing name/binaries/port
    }}

    def setUp(self):
        self.rep = audit_policy(self.BAD, ["nvd.nist.gov"], NVIDIA)

    def test_hard_errors(self):
        text = messages(self.rep, "hard_error")
        for needle in ["both set", "without `rules` or `access`", "valid DNS hostname", "`tls: terminate`",
                       "list is empty", "credentialed provider endpoint is uninspected"]:
            with self.subTest(needle=needle):
                self.assertIn(needle, text)

    def test_structural(self):
        text = messages(self.rep, "structural")
        for needle in ["does not match name", "missing `name`", "missing `binaries`", "missing `host` or `port`"]:
            with self.subTest(needle=needle):
                self.assertIn(needle, text)

    def test_breadth_warnings(self):
        text = messages(self.rep, "breadth_warning")
        for needle in ["L4-only", "`access: full`", "monitoring-only", "wildcard binary", "`**` path glob"]:
            with self.subTest(needle=needle):
                self.assertIn(needle, text)

    def test_cross_layer_mismatch(self):
        self.assertIn("nvd.nist.gov", messages(self.rep, "cross_layer"))


if __name__ == "__main__":
    unittest.main()
