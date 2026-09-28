<!-- Parent: ../AGENTS.md -->
<!-- Generated: 2026-09-28 | Updated: 2026-09-28 -->

# policy

## Purpose
Declarative policy for two of the three defense layers. These YAML files are the source of truth; code only enforces them.

## Key Files
| File | Description |
|------|-------------|
| `app_policy.yaml` | Harness layer: `roles` (tools + `doc_clearance`), `require_approval` (HITL), `egress_allowlist`, per-host `egress_url_rules` (path/query regex), `blocked_patterns`, `egress_secret_patterns`, demo `acl` |
| `openshell-policy.yaml` | Kernel layer (OpenShell): `filesystem_policy`, `landlock`, `network_policies` (`nvidia-build-api`: python3 only, L7 two paths; `cve-lookup`: GET CVE detail only) |

## For AI Agents

### Working In This Directory
- Keep the two layers consistent: egress hosts/paths allowed in `app_policy.yaml` must match `openshell-policy.yaml`;
  `guardops/policy_audit.py` flags cross-layer drift.
- After editing `openshell-policy.yaml`, run `scripts/audit_openshell_policy.py` (must PASS) and recapture `docs/evidence/openshell_policy_audit.txt`.
- Fail-closed rules: an allowlisted host without an `egress_url_rules` entry is denied; credentialed endpoints must be L7-inspected, not L4 passthrough.
- `egress_secret_patterns` apply only to `fetch_url` (to avoid IOC-hash false positives in tickets); `blocked_patterns` apply to all tool args.
- Role/tool changes affect `tests/test_policy_gate.py`, `test_rbac.py` and `test_agent_e2e.py`.

<!-- MANUAL: Any manually added notes below this line are preserved on regeneration -->
