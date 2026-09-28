<!-- Parent: ../AGENTS.md -->
<!-- Generated: 2026-09-28 | Updated: 2026-09-28 -->

# evidence

## Purpose
Verbatim transcripts from live runs (2026-09-28) that the README evidence table links to. Stored as `.txt` because `*.log` and `out/` are gitignored.

## Key Files
| File | Description |
|------|-------------|
| `scenario1_analyst.txt` | Legitimate incident response: skill → grounded search → permission → HITL → ticket; vendor doc quarantined |
| `scenario2_injection.txt` | Injection → exfil: live quarantine + fooled-model replay denied by the harness |
| `scenario3_rbac.txt` | Viewer attempts privileged tools → DENY |
| `rbac_retrieval.txt` | Role-spoofed query cannot reach HR-012 except for `hr` |
| `grounding_probe.txt` | Output of `scripts/probe_grounding.py` |
| `openshell_policy_audit.txt` | Policy auditor: 4 blocking issues → fixed → PASS |
| `openshell_kernel_deny.txt` | Real OpenShell OCSF ALLOWED/DENIED logs, Landlock and syscall probes |

## For AI Agents

### Working In This Directory
- Never fabricate or hand-edit transcripts; recapture by rerunning the command. Redact keys (none may contain `nvapi-`).
- If behavior changes so a transcript is stale, recapture it or state the gap in README "Honest Limitations".

<!-- MANUAL: Any manually added notes below this line are preserved on regeneration -->
