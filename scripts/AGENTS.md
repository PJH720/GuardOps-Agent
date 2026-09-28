<!-- Parent: ../AGENTS.md -->
<!-- Generated: 2026-09-28 | Updated: 2026-09-28 -->

# scripts

## Purpose
Operational CLIs that produce the evidence in `docs/evidence/` and the submission PDF.

## Key Files
| File | Description |
|------|-------------|
| `audit_openshell_policy.py` | Audits `policy/openshell-policy.yaml` with `guardops.policy_audit`; `--llm` adds a Nemotron review using the official SKILL.md as system context. Exit 1 on blocking finding |
| `probe_grounding.py` | Prints RBAC-filtered doc sets and grounding verdicts per query (calibration) |
| `openshell_probes.sh` | Probes P1–P7 run *inside* the sandbox (allowed/denied egress, binary scoping, Landlock, syscalls) |
| `build_pdf.sh` | `docs/submission.md` → PDF via pandoc + headless Chrome (Korean fonts) |

## For AI Agents

### Working In This Directory
- Python scripts insert the repo root into `sys.path`; run them from the repo root through uv.
- `openshell_probes.sh` is piped via `openshell sandbox exec … bash -s` (see `run_in_openshell.sh`); it must only use tools present in `sandbox/Dockerfile`.
- When probe output changes, recapture the matching `docs/evidence/*.txt` rather than hand-editing it.

<!-- MANUAL: Any manually added notes below this line are preserved on regeneration -->
