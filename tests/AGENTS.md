<!-- Parent: ../AGENTS.md -->
<!-- Generated: 2026-09-28 | Updated: 2026-09-28 -->

# tests

## Purpose
48 offline regression tests (stdlib `unittest`, not pytest) proving each deterministic layer holds, including when the model is fooled.

## Key Files
| File | Description |
|------|-------------|
| `test_agent_e2e.py` | Full ReAct loop via `MockLLM` (a model that falls for the injection) → gate → tools → audit, 3 demo scenarios (4) |
| `test_policy_gate.py` | Egress exfil / lookalike hosts / L7 path+query / secrets / role tool RBAC / redirects (15) |
| `test_injection.py` | Regex flagger + `search_runbook` labelling + quarantine modes (11) |
| `test_rbac.py` | Unauthorized docs unreachable from the retriever instance, role-spoofed queries (8) |
| `test_policy_audit.py` | OpenShell policy auditor + cross-layer check (6) |
| `test_grounding.py` | In-domain queries pass, out-of-domain rejected (4) |

## For AI Agents

### Working In This Directory
- Run from repo root with `-t .` so `import agent` / `import guardops` resolve:
  `uv run --with-requirements requirements.txt python -m unittest discover -s tests -t . -v`
- Single test: `… python -m unittest tests.test_policy_gate.PolicyGateTest.test_exfil_to_attacker_host_denied`
- Importing `agent` loads `.env`, builds the corpus index and creates `out/`; patch module globals with `unittest.mock` rather than env.
- No network: guard/LLM calls must be mocked or skipped (`_offline`, `MockLLM`).
- Never write key-shaped literals — build them at runtime (`FAKE_KEY = "nvapi" + "-" + ...`).
- If the total count changes, update the "48 tests" mentions in `README.md` and `docs/submission.md`.

<!-- MANUAL: Any manually added notes below this line are preserved on regeneration -->
