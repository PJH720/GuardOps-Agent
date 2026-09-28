<!-- Generated: 2026-09-28 | Updated: 2026-09-28 -->

# GuardOps-Agent

## Purpose
SecOps ReAct agent on NVIDIA Nemotron (build.nvidia.com) for the NVIDIA Korea Agentic AI Hackathon 2026 (team NexaGuard).
It automates alert → runbook → permission check → ticket, and is built so the agent cannot become the attack path:
prompt injection, exfiltration and over-privileged retrieval are stopped by **deterministic controls around the LLM**
in three layers (Prompt → Harness → Sandbox). Code comments, prompts and the corpus are Korean; README is English.

## Key Files
| File | Description |
|------|-------------|
| `agent.py` | Single-file ReAct loop: `chat()` client, `guard_input()`, `PolicyGate` (tool RBAC, L7 egress, HITL), tools, `MockLLM`, audit log |
| `check_api.py` | build.nvidia.com probe: model list, one tool call, one Content Safety call (key is masked) |
| `requirements.txt` | Only deps: requests, pyyaml, python-dotenv (no pyproject) |
| `.env.example` | All runtime knobs (`NV_MODEL`, `NV_GUARD_*`, `MAX_STEPS`, `AGENT_DEFAULT_ROLE`) |
| `run_in_openshell.sh` | Verified procedure to run the agent + probes inside a real NVIDIA OpenShell sandbox |
| `README.md` | Architecture, NVIDIA tech usage, evidence table, honest limitations |

## Subdirectories
| Directory | Purpose |
|-----------|---------|
| `guardops/` | Deterministic security core: RBAC, BM25 retriever + grounding gate, query sanitizer, injection flagger, policy auditor (see `guardops/AGENTS.md`) |
| `policy/` | App-layer policy and kernel-layer OpenShell policy (see `policy/AGENTS.md`) |
| `skills/` | Agent Skills (`SKILL.md`) loaded progressively by the agent (see `skills/AGENTS.md`) |
| `knowledge/` | RBAC-tagged enterprise corpus. **Intentionally has no AGENTS.md:** `build_index` indexes every `*.md` there |
| `tests/` | 48 stdlib unittest tests, no network (see `tests/AGENTS.md`) |
| `scripts/` | Policy auditor CLI, grounding probe, OpenShell probes, PDF build (see `scripts/AGENTS.md`) |
| `sandbox/` | OpenShell sandbox image (see `sandbox/AGENTS.md`) |
| `docs/` | Submission text, PDF, captured live evidence (see `docs/AGENTS.md`) |
| `out/` | Runtime output: `audit.jsonl`, `tickets/*.json` (gitignored except `.gitkeep`) |

## For AI Agents

### Working In This Directory
- Run Python only via `uv run --with-requirements requirements.txt python …` (bare `python3` / `uv pip` are hook-blocked).
- Never overwrite/delete `.env` or `.gitignore`; never print `NVIDIA_API_KEY`.
- `.gitignore` `AGENT.*` + case-insensitive macOS FS ignores `agent.py` → `git add -f agent.py`. `lib/`, `out/`, `*.log` are ignored too.
- Stage explicit paths only; never `.omc/`, `.serena/`, `ref/`, `.env`. Grep staged diff for `nvapi-` before pushing.
- Tool schemas are shown to every role on purpose — authorization belongs to `PolicyGate`, not the model. Don't filter schemas per role.
- Every claim in README/docs must be backed by a file in `docs/evidence/`.

### Testing Requirements
```bash
uv run --with-requirements requirements.txt python -m unittest discover -s tests -t . -v   # all, offline
uv run --with-requirements requirements.txt python agent.py --mock --auto-approve          # full loop, no API key
```

### Common Patterns
- Deterministic-first: every security verdict is regex/YAML/set logic; the LLM classifier is a second, independent signal.
- Fail-closed defaults (missing egress URL rule → deny; missing clearance → `[all]` only).
- Every verdict goes through `audit(event, **kw)` → `out/audit.jsonl`.

## Dependencies

### External
- NVIDIA build.nvidia.com (OpenAI-compatible): `nvidia/nemotron-3-super-120b-a12b`, `nvidia/nemotron-3.5-content-safety`
- NVIDIA OpenShell 0.1.1 (sandbox layer), requests, pyyaml, python-dotenv

<!-- MANUAL: Any manually added notes below this line are preserved on regeneration -->
