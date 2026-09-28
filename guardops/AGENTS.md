<!-- Parent: ../AGENTS.md -->
<!-- Generated: 2026-09-28 | Updated: 2026-09-28 -->

# guardops

## Purpose
Python port of the team's earlier Next.js on-prem-rag-service security core (`lib/*.ts`) plus the OpenShell
policy auditor. Everything here is deterministic and runs *before* any LLM sees retrieved text.

## Key Files
| File | Description |
|------|-------------|
| `rbac.py` | `ACCESS_ROLES` and `can_view(clearance, access_role)` — single source of truth for doc visibility |
| `retriever.py` | `build_index` (frontmatter + `##` section chunks, BM25 stats), `RbacBm25Retriever`, `evaluate_grounding` |
| `search.py` | `sanitize_retrieval_query` (strips role-spoofing phrases), `expand_synonyms` (KO groups + KO↔EN bridges) |
| `tokenizer.py` | Korean hybrid tokenizer: word tokens + Hangul bi/tri-grams |
| `injection.py` | `INJECTION_PATTERNS` + `scan()` — labels (does not strip) injected instructions in retrieved docs |
| `policy_audit.py` | `audit_policy()` / `format_report()`: official NVIDIA generate-sandbox-policy Step 6 checklist + cross-layer check vs app egress |

## For AI Agents

### Working In This Directory
- **RBAC invariant:** `RbacBm25Retriever.__init__` keeps only permitted chunks as an immutable tuple. Never move
  authorization into `search()` or make the chunk store mutable — tests assert unauthorized docs are unreachable from the instance.
- Grounding thresholds come from env: `RAG_REJECTION_THRESHOLD` (10), `RAG_SHALLOW_SCORE` (18), `RAG_MIN_COMPOSITE` (0.10).
  Re-run `scripts/probe_grounding.py` and update `docs/evidence/grounding_probe.txt` if you change them.
- The gate is lexical; RBAC, not grounding, is the confidentiality boundary.
- Adding an injection pattern: extend `INJECTION_PATTERNS` and add a case in `tests/test_injection.py`; keep false positives low (quarantine default is `dual`).
- Keep dataclasses `frozen=True`; no network or LLM calls in this package.

### Testing Requirements
`tests/test_rbac.py`, `test_grounding.py`, `test_injection.py`, `test_policy_audit.py`.

## Dependencies

### Internal
- Consumed by `agent.py` (`tool_search_runbook`, `_screen_hit`) and `scripts/`. Reads `knowledge/*.md` and `policy/*.yaml` via callers.

### External
- pyyaml

<!-- MANUAL: Any manually added notes below this line are preserved on regeneration -->
