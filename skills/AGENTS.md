<!-- Parent: ../AGENTS.md -->
<!-- Generated: 2026-09-28 | Updated: 2026-09-28 -->

# skills

## Purpose
Agent Skills (NVIDIA Agent Skills spec: `<name>/SKILL.md` with YAML `name`/`description` frontmatter).
`agent.load_skills()` globs `*/SKILL.md`; only name + description enter the system prompt, bodies are fetched with `load_skill` (progressive disclosure).

## Subdirectories
| Directory | Purpose |
|-----------|---------|
| `incident-response/` | Custom (Korean): first-response procedure for abnormal login / account takeover / leak; load first on alerts |
| `access-review/` | Custom (Korean): privilege-escalation / access review under least privilege |
| `generate-sandbox-policy/` | **Official NVIDIA/OpenShell skill, Apache-2.0, vendored unmodified** (`SKILL.md`, `examples.md`, `NOTICE.md`). Its Step 6 is implemented in `guardops/policy_audit.py` |

## For AI Agents

### Working In This Directory
- Do not modify anything under `generate-sandbox-policy/` (license + "unmodified" claim in README). No AGENTS.md is placed there for that reason.
- New skill = new `<name>/SKILL.md` with frontmatter; the directory name is the fallback `name`. Keep `description` short — it is in every system prompt.
- Skill bodies are instructions to the model, not security controls; enforcement lives in `PolicyGate` / `guardops/`.

<!-- MANUAL: Any manually added notes below this line are preserved on regeneration -->
