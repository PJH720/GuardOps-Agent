# NOTICE — vendored official NVIDIA skill

| Field | Value |
|---|---|
| Skill | `generate-sandbox-policy` |
| Publisher | NVIDIA Corporation — [NVIDIA/OpenShell](https://github.com/NVIDIA/OpenShell) (`skills/generate-sandbox-policy`), listed in the [build.nvidia.com/skills](https://build.nvidia.com/skills) catalog |
| License | [Apache License 2.0](https://github.com/NVIDIA/OpenShell/blob/main/LICENSE) — Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES |
| Modifications | **None.** `SKILL.md` and `examples.md` are vendored byte-for-byte. |
| SHA-256 | `SKILL.md` 6764108a156e2087a024e7eb698d8defd0f0a5f4da910e626e940c6162b98e91 · `examples.md` 60a3912debe46b70f2a7ec38ae88275223db1d312f21646194d580cbc4c8dc02 |

## How GuardOps-Agent uses it

1. **Agent runtime (progressive disclosure):** `agent.py` `load_skills()` discovers it like our own skills, so only its name and description enter the Nemotron system prompt. The ~640-line body loads only when the model calls `load_skill("generate-sandbox-policy")`.
2. **Policy audit:** `guardops/policy_audit.py` implements the skill's *Step 6 — Validate and Warn* checklist deterministically. `scripts/audit_openshell_policy.py` runs it against `policy/openshell-policy.yaml`. With `--llm`, it also asks Nemotron (build.nvidia.com) to review the policy using this SKILL.md as its system context.
