#!/usr/bin/env python3
"""Audit policy/openshell-policy.yaml with the official NVIDIA `generate-sandbox-policy` skill checklist.

Usage:
  uv run --with-requirements requirements.txt python scripts/audit_openshell_policy.py [policy.yaml] [--llm]
  --llm : also ask Nemotron (build.nvidia.com) to review the policy with the official SKILL.md as system context
Exit code 1 if any blocking finding (hard error / structural / cross-layer) exists.
"""
from __future__ import annotations

import sys
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from guardops.policy_audit import audit_policy, format_report  # noqa: E402

SKILL = ROOT / "skills" / "generate-sandbox-policy" / "SKILL.md"
CREDENTIALED_HOSTS = frozenset({"integrate.api.nvidia.com"})  # run_in_openshell.sh attaches provider nvidia-build


def llm_review(policy_text: str) -> str:
    import agent  # loads .env, reuses the build.nvidia.com client (retry, timeouts)

    system = ("You are an OpenShell sandbox-policy reviewer. Follow this official NVIDIA skill exactly, "
              "especially 'Step 6: Validate and Warn'. Answer in Korean, concise, as a checklist with "
              "PASS/WARN/FAIL per item and a final verdict.\n\n" + SKILL.read_text(encoding="utf-8"))
    user = ("다음 GuardOps-Agent 샌드박스 정책을 검토해줘. 에이전트(python3)는 NVIDIA 추론 API 와 CVE 조회만 필요하고, "
            "integrate.api.nvidia.com 은 자격증명 provider(nvidia-build)가 붙는다.\n\n```yaml\n" + policy_text + "\n```")
    msg = agent.chat([{"role": "system", "content": system}, {"role": "user", "content": user}],
                     timeout=300, max_tokens=8192)
    return msg.get("content") or ""


def main() -> int:
    args = [a for a in sys.argv[1:] if not a.startswith("--")]
    path = Path(args[0]) if args else ROOT / "policy" / "openshell-policy.yaml"
    policy_text = path.read_text(encoding="utf-8")
    app = yaml.safe_load((ROOT / "policy" / "app_policy.yaml").read_text(encoding="utf-8"))
    rep = audit_policy(yaml.safe_load(policy_text), app.get("egress_allowlist", []), CREDENTIALED_HOSTS)
    print(f"skill: {SKILL.relative_to(ROOT)} (official NVIDIA/OpenShell, Apache-2.0)")
    print(format_report(rep, f"deterministic audit of {path.name}"))
    if "--llm" in sys.argv:
        print("\n=== Nemotron review (build.nvidia.com, official SKILL.md as system context) ===")
        print(llm_review(policy_text))
    return 1 if rep.blocking else 0


if __name__ == "__main__":
    raise SystemExit(main())
