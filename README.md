# 🛡️ GuardOps-Agent

> **NVIDIA Korea Agentic AI Hackathon (2026)**  
> **Mission**: Enterprise Security Operations Agent with Multi-Layer Defense  
> **Tech Stack**: NVIDIA Nemotron (build.nvidia.com) · NVIDIA Agent Skills · NVIDIA OpenShell · RBAC Grounding

---

## 🌟 Overview

**GuardOps-Agent** is an enterprise-grade autonomous security operations agent designed to investigate anomalies, verify permissions, and execute runbook procedures while deterministically preventing prompt injection and data exfiltration (Lethal Trifecta).

### 🛡️ 3-Layer Defense Architecture
1. **Prompt Layer (Intent & Planning)**: Uses `nvidia/nemotron-3-super-120b-a12b` via `build.nvidia.com` with progressive skill loading (`SKILL.md`).
2. **Harness Layer (Policy Gate)**: Deny-by-default deterministic RBAC and strict egress allowlist (`app_policy.yaml`).
3. **Sandbox Layer (OS Kernel)**: Kernel-level isolation using NVIDIA OpenShell (Landlock, seccomp, OPA network filtering).

---

## 🚀 Quickstart

```bash
# 1. Environment Setup
pip install -r requirements.txt
export NVIDIA_API_KEY="nvapi-..."

# 2. Verify API & Models
python3 check_api.py

# 3. Run Agent (Mock Mode)
python3 agent.py --mock --auto-approve

# 4. Run Agent (Real Model)
python3 agent.py --role analyst "Investigate abnormal login alert on DB server"
```

---

## 📄 License
MIT License
