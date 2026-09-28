<!-- Parent: ../AGENTS.md -->
<!-- Generated: 2026-09-28 | Updated: 2026-09-28 -->

# sandbox

## Purpose
Container image for the OpenShell sandbox layer, built by `run_in_openshell.sh` as `guardops-sandbox:0.1`.

## Key Files
| File | Description |
|------|-------------|
| `Dockerfile` | `nvcr.io/nvidia/base/ubuntu:24.04` + distro `python3` (+ yaml/requests/dotenv from apt) + `curl` (only to demo binary-scoped DENY) |

## For AI Agents

### Working In This Directory
- `policy/openshell-policy.yaml` allows only the real executable `/usr/bin/python3.12` (OpenShell identifies binaries by resolved path, not the `/usr/bin/python3` symlink) to reach the network; a base-image Python version change requires updating that policy.
- Install deps from apt, not pip, so the image matches `requirements.txt` without network access at runtime.
- Code is uploaded at run time from `git archive HEAD` — uncommitted changes are not in the sandbox.

<!-- MANUAL: Any manually added notes below this line are preserved on regeneration -->
