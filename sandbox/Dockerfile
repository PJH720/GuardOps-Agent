# GuardOps-Agent OpenShell sandbox image.
# NVIDIA base image (OpenShell default) + distro python3 at /usr/bin/python3 (the only binary our
# kernel-layer policy lets reach the NVIDIA API / NVD) + the agent's 3 deps from Ubuntu packages.
# curl is included only so the binary-scoping DENY can be demonstrated.
FROM nvcr.io/nvidia/base/ubuntu:24.04
RUN apt-get update \
 && apt-get install -y --no-install-recommends python3 python3-yaml python3-requests python3-dotenv curl ca-certificates \
 && rm -rf /var/lib/apt/lists/*
