#!/usr/bin/env bash
# GuardOps-Agent 를 OpenShell 샌드박스 안에서 실행 (커널 레벨 2차 방어 시연용)
# 사전: OpenShell 설치  curl -LsSf https://raw.githubusercontent.com/NVIDIA/OpenShell/main/install.sh | sh
#       Docker 실행 중, export NVIDIA_API_KEY=nvapi-...
# 주의: OpenShell 버전에 따라 플래그가 다를 수 있음 → `openshell sandbox create --help` 로 확인
set -euo pipefail
cd "$(dirname "$0")"
openshell provider create --name nvidia-build --type nvidia --credential NVIDIA_API_KEY || true
openshell sandbox create --name guardops \
  --policy policy/openshell-policy.yaml \
  --provider nvidia-build \
  --upload .:/sandbox/guardops
echo "샌드박스 접속:   openshell sandbox connect guardops"
echo "샌드박스 안에서: cd /sandbox/guardops && pip install -r requirements.txt && python3 agent.py --auto-approve"
echo "차단 로그 확인:  openshell logs guardops --since 5m --source sandbox   # attacker.example DENIED 확인"
