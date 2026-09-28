#!/usr/bin/env bash
# GuardOps-Agent 를 NVIDIA OpenShell 샌드박스(커널 계층 방어) 안에서 실행하고 DENY 증거를 수집한다.
# 2026-09-28 OpenShell 0.1.1 로 실제 검증된 절차 (증거: docs/evidence/openshell_kernel_deny.txt).
#
# 사전 준비
#   1) OpenShell 설치: curl -LsSf https://raw.githubusercontent.com/NVIDIA/OpenShell/main/install.sh | sh
#      (macOS: Apple Silicon + Docker Desktop 필요. VM 드라이버는 e2fsprogs 필요: brew install e2fsprogs)
#   2) 로컬 게이트웨이 실행. macOS 에서는 VM 드라이버를 쓴다 — Docker 드라이버는 --network host 를 쓰는데
#      Docker Desktop 에서는 그 "host" 가 Mac 이 아니라 Docker VM 이라 샌드박스가 게이트웨이에 닿지 못한다.
#      - Homebrew 설치가 정상인 경우:  OPENSHELL_COMPUTE_DRIVER=vm brew services restart openshell
#      - 이 저장소에서 실제 검증한 경로(Homebrew 가 Xcode CLT 버전 문제로 막힌 macOS, 수동 설치):
#          OPENSHELL_COMPUTE_DRIVER=vm ~/.local/openshell/run-gateway.sh &      # Docker Desktop 실행 상태에서
#          export PATH="$HOME/.local/openshell/bin:$PATH"
#      - 최초 1회: openshell gateway add https://localhost:17670 --local --name openshell
set -euo pipefail
cd "$(dirname "$0")"

NAME="${SANDBOX_NAME:-guardops}"
IMAGE="guardops-sandbox:0.1"
STAGE="$(mktemp -d)"
trap 'rm -rf "$STAGE"' EXIT

# 1. 샌드박스 이미지: NVIDIA base + /usr/bin/python3.12 (정책이 허용하는 유일한 바이너리) + 에이전트 의존성
docker build -q -t "$IMAGE" sandbox >/dev/null

# 2. 추적되는 파일만 업로드 (.env·ref/ 제외 — git archive 는 커밋된 파일만 포함)
git archive HEAD | tar -x -C "$STAGE"

# 3. 커널 계층 정책 사전 감사 (공식 NVIDIA generate-sandbox-policy 스킬 체크리스트)
if command -v uv >/dev/null; then PY=(uv run -q --with-requirements requirements.txt python); else PY=(python3); fi
"${PY[@]}" scripts/audit_openshell_policy.py >/dev/null && echo "policy audit: PASS"

# 4. 샌드박스 생성
openshell sandbox delete "$NAME" >/dev/null 2>&1 || true
openshell sandbox create --name "$NAME" --from "$IMAGE" --policy policy/openshell-policy.yaml \
  --upload "$STAGE/.:/sandbox/guardops" --no-git-ignore --no-auto-providers --no-tty --detach

# 5. 프로브(허용/차단 경로) + 샌드박스 안에서 에이전트 루프 회귀(속은 모델 테스트 더블, 키 불필요)
openshell sandbox exec -n "$NAME" --no-tty --timeout 180 -- bash -s < scripts/openshell_probes.sh
printf 'cd /sandbox/guardops/* && python3 -m unittest tests.test_agent_e2e -v\n' \
  | openshell sandbox exec -n "$NAME" --no-tty --timeout 180 -- bash -s

# 6. 커널 계층 판정 로그 (OCSF): engine:opa = 바이너리+호스트, engine:l7 = 메서드+경로
openshell logs "$NAME" --since 10m --source sandbox | grep -E '(NET|HTTP):[A-Z]+ .*(ALLOWED|DENIED)'

echo "정리: openshell sandbox delete $NAME"
