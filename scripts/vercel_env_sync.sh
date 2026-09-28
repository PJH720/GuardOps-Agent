#!/usr/bin/env bash
# .env 의 값을 Vercel production 환경변수로 등록한다. 값은 stdin 으로만 전달하고 화면에 출력하지 않는다.
#
#   ./scripts/vercel_env_sync.sh                                # Nemotron(NVIDIA API) + Content Safety 설정
#   ./scripts/vercel_env_sync.sh --onprem https://<tunnel-host>  # DGX Spark relay 입구 (scripts/onprem_ingress.sh 출력 URL)
#
# 등록 후 반영하려면 재배포가 필요하다: vercel deploy --prod
set -euo pipefail
cd "$(dirname "$0")/.."

ENV_FILE=".env"
[[ -f "$ENV_FILE" ]] || { echo "✗ $ENV_FILE 가 없습니다" >&2; exit 1; }

read_env() {  # 마지막 정의 우선, 양끝 따옴표 제거. 값은 절대 echo 하지 않는다.
  local line
  line=$(grep -E "^$1=" "$ENV_FILE" | tail -n 1 || true)
  line=${line#*=}
  line=${line%\"}; line=${line#\"}; line=${line%\'}; line=${line#\'}
  printf '%s' "$line"
}

push() {  # push KEY VALUE [--sensitive]
  local key=$1 value=$2 extra=${3:-}
  if [[ -z "$value" ]]; then echo "· $key: .env 에 없음 → 건너뜀"; return; fi
  # shellcheck disable=SC2086
  printf '%s' "$value" | vercel env add "$key" production --force $extra >/dev/null
  echo "✓ $key 등록 (production${extra:+, sensitive})"
}

if [[ "${1:-}" == "--onprem" ]]; then
  url=${2:-}
  [[ "$url" == https://* ]] || { echo "✗ 사용법: $0 --onprem https://<tunnel-host>" >&2; exit 1; }
  push ONPREM_BASE_URL "${url%/}/v1"
  push ONPREM_API_KEY "$(read_env ONPREM_RELAY_TOKEN)" --sensitive
  push ONPREM_MODEL "$(read_env ONPREM_MODEL)"
  push ONPREM_GUARD "$(read_env ONPREM_GUARD)"
else
  push NVIDIA_API_KEY "$(read_env NVIDIA_API_KEY)" --sensitive
  for key in NV_BASE_URL NV_MODEL NV_GUARD_MODEL NV_GUARD_FAIL_OPEN NV_GUARD_QUARANTINE MAX_STEPS AGENT_DEFAULT_ROLE; do
    push "$key" "$(read_env "$key")"
  done
fi
echo "→ 반영: vercel deploy --prod"
