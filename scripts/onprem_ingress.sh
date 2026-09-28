#!/usr/bin/env bash
# DGX Spark 공개 입구: 인증 relay(127.0.0.1:8787) + Cloudflare 임시 터널. SGLang 원본은 공개하지 않는다.
#
#   ./scripts/onprem_ingress.sh          # 시작 → 공개 URL 출력
#   ./scripts/onprem_ingress.sh stop     # 종료
#
# 출력된 URL 을 Vercel 에 등록: ./scripts/vercel_env_sync.sh --onprem <URL> && vercel deploy --prod
# 한계: 이 맥이 켜져 있어야 하며, 재시작하면 URL 이 바뀐다(env 재등록 + 재배포 필요).
set -euo pipefail
cd "$(dirname "$0")/.."
mkdir -p out
PORT=8787

stop() {
  for name in tunnel relay; do
    pidfile="out/onprem_${name}.pid"
    if [[ -f "$pidfile" ]]; then kill "$(cat "$pidfile")" 2>/dev/null || true; rm -f "$pidfile"; fi
  done
}

if [[ "${1:-}" == "stop" ]]; then stop; echo "✓ relay + tunnel 종료"; exit 0; fi
stop

# relay 토큰: 없을 때만 생성해 .env 에 추가 (값은 출력하지 않는다)
if ! grep -qE '^ONPREM_RELAY_TOKEN=.' .env; then
  printf '\n# DGX Spark 인증 relay 토큰 (scripts/onprem_ingress.sh 생성, Vercel 의 ONPREM_API_KEY 로 등록)\nONPREM_RELAY_TOKEN=%s\n' \
    "$(uv run python -c 'import secrets; print(secrets.token_urlsafe(32))')" >> .env
  echo "✓ ONPREM_RELAY_TOKEN 생성 (.env)"
fi

nohup uv run --with-requirements requirements.txt python scripts/onprem_relay.py --port "$PORT" \
  > out/onprem_relay.log 2>&1 &
echo $! > out/onprem_relay.pid

nohup cloudflared tunnel --no-autoupdate --url "http://127.0.0.1:${PORT}" > out/onprem_tunnel.log 2>&1 &
echo $! > out/onprem_tunnel.pid

for _ in $(seq 1 30); do
  url=$(grep -oE 'https://[a-z0-9-]+\.trycloudflare\.com' out/onprem_tunnel.log | head -n 1 || true)
  [[ -n "$url" ]] && break
  sleep 1
done
[[ -n "${url:-}" ]] || { echo "✗ 터널 URL 을 얻지 못했습니다 (out/onprem_tunnel.log 확인)" >&2; exit 1; }
echo "✓ DGX Spark 입구: $url"
echo "→ 다음: ./scripts/vercel_env_sync.sh --onprem $url && vercel deploy --prod"
