#!/usr/bin/env bash
# docs/submission.md → docs/[NVIDIA 해커톤_NexaGuard_GuardOps-Agent].pdf (Google Form 업로드용)
# 필요: pandoc, Google Chrome (headless 인쇄가 한글 폰트를 올바르게 렌더링)
set -euo pipefail
cd "$(dirname "$0")/.."
CHROME="${CHROME:-/Applications/Google Chrome.app/Contents/MacOS/Google Chrome}"
OUT="docs/[NVIDIA 해커톤_NexaGuard_GuardOps-Agent].pdf"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT
pandoc docs/submission.md -s --metadata pagetitle="GuardOps-Agent — NexaGuard" \
  --css docs/pdf.css --embed-resources -o "$TMP/submission.html"
"$CHROME" --headless=new --disable-gpu --no-pdf-header-footer \
  --print-to-pdf="$PWD/$OUT" "file://$TMP/submission.html" 2>/dev/null
echo "built: $OUT"
