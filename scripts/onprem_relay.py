#!/usr/bin/env python3
"""DGX Spark SGLang 인증 relay — Vercel 의 GuardOps 콘솔이 사설망 안의 Qwen 에 닿기 위한 유일한 공개 입구.

SGLang 은 무인증이므로 절대 직접 공개하지 않는다. 이 relay 만 터널(scripts/onprem_ingress.sh)로 공개된다.
  - Bearer 토큰(ONPREM_RELAY_TOKEN) 필수, 상수 시간 비교
  - 허용 경로 2개뿐: POST /v1/chat/completions, GET /v1/models (그 외 404, 문서 경로 비활성)
  - 요청 본문 64KB 상한, max_tokens ≤ 2048 강제, model 은 ONPREM_MODEL 로 고정, stream 미지원
  - upstream = .env 의 ONPREM_BASE_URL (사설망 주소). 클라이언트의 Authorization 은 upstream 으로 넘기지 않는다.

  uv run --with-requirements requirements.txt python scripts/onprem_relay.py [--port 8787]
"""
from __future__ import annotations

import argparse
import asyncio
import hmac
import json
import os
from pathlib import Path

import requests
import uvicorn
from dotenv import load_dotenv
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse, Response

ROOT = Path(__file__).resolve().parents[1]
load_dotenv(ROOT / ".env")

UPSTREAM = os.getenv("ONPREM_BASE_URL", "").rstrip("/")
MODEL = os.getenv("ONPREM_MODEL", "Inferact/Qwen3.8-Flash-Next-NVFP4")
TOKEN = os.getenv("ONPREM_RELAY_TOKEN", "")
MAX_BODY_BYTES = 64 * 1024
MAX_TOKENS = 2048
UPSTREAM_TIMEOUT = 180

app = FastAPI(docs_url=None, redoc_url=None, openapi_url=None)


def _authorized(request: Request) -> bool:
    supplied = request.headers.get("authorization", "")
    return bool(TOKEN) and hmac.compare_digest(supplied.encode(), f"Bearer {TOKEN}".encode())


def _deny(status: int, message: str) -> JSONResponse:
    return JSONResponse({"error": {"message": message}}, status_code=status)


@app.get("/v1/models")
async def models(request: Request) -> Response:
    if not _authorized(request):
        return _deny(401, "unauthorized")
    try:
        r = await asyncio.to_thread(requests.get, f"{UPSTREAM}/models", timeout=5)
        r.raise_for_status()
        served = [m for m in r.json().get("data", []) if m.get("id") == MODEL]
    except (requests.RequestException, ValueError):
        return _deny(502, "DGX Spark upstream unreachable")
    return JSONResponse({"object": "list", "data": served})


@app.post("/v1/chat/completions")
async def chat_completions(request: Request) -> Response:
    if not _authorized(request):
        return _deny(401, "unauthorized")
    body = await request.body()
    if len(body) > MAX_BODY_BYTES:
        return _deny(413, f"request body exceeds {MAX_BODY_BYTES} bytes")
    try:
        payload = json.loads(body)
    except ValueError:
        return _deny(400, "invalid JSON")
    if not isinstance(payload, dict) or not isinstance(payload.get("messages"), list):
        return _deny(400, "messages[] is required")
    if payload.get("stream"):
        return _deny(400, "stream is not supported by this relay")
    try:
        requested = int(payload.get("max_tokens") or MAX_TOKENS)
    except (TypeError, ValueError):
        return _deny(400, "max_tokens must be an integer")
    payload = {**payload, "model": MODEL, "max_tokens": max(1, min(requested, MAX_TOKENS))}
    try:
        r = await asyncio.to_thread(requests.post, f"{UPSTREAM}/chat/completions", json=payload,
                                    timeout=UPSTREAM_TIMEOUT)
    except requests.RequestException:
        return _deny(502, "DGX Spark upstream unreachable")
    return Response(r.content, status_code=r.status_code, media_type="application/json")


def main() -> None:
    ap = argparse.ArgumentParser(description="GuardOps on-prem relay (DGX Spark SGLang)")
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=8787)
    a = ap.parse_args()
    if not UPSTREAM or not TOKEN:
        raise SystemExit("ONPREM_BASE_URL 과 ONPREM_RELAY_TOKEN 이 .env 에 있어야 합니다 (scripts/onprem_ingress.sh 가 토큰을 만든다).")
    uvicorn.run(app, host=a.host, port=a.port, log_level="warning")


if __name__ == "__main__":
    main()
