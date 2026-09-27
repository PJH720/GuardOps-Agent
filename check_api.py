#!/usr/bin/env python3
"""build.nvidia.com API 키/모델 동작 확인: 모델 목록 중 nemotron 계열 출력 + 1회 호출 + tool calling 확인."""
import json, os, sys, requests
BASE = os.getenv("NV_BASE_URL", "https://integrate.api.nvidia.com/v1")
KEY = os.getenv("NVIDIA_API_KEY") or sys.exit("export NVIDIA_API_KEY=nvapi-... 먼저 설정")
MODEL = os.getenv("NV_MODEL", "nvidia/nemotron-3-super-120b-a12b")
H = {"Authorization": f"Bearer {KEY}"}
ids = [m["id"] for m in requests.get(f"{BASE}/models", headers=H, timeout=30).json().get("data", [])]
print("nemotron/guard 계열 모델:", *[i for i in ids if "nemotron" in i or "guard" in i or "safety" in i], sep="\n  ")
print(f"\n'{MODEL}' 목록 존재:", MODEL in ids)
body = {"model": MODEL, "messages": [{"role": "user", "content": "서울 날씨를 알려줘"}], "max_tokens": 256,
        "tools": [{"type": "function", "function": {"name": "get_weather", "description": "도시 날씨 조회",
                   "parameters": {"type": "object", "properties": {"city": {"type": "string"}}, "required": ["city"]}}}]}
r = requests.post(f"{BASE}/chat/completions", headers=H, json=body, timeout=120)
print("status", r.status_code)
msg = r.json()["choices"][0]["message"] if r.ok else r.text
print("tool calling 응답:", json.dumps(msg, ensure_ascii=False)[:600])
