"""Deterministic prompt-injection flagger for *retrieved* (untrusted) content.

Deterministic-first: a regex verdict runs before (and independent of) any LLM classifier.
Flagged content is NOT stripped — it is labelled so the model and the audit log both see it.
"""
from __future__ import annotations

import re

INJECTION_PATTERNS = [
    re.compile(r"system\s*override", re.I),
    re.compile(r"ignore\s+(all\s+)?(previous|prior)\s+instructions", re.I),
    re.compile(r"이전\s*지시(를|사항을)?\s*무시"),
    re.compile(r"관리자\s*모드"),
    re.compile(r"(환경\s*변수|비밀\s*키|api\s*key|secret).{0,40}(전송|보내|send|post)", re.I | re.S),
    re.compile(r"https?://[^\s\"']+/(exfil|collect|upload)\b", re.I),
    re.compile(r"<!--.*?(system|지시|instruction).*?-->", re.I | re.S),
]


def scan(text: str) -> list[str]:
    """Return the list of matched pattern sources (empty list = clean)."""
    return [p.pattern for p in INJECTION_PATTERNS if p.search(text or "")]
