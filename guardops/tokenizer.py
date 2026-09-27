"""Korean hybrid tokenizer: word tokens + character bi-grams/tri-grams (port of lib/tokenizer.ts)."""
from __future__ import annotations

import re

_CLEAN = re.compile(r"[^\w\s가-힣0-9\-_]")
_HANGUL = re.compile(r"[가-힣]")


def tokenize(text: str) -> list[str]:
    if not text:
        return []
    clean = _CLEAN.sub(" ", text.lower()).strip()
    tokens: list[str] = []
    for word in clean.split():
        tokens.append(word)
        if _HANGUL.search(word):
            tokens.extend(word[i:i + 2] for i in range(len(word) - 1))
            if len(word) >= 3:
                tokens.extend(word[i:i + 3] for i in range(len(word) - 2))
    return tokens
