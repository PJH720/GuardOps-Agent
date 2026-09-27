"""Query pre-processing (port of lib/search.ts).

1. sanitize_retrieval_query: strips role-spoofing phrases ("인사팀 권한으로 알려줘") so they
   cannot pollute BM25 scoring. Authorization never depends on query text anyway — RBAC is
   bound to the retriever at construction time.
2. expand_synonyms: bidirectional KO synonym groups + KO↔EN bridges so English alerts can
   ground against the Korean runbook corpus.
"""
from __future__ import annotations

import re

from .tokenizer import tokenize

_ORG = r"(?:인사팀|엔지니어링|재무팀|보안팀|개발팀|경영진|관리자|임원|hr|eng|finance|admin)"
ROLE_SPOOFING_PATTERNS = [
    re.compile(_ORG + r"\s*(?:권한|역할|자격)(?:으로|에서|의|이|가)?\s*(?:답해?\s*(?:주세요|줘|주십시오)?|답변해?\s*(?:주세요|줘)?|알려\s*(?:주세요|줘)?|조회해?\s*(?:주세요|줘)?)", re.I),
    re.compile(_ORG + r"\s*(?:권한으로|권한상|으?로서?|자격으로|입장에서)\s*", re.I),
    re.compile(r"(?:나는|저는|본인은)\s*(?:인사팀|엔지니어링|재무팀|보안팀|개발팀|경영진|관리자|임원|hr팀?|eng팀?)\s*(?:소속|직원|담당자|팀원)?(?:입니다|이에요|이야|임)", re.I),
    re.compile(r"(?:system|시스템|assistant)\s*(?:프롬프트|prompt)?\s*(?:역할|role|메시지|message)?\s*(?:를?|을?|은?|는?|이?|가?|의?)?\s*(?:hr|eng|finance|admin|관리자|인사팀|개발팀)?\s*(?:로|으로)?\s*(?:변경|설정|바꿔|override|지정|전환|조작)(?:해?\s*(?:주세요|줘|주십시오|봐)?|합니다|함)?", re.I),
    re.compile(r"(?:모든|전체|모든\s*문서|기밀|비밀)\s*(?:문서|자료|정보)?\s*(?:를?|을?)\s*(?:열람|접근|조회|공개|보여)\s*(?:해?\s*(?:주세요|줘)?|하겠습니다|권한)", re.I),
]


def sanitize_retrieval_query(raw: str) -> str:
    if not raw:
        return ""
    q = raw
    for pat in ROLE_SPOOFING_PATTERNS:
        q = pat.sub(" ", q)
    q = re.sub(r"\s{2,}", " ", q)
    q = re.sub(r"^[^가-힣a-zA-Z0-9]+", "", q)
    return q.strip()


SYNONYM_GROUPS: list[list[str]] = [
    # --- ported from on-prem-rag-service ---
    ["사원", "직원", "임직원", "구성원", "인원", "총원", "인력"],
    ["부서장", "팀장", "실장", "본부장", "리더"],
    ["연봉", "급여", "보수", "임금"],
    ["생성형ai", "생성ai", "genai", "generativeai"],
    ["보안사고", "인시던트", "침해사고", "장애", "incident"],
    # --- SecOps KO↔EN bridges (GuardOps extension) ---
    ["로그인", "login", "logon", "접속"],
    ["이상", "abnormal", "anomaly", "비정상", "suspicious"],
    ["데이터베이스", "db", "database", "prod-db", "운영"],
    ["런북", "runbook", "playbook", "대응절차"],
    ["계정", "account", "credential", "credentials", "자격증명"],
    ["비밀번호", "password", "패스워드"],
    ["유출", "exfiltration", "leak", "exfil", "반출"],
    ["경보", "alert", "알림", "경고"],
    ["조치", "action", "response", "대응"],
    ["심각도", "severity", "등급"],
    ["에스컬레이션", "escalation", "보고"],
    ["벤더", "vendor", "외부", "공지", "notice"],
    ["패치", "patch", "업데이트"],
]

_INDEX: dict[str, list[str]] = {}
for _group in SYNONYM_GROUPS:
    for _word in _group:
        _INDEX[_word.lower().replace(" ", "")] = _group


def expand_synonyms(tokens: list[str]) -> list[str]:
    """Keep original tokens, add synonym tokens (deduplicated, order-preserving)."""
    expanded = dict.fromkeys(tokens)
    for tok in tokens:
        group = _INDEX.get(tok.lower().replace(" ", ""))
        if group:
            for syn in group:
                for st in tokenize(syn):
                    expanded.setdefault(st)
    return list(expanded)
