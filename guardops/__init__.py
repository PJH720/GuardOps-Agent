"""GuardOps enterprise RAG core — Python port of ref/on-prem-rag-service (lib/*.ts).

Deterministic security layers that run *before* any LLM sees retrieved text:
  - rbac:      single-source-of-truth document clearance check
  - retriever: RBAC-prefiltered BM25 (unauthorized chunks filtered at construction)
  - search:    role-spoofing query sanitizer + KO/EN synonym expansion
  - injection: deterministic prompt-injection flagger for retrieved content
"""
