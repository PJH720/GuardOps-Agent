"""RBAC-prefiltered BM25 retriever + grounding confidence gate.

Port of ref/on-prem-rag-service: scripts/ingest.ts (section chunking, BM25 stats) and
lib/retriever.ts (RbacBm25Retriever, evaluateGrounding).

Security core: RBAC is applied in the constructor. Chunks the role may not view are never
stored on the instance, so no bug in `search()` can surface them to the LLM prompt.
"""
from __future__ import annotations

import math
import os
import re
from dataclasses import dataclass
from pathlib import Path
from types import MappingProxyType

import yaml

from .rbac import ACCESS_ROLES, can_view
from .search import expand_synonyms
from .tokenizer import tokenize

K1 = 1.2
B = 0.75
MIN_SCORE = float(os.getenv("RAG_REJECTION_THRESHOLD", "10"))
MIN_SHALLOW_SCORE = float(os.getenv("RAG_SHALLOW_SCORE", "18"))
MIN_COMPOSITE = float(os.getenv("RAG_MIN_COMPOSITE", "0.10"))

_FRONTMATTER = re.compile(r"^---\n(.*?)\n---\n(.*)$", re.S)
_SECTION = re.compile(r"(?:^|\n)##\s+([^\n]+)\n(.*?)(?=\n##\s+|\Z)", re.S)


@dataclass(frozen=True)
class Chunk:
    id: str
    doc_id: str
    doc_title: str
    section_title: str
    access_role: str
    trust: str
    file_name: str
    content: str
    terms: MappingProxyType
    length: int


@dataclass(frozen=True)
class Hit:
    chunk: Chunk
    score: float
    matched_terms: tuple[str, ...]

    @property
    def normalized_score(self) -> float:
        return round(self.score / (self.score + 10), 2)


@dataclass(frozen=True)
class CorpusIndex:
    chunks: tuple[Chunk, ...]
    idf: MappingProxyType
    avgdl: float


def _make_chunk(idx: int, meta: dict, title: str, section: str, body: str, file_name: str) -> Chunk:
    tokens = tokenize(f"{title} {section}\n{body}")
    terms: dict[str, int] = {}
    for t in tokens:
        terms[t] = terms.get(t, 0) + 1
    return Chunk(
        id=f"chunk_{idx:03d}", doc_id=str(meta["doc_id"]), doc_title=title, section_title=section,
        access_role=str(meta["access_role"]), trust=str(meta.get("trust", "internal")),
        file_name=file_name, content=body, terms=MappingProxyType(terms), length=len(tokens),
    )


def build_index(corpus_dir: Path) -> CorpusIndex:
    """Parse frontmatter + split on `##` headings (identical to ingest.ts), compute BM25 stats."""
    chunks: list[Chunk] = []
    for path in sorted(corpus_dir.glob("*.md")):
        m = _FRONTMATTER.match(path.read_text(encoding="utf-8"))
        if not m:
            continue  # fail-closed: documents without RBAC metadata are never indexed
        meta, content = yaml.safe_load(m.group(1)) or {}, m.group(2)
        title = meta.get("title")
        if not meta.get("doc_id") or meta.get("access_role") not in ACCESS_ROLES or not title:
            continue
        sections = [(s.strip(), b.strip()) for s, b in _SECTION.findall(content) if b.strip()]
        if not sections and content.strip():
            sections = [(title, content.strip())]
        for section, body in sections:
            chunks.append(_make_chunk(len(chunks) + 1, meta, title, section, body, path.name))
    if not chunks:
        raise ValueError(f"no indexable documents in {corpus_dir}")
    n = len(chunks)
    df: dict[str, int] = {}
    for ch in chunks:
        for t in ch.terms:
            df[t] = df.get(t, 0) + 1
    idf = {t: math.log((n - f + 0.5) / (f + 0.5) + 1) for t, f in df.items()}
    return CorpusIndex(tuple(chunks), MappingProxyType(idf), sum(c.length for c in chunks) / n)


class RbacBm25Retriever:
    """BM25 over the subset of chunks the given clearance may view — fixed at construction."""

    def __init__(self, index: CorpusIndex, clearance: frozenset[str], k: int = 4):
        self.clearance = frozenset(clearance)
        self.k = k
        self._idf = index.idf
        self._avgdl = index.avgdl
        self._permitted: tuple[Chunk, ...] = tuple(
            c for c in index.chunks if can_view(self.clearance, c.access_role)
        )

    @property
    def permitted_doc_ids(self) -> frozenset[str]:
        return frozenset(c.doc_id for c in self._permitted)

    def search(self, query: str) -> tuple[list[Hit], int]:
        """Return (top-k hits, query token count before synonym expansion)."""
        raw_terms = tokenize(query)
        terms = expand_synonyms(raw_terms)
        if not terms:
            return [], 0
        scored: list[Hit] = []
        for ch in self._permitted:
            score, matched = 0.0, []
            norm = 1 - B + B * (ch.length / self._avgdl)
            for t in terms:
                tf = ch.terms.get(t, 0)
                if not tf:
                    continue
                matched.append(t)
                score += self._idf.get(t, 0.1) * ((tf * (K1 + 1)) / (tf + K1 * norm))
            if score > 0:
                scored.append(Hit(ch, score, tuple(matched)))
        scored.sort(key=lambda h: h.score, reverse=True)
        return scored[: self.k], len(set(raw_terms))


@dataclass(frozen=True)
class GroundingVerdict:
    grounded: bool
    reason: str  # ok | no_results | below_threshold | shallow_match | low_coverage
    top_score: float = 0.0
    coverage: float | None = None
    composite: float | None = None


def evaluate_grounding(hits: list[Hit], query_token_count: int | None = None) -> GroundingVerdict:
    """Deterministic confidence gate — decided BEFORE any retrieved text reaches the LLM."""
    if not hits:
        return GroundingVerdict(False, "no_results")
    top = hits[0]
    if top.score < MIN_SCORE:
        return GroundingVerdict(False, "below_threshold", top.score)
    if len(top.matched_terms) < 2 and top.score < MIN_SHALLOW_SCORE:
        return GroundingVerdict(False, "shallow_match", top.score)
    if query_token_count:
        coverage = min(1.0, len(top.matched_terms) / query_token_count)
        composite = coverage * (top.score / (top.score + 15))
        if composite < MIN_COMPOSITE:
            return GroundingVerdict(False, "low_coverage", top.score, coverage, composite)
        return GroundingVerdict(True, "ok", top.score, coverage, composite)
    return GroundingVerdict(True, "ok", top.score)
