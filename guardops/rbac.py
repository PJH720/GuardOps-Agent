"""RBAC single source of truth (port of lib/rbac.ts, extended to multi-clearance roles).

A document's `access_role` is one of: all | hr | eng | finance.
An agent role maps to a *clearance set* (policy/app_policy.yaml → doc_clearance).
"""
from __future__ import annotations

ACCESS_ROLES = frozenset({"all", "hr", "eng", "finance"})


def can_view(clearance: frozenset[str], access_role: str) -> bool:
    """Company-wide docs are visible to everyone; department docs need an exact clearance."""
    if access_role == "all":
        return True
    return access_role in clearance
