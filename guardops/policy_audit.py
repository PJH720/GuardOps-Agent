"""Deterministic OpenShell sandbox-policy auditor.

Implements "Step 6 — Validate and Warn" of the official NVIDIA OpenShell skill
`skills/generate-sandbox-policy/SKILL.md` (Apache-2.0, vendored unmodified) as code, plus a
GuardOps cross-layer check: every host the app-layer policy gate may reach must also be allowed
by the kernel-layer sandbox policy (otherwise the two defense layers disagree).
"""
from __future__ import annotations

import ipaddress
from dataclasses import dataclass, field

L7_PROTOCOLS = frozenset({"rest", "websocket"})
STANDARD_METHODS = frozenset({"GET", "HEAD", "POST", "PUT", "DELETE", "PATCH", "OPTIONS", "*"})


@dataclass(frozen=True)
class Finding:
    level: str      # hard_error | schema_warning | structural | breadth_warning | cross_layer
    policy: str
    message: str


@dataclass
class AuditReport:
    findings: list[Finding] = field(default_factory=list)

    def add(self, level: str, policy: str, message: str) -> None:
        self.findings.append(Finding(level, policy, message))

    def of(self, level: str) -> list[Finding]:
        return [f for f in self.findings if f.level == level]

    @property
    def blocking(self) -> list[Finding]:
        """Findings that would block sandbox startup or break defense-in-depth."""
        return [f for f in self.findings if f.level in {"hard_error", "structural", "cross_layer"}]


def _is_ip_literal(host: str) -> bool:
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return False


def _audit_endpoint(rep: AuditReport, key: str, ep: dict, credentialed_hosts: frozenset[str]) -> None:
    host, protocol = ep.get("host"), ep.get("protocol")
    has_rules, has_access = "rules" in ep, "access" in ep
    # --- Hard errors ---
    if has_rules and has_access:
        rep.add("hard_error", key, f"{host}: `rules` and `access` are both set (use one)")
    if protocol in L7_PROTOCOLS and not (has_rules or has_access):
        rep.add("hard_error", key, f"{host}: L7 protocol `{protocol}` without `rules` or `access`")
    if protocol == "tcp":
        if has_rules or has_access:
            rep.add("hard_error", key, f"{host}: `protocol: tcp` is L4-only and must not set rules/access")
        if not host or _is_ip_literal(host) or str(host).endswith("."):
            rep.add("hard_error", key, f"{host!r}: `protocol: tcp` needs a valid DNS hostname")
    if "tls" in ep and ep["tls"] != "skip":
        rep.add("hard_error", key, f"{host}: `tls: {ep['tls']}` is invalid (omit it or use `skip`)")
    if has_rules and not ep["rules"]:
        rep.add("hard_error", key, f"{host}: `rules` list is empty")
    l4_only = protocol in (None, "tcp")
    if host in credentialed_hosts and (l4_only or ep.get("tls") == "skip") \
            and not ep.get("allow_uninspected_credentials"):
        rep.add("hard_error", key, f"{host}: credentialed provider endpoint is uninspected (L4-only or tls: skip)")
    # --- Schema warnings ---
    if ep.get("tls") == "skip" and has_rules and ep.get("port") == 443:
        rep.add("schema_warning", key, f"{host}: `tls: skip` with L7 rules on 443 cannot be inspected")
    for r in ep.get("rules") or []:
        method = str((r.get("allow") or {}).get("method", "")).upper()
        if method and method not in STANDARD_METHODS:
            rep.add("schema_warning", key, f"{host}: non-standard HTTP method `{method}`")
    # --- Structural ---
    if not host or "port" not in ep:
        rep.add("structural", key, "endpoint is missing `host` or `port`")
    # --- Breadth warnings ---
    if l4_only:
        rep.add("breadth_warning", key, f"{host}: L4-only — all methods and paths allowed; prefer `protocol: rest`")
    if ep.get("access") == "full":
        rep.add("breadth_warning", key, f"{host}: `access: full` allows DELETE on all paths")
        if ep.get("enforcement") == "audit":
            rep.add("breadth_warning", key, f"{host}: `full` + `audit` is monitoring-only (no restriction)")
    if ep.get("access") == "read-write":
        rep.add("breadth_warning", key, f"{host}: `read-write` allows POST/PUT/PATCH on all paths")
    rules = ep.get("rules") or []
    if rules and all(str((r.get("allow") or {}).get("path", "")).endswith("**") for r in rules):
        rep.add("breadth_warning", key, f"{host}: every rule uses a `**` path glob (equivalent to a preset)")


def audit_policy(policy: dict, app_egress_hosts: list[str] | None = None,
                 credentialed_hosts: frozenset[str] = frozenset()) -> AuditReport:
    rep = AuditReport()
    network = policy.get("network_policies") or {}
    if not network:
        rep.add("structural", "-", "no `network_policies` defined (default-deny for everything)")
    kernel_hosts: set[str] = set()
    for key, pol in network.items():
        for req in ("name", "endpoints", "binaries"):
            if req not in pol:
                rep.add("structural", key, f"policy is missing `{req}`")
        if pol.get("name") not in (None, key):
            rep.add("structural", key, f"policy key `{key}` does not match name `{pol.get('name')}`")
        for b in pol.get("binaries") or []:
            path = b.get("path") if isinstance(b, dict) else None
            if not path:
                rep.add("structural", key, "binary entry is missing `path`")
            elif "*" in path:
                rep.add("breadth_warning", key, f"wildcard binary `{path}` — list specific binaries")
        endpoints = pol.get("endpoints") or []
        broad = [e for e in endpoints if e.get("protocol") in (None, "tcp") or e.get("access") in ("full", "read-write")]
        if len(broad) > 1:
            rep.add("breadth_warning", key, f"{len(broad)} broad endpoints share one policy")
        for ep in endpoints:
            kernel_hosts.add(str(ep.get("host", "")).lower())
            _audit_endpoint(rep, key, ep, credentialed_hosts)
    # --- GuardOps cross-layer check: app-layer egress must be a subset of kernel-layer egress ---
    for host in app_egress_hosts or []:
        if host.lower() not in kernel_hosts:
            rep.add("cross_layer", "-", f"app egress allowlist host `{host}` has no kernel-layer (OpenShell) rule "
                                        f"— the two defense layers disagree")
    return rep


def format_report(rep: AuditReport, title: str) -> str:
    lines = [f"=== {title} ==="]
    order = ["hard_error", "structural", "cross_layer", "schema_warning", "breadth_warning"]
    for level in order:
        items = rep.of(level)
        lines.append(f"[{level}] {len(items)}")
        lines.extend(f"   - ({f.policy}) {f.message}" for f in items)
    verdict = "PASS" if not rep.blocking else f"FAIL ({len(rep.blocking)} blocking)"
    lines.append(f"VERDICT: {verdict}")
    return "\n".join(lines)
