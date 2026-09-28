"""Headless GuardOps agent engine: one ReAct loop that yields typed events instead of printing.

The CLI (agent.py) and the web console (server.py) are both thin consumers of `run_agent()`.
Security order is fixed here, once: input guard → RBAC-bound retriever → PolicyGate on EVERY tool call →
human approval only for calls the gate already allowed → tool execution → search screening events.

HITL protocol: the generator yields an `approval_required` event and must be resumed with
`gen.send(True | False)`; every other event is resumed with `next()` / `send(None)`.
"""
from __future__ import annotations

import datetime as dt
import itertools
import json
import re
from dataclasses import dataclass, field
from typing import Any, Callable, Generator

SEVERITY_ORDER = ("low", "medium", "high", "critical")
_WITHHELD = re.compile(r"(\d+) chars withheld")


@dataclass(frozen=True)
class AgentEvent:
    id: int
    type: str
    layer: str      # L1 | L2 | L3 | agent | system
    status: str     # info | active | pass | warn | blocked
    stage: str      # goal | screening | grounding | reasoning | enforcement | action
    step: int
    payload: dict = field(default_factory=dict)
    timestamp: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {"id": self.id, "type": self.type, "layer": self.layer, "status": self.status, "stage": self.stage,
                "step": self.step, "payload": self.payload, "timestamp": self.timestamp}


@dataclass(frozen=True)
class EngineContext:
    role: str
    gate: Any                                   # agent.PolicyGate (built with auto_approve=True: never calls input())
    llm: Callable[..., dict]
    tools: dict                                 # name -> (fn, description, params)
    tool_schemas: Callable[[], list]
    system_prompt: str
    guard_input: Callable[[str], tuple[bool, str]]
    audit: Callable[..., None]
    reachable_docs: frozenset
    corpus_docs: frozenset
    doc_clearance: frozenset
    model: str
    guard_model: str
    quarantine_mode: str
    auto_approve: bool = False
    max_steps: int = 8


def cite_rule(reason: str, role: str, tool: str) -> str:
    """정책 판정 사유를 근거 규칙 위치로 변환 (UI 의 '인용 규칙' 표시용)."""
    r = reason.lower()
    if "not allowed to call" in r:
        return f"app_policy.yaml › roles.{role}.tools"
    if "not in allowlist" in r:
        return "app_policy.yaml › egress_allowlist"
    if "egress url policy" in r or "no egress url rule" in r or "fragment" in r or "scheme" in r:
        return "app_policy.yaml › egress_url_rules"
    if "userinfo" in r:
        return "app_policy.yaml › egress (no credentials in URL)"
    if "pattern" in r:
        return "app_policy.yaml › blocked_patterns / egress_secret_patterns"
    if "human approver" in r or "approved by human" in r or "auto-approved" in r:
        return "app_policy.yaml › require_approval (HITL)"
    if "unknown tool" in r:
        return "harness › tool registry"
    return f"app_policy.yaml › roles.{role}.tools · {tool}"


def summarize_result(tool: str, result: str) -> str:
    if tool == "load_skill" and isinstance(result, str) and not result.startswith("ERROR"):
        title = next((ln.lstrip("# ").strip() for ln in result.splitlines() if ln.startswith("#")), "skill")
        return f"SKILL.md loaded · {title} · {len(result)} chars"
    try:
        obj = json.loads(result)
    except (json.JSONDecodeError, TypeError):
        return result[:160] if isinstance(result, str) else ""
    if not isinstance(obj, dict):
        return ""
    if obj.get("denied"):
        return f"blocked: {obj.get('reason')}"
    if "ticket_id" in obj:
        return f"ticket {obj['ticket_id']} {obj.get('status', '')}".strip()
    if "granted" in obj:
        return f"{obj.get('user')} → {obj.get('resource')}: {'granted' if obj['granted'] else 'not granted'}"
    if obj.get("grounded") is True:
        return "grounded: " + ", ".join(h.get("doc_id", "?") for h in obj.get("hits", []))
    if obj.get("grounded") is False:
        return f"no grounded evidence ({obj.get('reason')}) — no content returned"
    if obj.get("redirect_blocked"):
        return f"redirect blocked ({obj.get('status')})"
    if "error" in obj:
        return f"error: {obj['error']}"
    if tool == "list_skills":
        return f"{len(obj)} skills available"
    return ""


def _risk(ticket_severity: str | None, quarantined: int, egress_denied: int, denied: int) -> str:
    derived = "critical" if (quarantined or egress_denied) else "high" if denied else "medium"
    if ticket_severity in SEVERITY_ORDER and SEVERITY_ORDER.index(ticket_severity) > SEVERITY_ORDER.index(derived):
        return ticket_severity
    return derived


def run_agent(ctx: EngineContext, goal: str) -> Generator[AgentEvent, bool | None, str]:
    seq = itertools.count(1)
    step = 0
    blocked: list[dict] = []
    tickets: list[dict] = []
    counts = {"quarantined": 0, "egress_denied": 0, "denied": 0}

    def ev(type_: str, layer: str, status: str, stage: str, **payload) -> AgentEvent:
        return AgentEvent(next(seq), type_, layer, status, stage, step, payload,
                          dt.datetime.now().isoformat(timespec="seconds"))

    # ── goal: RBAC 사전 필터는 이미 바인딩됨 (권한 밖 문서는 검색기 인스턴스에 존재하지 않음)
    ctx.audit("start", role=ctx.role, goal=goal, model=ctx.model,
              doc_clearance=sorted(ctx.doc_clearance), reachable_docs=sorted(ctx.reachable_docs))
    yield ev("session_started", "system", "info", "goal", role=ctx.role, goal=goal,
             auto_approve=ctx.auto_approve, model=ctx.model,
             doc_clearance=sorted(ctx.doc_clearance), reachable_docs=sorted(ctx.reachable_docs),
             excluded_docs=sorted(ctx.corpus_docs - ctx.reachable_docs), quarantine_mode=ctx.quarantine_mode)

    # ── Layer 1: 입력 Content Safety
    ok, why = ctx.guard_input(goal)
    ctx.audit("input_guard", ok=ok, detail=why)
    guard_label = ctx.guard_model or "disabled"
    yield ev("input_screened", "L1", "pass" if ok else "blocked", "screening", ok=ok, detail=why, model=guard_label)
    if not ok:
        blocked.append({"layer": "L1", "what": "user goal", "reason": why})
        refusal = f"입력이 안전 정책에 의해 거부되었습니다: {why}"
        yield ev("final_report", "system", "blocked", "screening", report=refusal, risk="high",
                 blocked_attempts=blocked, tickets=tickets, outcome="refused")
        return refusal

    messages = [{"role": "system", "content": ctx.system_prompt}, {"role": "user", "content": goal}]
    require_approval = set(ctx.gate.cfg.get("require_approval", []))

    for step in range(1, ctx.max_steps + 1):
        yield ev("step_started", "agent", "active", "reasoning", model=ctx.model)
        msg = ctx.llm(messages, tools=ctx.tool_schemas())
        calls = msg.get("tool_calls") or []
        content = msg.get("content") or ""
        messages.append({"role": "assistant", "content": content, **({"tool_calls": calls} if calls else {})})

        if not calls:
            ctx.audit("final", step=step)
            severity = tickets[-1].get("severity") if tickets else None
            yield ev("final_report", "system", "pass", "action", report=content,
                     risk=_risk(severity, counts["quarantined"], counts["egress_denied"], counts["denied"]),
                     blocked_attempts=blocked, tickets=tickets, counts=counts, outcome="completed")
            return content
        if content:
            yield ev("reasoning", "agent", "info", "reasoning", content=content)

        for tc in calls:
            name = tc["function"]["name"]
            try:
                args = json.loads(tc["function"].get("arguments") or "{}")
            except json.JSONDecodeError:
                args = {}
            yield ev("tool_proposed", "agent", "active", "enforcement", tool=name, args=args, call_id=tc.get("id"))

            # ── Layer 2: 결정론적 PolicyGate — 모든 호출에 먼저 (역할 RBAC → L7 egress → 차단 패턴)
            allowed, reason = ctx.gate.check(name, args) if name in ctx.tools else (False, "unknown tool")
            needs_human = allowed and name in require_approval and not ctx.auto_approve
            if needs_human:
                approved = yield ev("approval_required", "L2", "warn", "enforcement", tool=name, args=args,
                                    impact="irreversible", severity=args.get("severity"),
                                    rule=cite_rule("human approver", ctx.role, name),
                                    message=f"'{name}' 작업은 되돌릴 수 없습니다. 실행을 승인하시겠습니까?")
                approved = bool(approved)
                allowed, reason = (True, "approved by human") if approved else (False, "human approver rejected")
                ctx.audit("hitl_decision", step=step, tool=name, approved=approved)
                yield ev("approval_resolved", "L2", "pass" if approved else "blocked", "enforcement",
                         tool=name, approved=approved)

            rule = cite_rule(reason, ctx.role, name)
            yield ev("policy_decision", "L2", "pass" if allowed else "blocked", "enforcement", tool=name, args=args,
                     allowed=allowed, reason=reason, rule=rule, requires_approval=name in require_approval,
                     human_approved=(allowed if needs_human else None))
            if not allowed:
                counts["denied"] += 1
                blocked.append({"layer": "L2", "what": name, "reason": reason, "rule": rule})

            if allowed:
                try:
                    result = ctx.tools[name][0](**args)
                except TypeError as e:
                    result = json.dumps({"error": f"bad arguments: {e}"})
            else:
                result = json.dumps({"denied": True, "reason": reason}, ensure_ascii=False)

            if name == "fetch_url":
                if not allowed:
                    counts["egress_denied"] += 1
                yield ev("egress_decision", "L2", "pass" if allowed else "blocked", "enforcement",
                         url=str(args.get("url", "")), allowed=allowed, reason=reason, rule=rule)
            if name == "search_runbook" and allowed:
                yield from _search_events(ev, result, counts, blocked)

            ctx.audit("tool", step=step, tool=name, args=args, allowed=allowed, reason=reason,
                      result_preview=result[:200])
            if name == "create_incident_ticket" and allowed:
                tid = _json_field(result, "ticket_id")
                if tid:
                    ticket = {"id": tid, "title": args.get("title"), "severity": args.get("severity"),
                              "summary": args.get("summary"), "actions": args.get("actions") or []}
                    tickets.append(ticket)
                    yield ev("ticket_created", "agent", "pass", "action", **ticket)
            yield ev("tool_result", "agent", "info" if allowed else "blocked",
                     "grounding" if name == "search_runbook" else "action",
                     tool=name, allowed=allowed, summary=summarize_result(name, result), result=result[:4000])
            messages.append({"role": "tool", "tool_call_id": tc["id"], "content": result})

    ctx.audit("max_steps")
    limit = "최대 단계 수에 도달했습니다. out/audit.jsonl 을 확인하세요."
    yield ev("run_limit", "system", "warn", "action", message=limit, max_steps=ctx.max_steps)
    return limit


def _json_field(result: str, key: str):
    try:
        return json.loads(result).get(key)
    except (json.JSONDecodeError, AttributeError):
        return None


def _search_events(ev, result: str, counts: dict, blocked: list) -> Generator[AgentEvent, None, None]:
    """search_runbook 결과 → 격리(이중 탐지) / 정규식 단독 탐지 / grounding 판정 이벤트."""
    data = json.loads(result)
    hits = data.get("hits", [])
    seen: set[str] = set()  # 한 문서가 여러 청크로 검색돼도 경보는 문서당 한 번
    for h in hits:
        if h.get("doc_id") in seen or not (h.get("quarantined") or h.get("injection_suspected")):
            continue
        seen.add(h.get("doc_id"))
        if h.get("quarantined"):
            counts["quarantined"] += 1
            m = _WITHHELD.search(h.get("content", ""))
            blocked.append({"layer": "L1", "what": f"document {h.get('doc_id')}", "reason": "quarantined",
                            "rule": "dual-flag quarantine (regex + content safety)"})
            yield ev("doc_quarantined", "L1", "blocked", "grounding", doc_id=h.get("doc_id"), title=h.get("title"),
                     trust=h.get("trust"), reasons=h.get("reasons", []),
                     withheld_chars=int(m.group(1)) if m else None, warning=h.get("warning"))
        elif h.get("injection_suspected"):
            yield ev("injection_flagged", "L1", "warn", "grounding", doc_id=h.get("doc_id"), title=h.get("title"),
                     trust=h.get("trust"), patterns=h.get("injection_patterns", []),
                     content_safety=h.get("content_safety", "n/a"))
    yield ev("grounding_verdict", "L2", "pass" if data.get("grounded") else "warn", "grounding",
             grounded=bool(data.get("grounded")), reason=data.get("reason", "ok"),
             doc_ids=[h.get("doc_id") for h in hits])
