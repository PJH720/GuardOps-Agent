// Telemetry & kernel evidence drawer: audit trail, recorded OpenShell traces, live policy audit, RBAC proof, tickets.
import { $, esc, icon, jsonHtml, time, hydrateIcons } from './ui.js';

let evidenceCache = null;
let activeTab = 'audit';
let auditFilter = '';

export async function getEvidence(force = false) {
  if (!evidenceCache || force) {
    const res = await fetch('/api/evidence');
    evidenceCache = await res.json();
  }
  return evidenceCache;
}

/** Probe verdict from the recorded observation: did the kernel do what the probe expected? */
export function probeHeld(p) {
  const o = p.observed.toLowerCase();
  const blocked = /blocked|403|http 000|denied|not permitted|permission/.test(o);
  const allowed = /http 200|^ok/.test(o);
  return /denied/i.test(p.expect) ? blocked : allowed;
}

const EVENT_TONE = {
  quarantine: 'badge-block', injection_flag: 'badge-warn', egress_redirect_blocked: 'badge-block',
  hitl_decision: 'badge-warn', untrusted_doc_guard: 'badge-warn', guard_error: 'badge-block', web_error: 'badge-block',
};

function auditTone(r) {
  if (r.event === 'tool') return r.allowed ? 'badge-pass' : 'badge-block';
  if (r.event === 'input_guard' || r.event === 'grounding_gate') return (r.ok ?? r.grounded) ? 'badge-pass' : 'badge-block';
  return EVENT_TONE[r.event] || 'badge-idle';
}

function auditSub(r) {
  if (r.event === 'tool') return `${r.tool} · ${r.reason}`;
  if (r.event === 'quarantine') return `${r.doc_id} · ${(r.reasons || []).length} triggers · ${r.withheld_chars} chars withheld`;
  if (r.event === 'injection_flag') return `${r.doc_id} · ${(r.patterns || []).length} patterns`;
  if (r.event === 'grounding_gate') return `${r.grounded ? 'grounded' : 'rejected'} · ${r.query}`;
  if (r.event === 'hitl_decision') return `${r.tool} · ${r.approved ? 'approved' : 'rejected'}`;
  if (r.event === 'start') return `${r.role} · ${r.goal}`;
  return r.detail || r.reason || r.doc_id || '';
}

async function renderAudit(body) {
  const records = await (await fetch('/api/audit?limit=150')).json();
  body.innerHTML = `
    <div class="toolbar">
      <input id="audit-filter" placeholder="Filter events — e.g. tool, quarantine, fetch_url" value="${esc(auditFilter)}">
      <button class="btn btn-ghost" id="audit-refresh">${icon('refresh')}Refresh</button>
    </div>
    <p class="muted" style="margin:0;font-size:11.5px">out/audit.jsonl · newest first · ${records.length} records</p>
    <div id="audit-list" style="display:flex;flex-direction:column;gap:6px"></div>`;
  const list = $('#audit-list', body);
  const draw = () => {
    const q = auditFilter.toLowerCase();
    const rows = records.filter((r) => !q || JSON.stringify(r).toLowerCase().includes(q));
    list.innerHTML = rows.map((r) => `
      <details class="audit-rec">
        <summary>
          <span class="ts">${esc(time(r.ts))}</span>
          <span class="badge ${auditTone(r)}">${esc(r.event)}</span>
          <span class="sub">${esc(auditSub(r))}</span>
          ${r.channel ? `<span class="chip">${esc(r.channel)}</span>` : ''}
        </summary>
        <pre class="code">${jsonHtml(r)}</pre>
      </details>`).join('') || '<p class="muted">No matching records.</p>';
  };
  draw();
  $('#audit-filter', body).addEventListener('input', (e) => { auditFilter = e.target.value; draw(); });
  $('#audit-refresh', body).addEventListener('click', () => renderAudit(body));
}

async function renderKernel(body) {
  const ev = await getEvidence();
  const probes = ev.kernel_probes || [];
  const held = probes.filter(probeHeld).length;
  const denies = (ev.kernel_events || []).filter((e) => e.verdict === 'DENIED');
  body.innerHTML = `
    <div class="callout">${icon('info')}<div><strong>Recorded end-to-end sandbox run</strong> — <span class="mono">./run_in_openshell.sh</span>
      on NVIDIA OpenShell 0.1.1 (VM driver, Apple Hypervisor microVM). These are the real OCSF kernel/proxy events from that run,
      not a live trace of this browser session.</div></div>
    <div class="summary-row">
      <div class="stat is-good"><b>${held}/${probes.length}</b><span>probes held</span></div>
      <div class="stat is-bad"><b>${denies.length}</b><span>OCSF DENIED events</span></div>
      <div class="stat"><b>${(ev.kernel_events || []).length}</b><span>OCSF events total</span></div>
    </div>
    <h4 class="section-title">Attack probes · final run</h4>
    <table class="table"><thead><tr><th>ID</th><th>Probe</th><th>Expect</th><th>Observed</th><th></th></tr></thead><tbody>
      ${probes.map((p) => `<tr>
        <td>${esc(p.id)}</td><td class="wrap">${esc(p.desc)}</td><td>${esc(p.expect)}</td>
        <td class="wrap">${esc(p.observed)}</td>
        <td><span class="badge ${probeHeld(p) ? 'badge-pass' : 'badge-block'}">${probeHeld(p) ? 'HELD' : 'FAIL'}</span></td></tr>`).join('')}
    </tbody></table>
    <h4 class="section-title">OCSF network events</h4>
    <table class="table"><thead><tr><th>Run</th><th>Event</th><th>Verdict</th><th>Subject → target</th><th>Engine / reason</th></tr></thead><tbody>
      ${(ev.kernel_events || []).map((e) => `<tr>
        <td>${esc(e.run)}</td><td>${esc(e.kind)}</td>
        <td><span class="badge ${e.verdict === 'DENIED' ? 'badge-block' : 'badge-pass'}">${esc(e.verdict)}</span></td>
        <td class="wrap">${esc(e.detail)}</td><td class="wrap">${esc(e.meta || '')}</td></tr>`).join('')}
    </tbody></table>
    <details class="json"><summary>${icon('chevron')} Raw evidence file · docs/evidence/openshell_kernel_deny.txt</summary>
      <pre class="code" style="max-height:420px">${esc(ev.kernel_deny)}</pre></details>`;
}

async function renderPolicy(body) {
  const ev = await getEvidence();
  const live = ev.policy_audit_live || {};
  body.innerHTML = `
    <div class="callout">${icon('shield-check')}<div>Kernel policy <span class="mono">policy/openshell-policy.yaml</span> audited <strong>now</strong>
      with the official NVIDIA catalog skill <span class="mono">${esc(ev.skill?.name)}</span> (Step 6 “Validate and Warn”)
      plus a cross-layer check against the app-layer egress allowlist.</div></div>
    <div class="summary-row">
      <div class="stat ${live.pass ? 'is-good' : 'is-bad'}"><b>${live.pass ? 'PASS' : 'FAIL'}</b><span>verdict</span></div>
      <div class="stat ${live.blocking ? 'is-bad' : ''}"><b>${esc(live.blocking)}</b><span>blocking findings</span></div>
      <div class="stat ${ev.skill?.present ? 'is-good' : 'is-bad'}"><b>${ev.skill?.present ? 'Loaded' : 'Missing'}</b><span>official skill</span></div>
    </div>
    <pre class="code" style="max-height:none">${esc(live.text)}</pre>
    <details class="json"><summary>${icon('chevron')} Recorded before/after audit + Nemotron review</summary>
      <pre class="code" style="max-height:420px">${esc(ev.policy_audit_recorded)}</pre></details>`;
}

async function renderRbac(body) {
  const ev = await getEvidence();
  body.innerHTML = `
    <div class="callout">${icon('lock')}<div>The retriever is built <strong>per role</strong> with an immutable, pre-filtered chunk set.
      Documents outside the role's clearance do not exist in that retriever instance — the model cannot retrieve what it cannot see.</div></div>
    <pre class="code" style="max-height:none">${esc(ev.rbac_retrieval)}</pre>`;
}

async function renderTickets(body) {
  const tickets = await (await fetch('/api/tickets')).json();
  body.innerHTML = tickets.length ? tickets.map((t) => `
    <div class="ticket">
      <div class="ticket-id">${esc(t.id)}<span class="badge badge-warn">${esc((t.severity || '-').toUpperCase())}</span></div>
      <div class="ticket-title">${esc(t.title)}</div>
      <div class="ticket-summary">${esc(t.summary)}</div>
      ${(t.actions || []).length ? `<ul>${t.actions.map((a) => `<li>${esc(a)}</li>`).join('')}</ul>` : ''}
    </div>`).join('') : '<p class="muted">No tickets in out/tickets/.</p>';
}

const RENDERERS = { audit: renderAudit, kernel: renderKernel, policy: renderPolicy, rbac: renderRbac, tickets: renderTickets };

let renderSeq = 0;

async function show(tab) {
  activeTab = tab;
  const token = ++renderSeq;  // a slower earlier tab must never overwrite the tab the user clicked last
  document.querySelectorAll('#drawer-tabs .tab').forEach((b) => b.classList.toggle('is-on', b.dataset.tab === tab));
  const body = $('#drawer-body');
  body.innerHTML = '<p class="muted">Loading…</p>';
  const next = document.createElement('div');
  next.style.cssText = 'display:flex;flex-direction:column;gap:12px';
  try {
    await RENDERERS[tab](next);
  } catch (err) {
    next.innerHTML = `<p class="muted">Failed to load: ${esc(err)}</p>`;
  }
  if (token !== renderSeq) return;
  body.replaceChildren(next);
  hydrateIcons(body);
}

export function openDrawer(tab = activeTab) {
  $('#drawer').classList.add('is-open');
  $('#drawer').setAttribute('aria-hidden', 'false');
  $('#drawer-backdrop').classList.add('is-open');
  show(tab);
}

export function closeDrawer() {
  $('#drawer').classList.remove('is-open');
  $('#drawer').setAttribute('aria-hidden', 'true');
  $('#drawer-backdrop').classList.remove('is-open');
}

export function refreshDrawerIfOpen() {
  if ($('#drawer').classList.contains('is-open') && (activeTab === 'audit' || activeTab === 'tickets')) show(activeTab);
}

export function initDrawer() {
  $('#open-drawer').addEventListener('click', () => openDrawer());
  $('#close-drawer').addEventListener('click', closeDrawer);
  $('#drawer-backdrop').addEventListener('click', closeDrawer);
  $('#drawer-tabs').addEventListener('click', (e) => {
    const b = e.target.closest('.tab');
    if (b) show(b.dataset.tab);
  });
}
