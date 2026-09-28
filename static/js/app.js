// GuardOps Console — renders typed engine events ({type, layer, status, stage, step, payload, timestamp}).
// No decisions are made here: every verdict comes from the server-side engine (guardops/engine.py).
import { $, el, esc, icon, jsonHtml, time, hydrateIcons, sanitizeMarkdown } from './ui.js';
import { initDrawer, openDrawer, getEvidence, probeHeld, refreshDrawerIfOpen } from './drawer.js';

const ROLES = ['analyst', 'viewer', 'eng', 'hr', 'admin'];
const STAGES = ['goal', 'screening', 'grounding', 'reasoning', 'enforcement', 'action'];
const SCENARIO_TONE = { 1: 'accent', 2: 'danger', 3: 'info' };

const state = {
  role: 'analyst',
  backend: 'nvidia',     // nvidia | onprem | mock — server re-validates
  backends: [],
  running: false,
  ws: null,
  sessionId: null,
  scenarios: [],
  steps: new Map(),        // step number → step card element
  calls: new Map(),        // `${step}:${tool}` → call element (latest)
  counts: null,
  layerSticky: { L1: 'normal', L2: 'normal' },
  blocked: [],
  tickets: [],
};

function freshCounts() {
  return { screened: 0, flagged: 0, quarantined: 0, decisions: 0, denied: 0, approvals: 0 };
}

/* ───────────── HUD ───────────── */
const LAYER_TEXT = { normal: 'Normal', inspecting: 'Inspecting', blocked: 'Blocked', warn: 'Flagged', verified: 'Verified' };

function setLayer(layer, s) {
  const card = $(`#layer-${layer}`);
  if (!card) return;
  card.dataset.state = s;
  $('.state-text', card).textContent = LAYER_TEXT[s] || s;
}

function inspect(layer) { setLayer(layer, 'inspecting'); }

function settle(layer, outcome) {
  // blocked > warn > normal: once a layer blocks something in this run it stays red until the next run
  const rank = { normal: 0, warn: 1, blocked: 2 };
  if (outcome && rank[outcome] > rank[state.layerSticky[layer]]) state.layerSticky[layer] = outcome;
  setLayer(layer, state.layerSticky[layer]);
}

function renderCounts() {
  const c = state.counts;
  const set = (id, v, bad) => { const n = $(id); n.textContent = v; n.classList.toggle('is-bad', !!bad && v > 0); };
  set('#m-screened', c.screened);
  set('#m-flagged', c.flagged, true);
  set('#m-quarantined', c.quarantined, true);
  set('#m-decisions', c.decisions);
  set('#m-denied', c.denied, true);
  set('#m-approvals', c.approvals);
}

async function loadLayer3() {
  try {
    const ev = await getEvidence();
    const probes = ev.kernel_probes || [];
    $('#m-ocsf').textContent = (ev.kernel_events || []).filter((e) => e.verdict === 'DENIED').length;
    $('#m-ocsf').classList.add('is-bad');
    $('#m-probes').textContent = `${probes.filter(probeHeld).length}/${probes.length}`;
    $('#m-policy').textContent = ev.policy_audit_live?.pass ? 'PASS' : 'FAIL';
    $('#m-policy').classList.add(ev.policy_audit_live?.pass ? 'is-good' : 'is-bad');
  } catch { /* evidence is optional for running the console */ }
}

/* ───────────── Pipeline ───────────── */
function stageEl(stage) { return document.querySelector(`#pipeline li[data-stage="${stage}"]`); }

function setStage(stage, s, sub) {
  const node = stageEl(stage);
  if (!node) return;
  if (s === 'active') {
    document.querySelectorAll('#pipeline li[data-state="active"]').forEach((li) => {
      if (li !== node) li.dataset.state = li.dataset.sticky || 'done';
    });
    node.dataset.state = 'active';
  } else {
    const rank = { done: 0, warn: 1, blocked: 2 };
    const sticky = node.dataset.sticky;
    const keep = sticky && rank[sticky] > (rank[s] ?? 0) ? sticky : s;
    node.dataset.sticky = keep;
    node.dataset.state = keep;
  }
  if (sub !== undefined) $(`#ps-${stage}`).textContent = sub;
}

function resetPipeline() {
  const subs = { goal: 'Awaiting input', screening: 'Content Safety', grounding: 'Pre-filtered retriever',
    reasoning: 'ReAct', enforcement: 'PolicyGate', action: 'Tools · tickets' };
  STAGES.forEach((s) => {
    const node = stageEl(s);
    delete node.dataset.state;
    delete node.dataset.sticky;
    $(`#ps-${s}`).textContent = subs[s];
  });
}

/* ───────────── Timeline ───────────── */
function timeline() { return $('#timeline'); }

function append(node) {
  node.classList.add('enter');
  timeline().appendChild(node);
  hydrateIcons(node);
  node.scrollIntoView({ block: 'nearest', behavior: 'smooth' });
  return node;
}

function argText(v) { return typeof v === 'string' ? v : JSON.stringify(v); }

function argsHtml(args) {
  const entries = Object.entries(args || {});
  if (!entries.length) return '<span class="muted mono" style="font-size:11px">no arguments</span>';
  return `<div class="args">${entries.map(([k, v]) => `<span class="arg"><span class="arg-k">${esc(k)}</span>`
    + `<span class="arg-v" title="${esc(argText(v))}">${esc(argText(v))}</span></span>`).join('')}</div>`;
}

function stepCard(step) {
  let card = state.steps.get(step);
  if (card) return card;
  state.steps.forEach((c) => {
    c.dataset.live = 'false';
    c.classList.remove('is-open');
    $('.step-head', c).setAttribute('aria-expanded', 'false');
  });
  card = el(`
    <article class="step is-open" data-live="true" data-step="${step}">
      <button class="step-head" type="button" aria-expanded="true">
        <span class="step-idx">STEP ${String(step).padStart(2, '0')}</span>
        <span class="step-tools"><span class="thinking"><span class="spinner"></span>${esc(state.modelLabel || 'model')} reasoning…</span></span>
        <span class="step-summary"></span>
        <span class="step-verdict"></span>
        <span class="chev">${icon('chevron')}</span>
      </button>
      <div class="step-body"><div class="inner"><div class="content">
        <div class="reason-slot"></div><div class="calls"></div>
      </div></div></div>
    </article>`);
  $('.step-head', card).addEventListener('click', () => {
    const open = card.classList.toggle('is-open');
    $('.step-head', card).setAttribute('aria-expanded', String(open));
  });
  state.steps.set(step, card);
  return append(card);
}

function setStepVerdict(card, allowed) {
  if (card.dataset.verdict === 'blocked') return;
  card.dataset.verdict = allowed ? 'pass' : 'blocked';
  $('.step-verdict', card).innerHTML = allowed
    ? '<span class="badge badge-pass">ALLOW</span>' : '<span class="badge badge-block">DENIED</span>';
}

function defenseCard(tone, iconName, title, layerLabel, bodyHtml) {
  return append(el(`
    <section class="defense defense-${tone}" role="status">
      <div class="defense-head">
        <span class="defense-icon">${icon(iconName)}</span>
        <span class="defense-title">${esc(title)}</span>
        <span class="chip defense-layer">${esc(layerLabel)}</span>
      </div>
      <div class="defense-body">${bodyHtml}</div>
    </section>`));
}

function highlightHost(url) {
  try {
    const u = new URL(url);
    const i = url.indexOf(u.host);
    return `${esc(url.slice(0, i))}<span class="url-host">${esc(u.host)}</span>${esc(url.slice(i + u.host.length))}`;
  } catch { return esc(url); }
}

/* ───────────── Rail ───────────── */
function ticketHtml(t) {
  return `<div class="ticket">
    <div class="ticket-id">${esc(t.id)}<span class="badge badge-warn">${esc((t.severity || '-').toUpperCase())}</span></div>
    <div class="ticket-title">${esc(t.title)}</div>
    <div class="ticket-summary">${esc(t.summary)}</div>
    ${(t.actions || []).length ? `<ul>${t.actions.map((a) => `<li>${esc(a)}</li>`).join('')}</ul>` : ''}
  </div>`;
}

function renderRail() {
  $('#blocked-count').textContent = state.blocked.length;
  $('#blocked-count').classList.toggle('is-hot', state.blocked.length > 0);
  $('#blocked-list').innerHTML = state.blocked.length ? state.blocked.map((b) => `
    <li class="blocked-item">
      <span class="badge badge-block">${esc(b.layer)}</span><span class="what">${esc(b.what)}</span>
      <span class="why">${esc(b.reason)}</span>
    </li>`).join('') : '<li class="muted">Nothing blocked yet</li>';
  $('#ticket-rail').innerHTML = state.tickets.length ? state.tickets.map(ticketHtml).join('')
    : '<p class="muted">No ticket issued in this session</p>';
}

function block(layer, what, reason) {
  state.blocked.push({ layer, what, reason });
  renderRail();
}

/* ───────────── Event reducer ───────────── */
const handlers = {
  session_started(e) {
    const p = e.payload;
    state.sessionId = e.session_id;
    $('#session-id').textContent = e.session_id || '—';
    $('#s-role').textContent = p.role;
    const be = state.backends.find((b) => b.id === e.backend);
    $('#s-mode').textContent = be ? be.label : (p.mock ? 'Mock replay' : e.backend);
    $('#s-clearance').textContent = `[${p.doc_clearance.join(', ')}]`;
    $('#s-reachable').textContent = `${p.reachable_docs.length} docs`;
    $('#s-excluded').innerHTML = p.excluded_docs.length
      ? `<span class="excluded-label">Excluded at retriever construction</span>${p.excluded_docs.map((d) => `<span class="chip chip-danger">${esc(d)}</span>`).join('')}`
      : '';
    setStage('goal', 'done', p.role);
    $('#ps-grounding').textContent = `${p.reachable_docs.length} docs · ${p.excluded_docs.length} excluded`;
    timeline().innerHTML = '';
    append(el(`
      <div class="session-card">
        <span class="s-icon" data-icon="user"></span>
        <div class="goal">
          <div class="goal-text" title="${esc(p.goal)}">${esc(p.goal)}</div>
          <div class="goal-meta">
            <span class="chip">${esc(p.role)}</span>
            <span class="chip ${p.mock ? '' : 'chip-accent'}">${p.mock ? 'mock replay' : esc(short(p.model))}</span>
            ${e.backend === 'onprem' ? '<span class="chip chip-info">on-prem · DGX Spark · data stays in tailnet</span>' : ''}
            <span class="chip">clearance [${esc(p.doc_clearance.join(', '))}]</span>
            ${p.excluded_docs.length ? `<span class="chip chip-danger">${icon('eye-off')} ${esc(p.excluded_docs.join(', '))} excluded</span>` : ''}
            ${p.auto_approve ? '<span class="chip chip-warn">auto-approve</span>' : '<span class="chip">human approval on</span>'}
          </div>
        </div>
        <span class="ts">${esc(time(e.timestamp))}</span>
      </div>`));
    inspect('L1');
    setStage('screening', 'active');
  },

  input_screened(e) {
    const p = e.payload;
    state.counts.screened += 1;
    renderCounts();
    setStage('screening', p.ok ? 'done' : 'blocked', p.ok ? `SAFE · ${p.model}` : 'UNSAFE');
    settle('L1', p.ok ? 'normal' : 'blocked');
    if (p.ok) return;
    block('L1', 'user goal', p.detail);
    defenseCard('danger', 'shield-x', 'Goal blocked at input screening', 'L1 · Content Safety', `
      <div>Nemotron Content Safety classified the request as unsafe before any reasoning or tool use.</div>
      <div class="proof">${icon('shield-x')} verdict: ${esc(p.detail)} · model: ${esc(p.model)}</div>`);
  },

  step_started(e) {
    setStage('reasoning', 'active', `step ${e.step} · ${state.modelLabel || ''}`);
    stepCard(e.step);
    $('#run-status').textContent = `Running · step ${e.step}`;
  },

  reasoning(e) {
    const card = stepCard(e.step);
    $('.reason-slot', card).innerHTML = `<div class="block-label">Model reasoning</div><div class="reasoning">${esc(e.payload.content)}</div>`;
  },

  tool_proposed(e) {
    const p = e.payload;
    const card = stepCard(e.step);
    const tools = $('.step-tools', card);
    if ($('.thinking', tools)) tools.innerHTML = '';
    tools.insertAdjacentHTML('beforeend', `<span class="tool-name">${esc(p.tool)}</span>`);
    const call = el(`
      <div class="call">
        <div class="call-row"><span class="block-label" style="margin:0">Proposed</span><span class="tool-name">${esc(p.tool)}</span></div>
        <div class="call-row">${argsHtml(p.args)}</div>
        <div class="call-row gate-row"><span class="spinner"></span><span class="gate-reason">PolicyGate evaluating…</span></div>
      </div>`);
    $('.calls', card).appendChild(call);
    state.calls.set(`${e.step}:${p.tool}`, call);
    setStage('enforcement', 'active', p.tool);
    inspect('L2');
  },

  approval_required(e) {
    const call = state.calls.get(`${e.step}:${e.payload.tool}`);
    if (call) {
      $('.gate-row', call).innerHTML = '<span class="badge badge-warn">AWAITING APPROVAL</span>'
        + '<span class="gate-reason">gate pre-check passed · human decision required</span>';
    }
    $('#run-status').textContent = 'Waiting for human approval';
    $('#run-status').dataset.state = 'waiting';
    $('#conn').dataset.state = 'waiting';
    $('.conn-label').textContent = 'Approval';
    openModal(e.payload);
  },

  approval_resolved(e) {
    if (e.payload.approved) state.counts.approvals += 1;
    renderCounts();
    $('#run-status').dataset.state = 'running';
    $('#conn').dataset.state = 'running';
    $('.conn-label').textContent = 'Streaming';
  },

  policy_decision(e) {
    const p = e.payload;
    state.counts.decisions += 1;
    if (!p.allowed) state.counts.denied += 1;
    renderCounts();
    const card = stepCard(e.step);
    setStepVerdict(card, p.allowed);
    const call = state.calls.get(`${e.step}:${p.tool}`);
    if (call) {
      $('.gate-row', call).innerHTML = `
        <span class="badge ${p.allowed ? 'badge-pass' : 'badge-block'}">${p.allowed ? 'ALLOW' : 'DENIED'}</span>
        <span class="gate-reason grow">${esc(p.reason)}</span>
        ${p.human_approved === true ? '<span class="chip chip-accent">human approved</span>' : ''}
        ${p.human_approved === false ? '<span class="chip chip-danger">human rejected</span>' : ''}
        <span class="rule">${esc(p.rule)}</span>`;
    }
    if (!p.allowed) $('.step-summary', card).textContent = p.reason;
    setStage('enforcement', p.allowed ? 'done' : 'blocked', p.allowed ? `${p.tool} allowed` : `${p.tool} denied`);
    settle('L2', p.allowed ? 'normal' : 'blocked');
    if (p.allowed && p.tool === 'search_runbook') inspect('L1');
    if (p.allowed || p.tool === 'fetch_url') return;  // egress denials get their own card
    block('L2', p.tool, p.reason);
    defenseCard('danger', 'ban', `Policy gate denied ${p.tool}`, 'L2 · PolicyGate', `
      <div class="row"><span class="badge badge-block">DENIED</span><span class="gate-reason">${esc(p.reason)}</span></div>
      <div class="proof">${icon('file')} rule › ${esc(p.rule)}</div>
      <div class="muted" style="font-size:11.5px">Deterministic harness decision — the model's request never reached the tool.</div>`);
  },

  egress_decision(e) {
    const p = e.payload;
    if (p.allowed) return;
    block('L2', 'egress', p.url);
    defenseCard('danger', 'globe', 'Outbound request blocked', 'L2 · L7 egress', `
      <div class="url">${highlightHost(p.url)}</div>
      <div class="row"><span class="badge badge-block">DENY</span><span class="gate-reason">${esc(p.reason)}</span></div>
      <div class="proof">${icon('file')} rule › ${esc(p.rule)} · the OpenShell kernel policy has no route to this host either</div>`);
  },

  injection_flagged(e) {
    const p = e.payload;
    state.counts.flagged += 1;
    renderCounts();
    settle('L1', 'warn');
    setStage('grounding', 'warn', `${p.doc_id} flagged`);
    defenseCard('warn', 'alert', `Injection pattern detected in ${p.doc_id}`, 'L1 · Injection scan', `
      <div>Retrieved document <strong>${esc(p.title || p.doc_id)}</strong> (trust: ${esc(p.trust)}) contains hidden instructions.
        Content Safety: <span class="mono">${esc(p.content_safety)}</span> — not a dual flag, so the text is delivered
        <em>with an attack warning</em>. If the model is fooled anyway, the PolicyGate still refuses the action.</div>
      <div class="row">${(p.patterns || []).map((x) => `<span class="chip chip-warn">${esc(x)}</span>`).join('')}</div>`);
  },

  doc_quarantined(e) {
    const p = e.payload;
    state.counts.flagged += 1;
    state.counts.quarantined += 1;
    renderCounts();
    settle('L1', 'blocked');
    setStage('grounding', 'blocked', `${p.doc_id} quarantined`);
    block('L1', p.doc_id, 'quarantined (regex + content safety)');
    defenseCard('danger', 'shield-x', `Quarantine — ${p.doc_id} isolated from the model`, 'L1 · Dual-flag quarantine', `
      <div>Both the deterministic injection scan <strong>and</strong> Nemotron Content Safety flagged this untrusted document.
        Only a security envelope was passed to the LLM.</div>
      <div class="row">${(p.reasons || []).map((r) => `<span class="chip ${r.startsWith('content_safety') ? 'chip-danger' : 'chip-warn'}">${esc(r)}</span>`).join('')}</div>
      <div class="proof">${icon('eye-off')} ${esc(p.withheld_chars ?? '?')} chars withheld · payload never reached the model</div>`);
  },

  grounding_verdict(e) {
    const p = e.payload;
    state.counts.screened += new Set(p.doc_ids || []).size;
    renderCounts();
    settle('L1');
    setStage('grounding', p.grounded ? 'done' : 'warn',
      p.grounded ? `grounded · ${[...new Set(p.doc_ids)].join(', ')}` : 'no grounded evidence');
    if (!p.grounded) {
      defenseCard('warn', 'search', 'Grounding gate withheld results', 'L2 · Grounding gate',
        `<div>No document cleared the BM25 × coverage threshold (<span class="mono">${esc(p.reason)}</span>). The model is told to report “no evidence” instead of guessing.</div>`);
    }
  },

  tool_result(e) {
    const p = e.payload;
    const call = state.calls.get(`${e.step}:${p.tool}`);
    if (call) {
      call.insertAdjacentHTML('beforeend', `
        <div class="call-row">
          <span class="block-label" style="margin:0">Result</span>
          <span class="gate-reason grow">${esc(p.summary || (p.allowed ? 'completed' : 'not executed'))}</span>
          <details class="json"><summary>${icon('chevron')} JSON</summary><pre class="code">${jsonHtml(p.result)}</pre></details>
        </div>`);
    }
    const card = stepCard(e.step);
    if (p.allowed && !$('.step-summary', card).textContent) $('.step-summary', card).textContent = p.summary || '';
    if (p.allowed) setStage('action', 'active', p.tool);
  },

  ticket_created(e) {
    const p = e.payload;
    state.tickets.push(p);
    renderRail();
    setStage('action', 'done', p.id);
    defenseCard('pass', 'ticket', `Incident ticket ${p.id} created`, 'Action · out/tickets', `
      <div><strong>${esc(p.title)}</strong> — ${esc(p.summary)}</div>
      <div class="row"><span class="chip chip-warn">severity ${esc(p.severity)}</span>${(p.actions || []).map((a) => `<span class="chip">${esc(a)}</span>`).join('')}</div>`);
  },

  final_report(e) {
    const p = e.payload;
    const last = state.steps.get(e.step);
    if (last && $('.thinking', last)) {  // 도구 호출 없이 끝난 마지막 단계 = 최종 보고서 작성
      $('.step-tools', last).innerHTML = '<span class="tool-name">final report</span>';
      $('.step-summary', last).textContent = 'no further tool calls · report composed';
      $('.step-verdict', last).innerHTML = '<span class="badge badge-pass">DONE</span>';
      last.classList.remove('is-open');
    }
    STAGES.forEach((s) => {
      const node = stageEl(s);
      if (node.dataset.state === 'active') setStage(s, 'done');
    });
    state.steps.forEach((c) => { c.dataset.live = 'false'; });
    renderReport(p);
  },

  run_limit(e) {
    defenseCard('warn', 'alert', 'Step limit reached', 'Engine', `<div>${esc(e.payload.message)}</div>`);
  },
};

function renderReport(p) {
  const counts = p.counts || {};
  const tickets = p.tickets || [];
  const slot = $('#report-slot');
  slot.innerHTML = '';
  const node = el(`
    <article class="report enter">
      <header class="report-head">
        <span class="r-icon" data-icon="clipboard"></span>
        <div><h3>Security incident report</h3><p>Session ${esc(state.sessionId || '')} · ${esc(p.outcome)}</p></div>
        <span class="risk">Risk rating <span class="risk-pill risk-${esc(p.risk)}">${esc(p.risk)}</span></span>
      </header>
      <div class="report-grid">
        <div class="report-md">${sanitizeMarkdown(p.report)}</div>
        <aside class="report-side">
          <div class="stat-grid">
            <div class="stat ${counts.denied ? 'is-bad' : ''}"><b>${esc(counts.denied ?? 0)}</b><span>Policy denials</span></div>
            <div class="stat ${counts.quarantined ? 'is-bad' : ''}"><b>${esc(counts.quarantined ?? 0)}</b><span>Quarantined docs</span></div>
            <div class="stat ${counts.egress_denied ? 'is-bad' : ''}"><b>${esc(counts.egress_denied ?? 0)}</b><span>Egress blocked</span></div>
            <div class="stat ${tickets.length ? 'is-good' : ''}"><b>${tickets.length}</b><span>Tickets issued</span></div>
          </div>
          ${tickets.map(ticketHtml).join('')}
          ${(p.blocked_attempts || []).length ? `<div><div class="block-label">Blocked attempts</div>
            <ul class="blocked-list" style="margin:6px 0 0">${p.blocked_attempts.map((b) => `
              <li class="blocked-item"><span class="badge badge-block">${esc(b.layer)}</span><span class="what">${esc(b.what)}</span>
              <span class="why">${esc(b.rule || b.reason)}</span></li>`).join('')}</ul></div>` : ''}
        </aside>
      </div>
    </article>`);
  slot.appendChild(node);
  hydrateIcons(node);
  node.scrollIntoView({ block: 'start', behavior: 'smooth' });
}

/* ───────────── HITL modal ───────────── */
function openModal(p) {
  const a = p.args || {};
  $('#hitl-body').innerHTML = `
    <dl class="field"><dt>Action</dt><dd class="mono">${esc(p.tool)}</dd></dl>
    <dl class="field"><dt>Impact</dt><dd class="impact">
      <span class="chip chip-danger">${esc(p.impact)}</span>
      ${a.severity ? `<span class="chip chip-warn">severity ${esc(a.severity)}</span>` : ''}
    </dd></dl>
    ${a.title ? `<dl class="field"><dt>Title</dt><dd>${esc(a.title)}</dd></dl>` : ''}
    ${a.summary ? `<dl class="field"><dt>Summary</dt><dd>${esc(a.summary)}</dd></dl>` : ''}
    ${(a.actions || []).length ? `<dl class="field"><dt>Actions</dt><dd><ul>${a.actions.map((x) => `<li>${esc(x)}</li>`).join('')}</ul></dd></dl>` : ''}
    <div class="gate-note">${icon('shield-check')} PolicyGate pre-check passed for role ${esc(state.role)} · ${esc(p.rule)}</div>`;
  $('#hitl').classList.add('is-open');
  $('#hitl').setAttribute('aria-hidden', 'false');
  setTimeout(() => $('#hitl-approve').focus(), 60);
}

function respond(approved) {
  if (!$('#hitl').classList.contains('is-open')) return;
  $('#hitl').classList.remove('is-open');
  $('#hitl').setAttribute('aria-hidden', 'true');
  if (state.ws && state.ws.readyState === WebSocket.OPEN) {
    state.ws.send(JSON.stringify({ type: 'hitl_response', approved }));
  }
}

function initModal() {
  $('#hitl-approve').addEventListener('click', () => respond(true));
  $('#hitl-reject').addEventListener('click', () => respond(false));
  document.addEventListener('keydown', (ev) => {
    if (!$('#hitl').classList.contains('is-open')) return;
    if (ev.key === 'Escape') { ev.preventDefault(); respond(false); }
    if (ev.key === 'Enter' && document.activeElement !== $('#hitl-reject')) { ev.preventDefault(); respond(true); }
    if (ev.key === 'Tab') {  // focus trap between the two actions
      ev.preventDefault();
      (document.activeElement === $('#hitl-approve') ? $('#hitl-reject') : $('#hitl-approve')).focus();
    }
  });
}

/* ───────────── Run control ───────────── */
function setRunning(on) {
  state.running = on;
  document.querySelectorAll('.scenario, #role-seg .seg-btn, .seg-mode .seg-btn').forEach((b) => { b.disabled = on; });
  $('#run-btn').disabled = on;
  $('#auto-approve').disabled = on;
}

function resetRun() {
  state.steps.clear();
  state.calls.clear();
  state.counts = freshCounts();
  state.layerSticky = { L1: 'normal', L2: 'normal' };
  state.blocked = [];
  state.tickets = [];
  renderCounts();
  renderRail();
  setLayer('L1', 'normal');
  setLayer('L2', 'normal');
  resetPipeline();
  $('#report-slot').innerHTML = '';
}

function startRun(goal, role, autoApprove) {
  if (state.running || !goal) return;
  resetRun();
  setRunning(true);
  setStage('goal', 'active', 'submitting');
  $('#run-status').textContent = 'Connecting…';
  $('#run-status').dataset.state = 'running';
  $('#conn').dataset.state = 'running';
  $('.conn-label').textContent = 'Streaming';

  const proto = location.protocol === 'https:' ? 'wss:' : 'ws:';
  const ws = new WebSocket(`${proto}//${location.host}/ws/agent`);
  state.ws = ws;
  let finished = false;
  ws.onopen = () => ws.send(JSON.stringify({ goal, role, auto_approve: autoApprove, backend: state.backend }));
  ws.onmessage = (msg) => {
    const e = JSON.parse(msg.data);
    if (e.type === 'done') { finished = true; finish('done'); return; }
    if (e.type === 'error') {
      defenseCard('danger', 'alert', 'Run stopped', 'System', `<div>${esc(e.message)}</div>`);
      finished = true;
      finish('error');
      return;
    }
    const handler = handlers[e.type];
    if (handler) handler(e);
  };
  ws.onclose = () => { if (!finished && state.running) finish('error'); };
}

function finish(kind) {
  setRunning(false);
  $('#conn').dataset.state = kind === 'done' ? 'done' : 'error';
  $('.conn-label').textContent = kind === 'done' ? 'Completed' : 'Stopped';
  $('#run-status').dataset.state = '';
  $('#run-status').textContent = kind === 'done' ? `Completed · ${state.steps.size} steps` : 'Stopped';
  state.steps.forEach((c) => { c.dataset.live = 'false'; });
  refreshDrawerIfOpen();
}

/* ───────────── Controls ───────────── */
function setRole(role) {
  state.role = role;
  document.querySelectorAll('#role-seg .seg-btn').forEach((b) => {
    const on = b.dataset.role === role;
    b.classList.toggle('is-on', on);
    b.setAttribute('aria-checked', String(on));
  });
  $('#goal-role').textContent = role;
  $('#s-role').textContent = role;
}

function short(name) { return String(name || '').replace(/^(nvidia|Inferact)\//, ''); }

function setBackend(id) {
  const b = state.backends.find((x) => x.id === id);
  if (b && !b.available) return;
  state.backend = id;
  document.querySelectorAll('.seg-mode .seg-btn').forEach((btn) => {
    const on = btn.dataset.backend === id;
    btn.classList.toggle('is-on', on);
    btn.setAttribute('aria-checked', String(on));
  });
  if (!b) return;
  $('#s-mode').textContent = b.label;
  $('#model-name').textContent = short(b.model);
  state.modelLabel = id === 'mock' ? 'Mock' : id === 'onprem' ? 'Qwen' : 'Nemotron';
  $('#model-chip').title = `${b.label} — ${b.location}`;
  $('#l1-engine').textContent = b.guard ? short(b.guard) : (id === 'mock' ? 'mock: guard skipped' : 'guard disabled');
}

function shortTitle(t) {
  return String(t).replace(/^Scenario \d+:\s*/, '').replace(/\s*\(.*\)\s*$/, '');
}

async function loadScenarios() {
  state.scenarios = await (await fetch('/api/scenarios')).json();
  $('#scenarios').innerHTML = state.scenarios.map((s) => `
    <button class="scenario" type="button" data-id="${esc(s.id)}" data-tone="${SCENARIO_TONE[s.number] || 'accent'}">
      <span class="scenario-top"><span class="scenario-num">0${esc(s.number)} · ${esc(s.badge)}</span><span class="chip">${esc(s.role)}</span></span>
      <span class="scenario-title">${esc(shortTitle(s.title))}</span>
      <span class="scenario-proof">${esc(s.description)}</span>
    </button>`).join('');
  $('#scenarios').addEventListener('click', (ev) => {
    const b = ev.target.closest('.scenario');
    if (!b || state.running) return;
    const s = state.scenarios.find((x) => x.id === b.dataset.id);
    setRole(s.role);
    $('#goal-input').value = s.default_goal;
    $('#auto-approve').checked = s.auto_approve;
    startRun(s.default_goal, s.role, s.auto_approve);
  });
}

async function loadStatus() {
  try {
    const s = await (await fetch('/api/status')).json();
    state.backends = s.backends || [];
    state.backends.forEach((b) => {
      const btn = document.querySelector(`.seg-mode [data-backend="${b.id}"]`);
      if (!btn) return;
      btn.dataset.unavailable = String(!b.available);
      btn.title = `${b.label} · ${b.location} — ${b.available ? short(b.model) : `unavailable: ${b.reason}`}`;
    });
    const current = state.backends.find((b) => b.id === state.backend);
    setBackend(current?.available ? state.backend : (state.backends.find((b) => b.available)?.id || 'mock'));
  } catch { /* status is informational */ }
}

function init() {
  hydrateIcons();
  $('#role-seg').innerHTML = ROLES.map((r) => `<button class="seg-btn${r === state.role ? ' is-on' : ''}" data-role="${r}" role="radio" aria-checked="${r === state.role}">${r}</button>`).join('');
  $('#role-seg').addEventListener('click', (ev) => { const b = ev.target.closest('.seg-btn'); if (b && !state.running) setRole(b.dataset.role); });
  document.querySelector('.seg-mode').addEventListener('click', (ev) => { const b = ev.target.closest('.seg-btn'); if (b && !state.running) setBackend(b.dataset.backend); });
  $('#goal-form').addEventListener('submit', (ev) => {
    ev.preventDefault();
    startRun($('#goal-input').value.trim(), state.role, $('#auto-approve').checked);
  });
  $('#l3-link').addEventListener('click', () => openDrawer('kernel'));
  state.counts = freshCounts();
  initModal();
  initDrawer();
  loadScenarios();
  loadStatus();
  loadLayer3();
}

init();
