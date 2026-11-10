/* AEGIS // SENTINEL v2 — extended operator console.
 * Registers 8 new views, a DAG orchestrator, five configuration analyzers,
 * a MITRE ATT&CK coverage studio, case management, an investigation copilot,
 * quantitative risk and the capability manifest into the base UI.
 */
(function (root) {
  'use strict';
  var U = root.AEGIS_UI;
  var DATA = U.DATA, D2 = root.AEGIS_DATA2, E = U.E, A = root.AEGIS_ADVANCED;
  var S = U.S, ui = U.ui, h = U.h, esc = h.esc;
  var $ = U.$, section = h.section, icon = h.icon, sevPill = h.sevPill;

  /* ------------------------------ navigation ----------------------------- */
  U.registerNav('OPERATE', [
    { id: 'orchestrator', label: 'Mission Orchestrator', icon: 'cpu', key: 'Q' },
    { id: 'cases', label: 'Incident Cases', icon: 'file', key: 'W' }
  ]);
  U.registerNav('ANALYZE', [
    { id: 'ingest', label: 'Universal Ingest', icon: 'wave', key: 'E' },
    { id: 'lab', label: 'Analysis Lab', icon: 'lock', key: 'R' },
    { id: 'studio', label: 'Detection Studio', icon: 'target', key: 'T' },
    { id: 'investigate', label: 'Investigation Copilot', icon: 'search', key: 'Y' },
    { id: 'quant', label: 'Risk Quantification', icon: 'chart', key: 'U' }
  ]);
  U.registerNav('GOVERN', [
    { id: 'capabilities', label: 'Capability Manifest', icon: 'shield', key: 'I' }
  ]);
  U.registerMeta({
    orchestrator: { id: 'orchestrator', label: 'Mission Orchestrator', icon: 'cpu', key: 'Q' },
    cases: { id: 'cases', label: 'Incident Cases', icon: 'file', key: 'W' },
    ingest: { id: 'ingest', label: 'Universal Ingest', icon: 'wave', key: 'E' },
    lab: { id: 'lab', label: 'Analysis Lab', icon: 'lock', key: 'R' },
    studio: { id: 'studio', label: 'Detection Studio', icon: 'target', key: 'T' },
    investigate: { id: 'investigate', label: 'Investigation Copilot', icon: 'search', key: 'Y' },
    quant: { id: 'quant', label: 'Risk Quantification', icon: 'chart', key: 'U' },
    capabilities: { id: 'capabilities', label: 'Capability Manifest', icon: 'shield', key: 'I' }
  });

  /* ------------------------------- helpers ------------------------------- */
  function statRow(items) {
    return '<div class="stat-row">' + items.map(function (i) {
      return '<div><b>' + esc(i[0]) + '</b><span>' + esc(i[1]) + '</span></div>';
    }).join('') + '</div>';
  }
  function checksHtml(checks) {
    return '<div class="controls">' + checks.map(function (c) {
      return '<div class="control control-' + esc(c.status) + '"><div class="control-head">' + h.statusPill(c.status) +
        '<b>' + esc(c.title) + '</b><span>' + esc(c.id) + '</span></div><p>' + esc(c.evidence) + '</p>' +
        '<div class="control-fix"><span>FIX</span><code>' + esc(c.fix) + '</code></div></div>';
    }).join('') + '</div>';
  }
  function scoreBox(label, value, sub, tone) {
    return '<div class="lab-score ' + (tone || '') + '"><span>' + esc(label) + '</span><b>' + esc(value) + '</b><small>' + esc(sub) + '</small></div>';
  }
  function trace2(tag, text, kind) {
    ui.orchestratorLines = ui.orchestratorLines || [];
    ui.orchestratorLines.push({ t: h.ts(Date.now()).slice(-8), tag: tag, text: text, kind: kind || 'info' });
    if (ui.orchestratorLines.length > 80) ui.orchestratorLines.shift();
  }
  function terminal2() {
    var lines = ui.orchestratorLines || [];
    return '<div class="terminal"><div class="terminal-head"><span class="term-dots"><i></i><i></i><i></i></span>' +
      '<span>AEGIS ORCHESTRATOR · TASK TRACE</span><span class="term-state">' + (ui.orchestratorRunning ? 'RUNNING' : 'IDLE') + '</span></div>' +
      '<div class="terminal-body">' + (lines.length ? lines.map(function (l) {
        return '<div class="term-line term-' + esc(l.kind) + '"><span>' + esc(l.t) + '</span><b>' + esc(l.tag) + '</b> ' + esc(l.text) + '</div>';
      }).join('') : '<div class="term-line term-muted"><span>' + esc(h.ts(Date.now()).slice(-8)) + '</span><b>READY</b> Awaiting an orchestrated mission. All tasks pass the capability gate.</div>') + '</div></div>';
  }
  function activeTargets() {
    var need = ['posture', 'logs', 'headers', 'intel'];
    return E.activeAssets(S.state).filter(function (a) {
      return need.every(function (c) { return (a.checks || []).indexOf(c) !== -1; });
    });
  }
  function targetOptions() {
    var list = activeTargets();
    if (!list.length) return '<option value="">No asset permits the full mission scope</option>';
    if (!list.some(function (a) { return a.name === ui.orchTarget; })) ui.orchTarget = list[0].name;
    return list.map(function (a) {
      return '<option value="' + esc(a.name) + '" ' + (a.name === ui.orchTarget ? 'selected' : '') + '>' + esc(a.name) + '</option>';
    }).join('');
  }

  /* --------------------------- mission orchestrator ---------------------- */
  function dagHtml() {
    var tiers = {};
    D2.ORCHESTRATOR_PLAN.forEach(function (n) { (tiers[n.tier] = tiers[n.tier] || []).push(n); });
    return '<div class="dag">' + Object.keys(tiers).sort(function (a, b) { return a - b; }).map(function (t) {
      return '<div class="dag-col"><div class="dag-col-head">STAGE ' + t + '</div>' + tiers[t].map(function (n) {
        var st = (ui.orchestratorNodes || {})[n.id] || { status: 'IDLE' };
        var cls = String(st.status).toLowerCase();
        return '<div class="dag-node dag-' + cls + '"><div class="dag-node-top"><span>' + esc(n.cap) + '</span>' +
          '<b class="dag-badge">' + esc(st.status) + '</b></div><strong>' + esc(n.label) + '</strong>' +
          '<p>' + esc(n.desc) + '</p>' + (st.detail ? '<small>' + esc(st.detail) + '</small>' : '') + '</div>';
      }).join('') + '</div>';
    }).join('') + '</div>';
  }
  U.registerView('orchestrator', function () {
    var last = S.state.orchestratorRuns[0];
    var rows = last ? (last.nodes || []).map(function (n) {
      return '<tr><td><code>' + esc(n.id) + '</code></td><td>' + h.statusPill(n.status) + '</td><td>' + esc(n.detail || n.reason || '—') + '</td><td>' + esc(n.count || 0) + '</td></tr>';
    }).join('') : '';
    return '<div class="page-head"><div><div class="eyebrow">OPERATIONS · AUTONOMOUS ORCHESTRATION</div><h1>Mission Orchestrator</h1>' +
      '<p>A policy-gated task graph. Every node resolves its capability in the signed manifest and re-verifies the target scope before executing — locally, with no network calls.</p></div>' +
      '<div class="head-actions"><span class="chip chip-lock">' + icon('shield') + ' ' + D2.CAPABILITIES.filter(function (c) { return c.status === 'enabled'; }).length + ' CAPABILITIES SIGNED</span></div></div>' +
      section('Task graph', D2.ORCHESTRATOR_PLAN.length + ' tasks · ' + Math.max.apply(null, D2.ORCHESTRATOR_PLAN.map(function (n) { return n.tier; })) + ' stages · dependency-ordered',
        '<span class="tag">ALL LOCAL</span>', dagHtml()) +
      '<div class="grid-2"><div class="col-main">' +
        section('Dispatch', 'Select an authorized target, then run the full mission', '',
          '<div class="control-row"><label class="field flex"><span>Authorized target</span><select id="orch-target">' + targetOptions() + '</select></label>' +
          '<button class="btn btn-primary" data-action="orch-run" ' + (ui.orchestratorRunning ? 'disabled' : '') + '>' + icon('play') +
          (ui.orchestratorRunning ? ' Running…' : ' Run orchestrated mission') + '</button>' +
          '<button class="btn btn-ghost" data-action="nav" data-view="capabilities">View manifest</button></div>' + terminal2()) +
        section('Last run', last ? h.ts(last.at) + ' · ' + last.status : 'No runs yet', '',
          last ? statRow([[last.done + '/' + last.total, 'TASKS DONE'], [last.refused, 'REFUSED'], [last.durationMs + 'ms', 'DURATION'], [last.target, 'TARGET']]) +
            '<div class="table-wrap"><table class="table"><thead><tr><th>TASK</th><th>STATUS</th><th>DETAIL</th><th>COUNT</th></tr></thead><tbody>' + rows + '</tbody></table></div>' :
            h.empty('Dispatch a mission to see the per-task decision trace.')) +
      '</div><div class="col-side">' +
        section('Execution contract', 'What the orchestrator guarantees', '',
          '<ul class="policy-list compact">' +
          '<li>' + icon('check') + '<span><b>Capability resolution per task</b><small>Unknown or blocked capabilities are refused before execution.</small></span></li>' +
          '<li>' + icon('check') + '<span><b>Scope re-verification per task</b><small>Signature, expiry and permitted checks are re-checked every time.</small></span></li>' +
          '<li>' + icon('check') + '<span><b>Dependency enforcement</b><small>Nodes with incomplete dependencies are skipped, never guessed.</small></span></li>' +
          '<li>' + icon('check') + '<span><b>Ledger-sealed run</b><small>Every DONE / REFUSED outcome is appended to the hash chain.</small></span></li>' +
          '<li>' + icon('check') + '<span><b>Deterministic, offline</b><small>No host is contacted by any node in this graph.</small></span></li></ul>') +
        section('Task catalog', 'Capabilities used by this mission', '',
          D2.ORCHESTRATOR_PLAN.map(function (n) {
            return '<div class="task-row"><span class="stage-badge">S' + n.tier + '</span><div><b>' + esc(n.label) + '</b><small>' + esc(n.cap) + '</small></div></div>';
          }).join('')) +
      '</div></div>';
  });

  async function runOrchestrator() {
    if (ui.orchestratorRunning) return;
    var sel = $('orch-target');
    var target = sel ? sel.value : ui.orchTarget;
    if (!target) { U.toast('Register an asset that permits the full mission scope first.', 'bad'); return; }
    ui.orchTarget = target;
    ui.orchestratorRunning = true;
    ui.orchestratorNodes = {};
    ui.orchestratorLines = [];
    if (ui.view !== 'orchestrator') { ui.view = 'orchestrator'; U.render(); }
    trace2('BOOT', 'Orchestrator v2.0 initializing. Target: ' + target, 'info');
    trace2('POLICY', 'Capability manifest loaded · strict scope enforcement ON.', 'ok');
    U.renderView();
    await U.sleep(180);

    var ctx = { target: target }, done = 0, refused = 0, skipped = 0;
    var start = Date.now(), nodes = [];
    for (var i = 0; i < D2.ORCHESTRATOR_PLAN.length; i++) {
      var n = D2.ORCHESTRATOR_PLAN[i];
      var depsOk = n.deps.every(function (d) { return ui.orchestratorNodes[d] && ui.orchestratorNodes[d].status === 'DONE'; });
      if (!depsOk) {
        ui.orchestratorNodes[n.id] = { status: 'SKIPPED', detail: 'Dependency not satisfied.', count: 0 };
        skipped++;
        trace2('SKIP', n.id + ' skipped — upstream dependency incomplete.', 'bad');
        nodes.push({ id: n.id, status: 'SKIPPED', detail: 'Dependency not satisfied.', count: 0 });
      } else {
        var res = A.orchestratorStep(n, S.state, ctx);
        ui.orchestratorNodes[n.id] = { status: res.status, detail: res.detail || res.reason, count: res.count };
        if (res.status === 'DONE') { done++; trace2('DONE', n.label + ' → ' + (res.detail || 'complete'), 'ok'); }
        else { refused++; trace2('REFUSE', n.label + ' → ' + res.code + ': ' + res.reason, 'bad'); }
        S.audit('ORCH_' + n.id.toUpperCase(), target, res.status, res.detail || res.reason);
        nodes.push({ id: n.id, status: res.status, detail: res.detail || res.reason, count: res.count });
      }
      U.renderView();
      await U.sleep(190);
    }
    var status = refused ? 'PARTIAL' : skipped ? 'COMPLETE_WITH_SKIPS' : 'COMPLETE';
    S.recordOrchestratorRun({ id: E.uid('run'), at: Date.now(), target: target, status: status,
      done: done, refused: refused, skipped: skipped, total: D2.ORCHESTRATOR_PLAN.length,
      durationMs: Date.now() - start, nodes: nodes });
    trace2('SEAL', 'Run sealed in ledger. ' + done + ' done / ' + refused + ' refused / ' + skipped + ' skipped. No network egress.', 'ok');
    ui.orchestratorRunning = false;
    U.render();
    U.toast('Orchestrated mission ' + status.toLowerCase() + ' — ' + done + '/' + D2.ORCHESTRATOR_PLAN.length + ' tasks.', refused ? 'bad' : 'ok');
  }

  /* ---------------------------- universal ingest ------------------------- */
  var INGEST_SAMPLES = { jsonl: 'jsonl', nginx: 'nginx', syslog: 'logs', csv: 'csv' };
  U.registerView('ingest', function () {
    var saved = S.state.ingestResults;
    var r = saved && saved.result;
    var results = r ? statRow([[r.format.toUpperCase(), 'FORMAT'], [r.events.length, 'EVENTS'], [r.stats.sources, 'SOURCES'],
      [r.stats.tagged, 'TAGGED'], [r.stats.tactics, 'TACTICS']]) +
      '<div class="grid-2">' +
      '<div><h3 class="subhead">Normalized event stream</h3><div class="table-wrap table-tall"><table class="table"><thead><tr><th>#</th><th>SOURCE</th><th>ACTOR</th><th>ACTION</th><th>STATUS</th><th>RULES</th></tr></thead><tbody>' +
      r.events.slice(0, 40).map(function (e) {
        return '<tr><td><code>' + e.n + '</code></td><td><code>' + esc(e.src || '—') + '</code></td><td>' + esc(e.actor || '—') + '</td>' +
          '<td class="detail-cell">' + esc(e.action || '—') + '</td><td>' + esc(e.status || '—') + '</td>' +
          '<td>' + (e.tags.length ? e.tags.map(function (t) { return '<span class="mini-chip">' + esc(t.mitre) + '</span>'; }).join(' ') : '<span class="muted">—</span>') + '</td></tr>';
      }).join('') + '</tbody></table></div></div>' +
      '<div><h3 class="subhead">Tactic distribution</h3>' +
      Object.keys(r.stats.byTactic).map(function (k) {
        return h.bar(k.toUpperCase(), r.stats.byTactic[k], Math.max.apply(null, Object.values(r.stats.byTactic).concat([1])), '#5ad2ff');
      }).join('') + '</div></div>' : h.empty('Paste telemetry in any supported format and run normalization.');

    var chains = r ? A.attackChains(r) : { chains: [] };
    var chainHtml = chains.chains.length ? chains.chains.map(function (c) {
      return '<div class="chain-card"><div class="chain-head">' + sevPill(c.severity) + '<code>' + esc(c.src) + '</code>' +
        '<span class="chain-conf">' + c.confidence + '% confidence</span></div>' +
        '<div class="chain-steps">' + c.timeline.map(function (t) {
          return '<div class="chain-step"><span class="chain-dot"></span><div><b>' + esc(A.tacticName(t.tactic)) + '</b>' +
            '<small>' + esc(t.technique) + ' · ' + esc(t.action.slice(0, 70)) + '</small></div></div>';
        }).join('') + '</div>' +
        '<div class="chain-foot">' + c.events + ' events · ' + c.tagged + ' tagged · ' + c.tactics.length + ' tactics · ' + c.techniques.length + ' techniques</div></div>';
    }).join('') : h.empty('No multi-stage chains could be reconstructed from this telemetry.');

    var series = r ? A.eventRateSeries(r) : [];
    var anomaly = r ? A.anomalyDetect(series) : null;
    var anomalyHtml = anomaly ? '<div class="chart-wrap">' + h.areaChart(anomaly.values) + '</div>' +
      statRow([[anomaly.mean, 'MEAN'], [anomaly.stddev, 'STD DEV'], [anomaly.lower, 'IQR LOW'], [anomaly.upper, 'IQR HIGH'], [anomaly.outliers.length, 'OUTLIERS']]) +
      (anomaly.outliers.length ? '<div class="outlier-list">' + anomaly.outliers.map(function (o) {
        return '<div>' + icon('alert') + '<span>Bucket <b>' + o.index + '</b>: ' + o.value + ' events (z=' + o.z + ')</span></div>';
      }).join('') + '</div>' : '<p class="muted small">No statistically significant outliers at z &gt; 2 or outside 1.5×IQR.</p>') : h.empty('Run ingest to compute a statistical baseline.');

    return '<div class="page-head"><div><div class="eyebrow">ANALYSIS · NORMALIZATION</div><h1>Universal Ingest</h1>' +
      '<p>Auto-detects JSONL, nginx/apache combined, syslog/auth and CSV, normalizes them into one schema, tags every event with detection rules and reconstructs multi-stage attack chains.</p></div>' +
      '<div class="head-actions"><span class="chip">' + icon('wave') + ' 7 FORMATS · LOCAL</span></div></div>' +
      '<div class="grid-2"><div class="col-main">' +
        section('Telemetry source', 'Paste raw events — format is detected automatically',
          '<div class="sample-btns">' + Object.keys(INGEST_SAMPLES).map(function (k) {
            return '<button class="btn btn-xs" data-action="ingest-sample" data-kind="' + k + '">' + esc(k) + '</button>';
          }).join('') + '</div>',
          '<div class="control-row"><label class="field flex"><span>Associate with in-scope asset</span><select id="ingest-target">' + h.assetOptions('logs') + '</select></label></div>' +
          '<textarea class="code-area" data-draft="ingest" spellcheck="false">' + esc(S.state.drafts.ingest || '') + '</textarea>' +
          '<div class="form-actions"><button class="btn btn-primary" data-action="ingest-analyze">' + icon('wave') + ' Normalize & reconstruct</button></div>') +
        section('Normalization results', r ? h.ts(saved.at) : 'Awaiting input', '', results) +
        section('Reconstructed attack chains', chains.chains.length + ' multi-stage chain(s)', '<span class="tag">MITRE TACTICS</span>', chainHtml) +
      '</div><div class="col-side">' +
        section('Statistical anomaly baseline', 'Z-score · IQR · EWMA on event rate', '', anomalyHtml) +
        section('Supported schemas', 'Normalized event model', '',
          '<div class="schema-grid">' + ['ts', 'src', 'actor', 'action', 'target', 'status', 'ua', 'tags'].map(function (f) {
            return '<div><code>' + esc(f) + '</code><span>' + esc({ ts: 'timestamp', src: 'source address', actor: 'principal', action: 'event label', target: 'resource', status: 'HTTP/status code', ua: 'user agent', tags: 'rule + MITRE hits' }[f]) + '</span></div>';
          }).join('') + '</div>') +
      '</div></div>';
  });

  function ingestAnalyze() {
    var sel = $('ingest-target');
    var target = sel ? sel.value : (E.activeAssets(S.state)[0] || {}).name;
    if (!target) { U.toast('Register an in-scope asset first.', 'bad'); return; }
    var gate = A.evaluateCapability('telemetry.normalize', S.state, target);
    if (!gate.allowed) {
      S.recordCapabilityRequest('telemetry.normalize', 'REFUSED', gate.reason);
      U.modal('Capability refused', '<div class="refusal">' + icon('shield') + '<div><h3>' + esc(gate.code) + '</h3><p>' + esc(gate.reason) + '</p></div></div>',
        '<button class="btn btn-primary" data-action="close-modal">Close</button>');
      U.toast('Ingest refused: ' + gate.code, 'bad'); return;
    }
    var r = A.normalizeLogs(S.state.drafts.ingest || '');
    S.saveIngest(r, target);
    U.toast(r.format + ' detected · ' + r.events.length + ' events normalized.', 'ok');
    U.render();
  }

  /* -------------------------------- analysis lab ------------------------- */
  var LAB_TABS = [
    { id: 'email', label: 'Phishing / .eml', sample: 'email', scope: 'intel', cap: 'config.email' },
    { id: 'iam', label: 'IAM policy', sample: 'iam', scope: 'posture', cap: 'config.iam' },
    { id: 'k8s', label: 'Kubernetes', sample: 'k8s', scope: 'posture', cap: 'config.k8s' },
    { id: 'secrets', label: 'Secrets & entropy', sample: 'secrets', scope: 'posture', cap: 'config.secrets' },
    { id: 'deps', label: 'Dependencies / SBOM', sample: 'deps', scope: 'posture', cap: 'config.sbom' }
  ];
  function labResultHtml(tab, saved) {
    if (!saved) return h.empty('Run ' + tab.label + ' analysis on the supplied sample.');
    var r = saved.result;
    var extra = '';
    if (tab.id === 'email') {
      extra = '<div class="verdict verdict-' + (r.score < 45 ? 'bad' : r.score < 75 ? 'warn' : 'ok') + '">' + icon(r.score < 45 ? 'alert' : 'shield') +
        '<div><span>VERDICT</span><b>' + esc(r.verdict) + '</b><small>' + r.received + ' relay hops · ' + r.urls.length + ' indicators extracted</small></div></div>' +
        (r.urls.length ? '<h3 class="subhead">Defanged indicators</h3><div class="ioc-list">' + r.urls.slice(0, 10).map(function (i) {
          return '<div><span class="ioc-type">' + esc(i.type) + '</span><code>' + esc(i.defanged) + '</code></div>';
        }).join('') + '</div>' : '') + '<h3 class="subhead">Control evaluation</h3>' + checksHtml(r.checks);
    } else if (tab.id === 'secrets') {
      extra = (r.findings.length ? '<div class="table-wrap"><table class="table"><thead><tr><th>SEV</th><th>TYPE</th><th>MASKED VALUE</th><th>LINE</th><th>ENTROPY</th><th>ACTION</th></tr></thead><tbody>' +
        r.findings.map(function (f) {
          return '<tr><td>' + sevPill(f.severity) + '</td><td>' + esc(f.type) + '</td><td><code>' + esc(f.masked) + '</code></td><td>' + f.line + '</td><td>' + f.entropy + '</td><td class="detail-cell">' + esc(f.fix) + '</td></tr>';
        }).join('') + '</tbody></table></div>' : '<p class="muted small">No credential material detected.</p>');
    } else if (tab.id === 'deps') {
      extra = statRow([[r.packages.length, 'PACKAGES'], [r.findings.length, 'FINDINGS'], [r.format, 'FORMAT']]) +
        (r.findings.length ? '<div class="table-wrap"><table class="table"><thead><tr><th>SEV</th><th>PACKAGE</th><th>VERSION</th><th>ADVISORY</th><th>REMEDIATION</th></tr></thead><tbody>' +
          r.findings.map(function (f) {
            return '<tr><td>' + sevPill(f.severity) + '</td><td><b>' + esc(f.title) + '</b></td><td><code>' + esc(f.version) + '</code></td><td>' + esc(f.cve) + '</td><td class="detail-cell">' + esc(f.fix) + '</td></tr>';
          }).join('') + '</tbody></table></div>' : '<p class="muted small">No baseline matches.</p>') +
        '<p class="muted small">' + esc(r.note) + '</p>';
    } else {
      extra = checksHtml(r.checks);
    }
    return scoreBox('ANALYSIS SCORE', r.score + '/100', 'Analyzed ' + h.ts(saved.at), r.score < 60 ? 'bad' : r.score < 80 ? 'warn' : 'ok') + extra;
  }
  U.registerView('lab', function () {
    var tab = LAB_TABS.filter(function (t) { return t.id === ui.labTab; })[0] || LAB_TABS[0];
    var draftKey = 'lab_' + tab.id;
    var saved = S.state.labResults[tab.id];
    return '<div class="page-head"><div><div class="eyebrow">ANALYSIS · CONFIGURATION LAB</div><h1>Analysis Lab</h1>' +
      '<p>Five independent offline analyzers for email, cloud IAM, Kubernetes manifests, credential material and software dependencies. All operate on text you paste.</p></div>' +
      '<div class="head-actions"><span class="chip">' + icon('lock') + ' 5 ENGINES · NO UPLOAD</span></div></div>' +
      '<div class="lab-tabs">' + LAB_TABS.map(function (t) {
        return '<button class="lab-tab ' + (t.id === tab.id ? 'active' : '') + '" data-action="lab-tab" data-tab="' + t.id + '">' + esc(t.label) +
          (S.state.labResults[t.id] ? '<i class="tab-dot"></i>' : '') + '</button>';
      }).join('') + '</div>' +
      '<div class="grid-2"><div class="col-main">' +
        section(tab.label + ' input', 'Paste a sample or your own authorized configuration',
          '<button class="btn btn-xs" data-action="lab-sample" data-tab="' + tab.id + '">Load sample</button>',
          '<textarea class="code-area" data-draft="' + draftKey + '" spellcheck="false">' + esc(S.state.drafts[draftKey] || '') + '</textarea>' +
          '<div class="form-actions"><button class="btn btn-primary" data-action="lab-analyze" data-tab="' + tab.id + '">' + icon('target') + ' Run ' + esc(tab.label) + ' analysis</button>' +
          '<span class="form-hint">Capability: <code>' + esc(tab.cap) + '</code> · required scope: <code>' + esc(tab.scope) + '</code></span></div>') +
        section('Analysis output', saved ? tab.label + ' · ' + h.ts(saved.at) : 'Awaiting input', '', labResultHtml(tab, saved)) +
      '</div><div class="col-side">' +
        section('Analyzer catalog', 'What each engine evaluates', '',
          LAB_TABS.map(function (t) {
            var desc = {
              email: 'SPF/DKIM/DMARC alignment, Reply-To mismatch, relay chain, coercive language, defanged URLs.',
              iam: 'Wildcard actions/resources, public principals, PassRole, missing MFA conditions, NotAction.',
              k8s: 'Privileged pods, host namespaces, root user, capabilities, hostPath, image tags, limits, seccomp.',
              secrets: 'Provider token patterns, private keys, JWTs, credentialed URLs plus Shannon-entropy detection with masking.',
              deps: 'package.json, lockfiles, CycloneDX SBOM and requirements.txt against an offline advisory baseline.'
            }[t.id];
            return '<div class="task-row"><span class="stage-badge">' + esc(t.id.slice(0, 3).toUpperCase()) + '</span><div><b>' + esc(t.label) + '</b><small>' + esc(desc) + '</small></div></div>';
          }).join('')) +
        section('Handling', 'Privacy by design', '',
          '<ul class="policy-list compact"><li>' + icon('check') + '<span><b>Nothing is uploaded</b><small>Parsing happens in this browser tab.</small></span></li>' +
          '<li>' + icon('check') + '<span><b>Values are masked</b><small>Secret findings show only a redacted fingerprint.</small></span></li>' +
          '<li>' + icon('check') + '<span><b>Scope-gated</b><small>Each analyzer requires an in-scope asset permitting its check type.</small></span></li></ul>') +
      '</div></div>';
  });
  function labAnalyze(tabId) {
    var tab = LAB_TABS.filter(function (t) { return t.id === tabId; })[0];
    if (!tab) return;
    var target = (activeTargets()[0] || E.activeAssets(S.state)[0] || {}).name || '';
    var gate = A.evaluateCapability(tab.cap, S.state, target || null);
    if (!gate.allowed) {
      S.recordCapabilityRequest(tab.cap, 'REFUSED', gate.reason);
      U.toast('Analysis refused: ' + gate.code, 'bad');
      U.modal('Capability refused', '<div class="refusal">' + icon('shield') + '<div><h3>' + esc(gate.code) + '</h3><p>' + esc(gate.reason) + '</p></div></div>',
        '<button class="btn btn-primary" data-action="close-modal">Close</button>');
      return;
    }
    var text = S.state.drafts['lab_' + tab.id] || '';
    if (!text.trim()) { U.toast('Paste content first.', 'bad'); return; }
    var r = ({ email: A.analyzeEmail, iam: A.analyzeIamPolicy, k8s: A.analyzeK8s,
      secrets: A.secretScan, deps: A.analyzeDependencies })[tab.id](text);
    S.saveLab(tab.id, r, target || 'operator-supplied text');
    U.toast(tab.label + ' analysis complete · score ' + r.score + '/100.', r.score < 60 ? 'bad' : 'ok');
    U.render();
  }

  /* ---------------------------- detection studio ------------------------- */
  U.registerView('studio', function () {
    var cov = A.mitreCoverage(S.state);
    var matrix = cov.tactics.map(function (t) {
      return '<div class="matrix-row"><div class="matrix-label"><b>' + esc(t.short) + '</b><small>' + t.covered + '/' + t.total + '</small></div>' +
        '<div class="matrix-cells">' + t.techniques.map(function (x) {
          return '<span class="matrix-cell ' + (x.covered ? 'cov' : 'gap') + (x.observed ? ' obs' : '') + '" title="' + esc(x.id + ' · ' + x.name + (x.observed ? ' · observed' : '')) + '">' + esc(x.id.replace('T', '')) + '</span>';
        }).join('') + '</div></div>';
    }).join('');
    var rules = S.state.customRules.map(function (r) {
      return '<tr><td><b>' + esc(r.name) + '</b></td><td><code>' + esc(r.pattern) + '</code></td><td>' + sevPill(r.severity) + '</td><td>' + esc(r.mitre) + '</td><td>' + r.threshold + '</td>' +
        '<td><button class="btn btn-xs btn-danger" data-action="rule-delete" data-id="' + esc(r.id) + '">Delete</button></td></tr>';
    }).join('');
    var testResult = ui.ruleTest ? '<div class="rule-test ' + (ui.ruleTest.ok && ui.ruleTest.matched ? 'ok' : 'warn') + '">' +
      (ui.ruleTest.ok ? '<b>' + (ui.ruleTest.matched ? 'MATCHED' : 'NO MATCH') + '</b><span>' + ui.ruleTest.count + ' line(s) matched against current telemetry · threshold ' + esc(ui.ruleTest.threshold || 1) + '</span>' +
        (ui.ruleTest.samples.length ? '<pre class="samples">' + esc(ui.ruleTest.samples.join('\n')) + '</pre>' : '') :
        '<b>INVALID REGEX</b><span>' + esc(ui.ruleTest.error) + '</span>') + '</div>' : '';
    return '<div class="page-head"><div><div class="eyebrow">ANALYSIS · DETECTION ENGINEERING</div><h1>Detection Studio</h1>' +
      '<p>ATT&CK Navigator-style coverage heatmap across ' + cov.total + ' techniques, gap analysis, and an operator-authored regex rule engine with live testing.</p></div>' +
      '<div class="head-actions"><button class="btn btn-ghost" data-action="studio-export">' + icon('download') + ' Export coverage</button></div></div>' +
      '<div class="grid-2"><div class="col-main">' +
        section('ATT&CK coverage matrix', cov.covered + ' of ' + cov.total + ' techniques covered (' + cov.percent + '%)',
          '<span class="tag">LOCAL CATALOG</span>',
          '<div class="matrix-legend"><span><i class="cell-cov"></i>Detection rule</span><span><i class="cell-obs"></i>Observed in session</span><span><i class="cell-gap"></i>Coverage gap</span></div>' + matrix) +
        section('Custom detection rules', S.state.customRules.length + ' operator-authored rule(s)', '',
          '<form data-form="custom-rule" id="rule-form" class="form-grid">' +
          '<label class="field"><span>Rule name</span><input name="name" placeholder="Suspicious admin endpoint" required></label>' +
          '<label class="field"><span>MITRE technique</span><input name="mitre" value="T1059" placeholder="T1059"></label>' +
          '<label class="field"><span>Severity</span><select name="severity"><option value="critical">Critical</option><option value="high">High</option><option value="medium" selected>Medium</option><option value="low">Low</option></select></label>' +
          '<label class="field"><span>Match threshold <em>lines</em></span><input name="threshold" type="number" min="1" max="50" value="1"></label>' +
          '<label class="field field-wide"><span>Regular expression</span><input name="pattern" placeholder="(admin|root).*(denied|blocked)" required></label>' +
          '<label class="field field-wide"><span>Remediation guidance</span><input name="remediation" placeholder="Review the matching events and verify scope."></label>' +
          '<div class="form-actions field-wide"><button class="btn btn-primary" type="submit">' + icon('check') + ' Publish rule</button>' +
          '<button class="btn btn-ghost" type="button" data-action="rule-test">' + icon('wave') + ' Test against telemetry</button></div></form>' + testResult +
          (rules ? '<div class="table-wrap" style="margin-top:14px"><table class="table"><thead><tr><th>NAME</th><th>PATTERN</th><th>SEV</th><th>MITRE</th><th>THRESHOLD</th><th></th></tr></thead><tbody>' + rules + '</tbody></table></div>' : '<p class="muted small" style="margin-top:12px">No custom rules yet. Published rules join the orchestrator detection sweep.</p>')) +
      '</div><div class="col-side">' +
        section('Coverage posture', 'Rule-based technique coverage', '',
          '<div class="donut-row">' + h.donut([{ key: 'implemented', value: cov.covered }, { key: 'gap', value: cov.total - cov.covered }], cov.percent + '%', 'coverage') +
          '<div class="donut-legend"><div><span class="dot dot-implemented"></span>covered<b>' + cov.covered + '</b></div>' +
          '<div><span class="dot dot-gap"></span>gaps<b>' + (cov.total - cov.covered) + '</b></div></div></div>') +
        section('Priority coverage gaps', 'Techniques with no local detection rule', '',
          cov.gaps.slice(0, 12).map(function (g) {
            return '<div class="gap-row"><code>' + esc(g.id) + '</code><span>' + esc(g.name) + '</span><small>' + esc(A.tacticName(g.tactic)) + '</small></div>';
          }).join('') || h.empty('Full coverage.')) +
        section('Built-in catalog', DATA.LOG_RULES.length + ' mapped rules', '',
          DATA.LOG_RULES.slice(0, 8).map(function (r) {
            return '<div class="gap-row"><code>' + esc(r.mitre) + '</code><span>' + esc(r.name) + '</span>' + sevPill(r.severity) + '</div>';
          }).join('') + '<button class="btn btn-xs" style="margin-top:10px" data-action="nav" data-view="logs">Open signal analyzer</button>') +
      '</div></div>';
  });

  /* ------------------------------ incident cases ------------------------- */
  U.registerView('cases', function () {
    var cases = S.state.cases;
    var alertOpts = S.state.alerts.slice(0, 12).map(function (a) {
      return '<label class="check"><input type="checkbox" name="alerts" value="' + esc(a.id) + '"><span>' + esc(a.title.slice(0, 58)) + '</span></label>';
    }).join('');
    var list = cases.length ? cases.map(function (c) {
      var done = c.notes.length;
      return '<div class="case-card"><div class="case-top">' + sevPill(c.severity) + h.statusPill(c.status) +
        '<span class="muted small">' + esc(h.rel(c.createdAt)) + '</span></div><h3>' + esc(c.title) + '</h3>' +
        '<p>' + esc(c.summary || 'No summary provided.') + '</p>' +
        '<div class="case-meta"><span>' + icon('shield') + esc(c.asset) + '</span><span>' + icon('file') + done + ' notes</span>' +
        '<span>' + icon('target') + c.linkedAlerts.length + ' linked alerts</span><span>' + icon('clock') + esc(c.owner) + '</span></div>' +
        '<div class="case-actions"><button class="btn btn-xs" data-action="case-detail" data-id="' + esc(c.id) + '">Open case</button>' +
        '<button class="btn btn-xs btn-ghost" data-action="case-export" data-id="' + esc(c.id) + '">' + icon('download') + ' Export</button></div></div>';
    }).join('') : h.empty('No incident cases yet. Open one to link alerts and evidence.');
    return '<div class="page-head"><div><div class="eyebrow">OPERATIONS · CASE MANAGEMENT</div><h1>Incident Cases</h1>' +
      '<p>Link alerts and evidence into an auditable investigation record. Notes, status changes and exports are written to the ledger.</p></div>' +
      '<div class="head-actions"><span class="chip">' + icon('file') + ' ' + cases.length + ' CASES</span></div></div>' +
      '<div class="grid-2"><div class="col-side">' +
        section('Open a case', 'Record the investigation scope', '',
          '<form data-form="case-create" class="form-grid">' +
          '<label class="field field-wide"><span>Case title</span><input name="title" placeholder="Suspected account takeover — auth01" required></label>' +
          '<label class="field"><span>Severity</span><select name="severity"><option value="critical">Critical</option><option value="high" selected>High</option><option value="medium">Medium</option><option value="low">Low</option></select></label>' +
          '<label class="field"><span>Primary asset</span><select name="asset">' + E.activeAssets(S.state).map(function (a) { return '<option>' + esc(a.name) + '</option>'; }).join('') + '</select></label>' +
          '<label class="field field-wide"><span>Summary</span><textarea name="summary" class="code-area code-area-sm" placeholder="What happened, what is known, what is not known…"></textarea></label>' +
          '<div class="field field-wide"><span>Link alerts <em>optional</em></span><div class="alert-picker">' + (alertOpts || '<span class="muted small">No alerts available.</span>') + '</div></div>' +
          '<div class="form-actions field-wide"><button class="btn btn-primary" type="submit">' + icon('check') + ' Open case</button></div></form>') +
        section('Case handling', 'Accountability', '',
          '<ul class="policy-list compact"><li>' + icon('check') + '<span><b>Append-only notes</b><small>Each note is timestamped and ledger-sealed.</small></span></li>' +
          '<li>' + icon('check') + '<span><b>Status transitions logged</b><small>Open → investigating → contained → closed.</small></span></li>' +
          '<li>' + icon('check') + '<span><b>Workflow only</b><small>No external containment action is ever executed.</small></span></li></ul>') +
      '</div><div class="col-main">' + section('Case register', cases.length + ' case(s)', '', list) + '</div></div>';
  });
  function caseDetail(id) {
    var c = S.state.cases.filter(function (x) { return x.id === id; })[0];
    if (!c) return;
    var linked = S.state.alerts.filter(function (a) { return c.linkedAlerts.indexOf(a.id) !== -1; });
    var body = '<div class="detail">' + sevPill(c.severity) + h.statusPill(c.status) + '<h3>' + esc(c.title) + '</h3>' +
      '<p>' + esc(c.summary || 'No summary.') + '</p>' +
      '<div class="detail-grid"><div><span>ASSET</span><code>' + esc(c.asset) + '</code></div><div><span>OWNER</span><b>' + esc(c.owner) + '</b></div>' +
      '<div><span>OPENED</span><b>' + esc(h.ts(c.createdAt)) + '</b></div></div>' +
      '<h4>Linked alerts (' + linked.length + ')</h4>' + (linked.length ? linked.map(function (a) {
        return '<div class="gap-row">' + sevPill(a.severity) + '<span>' + esc(a.title) + '</span></div>';
      }).join('') : '<p class="muted small">None linked.</p>') +
      '<h4>Investigation notes</h4>' + (c.notes.length ? c.notes.map(function (n) {
        return '<div class="note"><b>' + esc(n.actor) + '</b><small>' + esc(h.ts(n.ts)) + '</small><p>' + esc(n.text) + '</p></div>';
      }).join('') : '<p class="muted small">No notes yet.</p>') +
      '<form data-form="case-note" class="note-form"><input type="hidden" name="caseId" value="' + esc(c.id) + '">' +
      '<textarea name="note" class="code-area code-area-sm" placeholder="Add an evidence note…" required></textarea>' +
      '<div class="form-actions"><button class="btn btn-primary" type="submit">Add note</button></div></form>';
    var footer = '<button class="btn btn-xs" data-action="case-status" data-id="' + esc(c.id) + '" data-status="investigating">Investigating</button>' +
      '<button class="btn btn-xs" data-action="case-status" data-id="' + esc(c.id) + '" data-status="contained">Contained</button>' +
      '<button class="btn btn-xs" data-action="case-status" data-id="' + esc(c.id) + '" data-status="closed">Close</button>' +
      '<button class="btn btn-primary" data-action="close-modal">Done</button>';
    U.modal('Incident case · ' + c.id.slice(-6), body, footer);
  }

  /* -------------------------- investigation copilot ---------------------- */
  U.registerView('investigate', function () {
    var r = ui.investigateResult;
    var table = r ? '<div class="query-summary">' + icon('search') + '<span>' + esc(r.summary) + '</span></div>' +
      '<div class="table-wrap table-tall"><table class="table"><thead><tr>' + r.columns.map(function (c) { return '<th>' + esc(c.toUpperCase()) + '</th>'; }).join('') + '</tr></thead><tbody>' +
      r.rows.map(function (row) {
        return '<tr>' + row.map(function (cell, i) { return '<td>' + (i === 0 && /critical|high|medium|low|info/.test(String(cell)) ? sevPill(String(cell)) : esc(cell)) + '</td>'; }).join('') + '</tr>';
      }).join('') + '</tbody></table></div>' : h.empty('Ask a question about findings, alerts, assets, indicators or the ledger.');
    var history = S.state.investigationHistory.length ? S.state.investigationHistory.slice(0, 8).map(function (x) {
      return '<button class="gap-row hist-row" data-action="investigate-example" data-query="' + esc(x.query) + '"><code>' + esc(x.intent) + '</code><span>' + esc(x.query) + '</span><small>' + x.count + ' rows</small></button>';
    }).join('') : '<p class="muted small">No queries yet.</p>';
    return '<div class="page-head"><div><div class="eyebrow">ANALYSIS · INVESTIGATION</div><h1>Investigation Copilot</h1>' +
      '<p>A local natural-language query interpreter over session evidence. It parses severity, asset, MITRE technique and intent — no model call, no data leaves the browser.</p></div></div>' +
      '<div class="grid-2"><div class="col-main">' +
        section('Ask the evidence', 'Plain-language queries over the local state', '',
          '<div class="query-bar"><input id="investigate-input" data-draft="investigate" value="' + esc(S.state.drafts.investigate || '') + '" placeholder="e.g. show critical findings for api.acme-lab.io">' +
          '<button class="btn btn-primary" data-action="investigate-run">' + icon('search') + ' Investigate</button></div>' +
          '<div class="example-chips">' + D2.QUERY_EXAMPLES.map(function (q) {
            return '<button class="example-chip" data-action="investigate-example" data-query="' + esc(q) + '">' + esc(q) + '</button>';
          }).join('') + '</div>' + table) +
      '</div><div class="col-side">' +
        section('Interpretation', 'What the parser understands', '',
          '<ul class="policy-list compact"><li>' + icon('check') + '<span><b>Intent</b><small>findings · alerts · assets · watchlist · ledger</small></span></li>' +
          '<li>' + icon('check') + '<span><b>Filters</b><small>severity words, asset names, MITRE IDs, open / untriaged</small></span></li>' +
          '<li>' + icon('check') + '<span><b>Deterministic</b><small>Same state + same query = same answer, always.</small></span></li>' +
          '<li>' + icon('check') + '<span><b>Audited</b><small>Every query is recorded in the ledger.</small></span></li></ul>') +
        section('Recent queries', S.state.investigationHistory.length + ' recorded', '', history) +
      '</div></div>';
  });
  function runInvestigation(q) {
    var query = String(q || '').trim();
    if (!query) { U.toast('Enter a query first.', 'bad'); return; }
    var result = A.investigate(query, S.state);
    result.query = query;
    ui.investigateResult = result;
    S.setDraft('investigate', query);
    S.recordInvestigation({ query: query, result: result });
    U.render();
    U.toast(result.count + ' record(s) matched · intent ' + result.type + '.', 'ok');
  }

  /* --------------------------- risk quantification ----------------------- */
  U.registerView('quant', function () {
    var r = S.state.quantResult;
    var maxBin = r ? Math.max.apply(null, r.bins.concat([1])) : 1;
    return '<div class="page-head"><div><div class="eyebrow">ANALYSIS · QUANTITATIVE RISK</div><h1>Risk Quantification</h1>' +
      '<p>Deterministic Monte Carlo simulation over the open finding register. Abstract risk units, transparent assumptions, fully offline.</p></div></div>' +
      '<div class="grid-2"><div class="col-main">' +
        section('Simulation control', 'Choose the number of iterations', '',
          '<div class="control-row"><label class="field flex"><span>Iterations</span><select id="quant-iterations">' +
          [1000, 2000, 5000, 10000, 20000].map(function (n) {
            return '<option value="' + n + '" ' + ((ui.quantIterations || 2000) === n ? 'selected' : '') + '>' + n.toLocaleString() + '</option>';
          }).join('') + '</select></label>' +
          '<button class="btn btn-primary" data-action="quant-run">' + icon('chart') + ' Run simulation</button></div>' +
          (r ? statRow([[r.p50, 'MEDIAN (P50)'], [r.p90, 'P90'], [r.p95, 'P95'], [r.mean, 'MEAN'], [r.iterations.toLocaleString(), 'ITERATIONS']]) +
            '<h3 class="subhead">Loss distribution</h3><div class="hist">' + r.bins.map(function (b, i) {
              return '<div class="hist-col"><div class="hist-bar" style="height:' + Math.round(b / maxBin * 100) + '%"></div><small>' + i + '</small></div>';
            }).join('') + '</div>' + '<div class="hist-axis"><span>low</span><span>risk units →</span><span>high</span></div>' : h.empty('Run a simulation to see the distribution.'))) +
      '</div><div class="col-side">' +
        section('Model inputs', 'Fully transparent assumptions', '',
          '<div class="table-wrap"><table class="table"><thead><tr><th>SEVERITY</th><th>EVENT PROB.</th><th>IMPACT</th></tr></thead><tbody>' +
          [['critical', '34%', '10.0'], ['high', '22%', '6.0'], ['medium', '12%', '3.0'], ['low', '5.5%', '1.4'], ['info', '2%', '0.6']].map(function (x) {
            return '<tr><td>' + sevPill(x[0]) + '</td><td>' + x[1] + '</td><td>' + x[2] + '</td></tr>';
          }).join('') + '</tbody></table></div>' +
          '<p class="muted small" style="margin-top:10px">Asset criticality multiplies impact (1.0× – 1.8×). Each open finding is sampled independently per iteration.</p>') +
        section('Interpretation', 'Read this correctly', '',
          '<ul class="policy-list compact"><li>' + icon('check') + '<span><b>Comparative, not absolute</b><small>Use it to compare postures, not to budget.</small></span></li>' +
          '<li>' + icon('check') + '<span><b>Deterministic</b><small>Seeded from the ledger state — reproducible.</small></span></li>' +
          '<li>' + icon('check') + '<span><b>No external data</b><small>No threat feed, no pricing service, no API.</small></span></li></ul>' +
          (r ? '<p class="muted small">' + esc(r.note) + '</p>' : '')) +
      '</div></div>';
  });

  /* --------------------------- capability manifest ----------------------- */
  U.registerView('capabilities', function () {
    var enabled = D2.CAPABILITIES.filter(function (c) { return c.status === 'enabled'; });
    var blocked = D2.CAPABILITIES.filter(function (c) { return c.status !== 'enabled'; });
    var reqs = S.state.capabilityRequests;
    return '<div class="page-head"><div><div class="eyebrow">GOVERNANCE · CAPABILITY MANIFEST</div><h1>Capability Manifest</h1>' +
      '<p>The agent can do <b>anything in the signed manifest</b> — and nothing outside it. This is the machine-readable answer to "can it do anything?".</p></div>' +
      '<div class="head-actions"><span class="chip chip-lock">' + icon('shield') + ' ' + enabled.length + ' ENABLED / ' + blocked.length + ' BLOCKED</span></div></div>' +
      '<div class="callout callout-info"><div class="callout-icon">' + icon('shield') + '</div><div><b>Unrestricted capability is not a feature — it is a hazard.</b>' +
      '<p>Every task resolves against this manifest before execution. Blocked classes (network scanning, exploitation, credential attacks, persistence, autonomous containment, scope bypass) are refused in code and the refusal is sealed in the ledger. Adding a capability requires changing the manifest in a reviewed commit.</p></div></div>' +
      '<div class="grid-2"><div class="col-main">' +
        section('Enabled capabilities', enabled.length + ' signed operations', '<span class="tag">ENFORCED IN CODE</span>',
          '<div class="table-wrap"><table class="table"><thead><tr><th>ID</th><th>OPERATION</th><th>GROUP</th><th>SCOPE</th><th>DESCRIPTION</th></tr></thead><tbody>' +
          enabled.map(function (c) {
            return '<tr><td><code>' + esc(c.id) + '</code></td><td><b>' + esc(c.name) + '</b></td><td>' + esc(c.group) + '</td><td><span class="mini-chip">' + esc(c.scope) + '</span></td><td class="detail-cell">' + esc(c.desc) + '</td></tr>';
          }).join('') + '</tbody></table></div>') +
        section('Blocked capability classes', blocked.length + ' explicitly prohibited', '<span class="tag">HARD REFUSAL</span>',
          blocked.map(function (c) {
            return '<div class="blocked-row">' + icon('x') + '<div><b>' + esc(c.name) + '</b><small>' + esc(c.reason) + '</small></div><code>' + esc(c.id) + '</code></div>';
          }).join('')) +
      '</div><div class="col-side">' +
        section('Request a capability', 'Test the policy engine — try any identifier', '',
          '<form data-form="capability-request">' +
          '<label class="field"><span>Capability identifier</span><input name="capability" list="cap-list" placeholder="net.scan" required><datalist id="cap-list">' +
          D2.CAPABILITIES.map(function (c) { return '<option value="' + esc(c.id) + '"></option>'; }).join('') + '</datalist></label>' +
          '<label class="field" style="margin-top:10px"><span>Justification</span><textarea name="justification" class="code-area code-area-sm" placeholder="Why is this needed?"></textarea></label>' +
          '<div class="form-actions"><button class="btn btn-primary" type="submit">' + icon('shield') + ' Evaluate request</button></div></form>') +
        section('Recent decisions', reqs.length + ' evaluated', '',
          reqs.length ? reqs.slice(0, 10).map(function (x) {
            return '<div class="gap-row"><code>' + esc(x.decision) + '</code><span>' + esc(x.id) + '</span><small>' + esc(h.rel(x.at)) + '</small></div>';
          }).join('') : h.empty('No capability requests yet.')) +
        section('Policy chain', 'Order of enforcement', '',
          '<div class="policy-chain">' + ['Manifest lookup', 'Status check (enabled)', 'Scope signature + expiry', 'Permitted check type', 'Ledger decision'].map(function (s, i) {
            return '<div><span>' + (i + 1) + '</span><b>' + esc(s) + '</b></div>';
          }).join('') + '</div>') +
      '</div></div>';
  });

  /* --------------------------- command center add-on --------------------- */
  var originalOverview = U.getView('overview');
  U.registerView('overview', function () {
    var modules = [
      ['20', 'CONSOLE VIEWS', 'grid'], ['7', 'INGEST FORMATS', 'wave'], ['16+', 'DETECTION RULES', 'target'],
      ['42', 'ATT&CK TECHNIQUES', 'chart'], ['150', 'HEXSTRIKE TOOLS', 'cpu'], ['41', 'OPENCODE TOOLS', 'cpu'], ['8', 'ORCHESTRATOR TASKS', 'bolt']
    ];
    var breadth = '<div class="breadth-grid">' + modules.map(function (m) {
      return '<div class="breadth-cell">' + icon(m[2]) + '<b>' + esc(m[0]) + '</b><span>' + esc(m[1]) + '</span></div>';
    }).join('') + '</div>';
    var engines = [
      ['Mission Orchestrator', 'Policy-gated DAG of 8 tasks', 'orchestrator', 'cpu'],
      ['Universal Ingest', 'Normalize + reconstruct attack chains', 'ingest', 'wave'],
      ['Analysis Lab', 'Email · IAM · K8s · secrets · SBOM', 'lab', 'lock'],
      ['Detection Studio', 'ATT&CK heatmap + custom rules', 'studio', 'target'],
      ['Investigation Copilot', 'Local natural-language queries', 'investigate', 'search'],
      ['Risk Quantification', 'Monte Carlo over open findings', 'quant', 'chart'],
      ['AEGIS Terminal', 'OpenCode workbench + HexStrike adapter', 'terminal', 'terminal']
    ];
    var rail = '<div class="quick-grid">' + engines.map(function (e) {
      return '<button class="quick" data-action="nav" data-view="' + e[2] + '">' + icon(e[3]) + '<b>' + esc(e[0]) + '</b><small>' + esc(e[1]) + '</small></button>';
    }).join('') + '</div>';
    return originalOverview() + section('Platform breadth', 'AEGIS SENTINEL v2.2 capability surface', '<span class="tag">ULTRA-ADVANCED / AUTHORIZED-ONLY</span>', breadth) +
      section('v2 engines', 'Jump into an advanced workflow', '', rail, 'panel-tight');
  });

  /* ------------------------------ actions -------------------------------- */
  U.registerAction('orch-run', function () { runOrchestrator(); });
  U.registerAction('ingest-analyze', function () { ingestAnalyze(); });
  U.registerAction('ingest-sample', function (t) {
    var kind = t.getAttribute('data-kind');
    var map = { jsonl: D2.SAMPLES.jsonl, nginx: D2.SAMPLES.nginx, syslog: DATA.SAMPLE_LOGS,
      csv: 'timestamp,src,actor,action,status\n2026-11-10T03:14:02Z,185.220.101.47,admin,failed_login,401\n2026-11-10T03:14:09Z,185.220.101.47,deploy,login_success,200\n2026-11-10T03:15:11Z,185.220.101.47,deploy,sudo,200\n2026-11-10T03:16:02Z,10.20.0.15,svc,sql_injection,500' };
    S.setDraft('ingest', map[kind] || map.jsonl);
    U.render(); U.toast(kind.toUpperCase() + ' sample loaded.', 'ok');
  });
  U.registerAction('lab-tab', function (t) { ui.labTab = t.getAttribute('data-tab'); U.render(); });
  U.registerAction('lab-sample', function (t) {
    var tab = t.getAttribute('data-tab');
    S.setDraft('lab_' + tab, D2.SAMPLES[({ email: 'email', iam: 'iam', k8s: 'k8s', secrets: 'secrets', deps: 'deps' })[tab]]);
    U.render(); U.toast('Sample loaded.', 'ok');
  });
  U.registerAction('lab-analyze', function (t) { labAnalyze(t.getAttribute('data-tab')); });
  U.registerAction('studio-export', function () {
    U.download('aegis-mitre-coverage.json', JSON.stringify(A.mitreCoverage(S.state), null, 2));
    S.audit('COVERAGE_EXPORT', 'mitre/navigator', 'EXPORTED', 'ATT&CK coverage matrix exported.'); S.save();
    U.toast('Coverage matrix exported.', 'ok');
  });
  U.registerAction('rule-test', function () {
    var form = $('rule-form');
    if (!form) return;
    var fd = new FormData(form);
    var rule = { pattern: fd.get('pattern'), severity: fd.get('severity'), threshold: fd.get('threshold'), name: fd.get('name') };
    var res = A.testCustomRule(rule, S.state.drafts.logs || '');
    res.threshold = rule.threshold;
    ui.ruleTest = res;
    U.renderView();
  });
  U.registerAction('rule-delete', function (t) { S.deleteCustomRule(t.getAttribute('data-id')); U.render(); U.toast('Rule removed.', 'ok'); });
  U.registerAction('case-detail', function (t) { caseDetail(t.getAttribute('data-id')); });
  U.registerAction('case-status', function (t) {
    S.setCaseStatus(t.getAttribute('data-id'), t.getAttribute('data-status'));
    caseDetail(t.getAttribute('data-id')); U.toast('Case status updated and logged.', 'ok');
  });
  U.registerAction('case-export', function (t) {
    var c = S.state.cases.filter(function (x) { return x.id === t.getAttribute('data-id'); })[0];
    if (!c) return;
    var linked = S.state.alerts.filter(function (a) { return c.linkedAlerts.indexOf(a.id) !== -1; });
    U.download('aegis-case-' + c.id.slice(-6) + '.json', JSON.stringify({ case: c, linkedAlerts: linked }, null, 2));
    S.audit('CASE_EXPORT', c.id, 'EXPORTED', 'Case bundle exported.'); S.save();
    U.toast('Case bundle exported.', 'ok');
  });
  U.registerAction('investigate-run', function () {
    var inp = $('investigate-input');
    runInvestigation(inp ? inp.value : '');
  });
  U.registerAction('investigate-example', function (t) { runInvestigation(t.getAttribute('data-query')); });
  U.registerAction('quant-run', function () {
    var sel = $('quant-iterations');
    var n = sel ? Number(sel.value) : 2000;
    ui.quantIterations = n;
    var r = A.monteCarloRisk(S.state, n);
    S.saveQuant(r);
    U.render(); U.toast(n.toLocaleString() + ' iterations complete · p90 ' + r.p90 + '.', 'ok');
  });

  /* ------------------------------- forms --------------------------------- */
  U.registerForm('custom-rule', function (form, fd) {
    var res = S.saveCustomRule({
      name: fd.get('name'), pattern: fd.get('pattern'), severity: fd.get('severity'),
      mitre: fd.get('mitre'), threshold: fd.get('threshold'), remediation: fd.get('remediation')
    });
    if (!res.ok) { U.toast(res.error, 'bad'); return; }
    ui.ruleTest = null;
    U.toast('Rule published — matches ' + res.test.count + ' line(s).', 'ok');
    U.render();
  });
  U.registerForm('case-create', function (form, fd) {
    var res = S.createCase({
      title: fd.get('title'), severity: fd.get('severity'), asset: fd.get('asset'),
      summary: fd.get('summary'), linkedAlerts: fd.getAll('alerts')
    });
    if (!res.ok) { U.toast(res.error, 'bad'); return; }
    U.toast('Case opened: ' + res.case.title, 'ok'); U.render();
  });
  U.registerForm('case-note', function (form, fd) {
    var id = String(fd.get('caseId') || '');
    if (S.addCaseNote(id, fd.get('note'))) { caseDetail(id); U.toast('Evidence note recorded.', 'ok'); }
  });
  U.registerForm('capability-request', function (form, fd) {
    var id = String(fd.get('capability') || '').trim();
    var justification = String(fd.get('justification') || '').trim();
    var target = (activeTargets()[0] || {}).name || null;
    var gate = A.evaluateCapability(id, S.state, target);
    var decision = gate.allowed ? 'GRANTED' : 'REFUSED';
    S.recordCapabilityRequest(id, decision, gate.reason + (justification ? ' Operator justification: ' + justification.slice(0, 160) : ''));
    U.modal('Capability decision', '<div class="refusal ' + (gate.allowed ? 'granted' : '') + '">' +
      icon(gate.allowed ? 'check' : 'shield') + '<div><h3>' + decision + ' · ' + esc(gate.code) + '</h3>' +
      '<p>' + esc(gate.reason) + '</p><div class="refusal-code"><span>CAPABILITY</span><code>' + esc(id) + '</code>' +
      '<span>MANIFEST</span><code>' + esc(gate.cap ? gate.cap.status : 'not present') + '</code>' +
      '<span>TARGET</span><code>' + esc(target || 'n/a') + '</code><span>LEDGER</span><code>#' + S.state.audit.length + '</code></div></div></div>',
      '<button class="btn btn-primary" data-action="close-modal">Close</button>');
    U.renderView();
    U.toast('Capability ' + id + ' → ' + decision, gate.allowed ? 'ok' : 'bad');
  });

  /* ------------------------------ commands ------------------------------- */
  U.registerCommands([
    { label: 'Run orchestrated mission', hint: 'OPERATE', icon: 'cpu', run: function () { U.navigate('orchestrator'); runOrchestrator(); } },
    { label: 'Normalize telemetry & reconstruct attack chains', hint: 'ANALYZE', icon: 'wave', run: function () { U.navigate('ingest'); ingestAnalyze(); } },
    { label: 'Open the capability manifest', hint: 'GOVERN', icon: 'shield', run: function () { U.navigate('capabilities'); } },
    { label: 'View ATT&CK coverage heatmap', hint: 'ANALYZE', icon: 'target', run: function () { U.navigate('studio'); } },
    { label: 'Run Monte Carlo risk simulation', hint: 'ANALYZE', icon: 'chart', run: function () { U.navigate('quant'); U.$('quant-iterations') && U.doc.querySelector('[data-action="quant-run"]').click(); } },
    { label: 'Ask the investigation copilot', hint: 'ANALYZE', icon: 'search', run: function () { U.navigate('investigate'); } }
  ]);

  // If the base module already booted (e.g. modules loaded individually),
  // rebuild the palette and repaint so the v2 views/nav are visible immediately.
  if (U.doc.querySelector('.shell')) { U.buildCommands(); U.render(); }
})(typeof globalThis !== 'undefined' ? globalThis : this);
