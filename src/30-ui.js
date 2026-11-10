/* AEGIS / SENTINEL — operator console (zero dependencies, zero network calls). */
(function (root) {
  'use strict';
  var DATA = root.AEGIS_DATA, E = root.AEGIS_ENGINE, S = root.AEGIS_STORE;
  var doc = root.document;

  var NAV = [
    { group: 'OPERATE', items: [
      { id: 'overview', label: 'Command Center', icon: 'grid', key: '1' },
      { id: 'scope', label: 'Authorization Scope', icon: 'shield', key: '2' },
      { id: 'agent', label: 'Autonomous Agent', icon: 'cpu', key: '3' }
    ]},
    { group: 'ANALYZE', items: [
      { id: 'logs', label: 'Signal Analyzer', icon: 'wave', key: '4' },
      { id: 'headers', label: 'Hardening Analyzer', icon: 'lock', key: '5' },
      { id: 'alerts', label: 'Alert Triage', icon: 'alert', key: '6' },
      { id: 'intel', label: 'IOC Workbench', icon: 'target', key: '7' }
    ]},
    { group: 'GOVERN', items: [
      { id: 'playbooks', label: 'Response Playbooks', icon: 'list', key: '8' },
      { id: 'compliance', label: 'Control Coverage', icon: 'chart', key: '9' },
      { id: 'audit', label: 'Audit Ledger', icon: 'chain', key: '0' },
      { id: 'policy', label: 'Rules of Engagement', icon: 'file', key: 'P' }
    ]}
  ];
  var VIEWS = {};
  NAV.forEach(function (g) { g.items.forEach(function (i) { VIEWS[i.id] = i; }); });
  VIEWS.findings = { id: 'findings', label: 'Finding Register', icon: 'list', key: 'F' };

  var ICONS = {
    grid: 'M3 3h7v7H3zM14 3h7v7h-7zM3 14h7v7H3zM14 14h7v7h-7z',
    shield: 'M12 2l8 4v6c0 5-3.4 8.6-8 10-4.6-1.4-8-5-8-10V6z',
    cpu: 'M6 6h12v12H6zM9 2v4M15 2v4M9 18v4M15 18v4M2 9h4M2 15h4M18 9h4M18 15h4',
    wave: 'M2 12h3l2-6 3 12 3-9 2 5 2-3h5',
    lock: 'M5 11h14v10H5zM8 11V7a4 4 0 018 0v4',
    alert: 'M12 3l10 18H2zM12 9v5M12 17h.01',
    target: 'M12 3a9 9 0 100 18 9 9 0 000-18zM12 7a5 5 0 100 10 5 5 0 000-10zM12 11a1 1 0 100 2 1 1 0 000-2z',
    list: 'M4 5h16M4 12h16M4 19h16',
    chart: 'M4 20V9M10 20V4M16 20v-7M22 20H2',
    chain: 'M9 15l6-6M7.5 10.5l-2 2a3.5 3.5 0 005 5l2-2M16.5 13.5l2-2a3.5 3.5 0 00-5-5l-2 2',
    file: 'M6 2h9l4 4v16H6zM15 2v5h4M9 12h7M9 16h7',
    chevron: 'M9 5l7 7-7 7',
    play: 'M7 4l13 8-13 8z',
    search: 'M11 4a7 7 0 100 14 7 7 0 000-14zM16 16l5 5',
    download: 'M12 3v12M7 11l5 5 5-5M4 20h16',
    check: 'M4 12l5 5L20 6',
    x: 'M5 5l14 14M19 5L5 19',
    clock: 'M12 3a9 9 0 100 18 9 9 0 000-18zM12 7v5l4 2',
    bolt: 'M13 2L4 14h6l-1 8 9-12h-6z'
  };
  function icon(name, cls) {
    return '<svg class="ico ' + (cls || '') + '" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.7" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="' + (ICONS[name] || ICONS.grid) + '"/></svg>';
  }
  function esc(s) {
    return String(s == null ? '' : s).replace(/[&<>"']/g, function (c) {
      return { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c];
    });
  }
  function $(id) { return doc.getElementById(id); }
  function ts(t) { return new Date(t || Date.now()).toLocaleString('en-GB', { day: '2-digit', month: 'short', hour: '2-digit', minute: '2-digit', second: '2-digit' }); }
  function day(t) { return new Date(t || Date.now()).toLocaleDateString('en-GB', { day: '2-digit', month: 'short', year: 'numeric' }); }
  function rel(t) {
    var m = Math.max(0, Math.round((Date.now() - t) / 60000));
    if (m < 1) return 'just now'; if (m < 60) return m + 'm ago';
    if (m < 1440) return Math.round(m / 60) + 'h ago'; return Math.round(m / 1440) + 'd ago';
  }
  function sevPill(s) { return '<span class="sev sev-' + esc(s) + '"><i></i>' + esc(DATA.SEVERITIES[s] ? DATA.SEVERITIES[s].label : s) + '</span>'; }
  function statusPill(s) {
    var map = { pass: 'ok', implemented: 'ok', active: 'ok', allowed: 'ok', ALLOWED: 'ok', GRANTED: 'ok', COMPLETE: 'ok', SEALED: 'ok',
      warn: 'warn', partial: 'warn', triaged: 'warn', REFUSED: 'bad', fail: 'bad', gap: 'bad', expired: 'bad' };
    return '<span class="pill pill-' + (map[s] || 'neutral') + '">' + esc(s) + '</span>';
  }
  function countBy(arr, key) {
    return arr.reduce(function (m, x) { var k = x[key] || 'unknown'; m[k] = (m[k] || 0) + 1; return m; }, {});
  }
  function short(h, n) { return h ? esc(String(h).slice(0, n || 12)) + '…' : '—'; }

  var ui = {
    view: 'overview', modal: null, palette: false, paletteQuery: '', paletteIndex: 0,
    selectedAsset: null, sweepLines: [], sweepRunning: false,
    alertFilter: 'all', assetQuery: '', toasts: [],
    labTab: 'email', orchestratorRunning: false, orchestratorNodes: {},
    ingestFormat: 'auto', ingestResult: null, investigateQuery: '', investigateResult: null,
    caseSelected: null, quantIterations: 2000
  };
  /* Extension points consumed by src/40-ui2.js (v2 capability modules). */
  var ACTION_HANDLERS = Object.create(null);
  var FORM_HANDLERS = Object.create(null);
  var EXTRA_COMMANDS = [];

  /* ---------------------------- tiny charts ----------------------------- */
  function activitySeries() {
    var rand = E.prng(E.sha256('activity:' + S.state.audit.length + ':' + S.state.findings.length));
    var base = 12 + Math.min(30, S.state.findings.length);
    var out = [];
    for (var i = 0; i < 16; i++) out.push(Math.max(3, Math.round(base * (0.45 + rand() * 0.9) + (i > 11 ? 8 : 0))));
    return out;
  }
  function areaChart(vals) {
    var w = 640, h = 168, pad = 10, max = Math.max.apply(null, vals.concat([1]));
    var pts = vals.map(function (v, i) {
      return [pad + i * (w - 2 * pad) / (vals.length - 1), h - pad - (v / max) * (h - 2 * pad)];
    });
    var line = 'M' + pts.map(function (p) { return p[0].toFixed(1) + ',' + p[1].toFixed(1); }).join(' L');
    var area = line + ' L' + (w - pad) + ',' + (h - pad) + ' L' + pad + ',' + (h - pad) + ' Z';
    var grid = [0.25, 0.5, 0.75].map(function (f) {
      return '<line x1="0" y1="' + (h * f).toFixed(0) + '" x2="' + w + '" y2="' + (h * f).toFixed(0) + '" stroke="rgba(125,164,190,.10)" stroke-width="1"/>';
    }).join('');
    return '<svg class="chart" viewBox="0 0 ' + w + ' ' + h + '" preserveAspectRatio="none" role="img" aria-label="Threat activity over the last 16 hours">' +
      '<defs><linearGradient id="ag" x1="0" y1="0" x2="0" y2="1"><stop offset="0" stop-color="#38e8c2" stop-opacity=".38"/><stop offset="1" stop-color="#38e8c2" stop-opacity="0"/></linearGradient></defs>' +
      grid + '<path d="' + area + '" fill="url(#ag)"/><path d="' + line + '" fill="none" stroke="#38e8c2" stroke-width="2.2" vector-effect="non-scaling-stroke"/>' +
      pts.map(function (p, i) { return i % 4 === 0 ? '<circle cx="' + p[0].toFixed(1) + '" cy="' + p[1].toFixed(1) + '" r="3" fill="#38e8c2"/>' : ''; }).join('') +
      '</svg>';
  }
  function donut(parts, centerLabel, centerSub) {
    var colors = { critical: '#ff5470', high: '#ff9f43', medium: '#ffd166', low: '#5ad2ff', info: '#8b9bb4',
      implemented: '#38e8c2', partial: '#ffd166', gap: '#ff5470', ok: '#38e8c2', warn: '#ffd166', bad: '#ff5470' };
    var total = parts.reduce(function (n, p) { return n + p.value; }, 0) || 1;
    var r = 52, c = 2 * Math.PI * r, off = 0;
    var rings = parts.filter(function (p) { return p.value > 0; }).map(function (p) {
      var len = p.value / total * c;
      var seg = '<circle cx="70" cy="70" r="' + r + '" fill="none" stroke="' + (colors[p.key] || '#5ad2ff') +
        '" stroke-width="15" stroke-dasharray="' + len.toFixed(2) + ' ' + (c - len).toFixed(2) +
        '" stroke-dashoffset="' + (-off).toFixed(2) + '" transform="rotate(-90 70 70)" stroke-linecap="butt"/>';
      off += len; return seg;
    }).join('');
    return '<svg class="donut" viewBox="0 0 140 140" role="img" aria-label="Distribution chart">' +
      '<circle cx="70" cy="70" r="52" fill="none" stroke="rgba(125,164,190,.12)" stroke-width="15"/>' + rings +
      '<text x="70" y="66" text-anchor="middle" class="donut-main">' + esc(centerLabel) + '</text>' +
      '<text x="70" y="88" text-anchor="middle" class="donut-sub">' + esc(centerSub) + '</text></svg>';
  }
  function bar(label, value, max, color) {
    return '<div class="barrow"><span class="barlabel">' + esc(label) + '</span>' +
      '<span class="bartrack"><span class="barfill" style="width:' + Math.round(value / (max || 1) * 100) + '%;background:' + (color || '#38e8c2') + '"></span></span>' +
      '<span class="barvalue">' + esc(value) + '</span></div>';
  }
  function kpi(label, value, sub, tone, iconName) {
    return '<div class="kpi kpi-' + (tone || '') + '"><div class="kpi-top"><span>' + esc(label) + '</span>' + icon(iconName || 'chart') + '</div>' +
      '<div class="kpi-value">' + value + '</div><div class="kpi-sub">' + esc(sub) + '</div></div>';
  }
  function section(title, sub, actions, body, extraClass) {
    return '<section class="panel ' + (extraClass || '') + '"><div class="panel-head"><div><h2>' + esc(title) + '</h2>' +
      (sub ? '<p>' + esc(sub) + '</p>' : '') + '</div>' + (actions ? '<div class="panel-actions">' + actions + '</div>' : '') +
      '</div><div class="panel-body">' + body + '</div></section>';
  }
  function empty(text) { return '<div class="empty">' + icon('search') + '<p>' + esc(text) + '</p></div>'; }

  /* ------------------------------- shell -------------------------------- */
  function shell() {
    var s = S.state;
    var active = E.activeAssets(s).length;
    var nav = NAV.map(function (g) {
      return '<div class="nav-group"><div class="nav-group-label">' + esc(g.group) + '</div>' +
        g.items.map(function (i) {
          return '<button class="nav-item ' + (ui.view === i.id ? 'active' : '') + '" data-action="nav" data-view="' + i.id + '" title="Alt+' + i.key + '">' +
            icon(i.icon) + '<span>' + esc(i.label) + '</span><kbd>' + i.key + '</kbd></button>';
        }).join('') + '</div>';
    }).join('');
    return '<div class="shell">' +
      '<aside class="sidebar">' +
        '<div class="brand"><div class="brand-mark">' + icon('shield') + '</div><div class="brand-text"><strong>AEGIS<span>//</span>SENTINEL</strong><small>AUTONOMOUS DEFENSE PLATFORM</small></div></div>' +
        '<div class="agent-status"><span class="pulse"></span><div><strong>AGENT ONLINE</strong><small>strict scope · passive only</small></div></div>' +
        '<nav class="nav">' + nav + '</nav>' +
        '<div class="side-foot"><div class="scope-mini"><div class="scope-mini-head"><span>AUTHORIZATION BOUNDARY</span><b>' + active + '/' + s.assets.length + '</b></div>' +
          '<div class="scope-track"><span style="width:' + Math.round(active / (s.assets.length || 1) * 100) + '%"></span></div>' +
          '<small>' + esc(s.settings.operator) + ' · local session</small></div>' +
          '<div class="build">v2.0.0 · 19 modules · <span>NO NETWORK EGRESS</span></div></div>' +
      '</aside>' +
      '<div class="workspace"><header class="topbar">' +
        '<div class="crumbs"><span>WORKSPACE</span><b>/</b><strong>' + esc(VIEWS[ui.view].label) + '</strong></div>' +
        '<div class="topbar-right"><span class="chip chip-lock">' + icon('shield') + ' AUTHORIZED-ONLY</span>' +
          '<span class="chip" id="clock">' + esc(ts(Date.now())) + '</span>' +
          '<button class="btn btn-ghost" data-action="palette-open" title="Command palette (Ctrl+K)">' + icon('search') + ' <kbd>⌘K</kbd></button>' +
          '<button class="btn btn-primary" data-action="run-sweep">' + icon('bolt') + ' Run sweep</button></div>' +
      '</header><main id="view" class="view">' + view() + '</main></div></div>' +
      '<div id="toasts" class="toasts"></div><div id="modal-root"></div><div id="palette-root"></div>';
  }

  function view() {
    try { return VIEWS[ui.view] && VIEWS_FUNC[ui.view] ? VIEWS_FUNC[ui.view]() : empty('Unknown view'); }
    catch (err) { return '<div class="panel"><div class="panel-body"><h2>Render error</h2><pre>' + esc(err.stack || err.message) + '</pre></div></div>'; }
  }
  var VIEWS_FUNC = {};

  /* ---------------------------- command center -------------------------- */
  VIEWS_FUNC.overview = function () {
    var s = S.state;
    var open = s.findings.filter(function (f) { return f.status === 'open'; });
    var crit = open.filter(function (f) { return f.severity === 'critical'; }).length;
    var untriaged = s.alerts.filter(function (a) { return a.status === 'new'; }).length;
    var risk = E.riskScore(s);
    var chain = E.verifyChain(s.audit);
    var detections = s.logResults ? s.logResults.detections.length : 0;
    var sev = countBy(open, 'severity');
    var parts = ['critical', 'high', 'medium', 'low'].map(function (k) { return { key: k, value: sev[k] || 0 }; });
    var top = open.slice().sort(function (a, b) { return E.sevRank(b.severity) - E.sevRank(a.severity); }).slice(0, 5);
    var events = s.events.slice(0, 7);

    var kpis = '<div class="kpi-grid">' +
      kpi('RISK INDEX', '<span class="' + (risk > 65 ? 'danger' : risk > 40 ? 'warn' : 'good') + '">' + risk + '</span><small>/100</small>', 'Composite posture signal', risk > 65 ? 'bad' : '', 'wave') +
      kpi('CRITICAL FINDINGS', crit, open.length + ' total open findings', crit ? 'bad' : '', 'alert') +
      kpi('ASSETS IN SCOPE', E.activeAssets(s).length, s.assets.length + ' registered · ' + (s.assets.length - E.activeAssets(s).length) + ' out of scope', '', 'shield') +
      kpi('SIGNAL DETECTIONS', detections, s.logResults ? s.logResults.stats.lines + ' log lines analyzed' : 'No telemetry analyzed yet', '', 'wave') +
      kpi('UNTRIAGED ALERTS', untriaged, s.alerts.length + ' alerts in queue', untriaged > 3 ? 'warn' : '', 'target') +
      kpi('LEDGER INTEGRITY', chain.valid ? 'VALID' : 'BROKEN', chain.count + ' chained entries', chain.valid ? '' : 'bad', 'chain') +
      '</div>';

    var chartBody = '<div class="chart-wrap">' + areaChart(activitySeries()) + '<div class="chart-axis"><span>-16h</span><span>-12h</span><span>-8h</span><span>-4h</span><span>now</span></div></div>' +
      '<div class="legend"><span><i style="background:#38e8c2"></i>Correlated events / hour</span><span class="muted">SIMULATED TELEMETRY</span></div>';
    var donutBody = '<div class="donut-row">' + donut(parts, String(open.length), 'open') +
      '<div class="donut-legend">' + parts.concat([{ key: 'info', value: sev.info || 0 }]).map(function (p) {
        return '<div><span class="dot dot-' + p.key + '"></span>' + esc(p.key) + '<b>' + (p.value || 0) + '</b></div>';
      }).join('') + '</div></div>';
    var risksBody = top.length ? top.map(function (f) {
      return '<button class="risk-row" data-action="finding-detail" data-id="' + esc(f.id) + '">' + sevPill(f.severity) +
        '<span class="risk-title">' + esc(f.title) + '</span><span class="risk-asset">' + esc(f.asset) + '</span>' + icon('chevron') + '</button>';
    }).join('') : empty('No open findings. Run a sweep or analyze telemetry.');
    var streamBody = events.length ? '<div class="timeline">' + events.map(function (e) {
      return '<div class="tl-item tl-' + esc(e.kind) + '"><span class="tl-dot"></span><div><p>' + esc(e.text) + '</p><small>' + esc(rel(e.ts)) + (e.simulated ? ' · simulated' : '') + '</small></div></div>';
    }).join('') + '</div>' : empty('No agent activity yet.');
    var scopeBody = '<div class="scope-list">' + E.activeAssets(s).slice(0, 4).map(function (a) {
      return '<div><span class="scope-ok">' + icon('check') + '</span><b>' + esc(a.name) + '</b><small>' + esc(a.env) + ' · ' + esc(a.criticality) + '</small></div>';
    }).join('') + '</div><div class="scope-note">' + icon('lock') + ' Every agent action passes the authorization gate. Out-of-scope targets are refused and logged.</div>';
    var quick = '<div class="quick-grid">' +
      '<button data-action="nav" data-view="agent" class="quick">' + icon('cpu') + '<b>Autonomous sweep</b><small>Scope-gated posture simulation</small></button>' +
      '<button data-action="nav" data-view="logs" class="quick">' + icon('wave') + '<b>Analyze telemetry</b><small>16 MITRE-mapped detection rules</small></button>' +
      '<button data-action="auto-triage" class="quick">' + icon('target') + '<b>Auto-triage queue</b><small>Explainable priority scoring</small></button>' +
      '<button data-action="export-state" class="quick">' + icon('download') + '<b>Export report</b><small>Full state + audit chain as JSON</small></button>' +
      '</div>';

    return '<div class="page-head"><div><div class="eyebrow">SECURITY OPERATIONS · OVERVIEW</div><h1>Command Center</h1>' +
      '<p>Autonomous, authorization-bound defense operations. All analysis executes locally on data you supply.</p></div>' +
      '<div class="head-actions"><span class="badge-demo">DEMO BASELINE LOADED</span>' +
      '<button class="btn btn-ghost" data-action="exec-summary">' + icon('file') + ' Executive summary</button>' +
      '<button class="btn btn-primary" data-action="run-sweep">' + icon('bolt') + ' Run sweep</button></div></div>' +
      kpis +
      '<div class="grid-2"><div class="col-main">' +
        section('Threat activity', 'Correlated signal volume, rolling 16 hours', '<span class="tag">LIVE MODEL</span>', chartBody) +
        section('Priority open risks', 'Highest severity findings requiring a decision', '<button class="btn btn-xs" data-action="nav" data-view="findings">All findings (' + open.length + ')</button>', risksBody) +
      '</div><div class="col-side">' +
        section('Severity distribution', 'Open findings by severity', '', donutBody) +
        section('Agent activity', 'Most recent decisions and refusals', '', streamBody) +
        section('Scope posture', 'Active authorization records', '', scopeBody) +
      '</div></div>' +
      section('Quick actions', 'Jump straight into an operational workflow', '', quick, 'panel-tight');
  };

  /* --------------------------- authorization ---------------------------- */
  VIEWS_FUNC.scope = function () {
    var s = S.state;
    var checks = DATA.CHECK_TYPES.map(function (c) {
      return '<label class="check"><input type="checkbox" name="checks" value="' + c.id + '" ' +
        ((s.drafts.checks || []).indexOf(c.id) !== -1 ? 'checked' : '') + '><span>' + esc(c.label) + '</span></label>';
    }).join('');
    var form = '<form data-form="asset" class="form-grid">' +
      '<label class="field"><span>Asset identifier <em>hostname · IP · CIDR</em></span><input name="name" required placeholder="app.example.internal" value="' + esc(s.drafts.asset || '') + '"></label>' +
      '<label class="field"><span>Type</span><select name="type"><option>Domain</option><option>Host</option><option>IPv4</option><option>CIDR</option><option>Cloud account</option></select></label>' +
      '<label class="field"><span>Owning team</span><input name="owner" required placeholder="Platform Team" value="' + esc(s.drafts.owner || '') + '"></label>' +
      '<label class="field"><span>Authorized by <em>accountable approver</em></span><input name="authorizedBy" required placeholder="J. Rivera (CISO)" value="' + esc(s.drafts.authorizedBy || '') + '"></label>' +
      '<label class="field"><span>Environment</span><select name="env"><option>Production</option><option>Staging</option><option>Development</option><option>Decommissioning</option></select></label>' +
      '<label class="field"><span>Business criticality</span><select name="criticality"><option value="critical">Critical</option><option value="high" selected>High</option><option value="medium">Medium</option><option value="low">Low</option></select></label>' +
      '<label class="field"><span>Authorization validity <em>days, max 730</em></span><input name="days" type="number" min="1" max="730" value="' + esc(s.drafts.days || '90') + '"></label>' +
      '<div class="field field-wide"><span>Permitted check types <em>least-privilege scope</em></span><div class="check-grid">' + checks + '</div></div>' +
      '<label class="attest field-wide"><input type="checkbox" name="confirmed" required><span>I confirm I own this asset or hold documented authorization to assess it. I understand the agent will only perform passive, offline analysis of data I supply.</span></label>' +
      '<div class="form-actions field-wide"><button class="btn btn-primary" type="submit">' + icon('shield') + ' Sign & register scope</button>' +
      '<span class="form-hint">A SHA-256 scope token is generated and sealed into the audit ledger.</span></div></form>';

    var rows = s.assets.map(function (a) {
      var gate = E.scopeCheck(s, a.name);
      return '<tr><td><div class="asset-name">' + icon('shield') + '<div><b>' + esc(a.name) + '</b><small>' + esc(a.type) + ' · ' + esc(a.owner) + '</small></div></div></td>' +
        '<td>' + esc(a.env) + '<small class="block">' + esc(a.criticality) + '</small></td>' +
        '<td><div class="chips">' + a.checks.map(function (c) { return '<span class="mini-chip">' + esc(c) + '</span>'; }).join('') + '</div></td>' +
        '<td>' + esc(day(a.expires)) + '<small class="block">' + esc(a.authorizedBy) + '</small></td>' +
        '<td><code title="' + esc(a.token) + '">' + short(a.token, 14) + '</code></td>' +
        '<td>' + (gate.allowed ? statusPill('active') : '<span class="pill pill-bad" title="' + esc(gate.code) + '">' + esc(gate.code) + '</span>') + '</td>' +
        '<td>' + (a.revoked ? '<span class="muted">revoked</span>' : '<button class="btn btn-xs btn-danger" data-action="revoke-asset" data-name="' + esc(a.name) + '">Revoke</button>') + '</td></tr>';
    }).join('');

    return '<div class="page-head"><div><div class="eyebrow">GOVERNANCE · AUTHORIZATION</div><h1>Authorization Scope</h1>' +
      '<p>An asset cannot be assessed until an accountable owner signs a scope record. Expired, revoked and unattested records are refused automatically.</p></div>' +
      '<div class="head-actions"><span class="chip chip-lock">' + icon('lock') + ' STRICT ENFORCEMENT ON</span>' +
      '<button class="btn btn-ghost" data-action="probe-unauth">' + icon('target') + ' Test refusal</button></div></div>' +
      '<div class="callout callout-info"><div class="callout-icon">' + icon('shield') + '</div><div><b>The authorization boundary is the product, not a disclaimer.</b>' +
      '<p>The agent never probes third-party systems, never exploits, and never bypasses this gate. Scope checks are enforced in code before any action and every ALLOW / REFUSE decision is written to the hash-chained ledger.</p></div></div>' +
      section('Register an authorized asset', 'Signed scope record with least-privilege check types', '', form) +
      section('Scope registry', s.assets.length + ' records · ' + E.activeAssets(s).length + ' active',
        '<span class="tag">SHA-256 SIGNED</span>',
        '<div class="table-wrap"><table class="table"><thead><tr><th>ASSET</th><th>CONTEXT</th><th>PERMITTED CHECKS</th><th>VALID UNTIL</th><th>SCOPE TOKEN</th><th>STATUS</th><th></th></tr></thead><tbody>' + rows + '</tbody></table></div>');
  };

  /* ------------------------------ agent --------------------------------- */
  VIEWS_FUNC.agent = function () {
    var s = S.state;
    if (!ui.selectedAsset || !E.scopeCheck(s, ui.selectedAsset, 'posture').allowed) {
      var act = E.activeAssets(s); ui.selectedAsset = act.length ? act[0].name : '';
    }
    var opts = E.activeAssets(s).map(function (a) {
      return '<option value="' + esc(a.name) + '" ' + (a.name === ui.selectedAsset ? 'selected' : '') + '>' + esc(a.name) + ' · ' + esc(a.env) + '</option>';
    }).join('');
    var gatePanel = '<div class="gate-grid">' +
      '<div class="gate"><span class="gate-n">01</span>' + icon('shield') + '<b>Scope resolution</b><p>Target must match a signed, unexpired, unrevoked authorization record.</p></div>' +
      '<div class="gate"><span class="gate-n">02</span>' + icon('list') + '<b>Check-type policy</b><p>Permitted operations are restricted to the allowlist on that record.</p></div>' +
      '<div class="gate"><span class="gate-n">03</span>' + icon('chain') + '<b>Immutable decision log</b><p>ALLOW and REFUSE outcomes are hashed into the audit chain.</p></div>' +
      '</div>';
    var consoleHtml = '<div class="terminal" id="terminal"><div class="terminal-head"><span class="term-dots"><i></i><i></i><i></i></span>' +
      '<span>AEGIS AGENT · DECISION TRACE</span><span class="term-state">' + (ui.sweepRunning ? 'RUNNING' : 'IDLE') + '</span></div>' +
      '<div class="terminal-body">' + (ui.sweepLines.length ? ui.sweepLines.map(function (l) {
        return '<div class="term-line term-' + esc(l.kind) + '"><span>' + esc(l.t) + '</span><b>' + esc(l.tag) + '</b> ' + esc(l.text) + '</div>';
      }).join('') : '<div class="term-line term-muted"><span>' + esc(ts(Date.now())) + '</span><b>READY</b> Awaiting operator instruction. Strict scope enforcement active.</div>') + '</div></div>';
    var decisions = (s.sweep.decisions || []).map(function (d) {
      return '<tr><td><code>' + esc(d.target) + '</code></td><td>' + statusPill(d.decision) + '</td><td>' + esc(d.code) + '</td><td>' + esc(d.reason) + '</td><td>' + d.count + '</td></tr>';
    }).join('');
    var recent = s.findings.filter(function (f) { return f.source === 'autonomous-sweep'; }).slice(-6).reverse().map(function (f) {
      return '<button class="risk-row" data-action="finding-detail" data-id="' + esc(f.id) + '">' + sevPill(f.severity) +
        '<span class="risk-title">' + esc(f.title) + '</span><span class="risk-asset">' + esc(f.asset) + '</span><span class="sim-tag">SIM</span></button>';
    }).join('');

    return '<div class="page-head"><div><div class="eyebrow">OPERATIONS · AUTONOMOUS AGENT</div><h1>Autonomous Agent</h1>' +
      '<p>Scope-gated posture simulation. Findings are generated deterministically from a local template catalog and labelled SIMULATED — no host is ever contacted.</p></div>' +
      '<div class="head-actions"><span class="chip chip-lock">' + icon('shield') + ' ' + (s.sweep.count || 0) + ' SWEEPS RUN</span></div></div>' +
      section('Decision pipeline', 'Three gates must pass before any action is taken', '', gatePanel) +
      '<div class="grid-2"><div class="col-main">' +
        section('Sweep control', 'Select an in-scope asset, then dispatch the agent', '',
          '<div class="control-row"><label class="field flex"><span>Target</span><select id="sweep-target">' + opts + '</select></label>' +
          '<button class="btn btn-primary" data-action="run-sweep-target" ' + (ui.sweepRunning ? 'disabled' : '') + '>' + icon('play') + (ui.sweepRunning ? ' Running…' : ' Dispatch sweep') + '</button>' +
          '<button class="btn btn-ghost" data-action="run-sweep" ' + (ui.sweepRunning ? 'disabled' : '') + '>All in-scope assets</button></div>' +
          '<div class="probe-row"><button class="btn btn-danger btn-xs" data-action="probe-unauth">' + icon('x') + ' Attempt out-of-scope target</button>' +
          '<span class="muted">Demonstrates the hard refusal path. The target is never contacted.</span></div>' + consoleHtml) +
        section('Sweep decisions', 'Last run · per-target authorization outcome', '', decisions ?
          '<div class="table-wrap"><table class="table"><thead><tr><th>TARGET</th><th>DECISION</th><th>CODE</th><th>REASON</th><th>FINDINGS</th></tr></thead><tbody>' + decisions + '</tbody></table></div>' :
          empty('No sweep has run yet. Dispatch one to see the decision trace.')) +
      '</div><div class="col-side">' +
        section('Recent simulated findings', 'Generated by the agent locally', '', recent || empty('Nothing generated yet.')) +
        section('Agent policy', 'Non-negotiable constraints', '',
          '<ul class="policy-list"><li>' + icon('check') + '<span><b>Passive analysis only</b><small>No packets are sent to any asset or third party.</small></span></li>' +
          '<li>' + icon('check') + '<span><b>Explicit scope required</b><small>Signed record, owner attestation and expiry checked per action.</small></span></li>' +
          '<li>' + icon('check') + '<span><b>No exploitation</b><small>No payload delivery, credential attacks, persistence or evasion.</small></span></li>' +
          '<li>' + icon('check') + '<span><b>Human approval for containment</b><small>Containment is a workflow state, never an external action.</small></span></li>' +
          '<li>' + icon('check') + '<span><b>Full accountability</b><small>Every decision is chained and verifiable in the ledger.</small></span></li></ul>') +
      '</div></div>';
  };

  /* ------------------------- findings (aux view) ------------------------ */
  VIEWS_FUNC.findings = function () {
    var s = S.state;
    var rows = s.findings.slice().sort(function (a, b) { return E.sevRank(b.severity) - E.sevRank(a.severity); }).map(function (f) {
      return '<tr><td>' + sevPill(f.severity) + '</td><td><b>' + esc(f.title) + '</b><small class="block">' + esc(f.category) + ' · ' + esc(f.mitre) + '</small></td>' +
        '<td><code>' + esc(f.asset) + '</code></td><td>' + esc(f.source) + (f.simulated ? ' <span class="sim-tag">SIM</span>' : '') + '</td>' +
        '<td>' + statusPill(f.status) + '</td><td><button class="btn btn-xs" data-action="finding-detail" data-id="' + esc(f.id) + '">Inspect</button></td></tr>';
    }).join('');
    return '<div class="page-head"><div><div class="eyebrow">OPERATIONS · FINDINGS</div><h1>Finding Register</h1><p>All posture findings, including simulated sweep output.</p></div></div>' +
      section('All findings', s.findings.length + ' records', '', '<div class="table-wrap"><table class="table"><thead><tr><th>SEV</th><th>FINDING</th><th>ASSET</th><th>SOURCE</th><th>STATUS</th><th></th></tr></thead><tbody>' + rows + '</tbody></table></div>');
  };

  /* -------------------------- signal analyzer --------------------------- */
  VIEWS_FUNC.logs = function () {
    var s = S.state, r = s.logResults;
    var opts = assetOptions('logs');
    var rules = '<div class="rule-list">' + DATA.LOG_RULES.map(function (rule) {
      return '<div class="rule"><span class="rule-id">' + esc(rule.id) + '</span>' + sevPill(rule.severity) +
        '<span class="rule-name">' + esc(rule.name) + '</span><span class="mitre">' + esc(rule.mitre) + '</span></div>';
    }).join('') + '</div>';
    var results = r ? '<div class="stat-row">' +
      '<div><b>' + r.stats.lines + '</b><span>LINES</span></div><div><b>' + r.detections.length + '</b><span>DETECTIONS</span></div>' +
      '<div><b>' + r.stats.ips + '</b><span>UNIQUE IPs</span></div><div><b>' + r.iocs.length + '</b><span>IOCs</span></div>' +
      '<div><b>' + r.stats.compromisedPatterns + '</b><span>ACCESS PATTERNS</span></div></div>' +
      (r.detections.length ? r.detections.map(function (d) {
        return '<div class="detection det-' + esc(d.severity) + '"><div class="det-head">' + sevPill(d.severity) +
          '<b>' + esc(d.name) + '</b><span class="rule-id">' + esc(d.rule) + '</span><span class="mitre">' + esc(d.mitre) + '</span><span class="det-count">' + d.count + ' hit(s)</span></div>' +
          '<p class="det-ev">' + esc(d.evidence) + '</p>' +
          (d.samples.length ? '<pre class="samples">' + esc(d.samples.join('\n')) + '</pre>' : '') +
          '<div class="det-fix">' + icon('check') + '<span><b>Recommended action</b> ' + esc(d.remediation) + '</span></div></div>';
      }).join('') : empty('No rule matched the supplied telemetry.')) : empty('Paste telemetry and run the analyzer. Detection runs entirely in your browser.');

    return '<div class="page-head"><div><div class="eyebrow">ANALYSIS · SIGNAL</div><h1>Signal Analyzer</h1>' +
      '<p>16 MITRE ATT&CK-mapped detection rules, threshold correlation, and IOC extraction over text you paste. Nothing leaves this browser.</p></div>' +
      '<div class="head-actions"><span class="chip">' + icon('list') + ' ' + DATA.LOG_RULES.length + ' RULES ACTIVE</span></div></div>' +
      '<div class="grid-2"><div class="col-main">' +
        section('Telemetry input', 'Auth logs, web access logs, EDR lines, proxy logs…',
          '<button class="btn btn-xs" data-action="load-sample" data-kind="logs">Load sample</button>',
          '<div class="control-row"><label class="field flex"><span>Associate with in-scope asset</span><select id="log-asset">' + opts + '</select></label></div>' +
          '<textarea class="code-area" data-draft="logs" spellcheck="false" placeholder="Paste log lines here…">' + esc(s.drafts.logs || '') + '</textarea>' +
          '<div class="form-actions"><button class="btn btn-primary" data-action="analyze-logs">' + icon('wave') + ' Analyze telemetry</button>' +
          '<button class="btn btn-ghost" data-action="clear-draft" data-key="logs">Clear</button></div>') +
        section('Detection results', r ? 'Run at ' + ts(r.at) : 'Awaiting input', '', results) +
      '</div><div class="col-side">' +
        section('Detection catalog', 'Locally evaluated rules', '', rules, 'panel-scroll') +
        (r ? section('Extracted indicators', r.iocs.length + ' unique IOCs', '<button class="btn btn-xs" data-action="nav" data-view="intel">Open workbench</button>',
          r.iocs.slice(0, 10).map(function (i) { return '<div class="ioc-mini"><span>' + esc(i.type) + '</span><code>' + esc(i.defanged) + '</code></div>'; }).join('') || empty('No indicators found.')) : '') +
      '</div></div>';
  };

  /* ------------------------ hardening analyzer -------------------------- */
  VIEWS_FUNC.headers = function () {
    var s = S.state, r = s.headerResults;
    var opts = assetOptions('headers');
    var result = r ? '<div class="grade-box grade-' + esc(r.grade) + '"><div class="grade-letter">' + esc(r.grade) + '</div>' +
      '<div><b>Hardening grade ' + esc(r.grade) + '</b><p>' + r.score + '/100 composite score · ' + r.checks.filter(function (c) { return c.status === 'pass'; }).length +
      ' passing · ' + r.checks.filter(function (c) { return c.status === 'warn'; }).length + ' warnings · ' +
      r.checks.filter(function (c) { return c.status === 'fail'; }).length + ' failures</p>' +
      '<div class="grade-track"><span style="width:' + r.score + '%"></span></div></div></div>' +
      '<div class="controls">' + r.checks.map(function (c) {
        return '<div class="control control-' + esc(c.status) + '"><div class="control-head">' + statusPill(c.status) + '<b>' + esc(c.name) + '</b><span>' + esc(c.framework) + '</span></div>' +
          '<p>' + esc(c.evidence) + '</p><div class="control-fix"><span>FIX</span><code>' + esc(c.fix) + '</code></div></div>';
      }).join('') + '</div>' : empty('Paste HTTP response headers to evaluate 12 hardening controls.');

    return '<div class="page-head"><div><div class="eyebrow">ANALYSIS · HARDENING</div><h1>Hardening Analyzer</h1>' +
      '<p>Deterministic evaluation of transport, browser, cookie and CORS controls against an OWASP-style baseline.</p></div>' +
      '<div class="head-actions"><button class="btn btn-ghost" data-action="copy-hardened">' + icon('download') + ' Copy hardened header set</button></div></div>' +
      '<div class="grid-2"><div class="col-main">' +
        section('Response headers', 'Paste a raw HTTP response or header block',
          '<button class="btn btn-xs" data-action="load-sample" data-kind="headers">Load sample</button>',
          '<div class="control-row"><label class="field flex"><span>Associate with in-scope asset</span><select id="header-asset">' + opts + '</select></label></div>' +
          '<textarea class="code-area code-area-sm" data-draft="headers" spellcheck="false">' + esc(s.drafts.headers || '') + '</textarea>' +
          '<div class="form-actions"><button class="btn btn-primary" data-action="analyze-headers">' + icon('lock') + ' Evaluate controls</button></div>') +
        section('Control evaluation', r ? 'Analyzed ' + ts(r.at) : 'Awaiting input', '', result) +
      '</div><div class="col-side">' +
        section('What is checked', '12 weighted controls', '',
          '<ul class="policy-list compact"><li>' + icon('check') + '<span><b>Transport</b><small>HSTS age, subdomain coverage</small></span></li>' +
          '<li>' + icon('check') + '<span><b>Browser policy</b><small>CSP, XCTO, framing, referrer, permissions</small></span></li>' +
          '<li>' + icon('check') + '<span><b>Session security</b><small>Secure, HttpOnly, SameSite</small></span></li>' +
          '<li>' + icon('check') + '<span><b>Information exposure</b><small>Version banners, cache control</small></span></li>' +
          '<li>' + icon('check') + '<span><b>Cross-origin</b><small>CORS wildcards + credentials, COOP/CORP</small></span></li></ul>') +
        section('Sample hardened set', 'Recommended starting point', '',
          '<pre class="samples">' + esc('Strict-Transport-Security: max-age=31536000; includeSubDomains\nContent-Security-Policy: default-src \'self\'; object-src \'none\'; frame-ancestors \'none\'\nX-Content-Type-Options: nosniff\nReferrer-Policy: strict-origin-when-cross-origin\nPermissions-Policy: camera=(), microphone=(), geolocation=()\nCross-Origin-Opener-Policy: same-origin\nCache-Control: no-store') + '</pre>') +
      '</div></div>';
  };

  /* ---------------------------- alert triage ---------------------------- */
  VIEWS_FUNC.alerts = function () {
    var s = S.state;
    var filters = ['all', 'new', 'triaged', 'escalated', 'contained', 'dismissed'].map(function (f) {
      return '<button class="filter ' + (ui.alertFilter === f ? 'active' : '') + '" data-action="alert-filter" data-value="' + f + '">' + esc(f) + '</button>';
    }).join('');
    var list = s.alerts.filter(function (a) { return ui.alertFilter === 'all' || a.status === ui.alertFilter; })
      .sort(function (a, b) {
        return (b.priority ? b.priority.score : E.sevRank(b.severity) * 20) - (a.priority ? a.priority.score : E.sevRank(a.severity) * 20);
      });
    var cards = list.length ? list.map(function (a) {
      var p = a.priority;
      return '<div class="alert-card alert-' + esc(a.severity) + '"><div class="alert-top">' + sevPill(a.severity) +
        (p ? '<span class="priority pr-' + esc(p.band) + '">' + esc(p.band) + ' · ' + p.score + '</span>' : '<span class="priority pr-new">UNSCORED</span>') +
        '<span class="alert-time">' + esc(rel(a.createdAt)) + '</span></div>' +
        '<h3>' + esc(a.title) + '</h3><div class="alert-meta"><span>' + icon('shield') + esc(a.asset) + '</span><span>' + icon('wave') + esc(a.source) + '</span>' +
        '<span>' + icon('target') + esc(a.phase) + '</span><span>' + icon('chart') + (a.confidence || 0) + '% confidence</span></div>' +
        '<p class="alert-ev">' + esc(a.evidence) + '</p>' +
        (p ? '<div class="reasoning"><b>AGENT REASONING</b><div>' + p.reasons.map(function (r) { return '<span>' + icon('check') + esc(r) + '</span>'; }).join('') + '</div>' +
          '<p class="recommend">' + icon('bolt') + '<b>Recommended:</b> ' + esc(p.recommended) + ' <em>Playbook: ' + esc(p.playbook) + '</em></p></div>' : '') +
        '<div class="alert-actions"><button class="btn btn-xs" data-action="alert-status" data-id="' + esc(a.id) + '" data-status="triaged">Acknowledge</button>' +
        '<button class="btn btn-xs" data-action="alert-status" data-id="' + esc(a.id) + '" data-status="escalated">Escalate</button>' +
        '<button class="btn btn-xs" data-action="alert-status" data-id="' + esc(a.id) + '" data-status="contained">Mark contained</button>' +
        '<button class="btn btn-xs btn-ghost" data-action="alert-status" data-id="' + esc(a.id) + '" data-status="dismissed">Dismiss</button>' +
        '<span class="status-tag">' + statusPill(a.status) + '</span></div></div>';
    }).join('') : empty('No alerts in this filter.');

    return '<div class="page-head"><div><div class="eyebrow">ANALYSIS · TRIAGE</div><h1>Alert Triage</h1>' +
      '<p>Explainable priority scoring combines severity, confidence, asset criticality, correlated findings, watchlist hits and signal age.</p></div>' +
      '<div class="head-actions"><button class="btn btn-primary" data-action="auto-triage">' + icon('cpu') + ' Auto-triage all</button></div></div>' +
      '<div class="callout callout-info"><div class="callout-icon">' + icon('shield') + '</div><div><b>Containment is a workflow state only.</b>' +
      '<p>Marking an alert contained records a human decision in the ledger. No block, isolation or firewall change is ever executed by this application.</p></div></div>' +
      section('Queue', s.alerts.length + ' alerts · ' + s.alerts.filter(function (a) { return a.status === 'new'; }).length + ' awaiting triage',
        '<div class="filters">' + filters + '</div>', cards, 'panel-tight');
  };

  /* ---------------------------- IOC workbench --------------------------- */
  VIEWS_FUNC.intel = function () {
    var s = S.state;
    var r = s.intelResults;
    var iocs = r ? r.iocs : [];
    var rows = iocs.length ? iocs.map(function (i, idx) {
      var watched = s.watchlist.some(function (w) { return w.value === i.value && w.type === i.type; });
      return '<tr><td><span class="ioc-type">' + esc(i.type) + '</span></td><td><code>' + esc(i.defanged) + '</code></td>' +
        '<td>' + esc(i.note || '—') + '</td><td>' + (watched ? '<span class="pill pill-warn">WATCHLIST</span>' : '<span class="muted">—</span>') + '</td>' +
        '<td>' + (watched ? '<span class="muted">tracked</span>' : '<button class="btn btn-xs" data-action="add-watchlist" data-index="' + idx + '">Watch</button>') + '</td></tr>';
    }).join('') : '';
    var watch = s.watchlist.length ? s.watchlist.map(function (w) {
      return '<div class="watch-row"><span class="ioc-type">' + esc(w.type) + '</span><code>' + esc(w.defanged || w.value) + '</code>' +
        '<small>' + esc(rel(w.addedAt)) + '</small><button class="btn btn-xs btn-ghost" data-action="remove-watchlist" data-id="' + esc(w.id) + '">' + icon('x') + '</button></div>';
    }).join('') : empty('No local indicators tracked yet.');
    return '<div class="page-head"><div><div class="eyebrow">ANALYSIS · INDICATORS</div><h1>IOC Workbench</h1>' +
      '<p>Extract IPs, domains, URLs, hashes, emails and CVE IDs from unstructured text; defang them for safe sharing and correlate against a local watchlist.</p></div>' +
      '<div class="head-actions"><button class="btn btn-ghost" data-action="copy-defanged">' + icon('download') + ' Copy defanged list</button></div></div>' +
      '<div class="grid-2"><div class="col-main">' +
        section('Indicator source', 'Paste reports, logs, alerts or phishing headers',
          '<button class="btn btn-xs" data-action="load-sample" data-kind="intel">Load sample</button>',
          '<textarea class="code-area code-area-sm" data-draft="intel" spellcheck="false">' + esc(s.drafts.intel || '') + '</textarea>' +
          '<div class="form-actions"><button class="btn btn-primary" data-action="extract-intel">' + icon('target') + ' Extract indicators</button></div>') +
        section('Extracted indicators', r ? r.iocs.length + ' unique · ' + ts(r.at) : 'Awaiting input', '',
          r ? (rows ? '<div class="table-wrap"><table class="table"><thead><tr><th>TYPE</th><th>DEFANGED VALUE</th><th>CONTEXT</th><th>MATCH</th><th></th></tr></thead><tbody>' + rows + '</tbody></table></div>' : empty('No indicators found in the supplied text.')) : empty('Run extraction to see defanged indicators.')) +
      '</div><div class="col-side">' +
        section('Local watchlist', s.watchlist.length + ' tracked indicators', '<span class="tag">LOCAL ONLY</span>', watch) +
        section('Handling policy', 'Safe by design', '',
          '<ul class="policy-list compact"><li>' + icon('check') + '<span><b>Defanged by default</b><small>Dots and schemes neutralised for sharing.</small></span></li>' +
          '<li>' + icon('check') + '<span><b>No reputation lookup</b><small>No third-party service is queried.</small></span></li>' +
          '<li>' + icon('check') + '<span><b>Local correlation only</b><small>Watchlist matches feed the triage score.</small></span></li></ul>') +
      '</div></div>';
  };

  /* ----------------------------- playbooks ------------------------------ */
  VIEWS_FUNC.playbooks = function () {
    var s = S.state;
    var cards = DATA.PLAYBOOKS.map(function (p) {
      var prog = s.playbookProgress[p.id] || new Array(p.steps.length).fill(false);
      var done = prog.filter(Boolean).length;
      return '<div class="pb-card"><div class="pb-head"><div><div class="pb-fn">' + esc(p.function) + ' · ' + esc(p.owner) + '</div><h3>' + esc(p.name) + '</h3></div>' + sevPill(p.severity) + '</div>' +
        '<div class="pb-prog"><div class="pb-track"><span style="width:' + Math.round(done / p.steps.length * 100) + '%"></span></div><b>' + done + '/' + p.steps.length + '</b></div>' +
        '<div class="pb-steps">' + p.steps.map(function (st, i) {
          return '<button class="pb-step ' + (prog[i] ? 'done' : '') + '" data-action="toggle-step" data-id="' + esc(p.id) + '" data-index="' + i + '">' +
            '<span class="pb-check">' + (prog[i] ? icon('check') : String(i + 1)) + '</span><span>' + esc(st) + '</span></button>';
        }).join('') + '</div></div>';
    }).join('');
    return '<div class="page-head"><div><div class="eyebrow">GOVERNANCE · RESPONSE</div><h1>Response Playbooks</h1>' +
      '<p>Trackable incident response checklists mapped to NIST CSF functions. Progress is persisted locally and sealed in the ledger on completion.</p></div></div>' +
      '<div class="pb-grid">' + cards + '</div>';
  };

  /* ---------------------------- compliance ------------------------------ */
  VIEWS_FUNC.compliance = function () {
    var s = S.state, c = E.complianceState(s);
    var counts = countBy(c, 'status');
    var impl = counts.implemented || 0, part = counts.partial || 0, gap = counts.gap || 0;
    var coverage = Math.round((impl + part * 0.5) / c.length * 100);
    var parts = [{ key: 'implemented', value: impl }, { key: 'partial', value: part }, { key: 'gap', value: gap }];
    var fns = ['GOVERN', 'IDENTIFY', 'PROTECT', 'DETECT', 'RESPOND'].map(function (f) {
      var group = c.filter(function (x) { return x.fn === f; });
      var score = group.reduce(function (n, x) { return n + (x.status === 'implemented' ? 1 : x.status === 'partial' ? 0.5 : 0); }, 0);
      return { f: f, score: score, max: group.length };
    });
    var rows = c.map(function (x) {
      return '<tr><td><code>' + esc(x.id) + '</code></td><td>' + esc(x.framework) + '</td><td><b>' + esc(x.title) + '</b><small class="block">' + esc(x.hint) + '</small></td>' +
        '<td><span class="fn">' + esc(x.fn) + '</span></td><td>' + statusPill(x.status) + '</td></tr>';
    }).join('');
    return '<div class="page-head"><div><div class="eyebrow">GOVERNANCE · CONTROL COVERAGE</div><h1>Control Coverage</h1>' +
      '<p>Live control evaluation against CIS Controls v8, NIST CSF 2.0 and MITRE ATT&CK, derived from the evidence recorded in this session.</p></div></div>' +
      '<div class="grid-2"><div class="col-side">' +
        section('Coverage', coverage + '% effective coverage', '', '<div class="donut-row">' +
          donut(parts, coverage + '%', 'coverage') + '<div class="donut-legend">' + parts.map(function (p) {
            return '<div><span class="dot dot-' + esc(p.key) + '"></span>' + esc(p.key) + '<b>' + p.value + '</b></div>';
          }).join('') + '</div></div>') +
        section('NIST CSF functions', 'Implementation by function', '', fns.map(function (x) {
          return bar(x.f, x.score, x.max || 1, x.score === x.max ? '#38e8c2' : '#ffd166');
        }).join('')) +
      '</div><div class="col-main">' +
        section('Control matrix', c.length + ' controls evaluated from session evidence', '',
          '<div class="table-wrap"><table class="table"><thead><tr><th>ID</th><th>FRAMEWORK</th><th>CONTROL</th><th>FUNCTION</th><th>STATUS</th></tr></thead><tbody>' + rows + '</tbody></table></div>') +
      '</div></div>';
  };

  /* ------------------------------ audit --------------------------------- */
  VIEWS_FUNC.audit = function () {
    var s = S.state, v = E.verifyChain(s.audit);
    var rows = s.audit.slice().reverse().map(function (e) {
      return '<tr><td><code>#' + e.seq + '</code></td><td>' + esc(ts(e.ts)) + '</td><td>' + esc(e.actor) + '</td>' +
        '<td><b>' + esc(e.action) + '</b></td><td><code>' + esc(e.target) + '</code></td><td>' + statusPill(e.decision) + '</td>' +
        '<td class="detail-cell">' + esc(e.detail) + '</td><td><code title="' + esc(e.hash) + '">' + short(e.hash, 10) + '</code></td></tr>';
    }).join('');
    return '<div class="page-head"><div><div class="eyebrow">GOVERNANCE · ASSURANCE</div><h1>Audit Ledger</h1>' +
      '<p>SHA-256 hash chain. Each entry commits to its own content and the previous hash, making edits or deletions detectable.</p></div>' +
      '<div class="head-actions"><button class="btn btn-primary" data-action="verify-chain">' + icon('chain') + ' Verify chain</button></div></div>' +
      '<div class="callout ' + (v.valid ? 'callout-ok' : 'callout-bad') + '"><div class="callout-icon">' + icon(v.valid ? 'check' : 'alert') + '</div>' +
      '<div><b>' + (v.valid ? 'CHAIN INTACT' : 'CHAIN BROKEN AT #' + v.brokenAt) + '</b><p>' +
      (v.valid ? v.count + ' entries verified · head <code>' + short(v.head, 24) + '</code>' : esc(v.reason)) +
      '</p></div></div>' +
      section('Immutable decision log', 'Newest first · every action, allow and refusal', '<span class="tag">APPEND-ONLY</span>',
        '<div class="table-wrap table-tall"><table class="table"><thead><tr><th>SEQ</th><th>TIME</th><th>ACTOR</th><th>ACTION</th><th>TARGET</th><th>DECISION</th><th>DETAIL</th><th>HASH</th></tr></thead><tbody>' + rows + '</tbody></table></div>');
  };

  /* ------------------------------ policy -------------------------------- */
  VIEWS_FUNC.policy = function () {
    var s = S.state, v = E.verifyChain(s.audit);
    return '<div class="page-head"><div><div class="eyebrow">GOVERNANCE · RULES OF ENGAGEMENT</div><h1>Rules of Engagement</h1>' +
      '<p>The operating contract for this agent. These constraints are enforced in code, not just written here.</p></div></div>' +
      '<div class="grid-2"><div class="col-main">' +
        section('Authorized-only design', 'What this platform will and will not do', '',
          '<div class="roe-grid"><div class="roe roe-ok"><h3>' + icon('check') + ' IN SCOPE</h3><ul>' +
          '<li>Analyzing logs, headers and text you paste, entirely in-browser</li>' +
          '<li>Assessing assets registered with a signed authorization record</li>' +
          '<li>Explainable alert triage, mitigation guidance and playbooks</li>' +
          '<li>Defanged IOC extraction and local correlation</li>' +
          '<li>Tamper-evident logging of every decision</li></ul></div>' +
          '<div class="roe roe-no"><h3>' + icon('x') + ' OUT OF SCOPE</h3><ul>' +
          '<li>Any activity against systems without documented authorization</li>' +
          '<li>Network scanning, probing, exploitation or payload delivery</li>' +
          '<li>Credential attacks, persistence, evasion or lateral movement</li>' +
          '<li>Autonomous containment of external systems</li>' +
          '<li>Exfiltrating operator data to any third-party service</li></ul></div></div>' +
          '<div class="callout callout-info"><div class="callout-icon">' + icon('file') + '</div><div><b>Honesty about the demo data</b>' +
          '<p>Baseline assets, alerts, findings and the activity chart are simulated sample records. Autonomous sweep findings come from a local template catalog and are labelled SIM. The log analyzer, header analyzer, IOC extractor, triage scorer and audit hash-chain are real deterministic code.</p></div></div>') +
        section('Operator settings', 'Session configuration', '',
          '<form data-form="operator" class="form-grid">' +
          '<label class="field"><span>Operator identity <em>written to the ledger</em></span><input name="operator" value="' + esc(s.settings.operator) + '"></label>' +
          '<label class="field"><span>Human approval for containment</span><select name="humanApproval"><option value="true" ' + (s.settings.humanApproval ? 'selected' : '') + '>Required (recommended)</option><option value="false" ' + (!s.settings.humanApproval ? 'selected' : '') + '>Advisory only</option></select></label>' +
          '<div class="field field-wide"><span>Strict scope enforcement</span><div class="locked">' + icon('lock') + ' <b>LOCKED ON</b> — cannot be disabled. Signature, expiry and permitted-check validation run before every agent action.</div></div>' +
          '<div class="form-actions field-wide"><button class="btn btn-primary" type="submit">Save settings</button></div></form>') +
      '</div><div class="col-side">' +
        section('Session data', 'Everything stays in this browser', '',
          '<p class="muted small">State is stored in localStorage under <code>aegis.sentinel.state.v1</code>. No account, no backend, no telemetry.</p>' +
          '<div class="data-actions"><button class="btn btn-xs" data-action="export-state">' + icon('download') + ' Export JSON</button>' +
          '<button class="btn btn-xs" data-action="import-state">' + icon('file') + ' Import JSON</button>' +
          '<button class="btn btn-xs btn-danger" data-action="reset-state">' + icon('x') + ' Reset session</button></div>' +
          '<div class="mini-stats"><div><b>' + s.assets.length + '</b><span>ASSETS</span></div><div><b>' + s.findings.length + '</b><span>FINDINGS</span></div>' +
          '<div><b>' + s.alerts.length + '</b><span>ALERTS</span></div><div><b>' + s.audit.length + '</b><span>LEDGER</span></div></div>') +
        section('Integrity', 'Ledger status', '',
          '<div class="integrity ' + (v.valid ? 'ok' : 'bad') + '">' + icon(v.valid ? 'check' : 'alert') +
          '<div><b>' + (v.valid ? 'VERIFIED' : 'BROKEN') + '</b><small>' + v.count + ' chained entries</small></div></div>' +
          '<p class="muted small">Verification recomputes every SHA-256 hash from the canonical entry fields and checks each <code>prevHash</code> link.</p>') +
        section('Architecture', 'Deployment footprint', '',
          '<ul class="policy-list compact"><li>' + icon('check') + '<span><b>Static, zero-dependency</b><small>Plain HTML, CSS and JavaScript. No build-time services.</small></span></li>' +
          '<li>' + icon('check') + '<span><b>No backend, no secrets</b><small>No API keys or credentials in the client.</small></span></li>' +
          '<li>' + icon('check') + '<span><b>No network egress</b><small>No fetch, WebSocket or external resource in the application.</small></span></li></ul>') +
      '</div></div>';
  };

  function assetOptions(checkType) {
    var s = S.state;
    var act = E.activeAssets(s).filter(function (a) {
      return !checkType || (a.checks || []).indexOf(checkType) !== -1;
    });
    if (!act.length) return '<option value="">No in-scope asset permits this check</option>';
    var selected = act.some(function (a) { return a.name === ui.selectedAsset; }) ? ui.selectedAsset : act[0].name;
    return act.map(function (a) {
      return '<option value="' + esc(a.name) + '" ' + (a.name === selected ? 'selected' : '') + '>' + esc(a.name) + '</option>';
    }).join('');
  }

  /* ------------------------------ overlays ------------------------------ */
  function toast(msg, kind) {
    var box = $('toasts');
    if (!box) return;
    var d = doc.createElement('div');
    d.className = 'toast toast-' + (kind || 'info');
    d.innerHTML = icon(kind === 'bad' ? 'alert' : kind === 'ok' ? 'check' : 'bolt') + '<span>' + esc(msg) + '</span>';
    box.appendChild(d);
    root.setTimeout(function () { d.classList.add('out'); root.setTimeout(function () { d.remove(); }, 300); }, 3400);
  }
  function modal(title, body, footer) {
    ui.modal = { title: title, body: body, footer: footer || '' };
    renderModal();
  }
  function renderModal() {
    var host = $('modal-root');
    if (!host) return;
    if (!ui.modal) { host.innerHTML = ''; return; }
    host.innerHTML = '<div class="modal-backdrop" data-action="close-modal"><div class="modal" role="dialog" aria-modal="true" aria-label="' + esc(ui.modal.title) + '" data-stop="1">' +
      '<div class="modal-head"><h2>' + esc(ui.modal.title) + '</h2><button class="icon-btn" data-action="close-modal" aria-label="Close">' + icon('x') + '</button></div>' +
      '<div class="modal-body">' + ui.modal.body + '</div>' +
      (ui.modal.footer ? '<div class="modal-foot">' + ui.modal.footer + '</div>' : '') + '</div></div>';
  }
  function closeModal() { ui.modal = null; renderModal(); }

  var COMMANDS = [];
  function buildCommands() {
    COMMANDS = NAV.flatMap(function (g) { return g.items; }).map(function (i) {
      return { label: 'Go to ' + i.label, hint: i.group || 'NAVIGATE', icon: i.icon, run: function () { navigate(i.id); } };
    }).concat([
      { label: 'Run autonomous sweep (all in-scope assets)', hint: 'AGENT', icon: 'bolt', run: function () { navigate('agent'); runSweep(null); } },
      { label: 'Test out-of-scope refusal', hint: 'AGENT', icon: 'shield', run: probeUnauthorized },
      { label: 'Auto-triage alert queue', hint: 'ANALYZE', icon: 'target', run: function () { autoTriage(); } },
      { label: 'Analyze sample telemetry', hint: 'ANALYZE', icon: 'wave', run: function () { navigate('logs'); analyzeLogs(); } },
      { label: 'Evaluate HTTP hardening', hint: 'ANALYZE', icon: 'lock', run: function () { navigate('headers'); analyzeHeaders(); } },
      { label: 'Extract indicators', hint: 'ANALYZE', icon: 'target', run: function () { navigate('intel'); extractIntel(); } },
      { label: 'Verify audit hash chain', hint: 'GOVERN', icon: 'chain', run: function () { navigate('audit'); verifyChain(); } },
      { label: 'Export session / report', hint: 'GOVERN', icon: 'download', run: exportState },
      { label: 'Open executive summary', hint: 'GOVERN', icon: 'file', run: executiveSummary }
    ].concat(EXTRA_COMMANDS));
  }
  function filteredCommands() {
    var q = ui.paletteQuery.toLowerCase();
    return COMMANDS.filter(function (c) { return !q || c.label.toLowerCase().indexOf(q) !== -1 || c.hint.toLowerCase().indexOf(q) !== -1; });
  }
  function renderPalette() {
    var host = $('palette-root');
    if (!host) return;
    if (!ui.palette) { host.innerHTML = ''; return; }
    var list = filteredCommands();
    ui.paletteIndex = Math.min(ui.paletteIndex, Math.max(0, list.length - 1));
    host.innerHTML = '<div class="palette-backdrop" data-action="palette-close"><div class="palette" data-stop="1">' +
      '<div class="palette-input">' + icon('search') + '<input id="palette-input" placeholder="Search commands, views, actions…" value="' + esc(ui.paletteQuery) + '" autocomplete="off"><kbd>ESC</kbd></div>' +
      '<div class="palette-list">' + (list.length ? list.map(function (c, i) {
        return '<button class="palette-item ' + (i === ui.paletteIndex ? 'sel' : '') + '" data-action="palette-run" data-index="' + i + '">' +
          icon(c.icon) + '<span>' + esc(c.label) + '</span><small>' + esc(c.hint) + '</small></button>';
      }).join('') : '<div class="empty"><p>No matching command</p></div>') + '</div>' +
      '<div class="palette-foot"><span>↑↓ navigate</span><span>↵ run</span><span>esc close</span><span>' + filteredCommands().length + ' commands</span></div></div></div>';
    var inp = $('palette-input');
    if (inp) {
      if (doc.activeElement !== inp) inp.focus();
      try { inp.setSelectionRange(inp.value.length, inp.value.length); } catch (e) {}
    }
  }
  function openPalette() { ui.palette = true; ui.paletteQuery = ''; ui.paletteIndex = 0; renderPalette(); }

  /* ------------------------------ actions ------------------------------- */
  function navigate(id) {
    if (!VIEWS[id] && !VIEWS_FUNC[id]) return;
    ui.view = id; ui.palette = false; ui.modal = null;
    render();
  }
  function render() {
    var host = $('app');
    if (!host) return;
    host.innerHTML = shell();
    renderModal(); renderPalette();
    root.scrollTo && root.scrollTo(0, 0);
  }
  function renderView() { var v = $('view'); if (v) v.innerHTML = view(); }
  function sleep(ms) { return new Promise(function (r) { root.setTimeout(r, ms); }); }

  function trace(tag, text, kind) {
    ui.sweepLines.push({ t: ts(Date.now()).slice(-8), tag: tag, text: text, kind: kind || 'info' });
    if (ui.sweepLines.length > 60) ui.sweepLines.shift();
  }

  async function runSweep(targets) {
    if (ui.sweepRunning) return;
    var s = S.state;
    ui.sweepRunning = true; s.sweep.running = true;
    navigateSafe('agent');
    var all = E.activeAssets(s).map(function (a) { return a.name; });
    var list = targets && targets.length ? targets : all;
    trace('BOOT', 'Agent dispatch received. Policy engine v1.0.0 initializing.', 'info');
    trace('GATE', 'Strict scope enforcement: ON. Passive-only mode: ON.', 'ok');
    renderViewSafe(); await sleep(190);

    // Include expired / unattested assets so the refusal path is visible.
    var requested = (targets && targets.length) ? targets : s.assets.map(function (a) { return a.name; });
    requested.forEach(function (name) {
      var g = E.scopeCheck(s, name, 'posture');
      trace(g.allowed ? 'ALLOW' : 'REFUSE', name + ' → ' + g.code + ': ' + g.reason, g.allowed ? 'ok' : 'bad');
    });
    renderViewSafe(); await sleep(260);

    var result = E.simulateSweep(s, s.sweep.count + 1, requested);
    trace('MODEL', 'Local posture model evaluated ' + result.decisions.filter(function (d) { return d.decision === 'ALLOWED'; }).length +
      ' in-scope asset(s); ' + result.findings.length + ' simulated candidate finding(s).', 'info');
    renderViewSafe(); await sleep(260);
    var added = S.applySweep(result, requested);
    s.sweep.decisions = result.decisions;
    S.save();
    trace('LEDGER', 'Decision trace sealed. ' + added + ' new finding(s) persisted.', 'ok');
    trace('DONE', 'Sweep complete. No network request was made at any stage.', 'ok');
    ui.sweepRunning = false; s.sweep.running = false;
    render();
    toast('Sweep complete — ' + added + ' finding(s), ' + result.decisions.filter(function (d) { return d.decision === 'REFUSED'; }).length + ' refusal(s).', 'ok');
  }
  function navigateSafe(id) { if (ui.view !== id) { ui.view = id; render(); } }
  function renderViewSafe() { if (ui.view === 'agent') renderView(); }

  function probeUnauthorized() {
    var s = S.state;
    var target = 'unauthorized-third-party.example';
    var g = E.scopeCheck(s, target, 'posture');
    S.audit('AGENT_REFUSAL', target, g.code, g.reason + ' No connection attempted.');
    S.event('refuse', 'REFUSED ' + target + ' — ' + g.code + '. No connection attempted.');
    S.save();
    trace('REFUSE', target + ' → ' + g.code + ': ' + g.reason, 'bad');
    trace('POLICY', 'Action blocked before execution. Decision written to ledger.', 'bad');
    if (ui.view !== 'agent') navigate('agent');
    else render();
    modal('Action refused', '<div class="refusal">' + icon('shield') + '<div><h3>' + esc(g.code) + '</h3><p>' + esc(g.reason) + '</p>' +
      '<p class="muted">The agent will not scan, probe or otherwise interact with <code>' + esc(target) + '</code>. This refusal is now entry #' + s.audit.length + ' in the tamper-evident ledger.</p>' +
      '<div class="refusal-code"><span>DECISION</span><code>REFUSED</code><span>TARGET</span><code>' + esc(target) + '</code><span>CONNECTIONS</span><code>0</code></div></div></div>',
      '<button class="btn btn-primary" data-action="close-modal">Understood</button>');
    toast('Agent refused out-of-scope target and logged the decision.', 'bad');
  }

  function analyzeLogs() {
    var s = S.state;
    var text = s.drafts.logs || '';
    if (!text.trim()) { toast('Paste telemetry first.', 'bad'); return; }
    var sel = $('log-asset');
    var target = sel ? sel.value : (E.activeAssets(s)[0] || {}).name;
    if (!target) { toast('Register an in-scope asset with log analysis permitted first.', 'bad'); return; }
    var gate = E.scopeCheck(s, target, 'logs');
    if (!gate.allowed) { refusedModal(target, gate, 'logs'); return; }
    var result = E.detectLogs(text);
    var created = S.applyLogResults(result, target);
    toast(result.detections.length + ' detection(s), ' + result.iocs.length + ' IOC(s), ' + created + ' new alert(s).', 'ok');
    render();
  }
  function analyzeHeaders() {
    var s = S.state;
    var text = s.drafts.headers || '';
    if (!text.trim()) { toast('Paste response headers first.', 'bad'); return; }
    var sel = $('header-asset');
    var target = sel ? sel.value : (E.activeAssets(s)[0] || {}).name;
    if (!target) { toast('Register an in-scope asset with header analysis permitted first.', 'bad'); return; }
    var gate = E.scopeCheck(s, target, 'headers');
    if (!gate.allowed) { refusedModal(target, gate, 'headers'); return; }
    var result = E.analyzeHeaders(text);
    S.applyHeaderResults(result, target);
    toast('Hardening grade ' + result.grade + ' (' + result.score + '/100).', result.score < 60 ? 'bad' : 'ok');
    render();
  }
  function extractIntel() {
    var s = S.state;
    var text = s.drafts.intel || '';
    if (!text.trim()) { toast('Paste text to extract indicators.', 'bad'); return; }
    var iocs = E.extractIOCs(text);
    S.applyIntelResults(iocs, 'operator-supplied text');
    toast(iocs.length + ' unique indicator(s) extracted and defanged.', 'ok');
    render();
  }
  function refusedModal(target, gate, check) {
    S.audit('ANALYSIS_REFUSED', target, gate.code, gate.reason + ' Check type: ' + check + '.');
    S.event('refuse', 'REFUSED analysis for ' + target + ' — ' + gate.code + '.');
    S.save();
    modal('Scope check failed', '<div class="refusal">' + icon('shield') + '<div><h3>' + esc(gate.code) + '</h3><p>' + esc(gate.reason) + '</p>' +
      '<p class="muted">Register an authorization record that permits <b>' + esc(check) + '</b> for this asset before retrying. No analysis was performed.</p></div></div>',
      '<button class="btn btn-primary" data-action="close-modal">Close</button>');
    toast('Scope check failed: ' + gate.code, 'bad');
  }
  function autoTriage() {
    var n = S.autoTriageAll();
    toast(n ? n + ' alert(s) triaged with explainable scoring.' : 'All alerts were already triaged.', 'ok');
    render();
  }
  function verifyChain() {
    var v = E.verifyChain(S.state.audit);
    S.audit('CHAIN_VERIFY', 'aegis/ledger', v.valid ? 'VALID' : 'BROKEN',
      v.valid ? v.count + ' entries recomputed and verified.' : 'Broken at #' + v.brokenAt + ': ' + v.reason);
    S.save();
    toast(v.valid ? 'Hash chain verified: ' + v.count + ' entries intact.' : 'Chain broken at #' + v.brokenAt, v.valid ? 'ok' : 'bad');
    render();
  }
  function download(name, text, type) {
    var blob = new Blob([text], { type: type || 'application/json' });
    var a = doc.createElement('a');
    a.href = URL.createObjectURL(blob); a.download = name;
    doc.body.appendChild(a); a.click();
    root.setTimeout(function () { URL.revokeObjectURL(a.href); a.remove(); }, 1000);
  }
  function copy(text) {
    if (root.navigator && root.navigator.clipboard) {
      root.navigator.clipboard.writeText(text).then(function () { toast('Copied to clipboard.', 'ok'); },
        function () { toast('Clipboard unavailable — use export instead.', 'bad'); });
    } else toast('Clipboard unavailable in this context.', 'bad');
  }
  function exportState() {
    download('aegis-report-' + new Date().toISOString().slice(0, 10) + '.json', S.exportState());
    S.audit('REPORT_EXPORT', 'aegis/state', 'EXPORTED', 'Full session state and ledger exported as JSON.'); S.save();
    toast('Report exported.', 'ok');
  }
  function executiveSummary() {
    var s = S.state, risk = E.riskScore(s), c = E.complianceState(s), v = E.verifyChain(s.audit);
    var open = s.findings.filter(function (f) { return f.status === 'open'; });
    var body = '<div class="summary"><div class="summary-hero"><div><span>COMPOSITE RISK INDEX</span><b>' + risk + '</b><small>/ 100</small></div>' +
      '<div><span>CONTROL COVERAGE</span><b>' + Math.round(c.filter(function (x) { return x.status === 'implemented'; }).length / c.length * 100) + '%</b><small>implemented</small></div>' +
      '<div><span>LEDGER</span><b>' + (v.valid ? 'VALID' : 'BROKEN') + '</b><small>' + s.audit.length + ' entries</small></div></div>' +
      '<h3>Posture</h3><p>' + E.activeAssets(s).length + ' of ' + s.assets.length + ' registered assets are within a valid authorization window. ' +
      open.length + ' findings remain open, including ' + open.filter(function (f) { return f.severity === 'critical'; }).length + ' at critical severity. ' +
      s.alerts.filter(function (a) { return a.status === 'new'; }).length + ' alerts await triage.</p>' +
      '<h3>Top actions</h3><ol>' + open.slice().sort(function (a, b) { return E.sevRank(b.severity) - E.sevRank(a.severity); }).slice(0, 5).map(function (f) {
        return '<li><b>' + esc(f.title) + '</b> — ' + esc(f.asset) + ' <span class="muted">(' + esc(f.remediation) + ')</span></li>';
      }).join('') + '</ol>' +
      '<h3>Assurance</h3><p>' + (s.headerResults ? 'Last hardening analysis graded ' + s.headerResults.grade + ' (' + s.headerResults.score + '/100). ' : 'No hardening analysis recorded. ') +
      (s.logResults ? s.logResults.detections.length + ' detections from ' + s.logResults.stats.lines + ' log lines. ' : 'No telemetry analyzed. ') +
      'All decisions are chained with SHA-256 and verification is ' + (v.valid ? 'passing' : 'failing') + '.</p>' +
      '<p class="muted small">Baseline records and sweep output are simulated. Analytic engines, scope enforcement and the ledger are real.</p></div>';
    modal('Executive summary', body, '<button class="btn btn-ghost" data-action="export-state">' + icon('download') + ' Export JSON</button><button class="btn btn-primary" data-action="close-modal">Close</button>');
  }
  function findingDetail(id) {
    var f = S.state.findings.filter(function (x) { return x.id === id; })[0];
    if (!f) return;
    var body = '<div class="detail">' + sevPill(f.severity) + '<h3>' + esc(f.title) + '</h3>' +
      '<div class="detail-grid"><div><span>ASSET</span><code>' + esc(f.asset) + '</code></div><div><span>CATEGORY</span><b>' + esc(f.category) + '</b></div>' +
      '<div><span>MITRE ATT&CK</span><b>' + esc(f.mitre) + '</b></div><div><span>CONFIDENCE</span><b>' + (f.confidence || '—') + '%</b></div>' +
      '<div><span>SOURCE</span><b>' + esc(f.source) + (f.simulated ? ' (SIMULATED)' : '') + '</b></div><div><span>STATUS</span>' + statusPill(f.status) + '</div></div>' +
      '<h4>Evidence</h4><p>' + esc(f.evidence) + '</p><h4>Remediation</h4><p>' + esc(f.remediation) + '</p>' +
      (f.simulated ? '<p class="muted small">This is an illustrative finding from the local template catalog, not a live measurement.</p>' : '') + '</div>';
    modal('Finding detail', body, '<button class="btn btn-primary" data-action="close-modal">Close</button>');
  }

  /* --------------------------- event wiring ----------------------------- */
  function onClick(ev) {
    var t = ev.target.closest('[data-action]');
    if (!t) return;
    var a = t.getAttribute('data-action');
    var s = S.state;
    // Clicks that land inside a dialog/panel must not trigger its backdrop action.
    if (t.classList.contains('modal-backdrop') || t.classList.contains('palette-backdrop')) {
      if (ev.target !== t) return;
      if (a === 'close-modal') { closeModal(); return; }
      if (a === 'palette-close') { ui.palette = false; renderPalette(); return; }
    }
    if (ACTION_HANDLERS[a]) { ACTION_HANDLERS[a](t, ev, s); return; }
    switch (a) {
      case 'nav': navigate(t.getAttribute('data-view')); break;
      case 'palette-open': openPalette(); break;
      case 'palette-close': ui.palette = false; renderPalette(); break;
      case 'palette-run': {
        var list = filteredCommands(); var c = list[Number(t.getAttribute('data-index'))];
        ui.palette = false; renderPalette();
        if (c) c.run();
        break;
      }
      case 'close-modal': closeModal(); break;
      case 'run-sweep': runSweep(null); break;
      case 'run-sweep-target': {
        var sel = $('sweep-target'); var name = sel ? sel.value : '';
        if (!name) { toast('No authorized assets available.', 'bad'); break; }
        ui.selectedAsset = name; runSweep([name]); break;
      }
      case 'probe-unauth': probeUnauthorized(); break;
      case 'analyze-logs': analyzeLogs(); break;
      case 'analyze-headers': analyzeHeaders(); break;
      case 'extract-intel': extractIntel(); break;
      case 'auto-triage': autoTriage(); break;
      case 'verify-chain': verifyChain(); break;
      case 'export-state': exportState(); break;
      case 'exec-summary': executiveSummary(); break;
      case 'finding-detail': findingDetail(t.getAttribute('data-id')); break;
      case 'load-sample': {
        var kind = t.getAttribute('data-kind');
        var val = kind === 'headers' ? DATA.SAMPLE_HEADERS : kind === 'intel' ? DATA.SAMPLE_INTEL : DATA.SAMPLE_LOGS;
        S.setDraft(kind, val); render(); toast('Sample data loaded.', 'ok'); break;
      }
      case 'clear-draft': S.setDraft(t.getAttribute('data-key'), ''); render(); break;
      case 'revoke-asset': {
        var nm = t.getAttribute('data-name');
        var res = S.revokeAsset(nm);
        if (res.ok) { toast('Authorization revoked for ' + nm, 'bad'); render(); }
        break;
      }
      case 'alert-status': {
        var note = t.getAttribute('data-status') === 'contained' ? 'workflow only; no external action' : '';
        S.setAlertStatus(t.getAttribute('data-id'), t.getAttribute('data-status'), note);
        toast('Alert updated and logged.', 'ok'); render(); break;
      }
      case 'alert-filter': ui.alertFilter = t.getAttribute('data-value'); render(); break;
      case 'add-watchlist': {
        var idx = Number(t.getAttribute('data-index'));
        var ioc = (s.intelResults && s.intelResults.iocs[idx]) || null;
        if (ioc) { var okAdd = S.addWatchlist(ioc); toast(okAdd ? 'Indicator added to watchlist.' : 'Already tracked.', okAdd ? 'ok' : 'info'); render(); }
        break;
      }
      case 'remove-watchlist': S.removeWatchlist(t.getAttribute('data-id')); render(); break;
      case 'toggle-step': S.togglePlaybookStep(t.getAttribute('data-id'), Number(t.getAttribute('data-index'))); render(); break;
      case 'copy-defanged': {
        var list2 = s.intelResults ? s.intelResults.iocs.map(function (i) { return i.defanged; }).join('\n') : '';
        if (!list2) { toast('Extract indicators first.', 'bad'); break; }
        copy(list2); break;
      }
      case 'copy-hardened': copy(
        "Strict-Transport-Security: max-age=31536000; includeSubDomains\n" +
        "Content-Security-Policy: default-src 'self'; object-src 'none'; frame-ancestors 'none'\n" +
        "X-Content-Type-Options: nosniff\nReferrer-Policy: strict-origin-when-cross-origin\n" +
        "Permissions-Policy: camera=(), microphone=(), geolocation=()\n" +
        "Cross-Origin-Opener-Policy: same-origin\nCross-Origin-Resource-Policy: same-origin\nCache-Control: no-store");
        break;
      case 'import-state': {
        modal('Import state', '<p class="muted">Paste a previously exported AEGIS JSON state file. The imported ledger must contain a valid chain.</p>' +
          '<form data-form="import"><textarea class="code-area code-area-sm" name="json" placeholder="{ … }"></textarea>' +
          '<div class="form-actions"><button class="btn btn-primary" type="submit">Import</button></div></form>',
          '');
        break;
      }
      case 'reset-state': {
        modal('Reset session', '<div class="refusal">' + icon('alert') + '<div><h3>Reset all local data?</h3>' +
          '<p class="muted">This clears assets, findings, alerts and the audit ledger from this browser and reloads the simulated baseline. This cannot be undone.</p></div></div>',
          '<button class="btn btn-ghost" data-action="close-modal">Cancel</button><button class="btn btn-danger" data-action="confirm-reset">Reset</button>');
        break;
      }
      case 'confirm-reset': S.reset(); closeModal(); render(); toast('Session reset to baseline.', 'ok'); break;
    }
  }
  function onSubmit(ev) {
    var form = ev.target.closest('[data-form]');
    if (!form) return;
    ev.preventDefault();
    var kind = form.getAttribute('data-form');
    var fd = new FormData(form);
    if (FORM_HANDLERS[kind]) { FORM_HANDLERS[kind](form, fd); return; }
    if (kind === 'asset') {
      var payload = {
        name: fd.get('name'), type: fd.get('type'), owner: fd.get('owner'),
        authorizedBy: fd.get('authorizedBy'), env: fd.get('env'), criticality: fd.get('criticality'),
        days: fd.get('days'), confirmed: fd.get('confirmed') === 'on',
        checks: fd.getAll('checks')
      };
      var res = S.addAsset(payload);
      if (!res.ok) { toast(res.error, 'bad'); return; }
      S.setDraft('asset', ''); S.setDraft('owner', ''); S.setDraft('authorizedBy', '');
      toast('Scope signed for ' + res.asset.name + '.', 'ok'); render();
    } else if (kind === 'operator') {
      S.setSetting('operator', String(fd.get('operator') || 'analyst@local'));
      S.setSetting('humanApproval', fd.get('humanApproval') === 'true');
      toast('Settings saved and logged.', 'ok'); render();
    } else if (kind === 'import') {
      try { S.importState(String(fd.get('json') || '')); closeModal(); render(); toast('State imported.', 'ok'); }
      catch (e) { toast('Import failed: ' + e.message, 'bad'); }
    }
  }
  function onInput(ev) {
    var t = ev.target;
    if (t.hasAttribute && t.hasAttribute('data-draft')) S.setDraft(t.getAttribute('data-draft'), t.value);
    if (t.id === 'palette-input') { ui.paletteQuery = t.value; ui.paletteIndex = 0; renderPalette(); }
  }
  function onChange(ev) {
    var t = ev.target;
    if (t.id === 'sweep-target') ui.selectedAsset = t.value;
    if (t.name === 'checks') {
      S.state.drafts.checks = Array.from(doc.querySelectorAll('input[name="checks"]:checked')).map(function (x) { return x.value; });
      S.save();
    }
  }
  function onKeydown(ev) {
    var k = ev.key;
    if ((ev.ctrlKey || ev.metaKey) && k.toLowerCase() === 'k') { ev.preventDefault(); ui.palette ? (ui.palette = false, renderPalette()) : openPalette(); return; }
    if (k === 'Escape') { if (ui.palette) { ui.palette = false; renderPalette(); } else if (ui.modal) closeModal(); return; }
    if (ui.palette) {
      var list = filteredCommands();
      if (k === 'ArrowDown') { ev.preventDefault(); ui.paletteIndex = Math.min(list.length - 1, ui.paletteIndex + 1); renderPalette(); }
      else if (k === 'ArrowUp') { ev.preventDefault(); ui.paletteIndex = Math.max(0, ui.paletteIndex - 1); renderPalette(); }
      else if (k === 'Enter') { ev.preventDefault(); var c = list[ui.paletteIndex]; ui.palette = false; renderPalette(); if (c) c.run(); }
      return;
    }
    if (ev.altKey && !ev.ctrlKey && !ev.metaKey) {
      var found = null;
      NAV.forEach(function (g) { g.items.forEach(function (i) { if (i.key === k.toUpperCase()) found = i.id; }); });
      if (found) { ev.preventDefault(); navigate(found); }
    }
  }

  /* Public extension API. Loaded synchronously by 40-ui2.js before boot(). */
  root.AEGIS_UI = {
    DATA: DATA, E: E, S: S, ui: ui, $: $, doc: doc,
    h: {
      esc: esc, icon: icon, ts: ts, rel: rel, day: day, sevPill: sevPill,
      statusPill: statusPill, section: section, kpi: kpi, bar: bar, donut: donut,
      empty: empty, areaChart: areaChart, activitySeries: activitySeries,
      countBy: countBy, short: short, sevRank: E.sevRank, assetOptions: assetOptions
    },
    modal: modal, closeModal: closeModal, toast: toast, navigate: navigate,
    render: render, renderView: renderView, download: download, copy: copy,
    trace: trace, sleep: sleep, executiveSummary: executiveSummary,
    registerNav: function (group, items) {
      var g = NAV.filter(function (x) { return x.group === group; })[0];
      if (!g) { g = { group: group, items: [] }; NAV.push(g); }
      items.forEach(function (i) { g.items.push(i); });
    },
    registerMeta: function (map) { Object.keys(map).forEach(function (k) { VIEWS[k] = map[k]; }); },
    registerView: function (id, fn) { VIEWS_FUNC[id] = fn; },
    getView: function (id) { return VIEWS_FUNC[id]; },
    registerAction: function (name, fn) { ACTION_HANDLERS[name] = fn; },
    registerForm: function (name, fn) { FORM_HANDLERS[name] = fn; },
    registerCommands: function (list) { list.forEach(function (c) { EXTRA_COMMANDS.push(c); }); }
  };

  function boot() {
    S.init();
    buildCommands();
    render();
    doc.addEventListener('click', onClick);
    doc.addEventListener('submit', onSubmit);
    doc.addEventListener('input', onInput);
    doc.addEventListener('change', onChange);
    doc.addEventListener('keydown', onKeydown);
    root.setInterval(function () {
      var c = $('clock'); if (c) c.textContent = ts(Date.now());
    }, 1000);
  }

  if (doc.readyState === 'loading') doc.addEventListener('DOMContentLoaded', boot);
  else boot();
})(typeof globalThis !== 'undefined' ? globalThis : this);
