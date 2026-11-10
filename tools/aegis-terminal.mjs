#!/usr/bin/env node
/* AEGIS // SENTINEL — local operator terminal (CLI companion to the web console).
 *
 * Usage: node tools/aegis-terminal.mjs [--no-color]
 *
 * This is a real terminal program, but it is NOT a shell. It interprets AEGIS
 * commands against the same offline engines and the same authorization gate as
 * the browser console. No OS process is spawned, no socket is opened and state
 * is kept in memory only (nothing is written to disk).
 */
import readline from 'node:readline';
import { createRequire } from 'node:module';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const require = createRequire(import.meta.url);
const here = dirname(fileURLToPath(import.meta.url));
const src = join(here, '..', 'src');
const DATA = require(join(src, '00-data.js'));
const D2 = require(join(src, '05-data2.js'));
const E = require(join(src, '10-engine.js'));
const A = require(join(src, '15-advanced.js'));
const HX = require(join(src, '16-hexstrike.js'));

const COLOR = !process.argv.includes('--no-color');
const c = (code, s) => COLOR ? `\x1b[${code}m${s}\x1b[0m` : String(s);
const OK = (s) => c('32', s), BAD = (s) => c('31', s), WARN = (s) => c('33', s);
const INFO = (s) => c('36', s), MUTE = (s) => c('90', s), HEAD = (s) => c('1;37', s);
const out = (s = '', kind) => process.stdout.write((kind || ((x) => x))(String(s)) + '\n');
const print = (s, tone) => out(s, tone);
const pad = (s, n) => { s = String(s == null ? '' : s); return s.length >= n ? s.slice(0, n) : s + ' '.repeat(n - s.length); };

/* --------------------------- in-memory state ----------------------------- */
const now = Date.now();
const state = {
  version: 1,
  assets: DATA.ASSET_SEEDS.map((a, i) => ({
    id: 'ast' + i, name: a.name, type: a.type, owner: a.owner, env: a.env,
    criticality: a.criticality, authorizedBy: a.authorizedBy,
    expires: new Date(now + a.days * 86400000).toISOString(),
    checks: a.checks.slice(), confirmed: a.confirmed, revoked: false, createdAt: now,
    token: E.sha256(a.name + ':' + i)
  })),
  findings: DATA.FINDING_SEEDS.map((f, i) => ({ id: 'f' + i, ...f, status: 'open', simulated: true, createdAt: now })),
  alerts: DATA.ALERT_SEEDS.map((a, i) => ({ id: 'a' + i, ...a, status: 'new', priority: null, createdAt: now })),
  audit: [], watchlist: [], cases: [], customRules: [], playbookProgress: {},
  ingestResults: null, labResults: {}, orchestratorRuns: [], investigationHistory: [],
  capabilityRequests: [], quantResult: null, events: [],
  settings: { operator: 'operator@local', humanApproval: true, strictScope: true },
  drafts: { ingest: D2.SAMPLES.jsonl, logs: DATA.SAMPLE_LOGS, headers: DATA.SAMPLE_HEADERS, intel: DATA.SAMPLE_INTEL }
};
function audit(action, target, decision, detail) {
  const prev = state.audit.length ? state.audit[state.audit.length - 1].hash : '0'.repeat(64);
  const e = { seq: state.audit.length + 1, ts: Date.now(), actor: state.settings.operator,
    action, target: String(target || '—'), decision, detail: String(detail || ''), prevHash: prev };
  e.hash = E.entryHash(e);
  state.audit.push(e);
}
audit('GENESIS', 'aegis/ledger', 'SEALED', 'CLI session started. Strict scope enforcement enabled.');

const defaultTarget = () => (E.activeAssets(state)[0] || {}).name || null;
const sm = HX.summary();

const BANNER = [
  c('32', '  █████╗ ███████╗ ██████╗ ██╗███████╗    ████████╗███████╗██████╗ ███╗   ███╗'),
  c('32', ' ██╔══██╗██╔════╝██╔════╝ ██║██╔════╝    ╚══██╔══╝██╔════╝██╔══██╗████╗ ████║'),
  c('32', ' ███████║█████╗  ██║  ███╗██║███████╗       ██║   █████╗  ██████╔╝██╔████╔██║'),
  c('32', ' ██╔══██║██╔══╝  ██║   ██║██║╚════██║       ██║   ██╔══╝  ██╔══██╗██║╚██╔╝██║'),
  c('32', ' ██║  ██║███████╗╚██████╔╝██║███████║       ██║   ███████╗██║  ██║██║ ╚═╝ ██║'),
  c('32', ' ╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚═╝╚══════╝       ╚═╝   ╚══════╝╚═╝  ╚═╝╚═╝     ╚═╝'),
  '',
  OK('AEGIS // SENTINEL v2.1 · local operator terminal · authorization-bound, fully offline'),
  INFO(`HexStrike AI v${HX.UPSTREAM.version} adapter · ${sm.total} tools · ${sm.adapters} offline · ${sm.blocked} refused · ${sm.unavailable} server-only`),
  WARN('NOT A SHELL: no process, socket or filesystem access. State is in memory only.'),
  MUTE('Type `help` for commands. ↑/↓ history · Tab completion · Ctrl+D or `exit` to quit.'),
  ''
];

function kv(rows) { rows.forEach(([k, v]) => print('  ' + pad(k, 22) + v)); }
function table(headers, rows, widths = [34, 12, 24, 20]) {
  print(HEAD('  ' + headers.map((h, i) => pad(h, widths[i] || 18)).join('').trimEnd()));
  print(MUTE('  ' + '─'.repeat(90)));
  rows.forEach((r) => print('  ' + r.map((x, i) => pad(x, widths[i] || 18)).join('').trimEnd()));
}

function runTool(id, target) {
  if (!id) { print(BAD('Usage: hexstrike run <tool> [target]')); return 'INVALID'; }
  const g = HX.evaluate(id, state, target);
  if (!g.allowed) {
    audit('HEXSTRIKE_TOOL', id, 'REFUSED', g.reason);
    print(BAD('  REFUSED  ' + id));
    print(BAD('  CODE     ' + g.code));
    print(MUTE('  CAP      ' + (g.mappedCapability || '—')));
    print(WARN('  REASON   ' + g.reason));
    print(MUTE('  No upstream binary, process or network call was made.'));
    return 'REFUSED';
  }
  const r = HX.call(id, { target, id: Date.now() % 100000 }, state);
  if (!r.result) { audit('HEXSTRIKE_TOOL', id, 'REFUSED', JSON.stringify(r.error)); print(BAD('  ' + JSON.stringify(r.error))); return 'REFUSED'; }
  audit('HEXSTRIKE_TOOL', id, 'ALLOWED', r.result.summary);
  print(OK('  GRANTED  ' + id));
  print(MUTE('  CAP      ' + r.result.capability + '  ·  engine ' + r.result.engine));
  print(OK('  SUMMARY  ' + r.result.summary));
  print('  DATA     ' + JSON.stringify(r.result.data));
  print(MUTE('  Executed locally on labelled sample data. No egress.'));
  return 'ALLOWED';
}

const COMMANDS = {
  help: { args: '[command]', desc: 'List commands or explain one', run(argv) {
    if (argv[0]) {
      const x = COMMANDS[argv[0].toLowerCase()];
      if (!x) { print(BAD('No such command: ' + argv[0])); return 'UNKNOWN'; }
      print(OK(argv[0] + ' ' + x.args)); print('  ' + x.desc); return;
    }
    print(HEAD('AVAILABLE COMMANDS'));
    Object.keys(COMMANDS).sort().forEach((k) => print('  ' + pad(k + ' ' + COMMANDS[k].args, 34) + COMMANDS[k].desc));
    print(MUTE('  Tip: hexstrike tools web · hexstrike run trivy_scan · mcp manifest --json'));
  } },
  banner: { args: '', desc: 'Reprint the banner', run() { BANNER.forEach((l) => out(l)); } },
  clear: { args: '', desc: 'Clear the screen', run() { process.stdout.write('\x1b[2J\x1b[H'); } },
  history: { args: '', desc: 'Show command history', run() { history.slice(-20).forEach((h, i) => print('  ' + pad(String(history.length - 20 + i + 1), 5) + h)); } },
  whoami: { args: '', desc: 'Operator identity', run() { print(OK(state.settings.operator)); } },
  date: { args: '', desc: 'UTC timestamp', run() { print(new Date().toISOString()); } },
  echo: { args: '<text>', desc: 'Print text', run(argv) { print(argv.join(' ')); } },
  status: { args: '', desc: 'Platform status', run() {
    const v = E.verifyChain(state.audit);
    print(HEAD('PLATFORM STATUS'));
    kv([['BUILD', 'v2.1.0 · 9 modules · 20 views · NO NETWORK EGRESS'],
      ['OPERATOR', state.settings.operator], ['STRICT SCOPE', String(state.settings.strictScope)],
      ['ASSETS IN SCOPE', E.activeAssets(state).length + ' / ' + state.assets.length],
      ['OPEN FINDINGS', state.findings.filter((f) => f.status === 'open').length],
      ['UNTRIAGED ALERTS', state.alerts.filter((a) => !a.priority).length],
      ['LEDGER', (v.valid ? 'VALID' : 'INVALID') + ' · ' + state.audit.length + ' entries'],
      ['HEXSTRIKE', sm.total + ' tools / ' + sm.adapters + ' offline adapters']]);
  } },
  scope: { args: 'list|check <target> [type]', desc: 'Query the authorization gate', run(argv) {
    const sub = (argv[0] || 'list').toLowerCase();
    if (sub === 'list') {
      table(['ASSET', 'STATE', 'ENV', 'SIGNED BY'], state.assets.map((a) => [
        a.name, E.activeAssets(state).some((x) => x.name === a.name) ? 'ACTIVE' : 'INACTIVE', a.env, a.authorizedBy
      ]));
      return;
    }
    if (sub === 'check') {
      if (!argv[1]) { print(BAD('Usage: scope check <target> [checkType]')); return 'INVALID'; }
      const g = E.scopeCheck(state, argv[1], argv[2] || 'posture');
      print('  TARGET   ' + argv[1]);
      print('  DECISION ' + (g.allowed ? OK('ALLOWED') : BAD('REFUSED')));
      print('  CODE     ' + (g.allowed ? 'SCOPE_VALID' : g.code));
      print('  REASON   ' + g.reason);
      audit('TERMINAL_SCOPE_CHECK', argv[1], g.allowed ? 'ALLOWED' : 'REFUSED', g.reason);
      return g.allowed ? 'ALLOWED' : 'REFUSED';
    }
    print(BAD('Unknown scope subcommand: ' + sub)); return 'INVALID';
  } },
  cap: { args: 'list|blocked|request <id> [target]', desc: 'Inspect / test the manifest', run(argv) {
    const sub = (argv[0] || 'list').toLowerCase();
    if (sub === 'list' || sub === 'blocked') {
      D2.CAPABILITIES.filter((x) => sub === 'blocked' ? x.status !== 'enabled' : x.status === 'enabled')
        .forEach((x) => print('  ' + pad(x.id, 26) + (x.status === 'enabled' ? OK('ENABLED ') : BAD('BLOCKED ')) + x.name));
      return;
    }
    if (sub === 'request') {
      if (!argv[1]) { print(BAD('Usage: cap request <capability-id> [target]')); return 'INVALID'; }
      const g = A.evaluateCapability(argv[1], state, argv[2] || defaultTarget());
      audit('CAPABILITY_REQUEST', argv[1], g.allowed ? 'GRANTED' : 'REFUSED', g.reason);
      print('  ' + pad(argv[1], 28) + (g.allowed ? OK('GRANTED') : BAD('REFUSED')) + '  ' + g.code);
      print('  ' + g.reason);
      return g.allowed ? 'ALLOWED' : 'REFUSED';
    }
    print(BAD('Unknown cap subcommand: ' + sub)); return 'INVALID';
  } },
  hexstrike: { args: 'info|tools|tool|agents|plan|run', desc: 'HexStrike adapter console', run(argv) {
    const sub = (argv[0] || 'info').toLowerCase();
    if (sub === 'info') {
      print(HEAD('HEXSTRIKE AI COMPATIBILITY LAYER'));
      kv([['UPSTREAM', HX.UPSTREAM.repo + '@' + HX.UPSTREAM.version], ['LICENSE', HX.UPSTREAM.license],
        ['DECORATED TOOLS', sm.decorated], ['UNIQUE CATALOG', sm.total], ['OFFLINE ADAPTERS', sm.adapters],
        ['HARD-REFUSED', sm.blocked], ['SERVER-ONLY', sm.unavailable], ['AGENTS', sm.agents],
        ['INTEGRATION', HX.UPSTREAM.note]]);
      print(WARN('  No upstream Python code, binary or network endpoint is bundled or executed.'));
      return;
    }
    if (sub === 'tools') {
      const list = HX.tools(argv.slice(1).join(' '));
      print(HEAD('HEXSTRIKE TOOL CATALOG · ' + list.length + ' match(es)'));
      table(['TOOL', 'MODE', 'CAPABILITY', 'CATEGORY'], list.slice(0, 40).map((t) => [t.id, t.mode.toUpperCase(), t.cap || '—', t.category]));
      if (list.length > 40) print(MUTE('  … ' + (list.length - 40) + ' more. Narrow with a filter.'));
      return;
    }
    if (sub === 'tool') {
      const t = HX.get(argv[1]);
      if (!t) { print(BAD('Unknown tool: ' + (argv[1] || ''))); return 'UNKNOWN'; }
      print(HEAD('TOOL ' + t.id));
      kv([['MODE', t.mode.toUpperCase()], ['CATEGORY', t.category], ['CAPABILITY', t.cap || '—'], ['RISK', t.risk], ['REASON', t.reason]]);
      return;
    }
    if (sub === 'agents') {
      print(HEAD('HEXSTRIKE AGENT PERSONAS'));
      HX.AGENTS.forEach((a) => print('  ' + pad(a.id, 34) + (a.status === 'adapter' ? OK(pad('ADAPTER', 10)) : BAD(pad('BLOCKED', 10))) + a.role));
      return;
    }
    if (sub === 'plan') {
      const p = HX.plan(argv.slice(1).join(' '));
      print(HEAD('OFFLINE CAPABILITY PLAN · ' + JSON.stringify(p.goal)));
      p.steps.forEach((x) => print('  ' + pad(String(x.order), 4) + pad(x.tool, 36) +
        (x.decision === 'ELIGIBLE' ? OK(pad('ELIGIBLE', 10)) : BAD(pad('REFUSED', 10))) + (x.capability || '—')));
      return;
    }
    if (sub === 'run') return runTool(argv[1], argv[2] || defaultTarget());
    print(BAD('Usage: hexstrike info|tools [filter]|tool <id>|agents|plan <goal>|run <tool> [target]')); return 'INVALID';
  } },
  run: { args: '<tool> [target]', desc: 'Alias for hexstrike run', run(argv) { return runTool(argv[0], argv[1] || defaultTarget()); } },
  mcp: { args: 'manifest|tools|resources|prompts|call', desc: 'MCP contract & JSON-RPC adapter', run(argv) {
    const sub = (argv[0] || 'manifest').toLowerCase(), m = HX.MCP;
    if (sub === 'manifest') {
      if (argv.includes('--json')) { print(JSON.stringify(m, null, 2)); return; }
      print(HEAD('MCP SERVER MANIFEST'));
      kv([['NAME', m.name], ['VERSION', m.version], ['UPSTREAM', m.upstream], ['TRANSPORT', m.transport],
        ['ALWAYS ALLOW', JSON.stringify(m.alwaysAllow)], ['TOOLS', m.tools.length],
        ['RESOURCES', m.resources.length], ['PROMPTS', m.prompts.length], ['SAMPLING', String(m.capabilities.sampling)]]);
      print(MUTE('  Use `mcp manifest --json` for the full contract.'));
      return;
    }
    if (sub === 'tools') {
      const f = argv.slice(1).join(' ');
      m.tools.filter((t) => !f || t.name.includes(f) || t.mode === f || t.category === f).slice(0, 40)
        .forEach((t) => print('  ' + pad(t.name, 38) + (t.mode === 'adapter' ? OK(pad('ADAPTER', 12)) : BAD(pad(t.mode.toUpperCase(), 12))) + (t.capability || '—')));
      return;
    }
    if (sub === 'resources' || sub === 'prompts') {
      (sub === 'resources' ? m.resources : m.prompts).forEach((x) => print('  ' + pad(x.uri || x.name, 34) + x.description));
      return;
    }
    if (sub === 'call') {
      if (!argv[1]) { print(BAD('Usage: mcp call <tool> [--target=…] [--data=…]')); return 'INVALID'; }
      const args = { id: Date.now() % 100000 };
      argv.slice(2).forEach((a) => { const mm = a.match(/^--([A-Za-z0-9_]+)=(.*)$/); if (mm) args[mm[1]] = mm[2]; });
      const r = HX.call(argv[1], args, state);
      const allowed = !!r.result;
      audit('MCP_CALL', argv[1], allowed ? 'ALLOWED' : 'REFUSED', allowed ? r.result.summary : r.error.data.reason);
      print(allowed ? JSON.stringify(r, null, 2) : BAD(JSON.stringify(r, null, 2)));
      return allowed ? 'ALLOWED' : 'REFUSED';
    }
    print(BAD('Usage: mcp manifest|tools [filter]|resources|prompts|call <tool> [--k=v]')); return 'INVALID';
  } },
  orchestrator: { args: 'run [target]', desc: 'Execute the 8-task DAG', run(argv) {
    if (argv[0] !== 'run') { print(BAD('Usage: orchestrator run [target]')); return 'INVALID'; }
    const target = argv[1] || defaultTarget();
    const gate = A.evaluateCapability('scope.verify', state, target);
    if (!gate.allowed) { print(BAD('REFUSED ' + gate.code + ': ' + gate.reason)); audit('ORCHESTRATOR_RUN', target, 'REFUSED', gate.reason); return 'REFUSED'; }
    print(HEAD('ORCHESTRATOR · target ' + target));
    const ctx = { target }, start = Date.now(); let done = 0;
    D2.ORCHESTRATOR_PLAN.forEach((n, i) => {
      const depsOk = n.deps.every((d) => ctx['done_' + d]);
      if (!depsOk) { ctx['done_' + n.id] = false; print(BAD('  [' + (i + 1) + '/8] ' + pad(n.id, 12) + 'SKIPPED')); return; }
      const r = A.orchestratorStep(n, state, ctx);
      ctx['done_' + n.id] = r.status === 'DONE';
      if (r.status === 'DONE') done++;
      print('  [' + (i + 1) + '/8] ' + pad(n.id, 12) + (r.status === 'DONE' ? OK(pad('DONE', 9)) : BAD(pad(r.status, 9))) + r.detail);
      audit('ORCH_' + n.id.toUpperCase(), target, r.status, r.detail);
    });
    audit('ORCHESTRATOR_RUN', target, done === 8 ? 'COMPLETE' : 'PARTIAL', done + '/8 tasks · ' + (Date.now() - start) + 'ms');
    print(OK('  ' + done + '/8 tasks complete · ledger sealed.'));
    return 'ALLOWED';
  } },
  ingest: { args: 'analyze [sample]', desc: 'Normalize telemetry', run(argv) {
    if (argv[0] !== 'analyze') { print(BAD('Usage: ingest analyze [jsonl|nginx|syslog|deps|…]')); return 'INVALID'; }
    const key = argv[1] || 'draft';
    const text = key === 'draft' ? state.drafts.ingest : (D2.SAMPLES[key] || DATA.SAMPLE_LOGS);
    const r = A.normalizeLogs(text), ch = A.attackChains(r);
    state.ingestResults = r;
    audit('UNIVERSAL_INGEST', defaultTarget() || 'local', 'COMPLETE', r.format + ' · ' + r.events.length + ' events');
    kv([['FORMAT', r.format], ['EVENTS', r.events.length + ' (' + r.stats.tagged + ' tagged)'],
      ['SOURCES', r.stats.sources], ['CHAINS', ch.chains.length]]);
    return 'ALLOWED';
  } },
  lab: { args: 'run <tab>', desc: 'Run an Analysis Lab engine', run(argv) {
    const tab = argv[0] === 'run' ? argv[1] : argv[0];
    const map = { email: A.analyzeEmail, iam: A.analyzeIamPolicy, k8s: A.analyzeK8s,
      secrets: A.secretScan, deps: A.analyzeDependencies };
    if (!map[tab]) { print(BAD('Usage: lab run <email|iam|k8s|secrets|deps>')); return 'INVALID'; }
    const r = map[tab](D2.SAMPLES[tab] || '');
    state.labResults[tab] = r;
    audit('LAB_ANALYSIS_' + tab.toUpperCase(), 'local', 'COMPLETE', 'score ' + r.score);
    print((r.score < 60 ? BAD : OK)('  ' + tab.toUpperCase() + ' · score ' + r.score + '/100 · ' +
      (r.checks ? r.checks.length + ' controls' : r.findings ? r.findings.length + ' findings' : r.packages ? r.packages.length + ' packages' : r.verdict || 'complete')));
    return 'ALLOWED';
  } },
  mitre: { args: 'coverage', desc: 'ATT&CK coverage', run() {
    const x = A.mitreCoverage(state);
    print(OK('  COVERAGE  ' + x.covered + '/' + x.total + ' (' + x.percent + '%)'));
    print(WARN('  GAPS      ' + x.gaps.length));
    x.tactics.forEach((t) => print('  ' + pad(t.short, 12) + pad(t.covered + '/' + t.total, 9) + Math.round(t.covered / t.total * 100) + '%'));
  } },
  investigate: { args: '<query>', desc: 'Local investigation copilot', run(argv) {
    const q = argv.join(' ');
    if (!q) { print(BAD('Usage: investigate <query>')); return 'INVALID'; }
    const r = A.investigate(q, state);
    audit('INVESTIGATION', r.type, 'QUERY', q + ' → ' + r.count + ' records');
    print(OK('  INTENT    ' + r.type)); print('  MATCHES   ' + r.count);
    print(MUTE('  FILTERS   ' + JSON.stringify(r.parsed)));
    r.rows.slice(0, 8).forEach((x) => print('  · ' + JSON.stringify(x).slice(0, 110)));
    return 'ALLOWED';
  } },
  quant: { args: 'run [iterations]', desc: 'Monte Carlo risk model', run(argv) {
    const n = Math.max(200, Math.min(20000, parseInt(argv[0] === 'run' ? argv[1] : argv[0], 10) || 2000));
    const r = A.monteCarloRisk(state, n);
    state.quantResult = r;
    audit('RISK_QUANT', 'portfolio', 'COMPLETE', n + ' iterations · p90 ' + r.p90);
    kv([['ITERATIONS', r.iterations], ['P50 / P90 / P95', r.p50 + ' / ' + r.p90 + ' / ' + r.p95], ['OPEN FINDINGS', r.open]]);
    return 'ALLOWED';
  } },
  triage: { args: '', desc: 'Score alert queue', run() {
    let n = 0;
    state.alerts.forEach((a) => { if (!a.priority) { a.priority = E.triage(a, state); a.status = 'triaged'; n++; } });
    audit('AUTO_TRIAGE', 'alert-queue', 'COMPLETE', n + ' alerts scored');
    print(OK('  ' + n + ' alert(s) scored with explainable reasoning.'));
    print(WARN('  Containment still requires human approval.'));
  } },
  findings: { args: '[severity]', desc: 'Open findings', run(argv) {
    const f = (argv[0] || '').toLowerCase();
    const list = state.findings.filter((x) => x.status === 'open' && (!f || x.severity === f));
    table(['SEVERITY', 'ASSET', 'TITLE'], list.slice(0, 25).map((x) => [x.severity.toUpperCase(), x.asset, x.title.slice(0, 34)]));
    print(MUTE('  ' + list.length + ' open finding(s)'));
  } },
  alerts: { args: '', desc: 'Alert queue', run() {
    table(['PRIORITY', 'STATUS', 'SOURCE', 'TITLE'], state.alerts.slice(0, 20).map((x) => [
      x.priority ? String(x.priority.score || 'scored') : '—', x.status, x.source || '—', (x.title || '').slice(0, 30)]));
  } },
  cases: { args: 'list', desc: 'Incident cases', run() {
    if (!state.cases.length) { print(MUTE('  No cases in this CLI session (state is in memory only).')); return; }
    table(['ID', 'STATUS', 'SEVERITY', 'TITLE'], state.cases.map((x) => [x.id, x.status, x.severity, x.title]));
  } },
  audit: { args: 'verify|tail [n]', desc: 'Ledger verification', run(argv) {
    const sub = (argv[0] || 'verify').toLowerCase();
    if (sub === 'verify') {
      const v = E.verifyChain(state.audit);
      print((v.valid ? OK : BAD)('  LEDGER ' + (v.valid ? 'VALID' : 'INVALID') + ' · ' + state.audit.length + ' entries · SHA-256 hash chain'));
      return v.valid ? 'ALLOWED' : 'REFUSED';
    }
    state.audit.slice(-(parseInt(argv[1], 10) || 12)).forEach((e) =>
      print('  #' + pad(String(e.seq), 5) + pad(e.action, 28) + (e.decision === 'REFUSED' ? BAD(pad(e.decision, 12)) : pad(e.decision, 12)) + String(e.target).slice(0, 28)));
  } },
  policy: { args: '', desc: 'Rules of engagement', run() {
    print(HEAD('RULES OF ENGAGEMENT · ENFORCED IN CODE'));
    [ 'IN SCOPE    : offline analysis of operator-supplied text; signed, unexpired authorization records;',
      '              explainable triage; mitigation guidance; defanged IOC correlation; hash-chained audit.',
      'OUT OF SCOPE: activity without authorization; active scanning; exploitation; credential attacks;',
      '              persistence/evasion; autonomous containment; third-party egress; scope bypass.',
      'HEXSTRIKE   : catalog-only adapter. Offensive tool names are refused and logged, never executed.'
    ].forEach((l) => print(WARN('  ' + l)));
  } },
  exit: { args: '', desc: 'Quit the terminal', run() { print(MUTE('  Session ended. Ledger entries were in memory only.')); rl.close(); } }
};

const history = [];
function tokenize(s) {
  const out = []; let cur = '', q = null;
  for (const ch of s) {
    if (q) { if (ch === q) q = null; else cur += ch; continue; }
    if (ch === '"' || ch === "'") { q = ch; continue; }
    if (/\s/.test(ch)) { if (cur) { out.push(cur); cur = ''; } continue; }
    cur += ch;
  }
  if (cur) out.push(cur);
  return out;
}
function execute(raw) {
  const line = String(raw || '').trim();
  if (!line) return;
  history.push(line);
  const t = tokenize(line), name = (t[0] || '').toLowerCase(), argv = t.slice(1);
  print(INFO('aegis ❯ ' + line));
  const cmd = COMMANDS[name];
  let decision = 'ALLOWED';
  if (!cmd) { print(BAD('command not found: ' + name + '  (try `help`)')); decision = 'UNKNOWN'; }
  else {
    try { const r = cmd.run(argv); if (r && r.decision) decision = r.decision; }
    catch (err) { print(BAD('runtime error: ' + (err && err.message ? err.message : String(err)))); decision = 'ERROR'; }
  }
  audit('TERMINAL_CMD', name || '(empty)', decision, line.slice(0, 180));
  print('');
}

const rl = readline.createInterface({
  input: process.stdin, output: process.stdout, prompt: OK('aegis ❯ '), terminal: true,
  completer(partial) {
    const parts = partial.split(/\s+/), last = parts[parts.length - 1];
    let pool;
    if (parts.length === 1) pool = Object.keys(COMMANDS);
    else if (parts[0] === 'hexstrike' || parts[0] === 'mcp' || parts[0] === 'run') pool = HX.TOOLS.map((t) => t.id).concat(['info', 'tools', 'tool', 'agents', 'plan', 'run', 'manifest', 'call', 'resources', 'prompts']);
    else pool = Object.keys(COMMANDS);
    const hits = pool.filter((x) => x.startsWith(last));
    return [hits.length ? hits : pool, last];
  }
});

BANNER.forEach((l) => out(l));
rl.prompt();
rl.on('line', (line) => { execute(line); rl.prompt(); });
rl.on('close', () => { print(MUTE('AEGIS terminal closed.')); process.exit(0); });
