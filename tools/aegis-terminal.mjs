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
const OP = require(join(src, '17-opencode.js'));

const COLOR = !process.argv.includes('--no-color');
const c = (code, s) => COLOR ? `\x1b[${code}m${s}\x1b[0m` : String(s);
const OK = (s) => c('32', s), BAD = (s) => c('31', s), WARN = (s) => c('33', s);
const INFO = (s) => c('36', s), MUTE = (s) => c('90', s), HEAD = (s) => c('1;37', s);
let quiet = false, capture = null, lastLine = '';
const vars = {}, aliases = {}, scripts = {};
const session = OP.createSession({ title: 'Local operator workbench' });
const out = (s = '', kind) => {
  const text = String(s);
  if (quiet) { const clean = text.replace(/\x1b\[[0-9;]*m/g, ''); if (capture) capture.push(clean); if (clean.trim()) lastLine = clean.trim(); return; }
  if (text.trim()) lastLine = text.trim();
  process.stdout.write((kind || ((x) => x))(text) + '\n');
};
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
  OK('AEGIS // SENTINEL v2.2 · local operator terminal · authorization-bound, fully offline'),
  INFO(`OpenCode v${OP.UPSTREAM.version} workbench · ${OP.summary().tools} tools · ${OP.summary().agents} agents · VFS · planner · approvals`),
  INFO(`HexStrike AI v${HX.UPSTREAM.version} adapter · ${sm.total} tools · ${sm.adapters} offline · ${sm.blocked} refused · ${sm.unavailable} server-only`),
  WARN('NOT A SHELL: no process, socket, model call or filesystem access. State is in memory only.'),
  MUTE('Type `help` or `oc help`. Pipelines | · chains && · $vars · aliases · scripts · Ctrl+D to quit.'),
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

/* -------------------- OpenCode workbench helpers ------------------------ */
function ocCall(id, args = {}) {
  const res = OP.execute({ tool: id, args }, session);
  audit('OPENCODE_TOOL', String(id), res.status, JSON.stringify(args).slice(0, 180) + ' · ' + (res.reason || ''));
  print((res.status === 'DONE' ? OK : res.status === 'PENDING' ? WARN : BAD)('  ' + res.status + '  ' + res.tool + (res.code ? '  (' + res.code + ')' : '')));
  if (res.reason) print(MUTE('  REASON   ' + res.reason));
  (res.output || []).slice(0, 80).forEach((l) => print('  │ ' + l));
  if (res.status === 'PENDING') print(WARN('  APPROVAL ' + res.approvalId + ' — `oc approve ' + res.approvalId + '`'));
  if (res.diff) print(WARN('  DIFF     virtual file changed; `diff` to review.'));
  return res.status === 'DONE' ? 'ALLOWED' : res.status === 'PENDING' ? 'PENDING' : 'REFUSED';
}
function ocPlan(goal) {
  const p = OP.plan(goal, session);
  print(HEAD('OPENCODE PLAN · ' + p.goal.toUpperCase()));
  print(OK('  ENGINE   ' + p.engine + ' · ' + p.steps.length + ' steps'));
  p.steps.forEach((x, i) => print('  ' + pad(String(i + 1) + '.', 4) + pad(x.title, 42) + '[' + x.tool + ']'));
  audit('OPENCODE_PLAN', p.goal || 'workspace', 'GENERATED', p.steps.length + ' steps.');
  print(MUTE('  No model call. `oc run "<goal>"` to execute.'));
}
function ocRun(goal) {
  const p = OP.plan(goal, session);
  let done = 0, blocked = null;
  print(HEAD('OPENCODE RUN · ' + (p.goal || 'workspace review')));
  for (let i = 0; i < p.steps.length; i++) {
    const step = p.steps[i], res = OP.execute(step, session);
    audit('OPENCODE_TOOL', step.tool, res.status, 'step ' + (i + 1) + '/' + p.steps.length);
    print((res.status === 'DONE' ? OK : WARN)('  [' + (i + 1) + '/' + p.steps.length + '] ' + pad(step.title, 42) + res.status + '  ' + step.tool));
    if (res.status === 'DONE') {
      done++; if (session.todos[i]) session.todos[i].status = 'done';
      if ((res.output || [])[0]) print(MUTE('        ' + String(res.output[0]).slice(0, 120)));
    } else { blocked = res; print(WARN('        ' + (res.reason || res.code))); break; }
  }
  audit('OPENCODE_RUN', p.goal || 'workspace', blocked ? 'PAUSED' : 'COMPLETED', done + '/' + p.steps.length + ' steps');
  print((blocked ? WARN : OK)('  RESULT   ' + done + '/' + p.steps.length + ' steps · ' + (blocked ? 'paused for human decision' : 'complete')));
  if (blocked && blocked.status === 'PENDING') print(WARN('  `oc approve ' + blocked.approvalId + '` then `oc run "' + (p.goal || '') + '"` again.'));
  return blocked ? 'PENDING' : 'ALLOWED';
}
function ocApprove(id, decision) {
  const r = OP.approve(session, id, decision, state.settings.operator);
  if (!r.ok) { print(BAD('  ' + r.error)); return 'UNKNOWN'; }
  audit('OPENCODE_APPROVAL', r.pending.tool, decision.toUpperCase(), 'Approval ' + id);
  print((decision === 'approve' ? OK : WARN)('  APPROVAL ' + id + ' · ' + decision.toUpperCase() + ' · ' + r.pending.tool));
  if (r.result) (r.result.output || []).slice(0, 20).forEach((l) => print('  │ ' + l));
  return decision === 'approve' ? 'ALLOWED' : 'DENIED';
}
function opencodeCmd(argv) {
  const sub = (argv[0] || 'status').toLowerCase(), s = OP.summary(session);
  if (sub === 'status' || sub === 'info' || sub === 'session') {
    print(HEAD('OPENCODE COMPATIBILITY LAYER'));
    kv([['UPSTREAM', OP.UPSTREAM.repo + '@v' + OP.UPSTREAM.version], ['INTEGRATION', 'contract only · no runtime/model/egress'],
      ['SESSION', session.id], ['AGENT', session.agent], ['GOAL', session.vars.goal || '(none)'],
      ['TOOLS', s.tools + ' (' + s.allow + ' allow · ' + s.ask + ' ask · ' + s.deny + ' deny)'],
      ['AGENTS', s.agents + ' · permissions ' + s.permissions], ['VFS', s.files + ' files · ' + s.changed + ' changed'],
      ['APPROVALS', s.pending + ' pending · ' + s.calls + ' tool calls']]);
    print(WARN('  Hard-denied: webfetch, websearch, external_directory, doom_loop.')); return;
  }
  if (sub === 'tools') {
    const list = OP.tools(argv.slice(1).join(' '));
    print(HEAD('OPENCODE TOOL CATALOG · ' + list.length + ' match(es)'));
    table(['TOOL', 'ACTION', 'PERMISSION', 'CAPABILITY'], list.slice(0, 40).map((t) => [t.id, t.action.toUpperCase(), t.key, t.cap])); return;
  }
  if (sub === 'tool') {
    const t = OP.get(argv[1]);
    if (!t) { print(BAD('No such tool: ' + argv[1])); return 'UNKNOWN'; }
    const g = OP.evaluate(t.id, session, {});
    print(HEAD('OPENCODE TOOL · ' + t.id.toUpperCase()));
    kv([['PERMISSION', t.key], ['BASE', t.action.toUpperCase()], ['EFFECTIVE', g.action.toUpperCase() + ' · ' + g.code],
      ['CAPABILITY', t.cap], ['DESCRIPTION', t.reason]]); return;
  }
  if (sub === 'agents') { print(HEAD('OPENCODE AGENTS'));
    table(['AGENT', 'MODE', 'DESCRIPTION'], OP.AGENTS.map((a) => [a.id, a.mode, a.desc.slice(0, 26)])); return; }
  if (sub === 'agent') {
    const r = OP.setAgent(session, argv[1] || '');
    if (!r.ok) { print(BAD('  ' + r.error)); return 'UNKNOWN'; }
    audit('OPENCODE_AGENT', argv[1], 'SELECTED', 'Permission defaults applied.');
    print(OK('  ACTIVE AGENT ' + argv[1] + ' · ' + r.agent.mode)); return;
  }
  if (sub === 'permissions') { print(HEAD('OPENCODE PERMISSION POLICY'));
    Object.keys(session.permissions).sort().forEach((k) => print('  ' + pad(k, 24) + pad(session.permissions[k].toUpperCase(), 10) + (OP.HARD_DENY[k] ? 'HARD-DENY' : 'configurable'))); return; }
  if (sub === 'permission') {
    const r = OP.setPermission(session, argv[1], (argv[2] || '').toLowerCase());
    if (!r.ok) { print(BAD('  ' + r.error)); return 'REFUSED'; }
    audit('OPENCODE_PERMISSION', argv[1], String(argv[2]).toUpperCase(), 'Policy changed.');
    print(OK('  POLICY ' + argv[1] + ' → ' + String(argv[2]).toUpperCase())); return;
  }
  if (sub === 'plan') { ocPlan(argv.slice(1).join(' ')); return; }
  if (sub === 'run') return ocRun(argv.slice(1).join(' '));
  if (sub === 'approve' || sub === 'deny') return ocApprove(argv[1], sub);
  if (sub === 'pending') return COMMANDS.approvals.run([]);
  if (sub === 'mcp') { const m = OP.mcp(); print(HEAD('OPENCODE MCP MANIFEST · ' + m.name));
    kv([['UPSTREAM', m.upstream], ['TRANSPORT', m.transport], ['TOOLS', m.tools.length], ['RESOURCES', m.resources.length],
      ['PROMPTS', m.prompts.length], ['SAMPLING', String(m.capabilities.sampling)], ['ALWAYS ALLOW', '[]']]); return; }
  if (sub === 'reset') { OP.reset(session); audit('OPENCODE_SESSION', 'workbench', 'RESET', 'VFS restored.'); print(OK('  Session reset.')); return; }
  if (sub === 'help') { print(HEAD('OPENCODE COMMANDS'));
    ['status · adapter state', 'tools [filter] · tool catalog', 'tool <id> · inspect one tool',
      'agents · built-in agents', 'agent <id> · apply permission profile',
      'permissions · policy table', 'permission <key> <allow|ask|deny> · change policy',
      'plan "<goal>" · deterministic plan', 'run "<goal>" · stream the plan',
      'approve|deny <id> · human decision', 'mcp · contract manifest', 'reset · restore VFS'].forEach((l) => print('  ' + l)); return; }
  print(BAD('Unknown opencode subcommand: ' + sub)); return 'UNKNOWN';
}
function vfsCmd(argv) {
  const sub = (argv[0] || 'ls').toLowerCase();
  if (sub === 'ls' || sub === 'list' || sub === 'tree') return ocCall(sub === 'tree' ? 'bash' : 'list', sub === 'tree' ? { command: 'tree' } : {});
  if (sub === 'cat' || sub === 'read') { if (!argv[1]) { print(BAD('Usage: vfs cat <path>')); return 'INVALID'; } return ocCall('read', { path: argv[1] }); }
  if (sub === 'write') { if (!argv[1]) { print(BAD('Usage: vfs write <path> <text>')); return 'INVALID'; } return ocCall('write', { path: argv[1], content: argv.slice(2).join(' ') }); }
  if (sub === 'edit') { if (!argv[2]) { print(BAD('Usage: vfs edit <path> <find> <replace>')); return 'INVALID'; } return ocCall('edit', { path: argv[1], find: argv[2], replace: argv.slice(3).join(' ') }); }
  if (sub === 'patch') { if (!argv[2]) { print(BAD('Usage: vfs patch <path> <old-line> <new-line>')); return 'INVALID'; }
    return ocCall('apply_patch', { path: argv[1], patch: '-' + argv[2] + '\n+' + argv.slice(3).join(' ') }); }
  if (sub === 'grep') { if (!argv[1]) { print(BAD('Usage: vfs grep <regex> [glob]')); return 'INVALID'; } return ocCall('grep', { pattern: argv[1], path: argv[2] || null }); }
  if (sub === 'glob') return ocCall('glob', { pattern: argv[1] || '*' });
  if (sub === 'diff') return COMMANDS.diff.run(argv.slice(1));
  if (sub === 'diagnostics' || sub === 'lsp') return ocCall('lsp', {});
  if (sub === 'reset') return opencodeCmd(['reset']);
  if (sub === 'help') { print(HEAD('VIRTUAL FILE SYSTEM'));
    ['ls|tree · list in-memory files', 'cat <path> · numbered read', 'grep <regex> [glob] · search',
      'glob <pattern> · match paths', 'write|edit|patch · virtual changes (approval required)',
      'diff [path] · unified diff', 'diagnostics · LSP-like findings', 'reset · restore seeds'].forEach((l) => print('  ' + l)); return; }
  print(BAD('Unknown vfs subcommand: ' + sub)); return 'UNKNOWN';
}

/* ---------------------- advanced shell features ------------------------- */
function builtinVars() {
  return { target: defaultTarget() || '—', agent: session.agent, session: session.id,
    last: lastLine, goal: session.vars.goal || '', date: new Date().toISOString(),
    operator: state.settings.operator, tools: sm.total };
}
function expandVars(line) {
  const b = builtinVars();
  return String(line).replace(/\$\{?([A-Za-z_][A-Za-z0-9_]*)\}?/g, (m, k) =>
    Object.prototype.hasOwnProperty.call(vars, k) ? String(vars[k]) :
    Object.prototype.hasOwnProperty.call(b, k) ? String(b[k]) : m);
}
function expandAlias(line) {
  const parts = tokenize(line), a = aliases[(parts[0] || '').toLowerCase()];
  return a ? a + (parts.length > 1 ? ' ' + parts.slice(1).join(' ') : '') : line;
}
function splitOutside(str, sep) {
  const out = []; let cur = '', q = null;
  for (let i = 0; i < str.length; i++) {
    const ch = str[i];
    if (q) { cur += ch; if (ch === q) q = null; continue; }
    if (ch === '"' || ch === "'") { q = ch; cur += ch; continue; }
    if (str.substr(i, sep.length) === sep) { if (cur.trim()) out.push(cur.trim()); cur = ''; i += sep.length - 1; continue; }
    cur += ch;
  }
  if (cur.trim()) out.push(cur.trim());
  return out;
}
function splitChain(line) {
  const segs = []; let cur = '', q = null, op = ';';
  for (let i = 0; i < line.length; i++) {
    const ch = line[i];
    if (q) { cur += ch; if (ch === q) q = null; continue; }
    if (ch === '"' || ch === "'") { q = ch; cur += ch; continue; }
    if (line.substr(i, 2) === '&&') { if (cur.trim()) segs.push({ cmd: cur.trim(), op }); cur = ''; op = '&&'; i++; continue; }
    if (ch === ';') { if (cur.trim()) segs.push({ cmd: cur.trim(), op }); cur = ''; op = ';'; continue; }
    cur += ch;
  }
  if (cur.trim()) segs.push({ cmd: cur.trim(), op });
  return segs;
}
function applyFilter(lines, expr) {
  const t = tokenize(expr), f = (t[0] || '').toLowerCase(), arg = t.slice(1).join(' '), n = parseInt(t[1], 10);
  if (f === 'grep' || f === 'match') { let re; try { re = new RegExp(arg, 'i'); } catch (e) { return ['Invalid regex: ' + e.message]; } return lines.filter((l) => re.test(l)); }
  if (f === 'exclude') return lines.filter((l) => l.toLowerCase().indexOf(arg.toLowerCase()) === -1);
  if (f === 'contains') return lines.filter((l) => l.toLowerCase().indexOf(arg.toLowerCase()) !== -1);
  if (f === 'head') return lines.slice(0, isNaN(n) ? 10 : n);
  if (f === 'tail') return lines.slice(-(isNaN(n) ? 10 : n));
  if (f === 'select') return [lines[(isNaN(n) ? 1 : n) - 1] || ''];
  if (f === 'wc' || f === 'count') return [lines.length + ' line(s)'];
  if (f === 'sort') return lines.slice().sort();
  if (f === 'uniq') return lines.filter((l, i, a) => i === 0 || l !== a[i - 1]);
  if (f === 'upper') return lines.map((l) => l.toUpperCase());
  if (f === 'lower') return lines.map((l) => l.toLowerCase());
  if (f === 'trim') return lines.map((l) => l.trim());
  if (f === 'prefix') return lines.map((l) => arg + l);
  if (f === 'json') { const blob = lines.join('\n'), st = blob.indexOf('{'); if (st === -1) return ['No JSON object.'];
    try { return JSON.stringify(JSON.parse(blob.slice(st)), null, 2).split('\n'); } catch (e) { return ['JSON parse failed: ' + e.message]; } }
  if (f === 'help') return ['Filters: grep · exclude · contains · head · tail · select · wc · sort · uniq · upper · lower · trim · prefix · json'];
  return ['Unknown filter: ' + f];
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
    print(MUTE('  Tip: | pipelines · && chains · $vars · aliases · scripts · oc help · vfs help'));
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
    kv([['BUILD', 'v2.2.0 · 10 modules · 20 views · NO NETWORK EGRESS'],
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
      'HEXSTRIKE   : catalog-only adapter. Offensive tool names are refused and logged, never executed.',
      'OPENCODE    : contract-only workbench. VFS writes need human approval; network and external',
      '              paths are hard-denied. No Bun runtime, no LLM provider, no disk writes.',
      '"ANYTHING"  : everything in the signed offline capability manifest — nothing outside it.'
    ].forEach((l) => print(WARN('  ' + l)));
  } },
  exit: { args: '', desc: 'Quit the terminal', run() { print(MUTE('  Session ended. Ledger entries were in memory only.')); rl.close(); } },

  /* ---------------- OpenCode-compatible governed workbench ------------- */
  opencode: { args: '<subcommand>', desc: 'OpenCode adapter and workbench', run: opencodeCmd },
  oc: { args: '<subcommand>', desc: 'Short alias for `opencode`', run: opencodeCmd },
  vfs: { args: '<subcommand>', desc: 'Virtual workspace operations', run: vfsCmd },
  sh: { args: '<command>', desc: 'Governed virtual shell (try `sh help`)', run(argv) {
    if (!argv.length) { print(BAD('Usage: sh <command>')); return 'INVALID'; }
    return ocCall('bash', { command: argv.join(' ') });
  } },
  tool: { args: '<tool-id> [json-args]', desc: 'Invoke one governed OpenCode tool', run(argv, raw) {
    if (!argv[0]) { print(BAD('Usage: tool <tool-id> [json-args]')); return 'INVALID'; }
    const json = raw ? String(raw).replace(/^\s*tool\s+\S+\s*/i, '').trim() : argv.slice(1).join(' ');
    let args = {};
    if (json) { try { args = JSON.parse(json); } catch (e) { print(BAD('Invalid JSON: ' + e.message)); return 'INVALID'; } }
    return ocCall(argv[0], args);
  } },
  diff: { args: '[virtual-path]', desc: 'Unified diff of virtual file changes', run(argv) {
    const d = OP.diffText(session, argv[0] || null);
    print(d || MUTE('No virtual file changes. Workspace clean.'));
  } },
  diagnostics: { args: '', desc: 'LSP-like diagnostics over the VFS', run() { return ocCall('lsp', {}); } },
  approvals: { args: '', desc: 'Pending human approvals', run() {
    print(HEAD('PENDING APPROVALS (' + session.pending.length + ')'));
    if (!session.pending.length) print(MUTE('  (none)'));
    session.pending.forEach((p) => print(WARN('  ' + pad(p.id, 18) + pad(p.tool, 18) + p.reason)));
    print(MUTE('  `oc approve <id>` or `oc deny <id>`.'));
  } },
  set: { args: '<name> <value>', desc: 'Set a shell variable', run(argv) {
    if (!argv[0]) { print(BAD('Usage: set <name> <value>')); return 'INVALID'; }
    vars[argv[0]] = argv.slice(1).join(' '); print(OK('  $' + argv[0] + ' = ' + vars[argv[0]]));
  } },
  unset: { args: '<name>', desc: 'Remove a shell variable', run(argv) { delete vars[argv[0]]; print(OK('  Removed.')); } },
  env: { args: '', desc: 'List shell variables', run() {
    print(HEAD('SHELL VARIABLES'));
    Object.entries(builtinVars()).forEach(([k, v]) => print('  ' + pad('$' + k, 16) + v));
    Object.entries(vars).forEach(([k, v]) => print(OK('  ' + pad('$' + k, 16) + v + '  (user)')));
  } },
  alias: { args: '<name> <command>', desc: 'Define a terminal alias', run(argv) {
    if (!argv[1]) { print(BAD('Usage: alias <name> <command>')); return 'INVALID'; }
    aliases[argv[0].toLowerCase()] = argv.slice(1).join(' '); print(OK('  Alias ' + argv[0] + ' → ' + argv.slice(1).join(' ')));
  } },
  unalias: { args: '<name>', desc: 'Remove a terminal alias', run(argv) { delete aliases[(argv[0] || '').toLowerCase()]; print(OK('  Removed.')); } },
  aliases: { args: '', desc: 'List aliases', run() {
    print(HEAD('ALIASES')); const k = Object.keys(aliases);
    if (!k.length) print(MUTE('  (none)'));
    k.forEach((x) => print('  ' + pad(x, 14) + '→ ' + aliases[x]));
  } },
  script: { args: '<save|run|list|delete>', desc: 'In-memory multi-command macros', run(argv) {
    const sub = (argv[0] || 'list').toLowerCase();
    if (sub === 'list') { const k = Object.keys(scripts); print(HEAD('SCRIPTS (' + k.length + ')'));
      if (!k.length) print(MUTE('  (none; `script save <name> "<cmd>; <cmd>"`)'));
      k.forEach((n) => print('  ' + pad(n, 16) + scripts[n].join(' ; '))); return; }
    if (sub === 'save') { if (!argv[2]) { print(BAD('Usage: script save <name> "<cmd>; <cmd>"')); return 'INVALID'; }
      scripts[argv[1]] = splitChain(argv.slice(2).join(' ')).map((x) => x.cmd);
      print(OK('  Saved ' + argv[1] + ' (' + scripts[argv[1]].length + ' steps).')); return; }
    if (sub === 'run') { const sc = scripts[argv[1]]; if (!sc) { print(BAD('No such script: ' + argv[1])); return 'UNKNOWN'; }
      print(HEAD('SCRIPT · ' + argv[1] + ' · ' + sc.length + ' step(s)'));
      let last = 'ALLOWED';
      for (let i = 0; i < sc.length; i++) { print(MUTE('  ── ' + (i + 1) + '/' + sc.length + '  ' + sc[i])); last = execLine(sc[i]);
        if (['REFUSED', 'ERROR', 'UNKNOWN'].includes(last)) break; }
      audit('TERMINAL_SCRIPT', argv[1], last, sc.length + ' steps');
      print('  Script finished · ' + last); return last; }
    if (sub === 'delete') { delete scripts[argv[1]]; print(OK('  Deleted.')); return; }
    print(BAD('Usage: script <save|run|list|delete>')); return 'INVALID';
  } },
  repeat: { args: '<n> <command>', desc: 'Repeat a command up to 10 times', run(argv) {
    const n = Math.max(1, Math.min(10, parseInt(argv[0], 10) || 1)), cmd = argv.slice(1).join(' ');
    if (!cmd) { print(BAD('Usage: repeat <n> <command>')); return 'INVALID'; }
    let last = 'ALLOWED';
    for (let i = 0; i < n; i++) { print(MUTE('  ── iteration ' + (i + 1) + '/' + n)); last = execLine(cmd); }
    audit('TERMINAL_REPEAT', cmd.split(/\s+/)[0], last, n + ' iterations'); return last;
  } },
  panel: { args: '<session|files|plan|diff|approvals|tools|audit>', desc: 'Switch workbench panel (CLI prints it)', run(argv) {
    const tab = (argv[0] || 'session').toLowerCase();
    if (!['session', 'files', 'plan', 'diff', 'approvals', 'tools', 'audit'].includes(tab)) { print(BAD('Usage: panel <tab>')); return 'INVALID'; }
    if (tab === 'files') OP.files(session).forEach((f) => print('  ├── ' + f));
    else if (tab === 'plan') session.todos.forEach((t, i) => print('  ' + (i + 1) + '. [' + (t.status === 'done' ? 'x' : ' ') + '] ' + t.text));
    else if (tab === 'diff') print(OP.diffText(session) || MUTE('  Workspace clean.'));
    else if (tab === 'approvals') return COMMANDS.approvals.run([]);
    else if (tab === 'tools') OP.TOOLS.slice(0, 18).forEach((t) => print('  ' + pad(t.id, 26) + t.action.toUpperCase()));
    else if (tab === 'audit') state.audit.slice(-10).forEach((e) => print('  #' + pad(String(e.seq), 5) + pad(e.action, 26) + e.decision));
    else return opencodeCmd(['status']);
    return;
  } },
  workbench: { args: '[reset]', desc: 'Workbench overview / reset', run(argv) {
    return opencodeCmd(argv[0] === 'reset' ? ['reset'] : ['status']);
  } }
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
function dispatch(line) {
  const t = tokenize(line), name = (t[0] || '').toLowerCase(), argv = t.slice(1);
  const cmd = COMMANDS[name];
  let decision = 'ALLOWED';
  if (!cmd) { print(BAD('command not found: ' + name + '  (try `help`)')); decision = 'UNKNOWN'; }
  else {
    try { const r = cmd.run(argv, line); if (r && r.decision) decision = r.decision; else if (typeof r === 'string') decision = r; }
    catch (err) { print(BAD('runtime error: ' + (err && err.message ? err.message : String(err)))); decision = 'ERROR'; }
  }
  audit('TERMINAL_CMD', name || '(empty)', decision, line.slice(0, 180));
  return decision;
}
function execLine(line) {
  const expanded = expandVars(expandAlias(String(line || '').trim()));
  if (!expanded) return 'ALLOWED';
  const parts = splitOutside(expanded, '|');
  if (parts.length > 1) {
    quiet = true; capture = [];
    let first = 'ALLOWED';
    try { first = dispatch(parts[0]); } catch (e) { first = 'ERROR'; }
    let lines = capture.slice();
    quiet = false; capture = null;
    for (let i = 1; i < parts.length; i++) lines = applyFilter(lines, expandVars(parts[i]));
    if (!lines.length) lines = ['(empty pipeline result)'];
    lines.forEach((l) => print(l));
    print(MUTE('  pipeline: ' + parts.length + ' stages · ' + lines.length + ' line(s)'));
    audit('TERMINAL_PIPE', parts[0].split(/\s+/)[0] || 'pipe', first, parts.length + ' stages');
    return first;
  }
  return dispatch(expanded);
}
function execute(raw) {
  const line = String(raw || '').trim();
  if (!line) return;
  history.push(line);
  print(INFO('aegis ❯ ' + line));
  const segs = splitChain(line);
  let ok = true;
  segs.forEach((s) => {
    if (s.op === '&&' && !ok) { print(MUTE('  skipped (previous && failed)')); return; }
    const d = execLine(s.cmd);
    ok = !['REFUSED', 'UNKNOWN', 'ERROR', 'INVALID'].includes(d);
  });
  print('');
}

const rl = readline.createInterface({
  input: process.stdin, output: process.stdout, prompt: OK('aegis ❯ '), terminal: true,
  completer(partial) {
    const parts = partial.split(/\s+/), last = parts[parts.length - 1];
    let pool;
    if (parts.length === 1) pool = Object.keys(COMMANDS);
    else if (parts[0] === 'hexstrike' || parts[0] === 'mcp' || parts[0] === 'run') pool = HX.TOOLS.map((t) => t.id).concat(['info', 'tools', 'tool', 'agents', 'plan', 'run', 'manifest', 'call', 'resources', 'prompts']);
    else if (['oc', 'opencode', 'vfs', 'tool'].includes(parts[0])) pool = OP.TOOLS.map((t) => t.id).concat(OP.files(session), ['status', 'tools', 'tool', 'agents', 'agent', 'permissions', 'permission', 'plan', 'run', 'approve', 'deny', 'mcp', 'reset', 'ls', 'cat', 'grep', 'glob', 'diff', 'diagnostics']);
    else pool = Object.keys(COMMANDS);
    const hits = pool.filter((x) => x.startsWith(last));
    return [hits.length ? hits : pool, last];
  }
});

BANNER.forEach((l) => out(l));
rl.prompt();
rl.on('line', (line) => { execute(line); rl.prompt(); });
rl.on('close', () => { print(MUTE('AEGIS terminal closed.')); process.exit(0); });
