import test from 'node:test';
import assert from 'node:assert/strict';
import { createRequire } from 'node:module';
import { readFileSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

const require = createRequire(import.meta.url);
const root = join(dirname(fileURLToPath(import.meta.url)), '..');
const D2 = require(join(root, 'src/05-data2.js'));
const OP = require(join(root, 'src/17-opencode.js'));

function state() {
  return {
    version: 1, assets: [], findings: [], alerts: [], audit: [], cases: [], drafts: {},
    settings: { operator: 'test@local', strictScope: true, humanApproval: true }
  };
}

test('OpenCode catalog mirrors the upstream tool/agent/permission surface', () => {
  const s = OP.summary();
  assert.equal(s.tools, 41);
  assert.equal(s.agents, 7);
  assert.equal(s.permissions, 15);
  assert.ok(s.allow > 0 && s.ask > 0 && s.deny > 0);
  assert.equal(new Set(OP.TOOLS.map((t) => t.id)).size, OP.TOOLS.length);
  assert.deepEqual(OP.AGENTS.map((a) => a.id).slice(0, 3), ['build', 'plan', 'general']);
  assert.ok(OP.TOOLS.some((t) => t.id === 'apply_patch'));
  assert.ok(OP.TOOLS.some((t) => t.id === 'webfetch' && t.action === 'deny'));
  assert.ok(OP.TOOLS.some((t) => t.id === 'todowrite'));
  assert.ok(OP.TOOLS.some((t) => t.id === 'worktree_create' && t.action === 'deny'));
});

test('Hard-denied keys cannot be relaxed even by an operator policy change', () => {
  const ses = OP.createSession();
  assert.equal(OP.evaluate('webfetch', ses).action, 'deny');
  assert.equal(OP.evaluate('websearch', ses).action, 'deny');
  assert.equal(OP.evaluate('session_move', ses).action, 'deny');
  assert.equal(OP.evaluate('doom_loop', ses).action, 'deny');
  for (const key of Object.keys(OP.HARD_DENY)) {
    const r = OP.setPermission(ses, key, 'allow');
    assert.equal(r.ok, false);
    assert.match(r.error, /Hard-denied|hard-denied|Hard-denied key/);
    assert.equal(ses.permissions[key], 'deny');
  }
  assert.equal(OP.setPermission(ses, 'edit', 'allow').ok, true);
  assert.equal(OP.evaluate('apply_patch', ses).action, 'allow');
  assert.equal(OP.setPermission(ses, 'edit', 'deny').ok, true);
  assert.equal(OP.evaluate('apply_patch', ses).action, 'deny');
  assert.equal(OP.evaluate('write', ses).action, 'deny');
  assert.equal(OP.setPermission(ses, 'edit', 'bogus').ok, false);
});

test('Agent profiles reset the permission baseline and keep hard denies', () => {
  const ses = OP.createSession();
  assert.equal(OP.setAgent(ses, 'plan').ok, true);
  assert.equal(ses.permissions.webfetch, 'deny');
  assert.equal(OP.evaluate('read', ses).action, 'allow');
  assert.equal(OP.evaluate('write', ses).action, 'deny');
  assert.equal(OP.setAgent(ses, 'build').ok, true);
  assert.equal(OP.evaluate('write', ses).action, 'ask');
  assert.equal(OP.evaluate('webfetch', ses).action, 'deny');
  assert.equal(OP.setAgent(ses, 'does-not-exist').ok, false);
});

test('VFS is real but virtual: read, glob, grep, diagnostics, write, patch and diff', () => {
  const ses = OP.createSession();
  assert.equal(OP.files(ses).length, 11);
  assert.ok(OP.readLines(ses, 'src/app.js').some((l) => l.includes('eval(html)')));
  assert.deepEqual(OP.glob(ses, 'src/*.js').sort(), ['src/app.js', 'src/auth.js', 'src/config.js']);
  const hits = OP.grep(ses, 'innerHTML', 'src/*');
  assert.ok(hits.length >= 1);
  const diags = OP.diagnostics(ses);
  assert.ok(diags.some((d) => d.code === 'EVAL-USAGE'));
  assert.ok(diags.some((d) => d.code === 'XSS-SINK'));
  assert.ok(diags.some((d) => d.code === 'HARDCODED-SECRET'));

  const pending = OP.execute({ tool: 'write', args: { path: 'notes/review.md', content: 'line one\nline two' } }, ses);
  assert.equal(pending.status, 'PENDING');
  assert.equal(ses.files['notes/review.md'], undefined);
  assert.equal(ses.pending.length, 1);
  const approved = OP.approve(ses, pending.approvalId, 'approve', 'operator');
  assert.equal(approved.ok, true);
  assert.equal(approved.result.status, 'DONE');
  assert.equal(ses.files['notes/review.md'], 'line one\nline two');
  assert.equal(ses.decisions[0].decision, 'APPROVE');

  const denied = OP.execute({ tool: 'write', args: { path: 'notes/deny.md', content: 'x' } }, ses);
  assert.equal(denied.status, 'PENDING');
  const d = OP.approve(ses, denied.approvalId, 'deny', 'operator');
  assert.equal(d.result.status, 'DENIED');
  assert.equal(ses.files['notes/deny.md'], undefined);

  const edit = OP.execute({ tool: 'apply_patch', args: {
    path: 'src/app.js', patch: '-  return res.send(eval(html));\n+  return res.send(safe(html));'
  } }, ses, { force: true });
  assert.equal(edit.status, 'DONE');
  assert.ok(ses.files['src/app.js'].includes('safe(html)'));
  assert.ok(!ses.files['src/app.js'].includes('eval(html)'));
  const dt = OP.diffText(ses, 'src/app.js');
  assert.match(dt, /--- a\/src\/app.js/);
  assert.match(dt, /\+  return res.send\(safe\(html\)\);/);
  assert.equal(OP.execute({ tool: 'webfetch', args: { url: 'https://example.com' } }, ses).status, 'REFUSED');
  assert.equal(OP.execute({ tool: 'not_a_tool', args: {} }, ses).status, 'REFUSED');

  OP.reset(ses);
  assert.equal(ses.files['notes/review.md'], undefined);
  assert.ok(ses.files['src/app.js'].includes('eval(html)'));
  assert.equal(OP.diffText(ses), '');
});

test('Governed virtual shell exposes allowlisted commands only', () => {
  const ses = OP.createSession();
  const help = OP.virtualShell(ses, 'help');
  assert.ok(help.join('\n').includes('Governed virtual shell'));
  assert.ok(OP.virtualShell(ses, 'ls').some((l) => l === 'src/app.js'));
  assert.ok(OP.virtualShell(ses, 'grep eval').some((l) => l.includes('src/app.js:')));
  assert.ok(OP.virtualShell(ses, 'cat src/app.js')[0].includes('1'));
  assert.ok(OP.virtualShell(ses, 'git status')[0].includes('clean'));
  assert.ok(OP.virtualShell(ses, 'curl https://example.com')[0].includes('not an allowlisted'));
  assert.equal(OP.virtualShell(ses, 'pwd')[0], '/workspace');
});

test('Deterministic planner streams steps and pauses for human approval', () => {
  const ses = OP.createSession();
  const p = OP.plan('audit headers and fix app', ses);
  assert.equal(p.engine, 'deterministic keyword planner (no model call)');
  assert.ok(p.steps.length >= 7);
  assert.ok(p.steps.some((x) => x.tool === 'read' && x.args.path === 'config/headers.txt'));
  assert.ok(p.steps.some((x) => x.tool === 'apply_patch'));
  assert.equal(ses.todos.length, p.steps.length);

  let done = 0, paused = null;
  for (const step of p.steps) {
    const r = OP.execute(step, ses);
    if (r.status === 'DONE') done++;
    else { paused = r; break; }
  }
  assert.ok(done >= 5);
  assert.ok(paused);
  assert.equal(paused.status, 'PENDING');
  assert.equal(paused.tool, 'apply_patch');
  const a = OP.approve(ses, paused.approvalId, 'approve', 'operator');
  assert.equal(a.result.status, 'DONE');
  assert.ok(a.result.diff.includes('safe') || a.result.diff.includes('escapeHtml'));
  assert.ok(ses.toolCalls.length >= 7);
});

test('MCP contract is explicit, offline and never auto-allows writes', () => {
  const m = OP.mcp();
  assert.equal(m.name, 'aegis-sentinel-opencode-adapter');
  assert.equal(m.upstream, 'sst/opencode@2.2.7');
  assert.equal(m.tools.length, OP.TOOLS.length);
  assert.deepEqual(m.alwaysAllow, []);
  assert.equal(m.capabilities.sampling, false);
  assert.equal(m.capabilities.filesystem, 'virtual-only');
  assert.equal(m.capabilities.shell, 'governed-virtual');
  assert.match(m.transport, /offline/);
  assert.ok(m.resources.some((r) => r.uri === 'aegis://diff'));
  assert.ok(m.prompts.some((p) => p.name === 'security-review'));
});

test('Source contains no process, socket, filesystem or network execution path', () => {
  const src = readFileSync(join(root, 'src/17-opencode.js'), 'utf8');
  for (const forbidden of ['child_process', 'process.spawn', 'execSync', 'require(\'http', 'require("http',
    'XMLHttpRequest', 'WebSocket', 'fetch(', 'fs.writeFile', 'node:fs', 'opencode serve', '--auto']) {
    assert.equal(src.includes(forbidden), false, 'forbidden token: ' + forbidden);
  }
  assert.ok(src.includes('no network egress'));
  assert.equal(D2.CAPABILITIES.filter((c) => c.status === 'blocked').length, 6);
});
