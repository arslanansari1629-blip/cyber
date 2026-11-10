import test from 'node:test';
import assert from 'node:assert/strict';
import { createRequire } from 'node:module';
import { readFileSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

const require = createRequire(import.meta.url);
const root = join(dirname(fileURLToPath(import.meta.url)), '..');
const DATA = require(join(root, 'src/00-data.js'));
const D2 = require(join(root, 'src/05-data2.js'));
const E = require(join(root, 'src/10-engine.js'));
const A = require(join(root, 'src/15-advanced.js'));
const HX = require(join(root, 'src/16-hexstrike.js'));

function state() {
  const now = Date.now();
  const assets = DATA.ASSET_SEEDS.map((a, i) => ({
    id: 'ast' + i, name: a.name, owner: a.owner, env: a.env, criticality: a.criticality,
    authorizedBy: a.authorizedBy, expires: new Date(now + a.days * 86400000).toISOString(),
    checks: a.checks.slice(), confirmed: a.confirmed, revoked: false, token: 'token' + i
  }));
  return {
    version: 1, assets, findings: [], alerts: [], audit: [], watchlist: [], cases: [],
    customRules: [], playbookProgress: {}, ingestResults: null, labResults: {},
    orchestratorRuns: [], investigationHistory: [], capabilityRequests: [], quantResult: null,
    logResults: null, headerResults: null, intelResults: null, events: [],
    sweep: { count: 0, decisions: [] },
    settings: { operator: 'test@local', humanApproval: true, strictScope: true },
    drafts: { ingest: D2.SAMPLES.jsonl }
  };
}

test('HexStrike catalog mirrors the upstream FastMCP tool names', () => {
  const s = HX.summary();
  assert.equal(s.decorated, 151);
  assert.equal(s.total, 150); // httpx_probe is declared twice upstream
  assert.equal(s.adapters, 35);
  assert.equal(s.blocked, 104);
  assert.equal(s.unavailable, 11);
  assert.equal(s.adapters + s.blocked + s.unavailable, s.total);
  assert.equal(s.agents, 12);
  assert.equal(s.blockedAgents, 3);
  assert.ok(s.categories.includes('cloud') && s.categories.includes('binary'));
  assert.equal(HX.TOOLS.length, new Set(HX.TOOLS.map((t) => t.id)).size);
  assert.ok(HX.TOOLS.every((t) => t.id && t.category && t.reason));
  assert.ok(HX.TOOLS.filter((t) => t.mode === 'blocked').every((t) => t.cap));
});

test('offensive upstream tools are bound to hard-refused AEGIS capabilities', () => {
  const cases = {
    nmap_scan: 'net.scan', masscan_high_speed: 'net.scan', gobuster_scan: 'net.scan',
    sqlmap_scan: 'net.scan', metasploit_run: 'credential.attack', hydra_attack: 'credential.attack',
    hashcat_crack: 'credential.attack', execute_command: 'exploit.execute',
    create_file: 'exploit.execute', msfvenom_generate: 'exploit.execute',
    terminate_process: 'contain.execute', pause_process: 'contain.execute'
  };
  Object.keys(cases).forEach((id) => {
    const t = HX.get(id);
    assert.ok(t, 'missing ' + id);
    assert.equal(t.mode, 'blocked', id);
    assert.equal(t.cap, cases[id], id);
    assert.ok(D2.CAPABILITIES.some((c) => c.id === t.cap && c.status !== 'enabled'), id + ' maps to a blocked manifest entry');
  });
});

test('safe upstream tools map to real enabled offline AEGIS engines', () => {
  const cases = {
    trivy_scan: 'config.sbom', prowler_scan: 'config.iam', kube_bench_cis: 'config.k8s',
    nuclei_scan: 'config.hardening', checkov_iac_scan: 'config.secrets',
    discover_attack_chains: 'telemetry.correlate', anew_data_processing: 'telemetry.normalize',
    create_vulnerability_report: 'govern.report'
  };
  Object.keys(cases).forEach((id) => {
    const t = HX.get(id);
    assert.equal(t.mode, 'adapter', id);
    assert.equal(t.cap, cases[id], id);
    assert.ok(D2.CAPABILITIES.some((c) => c.id === t.cap && c.status === 'enabled'), id);
    assert.ok(t.adapter && t.adapter.engine, id + ' has an engine');
  });
});

test('MCP-shaped manifest is offline, closed by default and complete', () => {
  const m = HX.MCP;
  assert.equal(m.name, 'aegis-sentinel-hexstrike-adapter');
  assert.match(m.transport, /offline/);
  assert.deepEqual(m.alwaysAllow, []);
  assert.equal(m.capabilities.sampling, false);
  assert.equal(m.capabilities.logging, false);
  assert.equal(m.tools.length, HX.TOOLS.length);
  assert.ok(m.tools.every((t) => t.mode === 'adapter' || t.mode === 'blocked' || t.mode === 'unavailable'));
  assert.ok(m.resources.some((r) => r.uri === 'aegis://ledger'));
  assert.ok(m.prompts.some((p) => p.name === 'explain-refusal'));
});

test('evaluate() refuses unknown, blocked and server-only tools', () => {
  const s = state();
  assert.equal(HX.evaluate('does_not_exist', s, null).code, 'UNKNOWN_TOOL');
  const b = HX.evaluate('nmap_scan', s, null);
  assert.equal(b.allowed, false);
  assert.equal(b.code, 'CAPABILITY_BLOCKED');
  assert.equal(b.mappedCapability, 'net.scan');
  assert.ok(b.reason.length > 20);
  const u = HX.evaluate('get_cache_stats', s, null);
  assert.equal(u.code, 'TOOL_UNAVAILABLE');
  assert.equal(u.tool.mode, 'unavailable');
});

test('evaluate() still enforces asset scope for adapter tools', () => {
  const s = state();
  const ok = HX.evaluate('trivy_scan', s, 'app.acme-lab.internal');
  assert.equal(ok.allowed, true);
  assert.equal(ok.code, 'CAPABILITY_GRANTED');
  const expired = HX.evaluate('trivy_scan', s, 'legacy.acme-lab.io');
  assert.equal(expired.allowed, false);
  assert.equal(expired.code, 'SCOPE_EXPIRED');
  const missing = HX.evaluate('trivy_scan', s, 'not-registered.example');
  assert.equal(missing.code, 'NO_SCOPE_RECORD');
});

test('call() executes real offline analysis and returns a JSON-RPC envelope', () => {
  const s = state();
  const r = HX.call('trivy_scan', { id: 7, target: 'app.acme-lab.internal' }, s);
  assert.equal(r.jsonrpc, '2.0');
  assert.equal(r.id, 7);
  assert.equal(r.tool, 'trivy_scan');
  assert.ok(r.result, 'adapter call returns a result');
  assert.equal(r.result.mode, 'offline-adapter');
  assert.equal(r.result.capability, 'config.sbom');
  assert.equal(r.result.engine, 'analyzeDependencies');
  assert.ok(r.result.data.findings >= 3);
  assert.ok(r.result.summary.includes('advisory'));

  const iam = HX.call('prowler_scan', { target: 'app.acme-lab.internal' }, s);
  assert.ok(iam.result.data.fails >= 3);
  const k8s = HX.call('kube_bench_cis', { target: 'app.acme-lab.internal' }, s);
  assert.ok(k8s.result.data.fails >= 5);
  const hdr = HX.call('nuclei_scan', { target: 'app.acme-lab.internal' }, s);
  assert.equal(hdr.result.data.checks, 12);
  const sec = HX.call('jwt_analyzer', { target: 'app.acme-lab.internal' }, s);
  assert.equal(sec.result.data.allMasked, true);
  const ch = HX.call('discover_attack_chains', { target: 'app.acme-lab.internal' }, s);
  assert.ok(ch.result.data.chains >= 1);
  const ioc = HX.call('analyze_target_intelligence', { target: 'app.acme-lab.internal' }, s);
  assert.ok(ioc.result.data.total >= 1);
  assert.ok(ioc.result.data.defangedSample.every((x) => typeof x === 'string'));
});

test('call() refuses offensive tools without running anything', () => {
  const s = state();
  const r = HX.call('nmap_scan', { target: 'app.acme-lab.internal' }, s);
  assert.ok(r.error, 'blocked tool returns a JSON-RPC error');
  assert.equal(r.error.message, 'CAPABILITY_BLOCKED');
  assert.equal(r.error.data.capability, 'net.scan');
  assert.equal(r.result, undefined);
  const u = HX.call('get_cache_stats', {}, s);
  assert.equal(u.error.message, 'TOOL_UNAVAILABLE');
});

test('plan() is deterministic and never schedules a refused tool as eligible', () => {
  const s = state();
  const a = HX.plan('harden the api headers'), b = HX.plan('harden the api headers');
  assert.deepEqual(a, b);
  assert.ok(a.steps.length >= 3);
  assert.ok(a.steps.every((x) => HX.get(x.tool)));
  assert.ok(a.steps.some((x) => x.tool === 'server_health'));
  assert.ok(a.steps.some((x) => x.tool === 'create_vulnerability_report'));
  assert.ok(a.steps.filter((x) => x.decision === 'ELIGIBLE').every((x) => HX.get(x.tool).mode === 'adapter'));
  const iam = HX.plan('review IAM policy for aws');
  assert.ok(iam.steps.some((x) => x.tool === 'prowler_scan'));
});

test('adapter layer contains no network or process primitives', () => {
  const src = readFileSync(join(root, 'src/16-hexstrike.js'), 'utf8');
  ['fetch(', 'XMLHttpRequest', 'WebSocket', 'require(\'http', 'child_process', 'process.spawn', 'fs.writeFile'].forEach((bad) => {
    assert.ok(!src.includes(bad), 'source must not contain ' + bad);
  });
  assert.ok(src.includes('No upstream code is bundled or executed'));
});

test('AEGIS capability evaluation remains independent of the adapter', () => {
  const s = state();
  assert.equal(A.evaluateCapability('net.scan', s).code, 'CAPABILITY_BLOCKED');
  assert.equal(A.evaluateCapability('scope.bypass', s).code, 'CAPABILITY_BLOCKED');
  assert.equal(A.evaluateCapability('telemetry.normalize', s, 'app.acme-lab.internal').allowed, true);
  assert.ok(E.verifyChain(s.audit).valid);
});
