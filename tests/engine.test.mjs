import test from 'node:test';
import assert from 'node:assert/strict';
import { createRequire } from 'node:module';
import { readFileSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

const require = createRequire(import.meta.url);
const root = join(dirname(fileURLToPath(import.meta.url)), '..');
const DATA = require(join(root, 'src/00-data.js'));
const E = require(join(root, 'src/10-engine.js'));

function state() {
  const now = Date.now();
  const assets = DATA.ASSET_SEEDS.map((a, i) => ({
    id: 'ast' + i, name: a.name, owner: a.owner, env: a.env, criticality: a.criticality,
    authorizedBy: a.authorizedBy, expires: new Date(now + a.days * 86400000).toISOString(),
    checks: a.checks.slice(), confirmed: a.confirmed, revoked: false, token: 'abc123def456'
  }));
  return {
    version: 1, assets, findings: [], alerts: [], audit: [], watchlist: [], playbookProgress: {},
    logResults: null, headerResults: null, events: [],
    settings: { operator: 'test@local', humanApproval: true, strictScope: true },
    sweep: { count: 0, decisions: [] }, drafts: {}
  };
}

test('SHA-256 matches known vectors (empty, abc, long, unicode)', () => {
  assert.equal(E.sha256(''), 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855');
  assert.equal(E.sha256('abc'), 'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad');
  assert.equal(E.sha256('a'.repeat(1000)), '41edece42d63e8d9bf515a9ba6932e1c20cbc9f5a5d134645adb5db1b9737ea3');
  assert.equal(E.sha256('नमस्ते 🔐'), '6894c9808b5ad7506b16bdfd96615d01243d688e2e1434266b9f846a91fb5ca1');
  const { createHash } = require('node:crypto');
  ['a'.repeat(55), 'a'.repeat(56), 'a'.repeat(64), 'a'.repeat(10000), 'mixed 🔐 words and numbers 2026'].forEach((s) => {
    assert.equal(E.sha256(s), createHash('sha256').update(s).digest('hex'));
  });
});

test('authorization gate refuses unknown, expired, revoked and unpermitted targets', () => {
  const s = state();
  assert.equal(E.scopeCheck(s, 'app.acme-lab.internal', 'posture').allowed, true);
  assert.equal(E.scopeCheck(s, 'third-party.example').code, 'NO_SCOPE_RECORD');
  assert.equal(E.scopeCheck(s, 'legacy.acme-lab.io').code, 'SCOPE_EXPIRED');
  assert.equal(E.scopeCheck(s, 'app.acme-lab.internal', 'nonexistent').code, 'CHECK_NOT_PERMITTED');
  s.assets[0].revoked = true;
  assert.equal(E.scopeCheck(s, 'app.acme-lab.internal').code, 'SCOPE_REVOKED');
  s.assets[0].revoked = false;
  s.assets[0].confirmed = false;
  assert.equal(E.scopeCheck(s, 'app.acme-lab.internal').code, 'OWNER_UNCONFIRMED');
  s.assets[0].confirmed = true;
  assert.equal(E.activeAssets(s).length, s.assets.length - 1); // expired legacy record
});

test('log engine detects brute force, success-after-failure, injection and evasion', () => {
  const r = E.detectLogs(DATA.SAMPLE_LOGS);
  const ids = r.detections.map((d) => d.rule);
  assert.ok(ids.includes('AUTH-BRUTE-FORCE'), 'brute force threshold rule fires');
  assert.ok(ids.includes('AUTH-SUCCESS-AFTER-FAIL'), 'correlation rule fires');
  assert.ok(ids.includes('SQL-INJECTION'));
  assert.ok(ids.includes('PATH-TRAVERSAL'));
  assert.ok(ids.includes('WEB-SHELL'));
  assert.ok(ids.includes('SCANNER-UA'));
  assert.ok(ids.includes('DEFENSE-EVASION'));
  assert.ok(ids.includes('SECRET-EXPOSURE'));
  assert.ok(ids.includes('STATUS-ANOMALY'));
  const brute = r.detections.find((d) => d.rule === 'AUTH-BRUTE-FORCE');
  assert.ok(brute.count >= 5 && brute.lines.length > 0);
  assert.ok(r.stats.lines > 20 && r.stats.ips >= 2);
  assert.equal(E.detectLogs('').detections.length, 0);
});

test('IOC extraction defangs values and classifies IP ranges', () => {
  const iocs = E.extractIOCs('Contact bad@evil.test from https://cdn-update.top/gate.php at 185.220.101.47 and 10.20.0.15. CVE-2026-1234 ' + 'a'.repeat(64));
  const types = iocs.map((i) => i.type);
  assert.ok(types.includes('url') && types.includes('ipv4') && types.includes('email') && types.includes('cve') && types.includes('sha256'));
  const url = iocs.find((i) => i.type === 'url');
  assert.ok(url.defanged.startsWith('hxxps') && url.defanged.includes('[.]'));
  assert.equal(E.ipClass('10.20.0.15'), 'Private / internal');
  assert.equal(E.ipClass('185.220.101.47'), 'Public / external');
  assert.equal(E.validIPv4('999.1.1.1'), false);
});

test('header analyzer fails weak HSTS, missing CSP and wildcard CORS with credentials', () => {
  const r = E.analyzeHeaders(DATA.SAMPLE_HEADERS);
  const byId = Object.fromEntries(r.checks.map((c) => [c.id, c]));
  assert.equal(byId.HSTS.status, 'warn');
  assert.equal(byId.CSP.status, 'fail');
  assert.equal(byId.CORS.status, 'fail');
  assert.equal(byId.COOKIE.status, 'fail');
  assert.equal(byId.BANNER.status, 'fail');
  assert.ok(r.score < 60);
  assert.ok(['C', 'D', 'F'].includes(r.grade));
  const hardened = E.analyzeHeaders([
    'strict-transport-security: max-age=31536000; includeSubDomains',
    "content-security-policy: default-src 'self'; object-src 'none'; frame-ancestors 'none'",
    'x-content-type-options: nosniff', 'x-frame-options: DENY',
    'referrer-policy: strict-origin-when-cross-origin', 'permissions-policy: camera=()',
    'set-cookie: session=x; Secure; HttpOnly; SameSite=Lax',
    'cache-control: no-store', 'cross-origin-opener-policy: same-origin',
    'cross-origin-resource-policy: same-origin'
  ].join('\n'));
  assert.ok(hardened.score > r.score);
  assert.ok(['A', 'B'].includes(hardened.grade));
});

test('triage is explainable and deterministic; watchlist raises priority', () => {
  const s = state();
  const alert = { id: 'a1', title: 'Suspicious activity', severity: 'high', asset: 'app.acme-lab.internal',
    confidence: 80, evidence: 'callback to cdn-update.top', status: 'new', createdAt: Date.now() };
  const a = E.triage(alert, s);
  assert.ok(a.score > 60 && a.band === 'P2' || a.band === 'P1');
  assert.ok(a.reasons.length >= 3 && a.reasons[0].includes('Base severity'));
  assert.equal(a.requiresApproval, true);
  s.watchlist.push({ value: 'cdn-update.top', type: 'domain' });
  s.findings.push({ asset: 'app.acme-lab.internal', status: 'open' });
  const b = E.triage(alert, s);
  assert.ok(b.score > a.score, 'watchlist + correlation increase priority');
});

test('audit hash chain verifies and detects tampering', () => {
  const s = state();
  let prev = '0'.repeat(64);
  [['GENESIS', 'ALLOW', 'one'], ['SWEEP', 'ALLOW', 'two'], ['REFUSAL', 'REFUSE', 'three']].forEach((x, i) => {
    const entry = { seq: i + 1, ts: 1700000000000 + i, actor: 'test', action: x[0],
      target: 'asset', decision: x[1], detail: x[2], prevHash: prev };
    entry.hash = E.entryHash(entry);
    s.audit.push(entry); prev = entry.hash;
  });
  assert.deepEqual(E.verifyChain(s.audit), { valid: true, count: 3, head: prev });
  s.audit[1].detail = 'tampered';
  assert.equal(E.verifyChain(s.audit).valid, false);
  assert.equal(E.verifyChain(s.audit).brokenAt, 2);
});

test('simulated sweep respects scope and never yields findings for refused targets', () => {
  const s = state();
  const r = E.simulateSweep(s, 1);
  const refused = r.decisions.filter((d) => d.decision === 'REFUSED');
  assert.equal(refused.length, 1);
  assert.equal(refused[0].code, 'SCOPE_EXPIRED');
  assert.ok(r.findings.every((f) => f.simulated && f.source === 'autonomous-sweep'));
  assert.ok(r.findings.every((f) => f.asset !== 'legacy.acme-lab.io'));
  assert.ok(r.findings.every((f) => !/^https?:/.test(f.asset)));
});

test('compliance evaluation returns every mapped control', () => {
  const s = state();
  s.logResults = E.detectLogs(DATA.SAMPLE_LOGS);
  s.headerResults = E.analyzeHeaders(DATA.SAMPLE_HEADERS);
  s.watchlist = [{ value: 'a.top' }, { value: 'b.top' }];
  s.playbookProgress['pb-phishing'] = [true, true, true, true];
  const c = E.complianceState(s);
  assert.equal(c.length, DATA.COMPLIANCE_CONTROLS.length);
  assert.ok(c.every((x) => ['implemented', 'partial', 'gap'].includes(x.status)));
  assert.equal(c.find((x) => x.id === 'NIST-DE.CM').status, 'implemented');
  assert.equal(c.find((x) => x.id === 'MITRE-DE').status, 'implemented');
});

test('bundle is present and contains every source module', () => {
  const bundle = readFileSync(join(root, 'dist/bundle.js'), 'utf8');
  ['00-data.js', '10-engine.js', '20-store.js', '30-ui.js'].forEach((f) => {
    assert.ok(bundle.includes(f), 'bundle contains ' + f);
  });
  assert.ok(bundle.includes('AEGIS_STORE') && bundle.includes('AEGIS_ENGINE'));
});
