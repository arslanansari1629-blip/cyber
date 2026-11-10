import test from 'node:test';
import assert from 'node:assert/strict';
import { createRequire } from 'node:module';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

const require = createRequire(import.meta.url);
const root = join(dirname(fileURLToPath(import.meta.url)), '..');
const DATA = require(join(root, 'src/00-data.js'));
const D2 = require(join(root, 'src/05-data2.js'));
const E = require(join(root, 'src/10-engine.js'));
const A = require(join(root, 'src/15-advanced.js'));

function state() {
  const now = Date.now();
  const assets = DATA.ASSET_SEEDS.map((a, i) => ({
    id: 'ast' + i, name: a.name, owner: a.owner, env: a.env, criticality: a.criticality,
    authorizedBy: a.authorizedBy, expires: new Date(now + a.days * 86400000).toISOString(),
    checks: a.checks.slice(), confirmed: a.confirmed, revoked: false, token: 'token' + i
  }));
  return {
    version: 1, assets, findings: DATA.FINDING_SEEDS.map((f, i) => ({
      id: 'f' + i, title: f.title, severity: f.severity, asset: f.asset,
      category: f.category, mitre: f.mitre, evidence: f.evidence, remediation: f.remediation,
      status: 'open', createdAt: now
    })),
    alerts: DATA.ALERT_SEEDS.map((a, i) => ({ id: 'a' + i, ...a, status: 'new', priority: null, createdAt: now })),
    audit: [], watchlist: [], cases: [], customRules: [], playbookProgress: {},
    ingestResults: null, labResults: {}, orchestratorRuns: [], investigationHistory: [],
    capabilityRequests: [], quantResult: null, logResults: null, headerResults: null,
    intelResults: null, events: [], sweep: { count: 0, decisions: [] },
    settings: { operator: 'test@local', humanApproval: true, strictScope: true },
    drafts: {
      logs: DATA.SAMPLE_LOGS, headers: DATA.SAMPLE_HEADERS, intel: DATA.SAMPLE_INTEL,
      ingest: D2.SAMPLES.jsonl
    }
  };
}

test('universal ingest auto-detects four formats and normalizes events', () => {
  const cases = [
    [D2.SAMPLES.jsonl, 'jsonl'], [D2.SAMPLES.nginx, 'nginx'],
    [DATA.SAMPLE_LOGS, 'syslog'], ['ts,src,actor,action,status\n1,10.0.0.1,root,login,200\n2,10.0.0.2,admin,denied,403', 'csv']
  ];
  cases.forEach(([text, expected]) => {
    const r = A.normalizeLogs(text);
    assert.equal(r.format, expected, 'format detection for ' + expected);
    assert.ok(r.events.length > 0);
    assert.ok(r.events.every((e) => e.n && typeof e.action === 'string' && Array.isArray(e.tags)));
  });
  const json = A.normalizeLogs(D2.SAMPLES.jsonl);
  assert.ok(json.events.some((e) => e.src === '185.220.101.47'));
  assert.ok(json.stats.tagged >= 3, 'detection rules tag normalized events');
  assert.ok(json.stats.sources >= 2);
});

test('attack-chain reconstruction finds multi-tactic progression with confidence', () => {
  const norm = A.normalizeLogs(D2.SAMPLES.jsonl);
  const c = A.attackChains(norm);
  assert.ok(c.chains.length >= 1, 'at least one chain reconstructed');
  const top = c.chains[0];
  assert.ok(top.tactics.length >= 2);
  assert.ok(top.techniques.length >= 2);
  assert.ok(top.confidence > 40 && top.confidence <= 96);
  assert.ok(top.timeline.every((t) => t.tactic && t.technique));
  assert.equal(A.attackChains({ events: [] }).chains.length, 0);
});

test('anomaly detection flags outliers using z-score and IQR', () => {
  const r = A.anomalyDetect([10, 11, 9, 10, 12, 9, 11, 10, 80, 10]);
  assert.ok(r.outliers.some((o) => o.value === 80 && o.z > 2));
  assert.equal(r.ewma.length, 10);
  assert.ok(r.upper > 12 && r.lower < 12);
  assert.equal(A.anomalyDetect([]).outliers.length, 0);
});

test('secret scanner masks values and reports entropy', () => {
  const r = A.secretScan(D2.SAMPLES.secrets);
  assert.ok(r.findings.length >= 5);
  assert.ok(r.findings.some((f) => f.type === 'AWS access key'));
  assert.ok(r.findings.some((f) => f.type === 'Private key block'));
  assert.ok(r.findings.every((f) => !f.masked.includes('AKIAIOSFODNN7EXAMPLEKEY')));
  assert.ok(r.findings.every((f) => f.entropy > 0 && f.fix));
  assert.ok(A.shannon('aaaaaaaa') < A.shannon('aB3$xY9!qL2'));
});

test('IAM analyzer flags wildcard actions, public principal and PassRole', () => {
  const r = A.analyzeIamPolicy(D2.SAMPLES.iam);
  const byId = Object.fromEntries(r.checks.map((c) => [c.id, c]));
  assert.equal(r.statements, 5);
  assert.equal(byId['WILD-ACTION'].status, 'fail');
  assert.equal(byId['PUBLIC-PRINCIPAL'].status, 'fail');
  assert.equal(byId['PASS-ROLE'].status, 'fail');
  assert.ok(r.score < 70);
  const bad = A.analyzeIamPolicy('not json');
  assert.equal(bad.parsed, false);
  assert.equal(bad.checks[0].status, 'fail');
});

test('Kubernetes analyzer catches privileged pods and host mounts', () => {
  const r = A.analyzeK8s(D2.SAMPLES.k8s);
  const byId = Object.fromEntries(r.checks.map((c) => [c.id, c]));
  ['PRIVILEGED', 'HOST-NS', 'ROOT-USER', 'PRIV-ESC', 'CAPS', 'HOSTPATH'].forEach((id) => {
    assert.equal(byId[id].status, 'fail', id);
  });
  assert.ok(r.score < 50);
  assert.equal(A.analyzeK8s('apiVersion: v1\nkind: Pod\nspec:\n  containers:\n  - name: ok\n    image: app:1.2.3\n    securityContext:\n      readOnlyRootFilesystem: true').score > r.score, true);
});

test('email analyzer produces a phishing verdict with defanged indicators', () => {
  const r = A.analyzeEmail(D2.SAMPLES.email);
  assert.equal(r.verdict, 'PHISHING LIKELY');
  assert.ok(r.received >= 2);
  assert.ok(r.checks.some((c) => c.id === 'AUTH' && c.status === 'fail'));
  assert.ok(r.checks.some((c) => c.id === 'REPLY-TO' && c.status === 'fail'));
  assert.ok(r.urls.some((u) => String(u.defanged).includes('[.]')));
  assert.ok(r.score < 45);
});

test('dependency analyzer matches offline advisory baseline', () => {
  const r = A.analyzeDependencies(D2.SAMPLES.deps);
  assert.equal(r.format, 'package.json');
  assert.ok(r.packages.length >= 5);
  const names = r.findings.map((f) => f.name);
  assert.ok(names.includes('lodash') && names.includes('minimist') && names.includes('axios'));
  assert.ok(r.findings.some((f) => f.cve === 'CVE-2021-44906'));
  const req = A.analyzeDependencies(D2.SAMPLES.requirements);
  assert.ok(req.findings.some((f) => f.name === 'requests'));
  assert.equal(A.compareVersions('4.17.20', '4.17.21'), -1);
  assert.equal(A.compareVersions('2.0.0', '1.9.9'), 1);
});

test('custom rule engine validates regex and honors threshold', () => {
  const ok = A.testCustomRule({ pattern: 'failed password', threshold: 2 }, DATA.SAMPLE_LOGS);
  assert.equal(ok.ok, true);
  assert.ok(ok.count >= 5 && ok.matched);
  const bad = A.testCustomRule({ pattern: '([', threshold: 1 }, DATA.SAMPLE_LOGS);
  assert.equal(bad.ok, false);
  assert.ok(bad.error);
  const high = A.testCustomRule({ pattern: 'impossible-never-match', threshold: 999 }, DATA.SAMPLE_LOGS);
  assert.equal(high.matched, false);
});

test('ATT&CK coverage computes over the full technique matrix', () => {
  const s = state();
  s.logResults = E.detectLogs(DATA.SAMPLE_LOGS);
  s.customRules = [{ mitre: 'T1595' }];
  const c = A.mitreCoverage(s);
  assert.equal(c.total, D2.TECHNIQUES.length);
  assert.equal(c.tactics.length, D2.MITRE_TACTICS.length);
  assert.ok(c.covered >= 10 && c.percent > 20);
  assert.ok(c.gaps.length > 0);
  assert.ok(c.tactics.every((t) => t.total === t.techniques.length));
  assert.equal(A.tacticOf('T1110'), 'credential');
  assert.equal(A.tacticName('c2'), 'Command & Control');
});

test('Monte Carlo risk is deterministic and reports percentiles', () => {
  const s = state();
  const a = A.monteCarloRisk(s, 1500), b = A.monteCarloRisk(s, 1500);
  assert.equal(a.p90, b.p90);
  assert.equal(a.iterations, 1500);
  assert.ok(a.p50 <= a.p90 && a.p90 <= a.p95);
  assert.equal(a.bins.length, 10);
  assert.equal(a.open, s.findings.length);
});

test('investigation copilot parses intent, severity, asset and MITRE filters', () => {
  const s = state();
  const a = A.investigate('show critical findings for api.acme-lab.io', s);
  assert.equal(a.type, 'findings');
  assert.ok(a.parsed.severities.includes('critical'));
  assert.ok(a.parsed.assets.includes('api.acme-lab.io'));
  const b = A.investigate('assets out of scope', s);
  assert.equal(b.type, 'assets');
  assert.equal(b.rows.length, 1); // expired legacy record
  const c = A.investigate('findings mapped to T1190', s);
  assert.equal(c.parsed.mitre, 'T1190');
  const d = A.investigate('summary of the ledger', s);
  assert.equal(d.type, 'ledger');
  const e = A.investigate('high severity alerts', s);
  assert.equal(e.type, 'alerts');
});

test('capability policy refuses unknown and blocked classes, grants enabled ones', () => {
  const s = state();
  assert.equal(A.evaluateCapability('net.scan', s).code, 'CAPABILITY_BLOCKED');
  assert.equal(A.evaluateCapability('scope.bypass', s).code, 'CAPABILITY_BLOCKED');
  assert.equal(A.evaluateCapability('does.not.exist', s).code, 'UNKNOWN_CAPABILITY');
  assert.equal(A.evaluateCapability('telemetry.normalize', s, 'app.acme-lab.internal').allowed, true);
  assert.equal(A.evaluateCapability('telemetry.normalize', s, 'legacy.acme-lab.io').code, 'SCOPE_EXPIRED');
  assert.equal(A.evaluateCapability('config.hardening', s, '10.20.0.0/24').code, 'CHECK_NOT_PERMITTED');
});

test('orchestrator steps execute real offline analysis and seal results', () => {
  const s = state();
  const ctx = { target: 'app.acme-lab.internal' };
  D2.ORCHESTRATOR_PLAN.forEach((n) => {
    const r = A.orchestratorStep(n, s, ctx);
    assert.equal(r.status, 'DONE', n.id + ' -> ' + r.code + ' ' + r.reason);
    assert.ok(typeof r.detail === 'string' && r.detail.length > 5);
  });
  assert.ok(ctx.ingest.events.length > 0);
  assert.ok(ctx.detect.detections.length > 0);
  assert.equal(ctx.harden.checks.length, 12);
  assert.ok(ctx.chains.chains.length >= 1);
  assert.ok(ctx.scores.length === s.alerts.length);
  assert.equal(ctx.coverage.total, D2.TECHNIQUES.length);
  assert.ok(ctx.report.findings > 0);
});
