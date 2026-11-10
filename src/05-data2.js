/* AEGIS // SENTINEL v2 — extended knowledge base: ATT&CK matrix, capability
 * manifest, orchestrator plan, advisory baseline and analysis samples.
 * Everything here is data. No network endpoints, no payloads, no exploits.
 */
(function (root) {
  'use strict';

  var MITRE_TACTICS = [
    { id: 'recon', name: 'Reconnaissance', short: 'RECON' },
    { id: 'resource', name: 'Resource Development', short: 'RESOURCE' },
    { id: 'initial', name: 'Initial Access', short: 'INITIAL' },
    { id: 'execution', name: 'Execution', short: 'EXEC' },
    { id: 'persistence', name: 'Persistence', short: 'PERSIST' },
    { id: 'privilege', name: 'Privilege Escalation', short: 'PRIVESC' },
    { id: 'evasion', name: 'Defense Evasion', short: 'EVASION' },
    { id: 'credential', name: 'Credential Access', short: 'CRED' },
    { id: 'discovery', name: 'Discovery', short: 'DISCOVERY' },
    { id: 'lateral', name: 'Lateral Movement', short: 'LATERAL' },
    { id: 'collection', name: 'Collection', short: 'COLLECT' },
    { id: 'c2', name: 'Command & Control', short: 'C2' },
    { id: 'exfil', name: 'Exfiltration', short: 'EXFIL' },
    { id: 'impact', name: 'Impact', short: 'IMPACT' }
  ];

  var TECHNIQUES = [
    { id: 'T1595', name: 'Active Scanning', tactic: 'recon' },
    { id: 'T1592', name: 'Gather Victim Host Information', tactic: 'recon' },
    { id: 'T1589', name: 'Gather Identity Information', tactic: 'recon' },
    { id: 'T1583', name: 'Acquire Infrastructure', tactic: 'resource' },
    { id: 'T1587', name: 'Develop Capabilities', tactic: 'resource' },
    { id: 'T1190', name: 'Exploit Public-Facing Application', tactic: 'initial' },
    { id: 'T1078', name: 'Valid Accounts', tactic: 'initial' },
    { id: 'T1566', name: 'Phishing', tactic: 'initial' },
    { id: 'T1195', name: 'Supply Chain Compromise', tactic: 'initial' },
    { id: 'T1059', name: 'Command and Scripting Interpreter', tactic: 'execution' },
    { id: 'T1059.007', name: 'JavaScript', tactic: 'execution' },
    { id: 'T1204', name: 'User Execution', tactic: 'execution' },
    { id: 'T1505.003', name: 'Web Shell', tactic: 'persistence' },
    { id: 'T1098', name: 'Account Manipulation', tactic: 'persistence' },
    { id: 'T1136', name: 'Create Account', tactic: 'persistence' },
    { id: 'T1548.002', name: 'Bypass User Account Control', tactic: 'privilege' },
    { id: 'T1068', name: 'Exploitation for Privilege Escalation', tactic: 'privilege' },
    { id: 'T1027', name: 'Obfuscated Files or Information', tactic: 'evasion' },
    { id: 'T1562.001', name: 'Disable or Modify Tools', tactic: 'evasion' },
    { id: 'T1070', name: 'Indicator Removal', tactic: 'evasion' },
    { id: 'T1110', name: 'Brute Force', tactic: 'credential' },
    { id: 'T1110.003', name: 'Password Spraying', tactic: 'credential' },
    { id: 'T1539', name: 'Steal Web Session Cookie', tactic: 'credential' },
    { id: 'T1552', name: 'Unsecured Credentials', tactic: 'credential' },
    { id: 'T1087', name: 'Account Discovery', tactic: 'discovery' },
    { id: 'T1046', name: 'Network Service Discovery', tactic: 'discovery' },
    { id: 'T1021', name: 'Remote Services', tactic: 'lateral' },
    { id: 'T1570', name: 'Lateral Tool Transfer', tactic: 'lateral' },
    { id: 'T1005', name: 'Data from Local System', tactic: 'collection' },
    { id: 'T1114', name: 'Email Collection', tactic: 'collection' },
    { id: 'T1071', name: 'Application Layer Protocol', tactic: 'c2' },
    { id: 'T1572', name: 'Protocol Tunneling', tactic: 'c2' },
    { id: 'T1105', name: 'Ingress Tool Transfer', tactic: 'c2' },
    { id: 'T1573', name: 'Encrypted Channel', tactic: 'c2' },
    { id: 'T1041', name: 'Exfiltration Over C2 Channel', tactic: 'exfil' },
    { id: 'T1567', name: 'Exfiltration Over Web Service', tactic: 'exfil' },
    { id: 'T1486', name: 'Data Encrypted for Impact', tactic: 'impact' },
    { id: 'T1490', name: 'Inhibit System Recovery', tactic: 'impact' },
    { id: 'T1496', name: 'Resource Hijacking', tactic: 'impact' },
    { id: 'T1537', name: 'Transfer Data to Cloud Account', tactic: 'exfil' },
    { id: 'T1187', name: 'Forced Authentication', tactic: 'credential' },
    { id: 'T1557', name: 'Adversary-in-the-Middle', tactic: 'credential' }
  ];

  /* Explicit, machine-readable capability manifest. Anything not listed as
   * enabled is refused by evaluateCapability() and the refusal is logged. */
  var CAPABILITIES = [
    { id: 'scope.verify', name: 'Verify authorization scope', group: 'GOVERN', status: 'enabled', scope: 'posture', desc: 'Validate signed record, attestation, expiry and permitted checks.' },
    { id: 'telemetry.normalize', name: 'Universal telemetry normalization', group: 'ANALYZE', status: 'enabled', scope: 'logs', desc: 'Auto-detect 7 log formats and normalize into a common event schema.' },
    { id: 'telemetry.detect', name: 'Signature & threshold detection', group: 'ANALYZE', status: 'enabled', scope: 'logs', desc: 'Run MITRE-mapped rules and operator-authored custom rules.' },
    { id: 'telemetry.correlate', name: 'Attack-chain reconstruction', group: 'ANALYZE', status: 'enabled', scope: 'logs', desc: 'Group events by source, infer tactic progression and confidence.' },
    { id: 'telemetry.anomaly', name: 'Statistical anomaly detection', group: 'ANALYZE', status: 'enabled', scope: 'logs', desc: 'Z-score, IQR and EWMA on operator-supplied time series.' },
    { id: 'config.hardening', name: 'HTTP hardening evaluation', group: 'ANALYZE', status: 'enabled', scope: 'headers', desc: '12 weighted response-header controls with remediation.' },
    { id: 'config.iam', name: 'IAM policy analysis', group: 'ANALYZE', status: 'enabled', scope: 'posture', desc: 'Detect wildcard actions, public principals and missing MFA conditions.' },
    { id: 'config.k8s', name: 'Kubernetes manifest analysis', group: 'ANALYZE', status: 'enabled', scope: 'posture', desc: 'Flag privileged pods, host namespaces, root users and hostPath mounts.' },
    { id: 'config.email', name: 'Phishing email analysis', group: 'ANALYZE', status: 'enabled', scope: 'intel', desc: 'Authentication results, header anomalies, URL and spoofing checks.' },
    { id: 'config.secrets', name: 'Secret & entropy scanning', group: 'ANALYZE', status: 'enabled', scope: 'posture', desc: 'Detect credential material with masking and Shannon entropy scoring.' },
    { id: 'config.sbom', name: 'Dependency / SBOM analysis', group: 'ANALYZE', status: 'enabled', scope: 'posture', desc: 'Compare versions against a local illustrative advisory baseline.' },
    { id: 'intel.ioc', name: 'IOC extraction & defanging', group: 'ANALYZE', status: 'enabled', scope: 'intel', desc: 'Hashes, URLs, domains, IPs, emails and CVE IDs, local correlation.' },
    { id: 'triage.score', name: 'Explainable alert triage', group: 'OPERATE', status: 'enabled', scope: 'logs', desc: 'Transparent multi-factor priority scoring with reasoning chains.' },
    { id: 'govern.playbook', name: 'Playbook orchestration', group: 'OPERATE', status: 'enabled', scope: 'posture', desc: 'Trackable NIST CSF response checklists.' },
    { id: 'govern.case', name: 'Incident case management', group: 'OPERATE', status: 'enabled', scope: 'posture', desc: 'Link alerts and evidence into an auditable investigation case.' },
    { id: 'govern.ledger', name: 'Tamper-evident decision ledger', group: 'GOVERN', status: 'enabled', scope: 'posture', desc: 'SHA-256 hash chain with full verification.' },
    { id: 'govern.report', name: 'Evidence report generation', group: 'GOVERN', status: 'enabled', scope: 'posture', desc: 'Executive summary, JSON export and MITRE coverage exports.' },
    { id: 'simulate.sweep', name: 'Local posture simulation', group: 'OPERATE', status: 'enabled', scope: 'posture', desc: 'Deterministic template-based findings. No host is contacted.' },
    { id: 'net.scan', name: 'Active network scanning of third parties', group: 'BLOCKED', status: 'blocked', reason: 'No documented authorization; outbound probing is outside the rules of engagement.' },
    { id: 'exploit.execute', name: 'Exploitation & payload delivery', group: 'BLOCKED', status: 'blocked', reason: 'Offensive action. The platform is defensive and passive only.' },
    { id: 'credential.attack', name: 'Credential attacks / password cracking', group: 'BLOCKED', status: 'blocked', reason: 'Offensive action against identities.' },
    { id: 'persistence.install', name: 'Persistence & evasion tooling', group: 'BLOCKED', status: 'blocked', reason: 'Offensive action; explicitly prohibited by policy.' },
    { id: 'contain.execute', name: 'Autonomous external containment', group: 'BLOCKED', status: 'blocked', reason: 'Requires a human-approved change through your own infrastructure tooling.' },
    { id: 'scope.bypass', name: 'Bypass or disable authorization', group: 'BLOCKED', status: 'blocked', reason: 'The scope gate is locked on and cannot be disabled by design.' }
  ];

  var ORCHESTRATOR_PLAN = [
    { id: 'scope', label: 'Scope resolution', cap: 'scope.verify', deps: [], desc: 'Resolve signed authorization records and refuse anything expired or unattested.', tier: 0 },
    { id: 'ingest', label: 'Telemetry ingest', cap: 'telemetry.normalize', deps: ['scope'], desc: 'Auto-detect format and normalize events into the common schema.', tier: 1 },
    { id: 'detect', label: 'Detection sweep', cap: 'telemetry.detect', deps: ['ingest'], desc: 'Run the 16 built-in rules plus operator-authored custom rules.', tier: 2 },
    { id: 'harden', label: 'Hardening evaluation', cap: 'config.hardening', deps: ['scope'], desc: 'Grade HTTP response headers against 12 controls.', tier: 1 },
    { id: 'correlate', label: 'Attack-chain correlation', cap: 'telemetry.correlate', deps: ['detect'], desc: 'Reconstruct tactic progression per source and score confidence.', tier: 3 },
    { id: 'triage', label: 'Explainable triage', cap: 'triage.score', deps: ['correlate'], desc: 'Score all alerts with a published reasoning chain.', tier: 4 },
    { id: 'coverage', label: 'Coverage & risk', cap: 'govern.report', deps: ['triage', 'harden'], desc: 'Compute MITRE coverage and quantitative risk estimates.', tier: 5 },
    { id: 'report', label: 'Evidence report', cap: 'govern.ledger', deps: ['coverage'], desc: 'Seal the run in the ledger and produce an exportable report.', tier: 6 }
  ];

  /* Illustrative offline advisory baseline (not a live vulnerability feed). */
  var ADVISORY_BASELINE = [
    { name: 'lodash', ecosystem: 'npm', below: '4.17.21', severity: 'high', cve: 'CVE-2021-23337', fix: 'Upgrade to >= 4.17.21' },
    { name: 'minimist', ecosystem: 'npm', below: '1.2.6', severity: 'critical', cve: 'CVE-2021-44906', fix: 'Upgrade to >= 1.2.6' },
    { name: 'axios', ecosystem: 'npm', below: '1.6.0', severity: 'high', cve: 'CVE-2023-45857', fix: 'Upgrade to >= 1.6.0' },
    { name: 'express', ecosystem: 'npm', below: '4.19.2', severity: 'medium', cve: 'CVE-2024-29041', fix: 'Upgrade to >= 4.19.2' },
    { name: 'follow-redirects', ecosystem: 'npm', below: '1.15.6', severity: 'medium', cve: 'CVE-2024-28849', fix: 'Upgrade to >= 1.15.6' },
    { name: 'requests', ecosystem: 'pypi', below: '2.31.0', severity: 'medium', cve: 'CVE-2023-32681', fix: 'Upgrade to >= 2.31.0' },
    { name: 'pyyaml', ecosystem: 'pypi', below: '6.0.1', severity: 'high', cve: 'CVE-2020-14343', fix: 'Upgrade to >= 6.0.1' },
    { name: 'urllib3', ecosystem: 'pypi', below: '2.0.7', severity: 'medium', cve: 'CVE-2023-45803', fix: 'Upgrade to >= 2.0.7' },
    { name: 'jinja2', ecosystem: 'pypi', below: '3.1.4', severity: 'medium', cve: 'CVE-2024-34064', fix: 'Upgrade to >= 3.1.4' },
    { name: 'cryptography', ecosystem: 'pypi', below: '42.0.4', severity: 'high', cve: 'CVE-2024-26130', fix: 'Upgrade to >= 42.0.4' }
  ];

  var SAMPLES = {
    email: [
      'Return-Path: <billing@acme-lab-secure.com>',
      'Received: from mail-sec-01.top (unknown [91.219.236.18]) by mx.acme-lab.io with ESMTP id 88A2; Tue, 10 Nov 2026 09:12:04 +0000',
      'Received: from localhost (127.0.0.1) by mail-sec-01.top with SMTP; Tue, 10 Nov 2026 09:11:58 +0000',
      'From: "Finance Team" <billing@acme-lab-secure.com>',
      'Reply-To: <verify-account@login-verify.xyz>',
      'To: analyst@acme-lab.io',
      'Subject: ACTION REQUIRED: invoice payment suspended - verify immediately',
      'Date: Tue, 10 Nov 2026 09:11:42 +0000',
      'Authentication-Results: mx.acme-lab.io; spf=fail smtp.mailfrom=acme-lab-secure.com; dkim=fail; dmarc=fail header.from=acme-lab.io',
      'X-Mailer: PHPMailer 5.2.1',
      '',
      'Your account will be suspended. Verify your credentials at https://login-verify.xyz/secure/update?id=8842',
      'or open http://cdn-update.top/gate.php. Contact: 185.220.101.47'
    ].join('\n'),
    iam: JSON.stringify({
      Version: '2012-10-17',
      Statement: [
        { Sid: 'DeployWideOpen', Effect: 'Allow', Action: '*', Resource: '*' },
        { Sid: 'PublicBucket', Effect: 'Allow', Principal: '*', Action: ['s3:GetObject', 's3:PutObject'], Resource: 'arn:aws:s3:::acme-public-*' },
        { Sid: 'PassRole', Effect: 'Allow', Action: ['iam:PassRole', 'sts:AssumeRole'], Resource: '*' },
        { Sid: 'DenyWithoutMFA', Effect: 'Deny', Action: 'iam:CreateUser', Resource: '*', Condition: { BoolIfExists: { 'aws:MultiFactorAuthPresent': 'false' } } },
        { Sid: 'LogWrite', Effect: 'Allow', Action: ['logs:CreateLogGroup', 'logs:PutLogEvents'], Resource: 'arn:aws:logs:*:*:*' }
      ]
    }, null, 2),
    k8s: [
      'apiVersion: apps/v1',
      'kind: Deployment',
      'metadata:',
      '  name: edge-worker',
      'spec:',
      '  replicas: 2',
      '  template:',
      '    spec:',
      '      hostNetwork: true',
      '      hostPID: true',
      '      containers:',
      '        - name: worker',
      '          image: registry.acme-lab.io/worker:latest',
      '          securityContext:',
      '            privileged: true',
      '            runAsUser: 0',
      '            allowPrivilegeEscalation: true',
      '            capabilities:',
      '              add: ["SYS_ADMIN", "NET_ADMIN"]',
      '          volumeMounts:',
      '            - name: hostroot',
      '              mountPath: /host',
      '      volumes:',
      '        - name: hostroot',
      '          hostPath:',
      '            path: /',
      '            type: Directory'
    ].join('\n'),
    secrets: [
      '# deploy/config.env — SIMULATED SAMPLE, rotate anything found here',
      'AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLEKEY',
      'AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY',
      'GITHUB_TOKEN=ghp_16CharactersLongExampleTokenValue123456',
      'DATABASE_URL=postgres://svc:Sup3rS3cretP@ss@db.acme-lab.internal:5432/app',
      'STRIPE_LIVE_KEY=sk_live_[DEFANGED_SAMPLE_VALUE_NOT_A_KEY]',
      'SESSION_SECRET=Y7xQ2mV9pLk4tR8wN3zB6cD1fH5jK0sA',
      '-----BEGIN RSA PRIVATE KEY-----',
      'MIIEowIBAAKCAQEAv3xampleKeyMaterialDoNotUseInProduction12345678',
      '-----END RSA PRIVATE KEY-----',
      'JWT=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c'
    ].join('\n'),
    deps: JSON.stringify({
      name: 'acme-edge-api', version: '2.4.0',
      dependencies: { lodash: '4.17.20', minimist: '1.2.5', axios: '1.5.1', express: '4.18.2', 'follow-redirects': '1.15.3', react: '18.2.0', typescript: '5.3.3' },
      devDependencies: { jest: '29.7.0' }
    }, null, 2),
    requirements: [
      'requests==2.30.0', 'pyyaml==5.4.1', 'urllib3==2.0.6', 'jinja2==3.1.3',
      'cryptography==41.0.7', 'flask==3.0.2', 'numpy==1.26.4'
    ].join('\n'),
    jsonl: [
      '{"time":"2026-11-10T03:14:02Z","src_ip":"185.220.101.47","user":"admin","event":"failed_login","status":401,"host":"auth01"}',
      '{"time":"2026-11-10T03:14:03Z","src_ip":"185.220.101.47","user":"root","event":"failed_login","status":401,"host":"auth01"}',
      '{"time":"2026-11-10T03:14:04Z","src_ip":"185.220.101.47","user":"deploy","event":"failed_login","status":401,"host":"auth01"}',
      '{"time":"2026-11-10T03:14:09Z","src_ip":"185.220.101.47","user":"deploy","event":"login_success","status":200,"host":"auth01"}',
      '{"time":"2026-11-10T03:15:11Z","src_ip":"185.220.101.47","user":"deploy","event":"sudo","status":200,"host":"auth01","cmd":"/bin/cat /etc/shadow"}',
      '{"time":"2026-11-10T03:16:02Z","src_ip":"10.20.0.15","user":"svc","event":"request","status":500,"host":"web01","path":"/products?id=1\' OR 1=1--","ua":"sqlmap/1.7.12"}',
      '{"time":"2026-11-10T03:16:04Z","src_ip":"10.20.0.15","user":"svc","event":"request","status":200,"host":"web01","path":"/shell.php?cmd=;cat /etc/passwd","ua":"curl/8.4"}',
      '{"time":"2026-11-10T03:19:31Z","src_ip":"10.20.0.15","user":"svc","event":"egress","status":200,"host":"web01","dst":"cdn-update.top"}'
    ].join('\n'),
    nginx: [
      '185.220.101.47 - - [10/Nov/2026:03:14:02 +0000] "POST /login HTTP/1.1" 401 128 "-" "python-requests/2.31.0"',
      '185.220.101.47 - - [10/Nov/2026:03:14:03 +0000] "POST /login HTTP/1.1" 401 128 "-" "python-requests/2.31.0"',
      '185.220.101.47 - - [10/Nov/2026:03:14:09 +0000] "POST /login HTTP/1.1" 200 542 "-" "python-requests/2.31.0"',
      '185.220.101.47 - - [10/Nov/2026:03:14:12 +0000] "GET /admin HTTP/1.1" 200 2210 "-" "python-requests/2.31.0"',
      '10.20.0.15 - - [10/Nov/2026:03:16:02 +0000] "GET /products?id=1%27%20OR%201=1-- HTTP/1.1" 500 1243 "-" "sqlmap/1.7.12"',
      '10.20.0.15 - - [10/Nov/2026:03:16:04 +0000] "GET /../../etc/passwd HTTP/1.1" 404 342 "-" "Nikto/2.1.6"',
      '10.20.0.15 - - [10/Nov/2026:03:16:05 +0000] "GET /api/session HTTP/1.1" 403 128 "-" "Mozilla/5.0"'
    ].join('\n')
  };

  var QUERY_EXAMPLES = [
    'show critical findings',
    'open findings for api.acme-lab.io',
    'alerts with high severity',
    'assets out of scope',
    'findings mapped to T1190',
    'summary of the ledger',
    'indicators in the watchlist',
    'untriaged alerts'
  ];

  var D2 = {
    MITRE_TACTICS: MITRE_TACTICS, TECHNIQUES: TECHNIQUES, CAPABILITIES: CAPABILITIES,
    ORCHESTRATOR_PLAN: ORCHESTRATOR_PLAN, ADVISORY_BASELINE: ADVISORY_BASELINE,
    SAMPLES: SAMPLES, QUERY_EXAMPLES: QUERY_EXAMPLES
  };
  root.AEGIS_DATA2 = D2;
  if (typeof module !== 'undefined' && module.exports) module.exports = D2;
})(typeof globalThis !== 'undefined' ? globalThis : this);
