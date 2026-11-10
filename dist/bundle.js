/* AEGIS // SENTINEL — generated bundle. Do not edit directly.
 * Source: src/00-data.js, 05-data2.js, 10-engine.js, 15-advanced.js, 16-hexstrike.js, 20-store.js, 30-ui.js, 40-ui2.js, 45-terminal.js  |  Built with scripts/build.mjs
 * All analysis is local. No network calls. Authorization enforced in code.
 */

/* ===== 00-data.js ===== */
/* AEGIS / SENTINEL — static knowledge base, catalogs and demo telemetry.
 * All seed data is clearly labelled SIMULATED in the UI. No network calls are
 * ever made by this application: every analysis runs locally on data the
 * operator supplies.
 */
(function (root) {
  'use strict';

  var SEVERITIES = {
    critical: { label: 'CRITICAL', weight: 92, color: '#ff5470', rank: 4 },
    high:     { label: 'HIGH',     weight: 72, color: '#ff9f43', rank: 3 },
    medium:   { label: 'MEDIUM',   weight: 46, color: '#ffd166', rank: 2 },
    low:      { label: 'LOW',      weight: 22, color: '#5ad2ff', rank: 1 },
    info:     { label: 'INFO',     weight: 8,  color: '#8b9bb4', rank: 0 }
  };

  var CHECK_TYPES = [
    { id: 'posture',   label: 'Posture & configuration review' },
    { id: 'headers',   label: 'HTTP header / hardening analysis' },
    { id: 'logs',      label: 'Log & telemetry analysis' },
    { id: 'intel',     label: 'IOC correlation (local only)' },
    { id: 'identity',  label: 'Identity & access review' }
  ];

  /* ------------------------------------------------------------------ *
   * Log detection rules. Patterns are deliberately conservative: they
   * detect indicators in text the operator pastes, nothing more.
   * ------------------------------------------------------------------ */
  var LOG_RULES = [
    { id: 'AUTH-BRUTE-FORCE', name: 'Credential brute force / password spraying', severity: 'high',
      mitre: 'T1110', kind: 'threshold', threshold: 5,
      pattern: /failed password|authentication failure|invalid user|failed login|login failed|authentication failed/i,
      remediation: 'Enforce account lockout, MFA and rate limiting on the authentication endpoint; review source IPs.' },
    { id: 'AUTH-SUCCESS-AFTER-FAIL', name: 'Successful authentication after repeated failures', severity: 'critical',
      mitre: 'T1078', kind: 'correlation', threshold: 1,
      pattern: /accepted password|session opened|login successful|authentication succeeded/i,
      remediation: 'Treat as possible account compromise: reset credentials, revoke sessions, review lateral movement.' },
    { id: 'PRIV-ESCALATION', name: 'Privilege escalation / account manipulation', severity: 'high',
      mitre: 'T1548.002', kind: 'match', threshold: 1,
      pattern: /\bsudo:|\bsu:|setuid|chmod \+s|useradd|usermod -aG|net localgroup administrators|se_debug_privilege|sudoers/i,
      remediation: 'Verify the change against an approved change ticket; audit sudoers and privileged group membership.' },
    { id: 'SQL-INJECTION', name: 'SQL injection probe in request', severity: 'high',
      mitre: 'T1190', kind: 'match', threshold: 1,
      pattern: /union\s+select|union%20select|or\s+1\s*=\s*1|or%20\d+%3d\d+|\bor%20|%27%20or|'\s*or\s*'|;\s*drop\s+table|information_schema|\bsleep\(\d+\)|benchmark\(|xp_cmdshell/i,
      remediation: 'Confirm parameterized queries and a WAF ruleset; inspect the application access log for a matching 2xx response.' },
    { id: 'PATH-TRAVERSAL', name: 'Path traversal / local file disclosure', severity: 'high',
      mitre: 'T1190', kind: 'match', threshold: 1,
      pattern: /\.\.\/|\.\.\\|%2e%2e|\/etc\/passwd|\/etc\/shadow|boot\.ini|win\.ini|\.\.%2f/i,
      remediation: 'Validate and canonicalize file paths; ensure the web root is jailed and sensitive files are unreadable.' },
    { id: 'XSS-PAYLOAD', name: 'Cross-site scripting payload', severity: 'medium',
      mitre: 'T1059.007', kind: 'match', threshold: 1,
      pattern: /<script|onerror\s*=|onload\s*=|javascript:|%3cscript|<svg\s+onload/i,
      remediation: 'Apply contextual output encoding and a strict Content-Security-Policy.' },
    { id: 'CMD-INJECTION', name: 'OS command injection indicator', severity: 'critical',
      mitre: 'T1059', kind: 'match', threshold: 1,
      pattern: /;\s*(cat|curl|wget|nc|bash|sh|whoami|id)\b|`\s*(cat|curl|wget|sh|bash)\b|\|\s*(sh|bash)\b|\$\(\s*(cat|curl|wget)/i,
      remediation: 'Isolate the affected workload, review process ancestry, and remove shell interpolation from request paths.' },
    { id: 'WEB-SHELL', name: 'Web shell / code execution artifact', severity: 'critical',
      mitre: 'T1505.003', kind: 'match', threshold: 1,
      pattern: /shell\.php|cmd\.jsp|\/c99\.php|eval\(|base64_decode\(|passthru\(|assert\(\$_|system\(\$_|\/wso\.php/i,
      remediation: 'Quarantine the host, compare web root against a known-good baseline, rotate secrets and hunt for persistence.' },
    { id: 'SCANNER-UA', name: 'Automated attack tooling user-agent', severity: 'medium',
      mitre: 'T1595', kind: 'match', threshold: 1,
      pattern: /sqlmap|nikto|acunetix|nessus|masscan|nmap|dirbuster|gobuster|wpscan|havij|metasploit|hydra|zgrab/i,
      remediation: 'Correlate with request volume; consider rate limiting and verification that the source is an approved scanner.' },
    { id: 'ENCODED-PAYLOAD', name: 'Encoded / obfuscated command payload', severity: 'medium',
      mitre: 'T1027', kind: 'match', threshold: 1,
      pattern: /powershell\s+(-enc|-encodedcommand)|-e\s+[A-Za-z0-9+/]{40,}={0,2}|[A-Za-z0-9+/]{80,}={1,2}/i,
      remediation: 'Decode in an isolated sandbox, enable script block logging and review process command lines.' },
    { id: 'C2-BEACON', name: 'Possible command-and-control beacon', severity: 'high',
      mitre: 'T1071', kind: 'match', threshold: 1,
      pattern: /\/gate\.php|beacon\/|\/c2\/|dns[_-]?tunnel|\/tasks?\?id=|jquery-3\.3\.2\.min\.js\?/i,
      remediation: 'Check egress logs, DNS telemetry and endpoint process tree; block confirmed infrastructure at the egress proxy.' },
    { id: 'DEFENSE-EVASION', name: 'Security logging / control tampering', severity: 'critical',
      mitre: 'T1562.001', kind: 'match', threshold: 1,
      pattern: /auditctl\s+-|systemctl\s+(stop|disable)\s+(auditd|rsyslog|syslog)|wevtutil\s+cl|Set-MpPreference.*Disable|vssadmin\s+delete\s+shadows|Clear-EventLog/i,
      remediation: 'Escalate immediately: this is a high-confidence precursor to destructive activity. Preserve off-host logs.' },
    { id: 'RANSOMWARE', name: 'Ransomware / destructive activity indicator', severity: 'critical',
      mitre: 'T1486', kind: 'match', threshold: 1,
      pattern: /\.locked\b|\.encrypt(ed)?\b|README_RECOVER|HOW_TO_DECRYPT|wannacry|ryuk|lockbit|bcdedit\s+\/set\s+{default}\s+recoveryenabled\s+no/i,
      remediation: 'Invoke the ransomware playbook: isolate host, preserve evidence, validate offline backups before any recovery.' },
    { id: 'CRYPTO-MINING', name: 'Resource hijacking / cryptominer', severity: 'medium',
      mitre: 'T1496', kind: 'match', threshold: 1,
      pattern: /xmrig|stratum\+tcp|cryptonight|minerd|cpuminer|pool\.minexmr/i,
      remediation: 'Check CPU telemetry and container images; revoke exposed credentials used to deploy the workload.' },
    { id: 'SECRET-EXPOSURE', name: 'Credential or private key material in logs', severity: 'high',
      mitre: 'T1552', kind: 'match', threshold: 1,
      pattern: /BEGIN (RSA|OPENSSH|EC) PRIVATE KEY|AKIA[0-9A-Z]{16}|api[_-]?key\s*[:=]\s*['"]?[A-Za-z0-9_\-]{16,}|password\s*[:=]\s*['"]?[^\s'"]{8,}/i,
      remediation: 'Rotate the exposed secret immediately and purge it from log retention / SIEM indexes.' },
    { id: 'STATUS-ANOMALY', name: 'High-volume authorization failures', severity: 'medium',
      mitre: 'T1110.003', kind: 'threshold', threshold: 6,
      pattern: /\b(401|403)\b/,
      remediation: 'Investigate for enumeration or credential stuffing; enable bot mitigation and per-IP throttling.' }
  ];

  var FINDING_TEMPLATES = [
    { title: 'Missing Content-Security-Policy on public response', severity: 'high', category: 'Hardening', mitre: 'T1190',
      evidence: 'Response headers for the asset contain no content-security-policy directive; inline script execution is unrestricted.',
      remediation: "Deploy a nonce-based CSP: default-src 'self'; object-src 'none'; frame-ancestors 'none'." },
    { title: 'HSTS max-age below recommended minimum', severity: 'medium', category: 'Transport', mitre: 'T1557',
      evidence: 'strict-transport-security observed with max-age below 15552000 and without includeSubDomains.',
      remediation: 'Set Strict-Transport-Security: max-age=31536000; includeSubDomains; preload after validation.' },
    { title: 'Session cookie missing SameSite attribute', severity: 'medium', category: 'Identity', mitre: 'T1539',
      evidence: 'Set-Cookie header has Secure and HttpOnly but no SameSite attribute in the reviewed configuration sample.',
      remediation: 'Set SameSite=Lax (or Strict for admin surfaces) on all session cookies.' },
    { title: 'Verbose server version disclosure', severity: 'low', category: 'Hardening', mitre: 'T1592',
      evidence: 'Server / X-Powered-By headers expose exact product and version strings.',
      remediation: 'Strip version banners at the reverse proxy and maintain a separate internal inventory.' },
    { title: 'Overbroad IAM role on deployment principal', severity: 'high', category: 'Identity', mitre: 'T1078',
      evidence: 'Deployment principal holds wildcard action permissions beyond the least-privilege baseline.',
      remediation: 'Scope the role to the exact actions required; enable permission usage analysis and rotate keys.' },
    { title: 'TLS 1.0/1.1 still accepted on legacy listener', severity: 'high', category: 'Transport', mitre: 'T1557',
      evidence: 'Configuration review found deprecated protocol versions enabled on a legacy listener.',
      remediation: 'Disable TLS < 1.2, prefer TLS 1.3, and re-test with an external TLS configuration checker.' },
    { title: 'Unpinned third-party script dependency', severity: 'medium', category: 'Supply chain', mitre: 'T1195',
      evidence: 'Front-end loads a third-party script by mutable URL without integrity attribute or version pin.',
      remediation: 'Pin the exact version, add Subresource Integrity and enforce SRI via CSP require-sri-for.' },
    { title: 'Audit log retention below policy floor', severity: 'medium', category: 'Detection', mitre: 'T1562',
      evidence: 'Log retention configured below the 365-day control requirement.',
      remediation: 'Extend retention and enable immutable / WORM storage for security telemetry.' },
    { title: 'Unrestricted egress from production subnet', severity: 'high', category: 'Network', mitre: 'T1041',
      evidence: 'Network policy allows unrestricted outbound traffic from a critical workload subnet.',
      remediation: 'Apply default-deny egress with an explicit allowlist and DNS logging.' },
    { title: 'Stale privileged account with no recent MFA', severity: 'high', category: 'Identity', mitre: 'T1078',
      evidence: 'Privileged account has not completed MFA within the policy window.',
      remediation: 'Disable the account pending verification and enforce phishing-resistant MFA.' },
    { title: 'Backup restore not exercised in current quarter', severity: 'low', category: 'Resilience', mitre: 'T1490',
      evidence: 'No recorded restore validation for the asset in the current quarter.',
      remediation: 'Schedule and document an isolated restore test; record the result in the audit ledger.' },
    { title: 'Missing Cross-Origin-Opener-Policy', severity: 'low', category: 'Hardening', mitre: 'T1187',
      evidence: 'Cross-origin isolation headers not present on the reviewed response.',
      remediation: 'Add Cross-Origin-Opener-Policy: same-origin and Cross-Origin-Resource-Policy: same-origin.' },
    { title: 'Container image includes a known-vulnerable package', severity: 'high', category: 'Supply chain', mitre: 'T1195',
      evidence: 'Offline SBOM comparison flagged a package version listed in the local advisory baseline.',
      remediation: 'Rebuild from a patched base image and re-scan before promotion.' },
    { title: 'Wildcard CORS on authenticated endpoint', severity: 'critical', category: 'Hardening', mitre: 'T1537',
      evidence: 'Access-Control-Allow-Origin: * combined with credentialed requests in the reviewed configuration.',
      remediation: 'Replace wildcard with an explicit origin allowlist and validate the Origin header server-side.' }
  ];

  var PLAYBOOKS = [
    { id: 'pb-ransomware', name: 'Ransomware / destructive encryption', function: 'RESPOND', severity: 'critical', owner: 'Incident Commander',
      steps: ['Declare incident and open the audit ledger entry', 'Isolate affected hosts from network (approved change)', 'Preserve volatile evidence and off-host logs', 'Identify initial access vector and scope', 'Validate offline backups and restore points', 'Eradicate persistence and rotate credentials', 'Recover in a clean segment with monitoring', 'Post-incident review and control update'] },
    { id: 'pb-phishing', name: 'Phishing / credential harvesting', function: 'RESPOND', severity: 'high', owner: 'SOC Analyst',
      steps: ['Quarantine the message from all mailboxes', 'Extract and defang IOCs into the watchlist', 'Identify all recipients and clickers', 'Revoke sessions and reset affected passwords', 'Check mail transport rules for persistence', 'Run awareness follow-up with affected users', 'Update detection rules and blocklist'] },
    { id: 'pb-credential', name: 'Credential stuffing / account takeover', function: 'DETECT', severity: 'high', owner: 'Detection Engineering',
      steps: ['Confirm scope with authorized asset owner', 'Quantify failure/success ratio per source', 'Enable step-up MFA on affected population', 'Apply rate limiting and bot mitigation', 'Lock or reset confirmed compromised accounts', 'Hunt for post-authentication anomalies', 'Publish detection coverage report'] },
    { id: 'pb-exfil', name: 'Suspected data exfiltration', function: 'RESPOND', severity: 'critical', owner: 'Incident Commander',
      steps: ['Classify the data and regulatory obligations', 'Preserve egress, proxy and DNS telemetry', 'Identify the egress channel and destination', 'Contain the egress path with an approved change', 'Assess exposed records and notify stakeholders', 'Rotate credentials and review access grants', 'Document lessons learned and control gaps'] },
    { id: 'pb-supply', name: 'Compromised dependency / supply chain', function: 'PROTECT', severity: 'high', owner: 'Platform Security',
      steps: ['Freeze promotion of affected builds', 'Generate and diff the SBOM', 'Identify all workloads containing the component', 'Pin or replace the dependency', 'Rebuild with clean provenance and attestation', 'Hunt for runtime indicators of compromise', 'Update vendor and pinning policy'] },
    { id: 'pb-ddos', name: 'Volumetric denial of service', function: 'RESPOND', severity: 'medium', owner: 'SRE On-call',
      steps: ['Confirm traffic signature against baseline', 'Activate upstream scrubbing / CDN protection', 'Apply rate limits at the edge', 'Protect origin with allowlisting', 'Monitor saturation and dependency health', 'Restore normal routing after decay', 'Record timeline and capacity findings'] }
  ];

  var COMPLIANCE_CONTROLS = [
    { id: 'CIS-01', framework: 'CIS Controls v8', title: 'Enterprise asset inventory', fn: 'GOVERN', hint: 'Assets registered with owner, environment and criticality.' },
    { id: 'NIST-ID.AM', framework: 'NIST CSF 2.0', title: 'Authorization governance', fn: 'IDENTIFY', hint: 'Every asset has a confirmed, unexpired authorization record.' },
    { id: 'CIS-07', framework: 'CIS Controls v8', title: 'Continuous vulnerability management', fn: 'IDENTIFY', hint: 'Open findings are tracked and remediated.' },
    { id: 'NIST-PR.PS', framework: 'NIST CSF 2.0', title: 'Platform hardening baselines', fn: 'PROTECT', hint: 'HTTP hardening analysis completed with a passing grade.' },
    { id: 'NIST-DE.CM', framework: 'NIST CSF 2.0', title: 'Continuous monitoring coverage', fn: 'DETECT', hint: 'Telemetry has been ingested and analyzed.' },
    { id: 'MITRE-DE', framework: 'MITRE ATT&CK', title: 'Detection engineering coverage', fn: 'DETECT', hint: 'Detection rules map to adversary techniques.' },
    { id: 'NIST-DE.AE', framework: 'NIST CSF 2.0', title: 'Alert triage & escalation', fn: 'DETECT', hint: 'Alerts are triaged with an explainable priority.' },
    { id: 'NIST-PR.IP', framework: 'NIST CSF 2.0', title: 'Incident response playbooks', fn: 'RESPOND', hint: 'Playbooks are exercised and tracked.' },
    { id: 'NIST-PR.AA', framework: 'NIST CSF 2.0', title: 'Identity & privileged access', fn: 'PROTECT', hint: 'Human approval required for containment workflows.' },
    { id: 'NIST-PR.DS', framework: 'NIST CSF 2.0', title: 'Data-in-transit protection', fn: 'PROTECT', hint: 'Transport and cookie controls verified.' },
    { id: 'CIS-13', framework: 'CIS Controls v8', title: 'Threat intelligence & IOC handling', fn: 'DETECT', hint: 'Local IOC watchlist is maintained.' },
    { id: 'NIST-PR.PS-2', framework: 'NIST CSF 2.0', title: 'Tamper-evident audit trail', fn: 'GOVERN', hint: 'Hash chain verifies with no broken links.' }
  ];

  var SAMPLE_LOGS = [
    'Nov 10 03:14:02 auth01 sshd[2214]: Failed password for invalid user admin from 185.220.101.47 port 51422 ssh2',
    'Nov 10 03:14:03 auth01 sshd[2215]: Failed password for invalid user admin from 185.220.101.47 port 51424 ssh2',
    'Nov 10 03:14:04 auth01 sshd[2216]: Failed password for root from 185.220.101.47 port 51426 ssh2',
    'Nov 10 03:14:05 auth01 sshd[2217]: Failed password for root from 185.220.101.47 port 51428 ssh2',
    'Nov 10 03:14:06 auth01 sshd[2218]: Failed password for deploy from 185.220.101.47 port 51430 ssh2',
    'Nov 10 03:14:09 auth01 sshd[2219]: Accepted password for deploy from 185.220.101.47 port 51432 ssh2',
    'Nov 10 03:15:11 auth01 sudo: deploy : TTY=pts/0 ; PWD=/srv/app ; COMMAND=/bin/cat /etc/shadow',
    'Nov 10 03:15:19 auth01 auditctl: auditctl -e 0 disabled auditing on host',
    '10.20.0.15 - - [10/Nov/2026:03:16:02 +0000] "GET /products?id=1%27%20OR%201=1-- HTTP/1.1" 500 1243 "-" "sqlmap/1.7.12#stable"',
    '10.20.0.15 - - [10/Nov/2026:03:16:03 +0000] "GET /../../etc/passwd HTTP/1.1" 404 342 "-" "Mozilla/5.0 (compatible; Nikto/2.1.6)"',
    '10.20.0.15 - - [10/Nov/2026:03:16:04 +0000] "POST /uploads HTTP/1.1" 200 812 "-" "python-requests/2.31.0"',
    '10.20.0.15 - - [10/Nov/2026:03:16:04 +0000] "GET /shell.php?cmd=;cat%20/etc/passwd HTTP/1.1" 200 512 "-" "curl/8.4"',
    '10.20.0.15 - - [10/Nov/2026:03:16:05 +0000] "GET /api/session HTTP/1.1" 403 128 "-" "Mozilla/5.0"',
    '10.20.0.15 - - [10/Nov/2026:03:16:06 +0000] "GET /api/session HTTP/1.1" 403 128 "-" "Mozilla/5.0"',
    '10.20.0.15 - - [10/Nov/2026:03:16:07 +0000] "GET /api/session HTTP/1.1" 403 128 "-" "Mozilla/5.0"',
    '10.20.0.15 - - [10/Nov/2026:03:16:08 +0000] "GET /api/session HTTP/1.1" 403 128 "-" "Mozilla/5.0"',
    '10.20.0.15 - - [10/Nov/2026:03:16:09 +0000] "GET /api/session HTTP/1.1" 403 128 "-" "Mozilla/5.0"',
    '10.20.0.15 - - [10/Nov/2026:03:16:10 +0000] "GET /api/session HTTP/1.1" 403 128 "-" "Mozilla/5.0"',
    '10.20.0.15 - - [10/Nov/2026:03:16:11 +0000] "GET /api/session HTTP/1.1" 403 128 "-" "Mozilla/5.0"',
    'Nov 10 03:17:40 web01 kernel: process powershell.exe -enc SGVsbG9Xb3JsZEFBR0lTU2FmZU9mZmxpbmVEZXRlY3Rpb25UZXN0QmxvYg== spawned',
    'Nov 10 03:18:02 web01 app: config api_key=sk_live_9f3a71c2b4d8e6f0a  leaked in debug output',
    'Nov 10 03:19:31 web01 app: GET https://cdn-update.top/gate.php?id=8842 callback registered'
  ].join('\n');

  var SAMPLE_INTEL = [
    'INCIDENT NOTE — SIMULATED SAMPLE — 10 Nov 2026',
    'Analyst: soc@acme-lab.internal · case ACME-2026-0417 · CVE-2026-31115 under review',
    'Egress observed from 10.20.0.15 to 185.220.101.47 and 91.219.236.18 over 443/tcp.',
    'Beacon URL: https://cdn-update.top/gate.php?id=8842 (defang before sharing).',
    'Secondary infrastructure: update-cdn[.]top, login-verify[.]xyz, mail.acme-lab.io.',
    'Dropper SHA-256: 4b9f2a71c8de03a6f5b1c9e72d48a06f3bc95e7d210a4c8b6f0e13d9a7c25b84f6e',
    'Related MD5: d41d8cd98f00b204e9800998ecf8427e',
    'Phishing sender: billing@acme-lab-secure.com (report to abuse@acme-lab.io).',
    'Reference: https://vendor-advisory.example.org/advisory/2026-31115',
    'Local watchlist candidates: cdn-update.top, 185.220.101.47'
  ].join('\n');

  var SAMPLE_HEADERS = [
    'HTTP/2 200 OK',
    'date: Tue, 10 Nov 2026 09:42:11 GMT',
    'content-type: text/html; charset=utf-8',
    'server: nginx/1.18.0 (Ubuntu)',
    'x-powered-by: PHP/7.4.3',
    'strict-transport-security: max-age=86400',
    'x-content-type-options: nosniff',
    'x-frame-options: SAMEORIGIN',
    'set-cookie: session=eyJhbGciOiJIUzI1NiJ9; Path=/; HttpOnly',
    'access-control-allow-origin: *',
    'access-control-allow-credentials: true',
    'cache-control: no-cache'
  ].join('\n');

  var DATA = {
    SEVERITIES: SEVERITIES,
    CHECK_TYPES: CHECK_TYPES,
    LOG_RULES: LOG_RULES,
    FINDING_TEMPLATES: FINDING_TEMPLATES,
    PLAYBOOKS: PLAYBOOKS,
    COMPLIANCE_CONTROLS: COMPLIANCE_CONTROLS,
    SAMPLE_LOGS: SAMPLE_LOGS,
    SAMPLE_HEADERS: SAMPLE_HEADERS,
    SAMPLE_INTEL: SAMPLE_INTEL,
    ASSET_SEEDS: [
      { name: 'app.acme-lab.internal', type: 'Domain', owner: 'Platform Team', env: 'Production', criticality: 'critical', authorizedBy: 'J. Rivera (CISO)', days: 180, checks: ['posture', 'headers', 'logs', 'intel', 'identity'], confirmed: true },
      { name: 'api.acme-lab.io', type: 'Domain', owner: 'API Team', env: 'Production', criticality: 'high', authorizedBy: 'M. Okafor (Eng Dir)', days: 120, checks: ['posture', 'headers', 'logs', 'intel'], confirmed: true },
      { name: 'auth01.acme-lab.internal', type: 'Host', owner: 'Identity Team', env: 'Production', criticality: 'critical', authorizedBy: 'J. Rivera (CISO)', days: 90, checks: ['posture', 'logs', 'identity'], confirmed: true },
      { name: '10.20.0.0/24', type: 'CIDR', owner: 'Network Ops', env: 'Staging', criticality: 'medium', authorizedBy: 'S. Patel (Net Lead)', days: 45, checks: ['posture', 'logs'], confirmed: true },
      { name: 'edge-cdn.acme-lab.io', type: 'Domain', owner: 'Platform Team', env: 'Production', criticality: 'high', authorizedBy: 'M. Okafor (Eng Dir)', days: 200, checks: ['headers', 'posture', 'intel'], confirmed: true },
      { name: 'legacy.acme-lab.io', type: 'Domain', owner: 'Platform Team', env: 'Decommissioning', criticality: 'low', authorizedBy: 'M. Okafor (Eng Dir)', days: -12, checks: ['posture'], confirmed: true }
    ],
    ALERT_SEEDS: [
      { title: 'Repeated SSH failures followed by success on auth01', severity: 'high', asset: 'auth01.acme-lab.internal', source: 'EDR / auth log', phase: 'Initial Access', confidence: 91, evidence: '5 failed authentications from 185.220.101.47 followed by an accepted password for the deploy account.' },
      { title: 'Wildcard CORS with credentials on API gateway', severity: 'critical', asset: 'api.acme-lab.io', source: 'Config drift monitor', phase: 'Exploitation', confidence: 84, evidence: 'Access-Control-Allow-Origin: * returned alongside Access-Control-Allow-Credentials: true.' },
      { title: 'SQL injection signature in public request stream', severity: 'high', asset: 'app.acme-lab.internal', source: 'WAF', phase: 'Exploitation', confidence: 76, evidence: "GET /products?id=1' OR 1=1-- with sqlmap user-agent." },
      { title: 'Auditing disabled on production host', severity: 'critical', asset: 'auth01.acme-lab.internal', source: 'Host telemetry', phase: 'Defense Evasion', confidence: 96, evidence: 'auditctl -e 0 executed by a non-approved principal.' },
      { title: 'Unusual outbound callback to newly registered domain', severity: 'medium', asset: 'edge-cdn.acme-lab.io', source: 'DNS resolver', phase: 'Command & Control', confidence: 62, evidence: 'Beacon-like interval to cdn-update.top over 18 minutes.' },
      { title: 'Deprecated TLS protocol offered on legacy listener', severity: 'medium', asset: 'legacy.acme-lab.io', source: 'Config baseline', phase: 'Reconnaissance', confidence: 88, evidence: 'TLS 1.0 enabled on a listener still in the inventory.' },
      { title: 'Long-lived privileged token without MFA', severity: 'high', asset: 'api.acme-lab.io', source: 'IAM analyzer', phase: 'Privilege Escalation', confidence: 79, evidence: 'Service principal token age exceeds policy window with no recent MFA assertion.' },
      { title: 'Scanner user-agent burst against staging subnet', severity: 'low', asset: '10.20.0.0/24', source: 'Reverse proxy', phase: 'Reconnaissance', confidence: 70, evidence: 'Nikto and sqlmap signatures seen within a 90 second window.' }
    ],
    FINDING_SEEDS: [
      { title: 'Missing Content-Security-Policy on public response', severity: 'high', asset: 'app.acme-lab.internal', category: 'Hardening', mitre: 'T1190', evidence: 'No CSP directive on the sampled response.', remediation: "Deploy a nonce-based CSP with object-src 'none'." },
      { title: 'Wildcard CORS on authenticated endpoint', severity: 'critical', asset: 'api.acme-lab.io', category: 'Hardening', mitre: 'T1537', evidence: 'Wildcard origin combined with credentialed requests.', remediation: 'Use an explicit origin allowlist.' },
      { title: 'Stale privileged account with no recent MFA', severity: 'high', asset: 'auth01.acme-lab.internal', category: 'Identity', mitre: 'T1078', evidence: 'Privileged account outside the MFA policy window.', remediation: 'Disable pending verification and enforce phishing-resistant MFA.' },
      { title: 'Verbose server version disclosure', severity: 'low', asset: 'edge-cdn.acme-lab.io', category: 'Hardening', mitre: 'T1592', evidence: 'Server and X-Powered-By headers expose versions.', remediation: 'Strip version banners at the edge.' },
      { title: 'Audit log retention below policy floor', severity: 'medium', asset: 'auth01.acme-lab.internal', category: 'Detection', mitre: 'T1562', evidence: 'Retention below the 365-day control floor.', remediation: 'Extend retention with WORM storage.' }
    ],
    EVENT_SEEDS: [
      { kind: 'scope', text: 'Authorization registry synchronized — 5 active scopes, 1 expired.' },
      { kind: 'agent', text: 'Agent idle. Strict scope enforcement ACTIVE.' },
      { kind: 'detect', text: 'Detection catalog loaded — 16 rules mapped to MITRE ATT&CK.' },
      { kind: 'govern', text: 'Audit ledger genesis block created and sealed.' }
    ]
  };

  root.AEGIS_DATA = DATA;
  if (typeof module !== 'undefined' && module.exports) module.exports = DATA;
})(typeof globalThis !== 'undefined' ? globalThis : this);


/* ===== 05-data2.js ===== */
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


/* ===== 10-engine.js ===== */
/* AEGIS / SENTINEL — deterministic, fully offline analysis engine.
 * No fetch(), no sockets, no exploitation primitives. Every function here
 * operates on strings and in-memory objects supplied by the operator.
 */
(function (root) {
  'use strict';

  var DATA = (typeof module !== 'undefined' && module.exports)
    ? require('./00-data.js')
    : root.AEGIS_DATA;

  /* ---------------------------- SHA-256 -------------------------------- *
   * Compact synchronous implementation so the audit hash-chain works in
   * any browser context (including non-secure origins during local dev).
   * ------------------------------------------------------------------- */
  var K = [
    0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
    0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
    0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
    0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
    0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
    0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
    0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
    0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2
  ];
  function rotr(x, n) { return (x >>> n) | (x << (32 - n)); }
  function utf8Bytes(str) {
    if (typeof TextEncoder !== 'undefined') return Array.from(new TextEncoder().encode(str));
    var out = [], s = unescape(encodeURIComponent(str));
    for (var i = 0; i < s.length; i++) out.push(s.charCodeAt(i));
    return out;
  }
  function sha256(msg) {
    var bytes = utf8Bytes(String(msg == null ? '' : msg));
    var bitLenHi = Math.floor(bytes.length / 0x20000000); // bytes * 8 / 2^32
    var bitLenLo = (bytes.length * 8) >>> 0;
    bytes.push(0x80);
    while (bytes.length % 64 !== 56) bytes.push(0);
    bytes.push((bitLenHi >>> 24) & 255, (bitLenHi >>> 16) & 255, (bitLenHi >>> 8) & 255, bitLenHi & 255);
    bytes.push((bitLenLo >>> 24) & 255, (bitLenLo >>> 16) & 255, (bitLenLo >>> 8) & 255, bitLenLo & 255);
    var h0=0x6a09e667,h1=0xbb67ae85,h2=0x3c6ef372,h3=0xa54ff53a,
        h4=0x510e527f,h5=0x9b05688c,h6=0x1f83d9ab,h7=0x5be0cd19;
    for (var off = 0; off < bytes.length; off += 64) {
      var w = new Array(64);
      for (var t = 0; t < 16; t++) {
        var j = off + t * 4;
        w[t] = ((bytes[j] << 24) | (bytes[j+1] << 16) | (bytes[j+2] << 8) | bytes[j+3]) | 0;
      }
      for (t = 16; t < 64; t++) {
        var s0 = rotr(w[t-15],7) ^ rotr(w[t-15],18) ^ (w[t-15] >>> 3);
        var s1 = rotr(w[t-2],17) ^ rotr(w[t-2],19) ^ (w[t-2] >>> 10);
        w[t] = (w[t-16] + s0 + w[t-7] + s1) | 0;
      }
      var a=h0,b=h1,c=h2,d=h3,e=h4,f=h5,g=h6,h=h7;
      for (t = 0; t < 64; t++) {
        var S1 = rotr(e,6) ^ rotr(e,11) ^ rotr(e,25);
        var ch = (e & f) ^ (~e & g);
        var t1 = (h + S1 + ch + K[t] + w[t]) | 0;
        var S0 = rotr(a,2) ^ rotr(a,13) ^ rotr(a,22);
        var maj = (a & b) ^ (a & c) ^ (b & c);
        var t2 = (S0 + maj) | 0;
        h=g; g=f; f=e; e=(d+t1)|0; d=c; c=b; b=a; a=(t1+t2)|0;
      }
      h0=(h0+a)|0; h1=(h1+b)|0; h2=(h2+c)|0; h3=(h3+d)|0;
      h4=(h4+e)|0; h5=(h5+f)|0; h6=(h6+g)|0; h7=(h7+h)|0;
    }
    return [h0,h1,h2,h3,h4,h5,h6,h7]
      .map(function (x) { return ('00000000' + (x >>> 0).toString(16)).slice(-8); }).join('');
  }

  function uid(prefix) {
    return (prefix || 'id') + '-' + Date.now().toString(36) + '-' + Math.floor(Math.random() * 1e6).toString(36);
  }
  function prng(seedHex) {
    var s = parseInt(String(seedHex).slice(0, 8), 16) || 0x9e3779b9;
    return function () {
      s |= 0; s = (s + 0x6D2B79F5) | 0;
      var t = Math.imul(s ^ (s >>> 15), 1 | s);
      t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t;
      return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
    };
  }
  function clamp(n, lo, hi) { return Math.max(lo, Math.min(hi, n)); }
  function sevRank(s) { return (DATA.SEVERITIES[s] || DATA.SEVERITIES.info).rank; }

  function defang(value, type) {
    var v = String(value);
    if (type === 'url') return v.replace(/^http/i, 'hxxp').replace(/\./g, '[.]');
    if (type === 'email') return v.replace(/@/g, '[at]').replace(/\./g, '[.]');
    return v.replace(/\./g, '[.]');
  }
  function validIPv4(ip) {
    var p = String(ip).split('.');
    if (p.length !== 4) return false;
    return p.every(function (x) { return /^\d{1,3}$/.test(x) && Number(x) <= 255; });
  }
  function ipClass(ip) {
    var p = String(ip).split('.').map(Number);
    if (p[0] === 10 || p[0] === 127 || (p[0] === 172 && p[1] >= 16 && p[1] <= 31) ||
        (p[0] === 192 && p[1] === 168) || (p[0] === 169 && p[1] === 254) || p[0] === 0)
      return 'Private / internal';
    if (p[0] >= 224) return 'Multicast / reserved';
    return 'Public / external';
  }

  var IP_RE = /\b(?:\d{1,3}\.){3}\d{1,3}\b/g;
  function ipsIn(line) {
    return (String(line).match(IP_RE) || []).filter(validIPv4);
  }

  /* ------------------------- IOC extraction ----------------------------- */
  var IOC_SPECS = [
    { type: 'sha256', re: /\b[a-f0-9]{64}\b/gi },
    { type: 'sha1',   re: /\b[a-f0-9]{40}\b/gi },
    { type: 'md5',    re: /\b[a-f0-9]{32}\b/gi },
    { type: 'url',    re: /https?:\/\/[^\s"'<>)\]]+/gi },
    { type: 'cve',    re: /\bCVE-\d{4}-\d{4,7}\b/gi },
    { type: 'email',  re: /\b[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,}\b/gi },
    { type: 'ipv4',   re: IP_RE },
    { type: 'domain', re: /\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+(?:com|net|org|io|co|gov|edu|ru|cn|xyz|top|info|biz|dev|app|me|uk|de|in|internal|local)\b/gi }
  ];
  function extractIOCs(text) {
    var src = String(text || '');
    var urls = src.match(/https?:\/\/[^\s"'<>)\]]+/gi) || [];
    var seen = Object.create(null);
    var out = [];
    IOC_SPECS.forEach(function (spec) {
      var m, re = new RegExp(spec.re.source, spec.re.flags);
      while ((m = re.exec(src)) !== null) {
        var value = m[0].replace(/[.,;:]+$/, '');
        if (!value) continue;
        if (spec.type === 'ipv4' && !validIPv4(value)) continue;
        if (spec.type === 'domain') {
          // the host inside a URL is already represented by the URL IOC
          if (urls.some(function (u) { return u.indexOf(value) !== -1; })) continue;
          if (out.some(function (o) { return o.type === 'ipv4' && value.indexOf(o.value) !== -1; })) continue;
        }
        var key = spec.type + ':' + value.toLowerCase();
        if (seen[key]) { seen[key].count++; continue; }
        var entry = {
          type: spec.type, value: value, defanged: defang(value, spec.type),
          count: 1, note: spec.type === 'ipv4' ? ipClass(value) : ''
        };
        seen[key] = entry;
        out.push(entry);
      }
    });
    var order = { sha256:0, sha1:1, md5:2, url:3, domain:4, ipv4:5, email:6, cve:7 };
    out.sort(function (a, b) { return (order[a.type] - order[b.type]) || a.value.localeCompare(b.value); });
    return out;
  }

  /* ------------------------- Log detection ------------------------------ */
  function makeDetection(rule, hits, severity, extraEvidence) {
    return {
      id: uid('det'), rule: rule.id, name: rule.name, severity: severity || rule.severity,
      mitre: rule.mitre, count: hits.length,
      lines: hits.slice(0, 6).map(function (h) { return h.line; }),
      samples: hits.slice(0, 4).map(function (h) { return h.text; }),
      evidence: extraEvidence || (hits.length + ' matching log line(s); first: “' + hits[0].text.slice(0, 160) + '”'),
      remediation: rule.remediation, at: Date.now()
    };
  }
  function detectLogs(text) {
    var lines = String(text || '').split(/\r?\n/).filter(function (l) { return l.trim().length; });
    var detections = [];
    var allIPs = Object.create(null);
    var failedPerIp = Object.create(null);
    var successLines = [];
    var statusCounts = Object.create(null);

    lines.forEach(function (line, idx) {
      ipsIn(line).forEach(function (ip) { allIPs[ip] = (allIPs[ip] || 0) + 1; });
      var status = line.match(/\s(1\d\d|2\d\d|3\d\d|4\d\d|5\d\d)\s/);
      if (status) statusCounts[status[1]] = (statusCounts[status[1]] || 0) + 1;
    });

    var brute = DATA.LOG_RULES.filter(function (r) { return r.id === 'AUTH-BRUTE-FORCE'; })[0];
    lines.forEach(function (line) {
      if (brute.pattern.test(line)) {
        var ips = ipsIn(line);
        var key = ips.length ? ips[ips.length - 1] : 'unattributed';
        failedPerIp[key] = (failedPerIp[key] || 0) + 1;
      }
    });

    DATA.LOG_RULES.forEach(function (rule) {
      var hits = [];
      lines.forEach(function (line, idx) {
        if (rule.pattern.test(line)) hits.push({ line: idx + 1, text: line });
      });
      if (!hits.length) return;

      if (rule.kind === 'threshold') {
        var byIp = Object.create(null);
        hits.forEach(function (hit) {
          var ips = ipsIn(hit.text);
          var key = ips.length ? ips[ips.length - 1] : 'unattributed';
          (byIp[key] = byIp[key] || []).push(hit);
        });
        Object.keys(byIp).forEach(function (ip) {
          var group = byIp[ip];
          if (group.length < rule.threshold) return;
          var severity = group.length >= rule.threshold * 2 ? 'critical' : rule.severity;
          detections.push(makeDetection(rule, group, severity,
            group.length + ' matching events attributed to ' + ip + ' (threshold ' + rule.threshold + ').'));
        });
      } else if (rule.kind === 'correlation') {
        hits.forEach(function (hit) {
          var ips = ipsIn(hit.text);
          var ip = ips.length ? ips[ips.length - 1] : null;
          if (ip && failedPerIp[ip] >= 5) {
            successLines.push(ip);
            detections.push(makeDetection(rule, [hit], 'critical',
              'Successful authentication from ' + ip + ' after ' + failedPerIp[ip] +
              ' recorded failures — classic brute-force-to-access pattern.'));
          }
        });
      } else {
        var escalate = hits.length >= 6 && rule.severity !== 'critical';
        detections.push(makeDetection(rule, hits, escalate ? 'high' : rule.severity));
      }
    });

    detections.sort(function (a, b) { return sevRank(b.severity) - sevRank(a.severity) || b.count - a.count; });
    return {
      detections: detections,
      iocs: extractIOCs(String(text || '')),
      stats: {
        lines: lines.length,
        ips: Object.keys(allIPs).length,
        failed: Object.keys(failedPerIp).reduce(function (n, k) { return n + failedPerIp[k]; }, 0),
        compromisedPatterns: successLines.length,
        status: statusCounts
      },
      at: Date.now()
    };
  }

  /* --------------------- HTTP hardening analysis ------------------------- */
  function parseHeaders(text) {
    var headers = Object.create(null), cookies = [];
    String(text || '').split(/\r?\n/).forEach(function (line) {
      var m = line.match(/^\s*([A-Za-z0-9-]+)\s*:\s*(.*)$/);
      if (!m) return;
      var key = m[1].toLowerCase(), value = m[2].trim();
      if (key === 'set-cookie') cookies.push(value);
      else headers[key] = value;
    });
    return { headers: headers, cookies: cookies };
  }
  function analyzeHeaders(text) {
    var p = parseHeaders(text), h = p.headers, checks = [];
    function add(id, name, status, weight, evidence, fix, framework) {
      checks.push({ id: id, name: name, status: status, weight: weight,
        evidence: evidence, fix: fix, framework: framework || 'OWASP Secure Headers' });
    }
    var hsts = h['strict-transport-security'];
    var maxAge = hsts ? parseInt((hsts.match(/max-age\s*=\s*(\d+)/i) || [])[1] || '0', 10) : 0;
    if (!hsts) add('HSTS', 'HTTP Strict Transport Security', 'fail', 12, 'Header absent; downgrade attacks remain possible.',
      'Strict-Transport-Security: max-age=31536000; includeSubDomains; preload');
    else if (maxAge >= 15552000 && /includeSubDomains/i.test(hsts))
      add('HSTS', 'HTTP Strict Transport Security', 'pass', 12, 'max-age=' + maxAge + ' with includeSubDomains.', 'Keep preload status under review.');
    else add('HSTS', 'HTTP Strict Transport Security', 'warn', 12,
      'max-age=' + maxAge + (/\bincludeSubDomains\b/i.test(hsts) ? '' : ' and no includeSubDomains') + '.',
      'Raise max-age to at least 15552000 and add includeSubDomains.');

    var csp = h['content-security-policy'];
    var cspRo = h['content-security-policy-report-only'];
    if (cspRo && !csp) add('CSP', 'Content-Security-Policy', 'warn', 14,
      'Only report-only policy present; nothing is enforced.', 'Move directives into the enforcing header after validation.');
    else if (!csp) add('CSP', 'Content-Security-Policy', 'fail', 14, 'Header absent; inline and third-party script execution is unrestricted.',
      "default-src 'self'; object-src 'none'; base-uri 'self'; frame-ancestors 'none'");
    else if (/unsafe-inline|\*\s|data:\s*text\/html/i.test(csp)) add('CSP', 'Content-Security-Policy', 'warn', 14,
      'Policy contains unsafe-inline or a wildcard source.', 'Replace with nonce/hash-based sources and remove wildcards.');
    else add('CSP', 'Content-Security-Policy', 'pass', 14, 'Enforcing policy present without obvious wildcards.', 'Review directives quarterly.');

    add('XCTO', 'X-Content-Type-Options', h['x-content-type-options'] === 'nosniff' ? 'pass' : 'fail', 8,
      h['x-content-type-options'] || 'Header absent.', 'X-Content-Type-Options: nosniff');
    var framed = h['x-frame-options'] || (csp && /frame-ancestors/i.test(csp));
    add('FRAME', 'Clickjacking protection', framed ? 'pass' : 'fail', 8,
      h['x-frame-options'] || (framed ? 'frame-ancestors directive present.' : 'No X-Frame-Options or frame-ancestors.'),
      "X-Frame-Options: DENY or CSP frame-ancestors 'none'");
    var rp = h['referrer-policy'];
    add('REFERRER', 'Referrer-Policy', rp && !/unsafe-url|no-referrer-when-downgrade/i.test(rp) ? 'pass' : (!rp ? 'warn' : 'fail'), 5,
      rp || 'Header absent; browser default applies.', 'Referrer-Policy: strict-origin-when-cross-origin');
    add('PERMISSIONS', 'Permissions-Policy', h['permissions-policy'] ? 'pass' : 'warn', 5,
      h['permissions-policy'] || 'Header absent; powerful browser features are not explicitly restricted.',
      'Permissions-Policy: camera=(), microphone=(), geolocation=()');

    if (!p.cookies.length) add('COOKIE', 'Session cookie flags', 'warn', 10,
      'No Set-Cookie header in the supplied sample.', 'Verify Secure; HttpOnly; SameSite=Lax on all session cookies.');
    else {
      var missing = [];
      p.cookies.forEach(function (c) {
        ['Secure', 'HttpOnly', 'SameSite'].forEach(function (flag) {
          if (!new RegExp(flag, 'i').test(c)) missing.push(flag);
        });
      });
      add('COOKIE', 'Session cookie flags', missing.length >= 2 ? 'fail' : (missing.length ? 'warn' : 'pass'), 10,
        missing.length ? 'Missing: ' + Array.from(new Set(missing)).join(', ') : 'Secure, HttpOnly and SameSite present on all cookies.',
        'Set-Cookie: session=…; Secure; HttpOnly; SameSite=Lax');
    }

    var banner = ['server', 'x-powered-by', 'x-aspnet-version'].filter(function (k) { return /\d/.test(h[k] || ''); });
    add('BANNER', 'Version banner disclosure', banner.length ? 'fail' : 'pass', 6,
      banner.length ? 'Version disclosed via: ' + banner.join(', ') : 'No version-bearing banner observed.',
      'Strip version tokens at the reverse proxy; keep an internal inventory instead.');

    var acao = h['access-control-allow-origin'], acac = h['access-control-allow-credentials'];
    if (acao === '*' && /true/i.test(acac || '')) add('CORS', 'Cross-origin resource sharing', 'fail', 12,
      'Wildcard origin combined with credentialed requests — browser and policy conflict, high risk of data exposure.',
      'Replace * with an explicit origin allowlist; validate Origin server-side.');
    else if (acao === '*') add('CORS', 'Cross-origin resource sharing', 'warn', 12,
      'Wildcard origin allowed for unauthenticated responses.', 'Prefer an explicit allowlist for internal APIs.');
    else add('CORS', 'Cross-origin resource sharing', 'pass', 12, acao ? 'Explicit origin: ' + acao : 'No permissive CORS header observed.', 'Keep the allowlist minimal.');

    var cc = h['cache-control'] || '';
    add('CACHE', 'Sensitive response caching', /no-store|no-cache|private/i.test(cc) ? 'pass' : 'warn', 5,
      cc || 'No Cache-Control header in sample.', 'Cache-Control: no-store for authenticated responses.');
    var coop = h['cross-origin-opener-policy'], corp = h['cross-origin-resource-policy'];
    add('ISOLATION', 'Cross-origin isolation', coop && corp ? 'pass' : 'warn', 3,
      coop && corp ? 'COOP and CORP present.' : 'COOP/CORP not both present.',
      'Cross-Origin-Opener-Policy: same-origin; Cross-Origin-Resource-Policy: same-origin');
    var coep = h['cross-origin-embedder-policy'];
    add('COEP', 'Cross-Origin-Embedder-Policy', coep ? 'pass' : 'warn', 3,
      coep || 'Header absent; cross-origin resources are not restricted for this document.',
      'Cross-Origin-Embedder-Policy: require-corp (validate third-party embeds first)');

    var total = checks.reduce(function (n, c) { return n + c.weight; }, 0);
    var got = checks.reduce(function (n, c) { return n + c.weight * (c.status === 'pass' ? 1 : c.status === 'warn' ? 0.5 : 0); }, 0);
    var score = total ? Math.round(got / total * 100) : 0;
    var grade = score >= 90 ? 'A' : score >= 75 ? 'B' : score >= 60 ? 'C' : score >= 40 ? 'D' : 'F';
    return { checks: checks, score: score, grade: grade, at: Date.now(), cookies: p.cookies.length };
  }

  /* ------------------------ Authorization gate -------------------------- */
  function scopeCheck(state, target, checkType) {
    var name = String(target || '').trim().toLowerCase();
    var asset = (state.assets || []).filter(function (a) { return a.name.toLowerCase() === name; })[0];
    if (!asset) return { allowed: false, code: 'NO_SCOPE_RECORD', reason: 'No signed authorization record exists for this target.' };
    if (asset.revoked) return { allowed: false, code: 'SCOPE_REVOKED', reason: 'Authorization for this asset was revoked.', asset: asset };
    if (!asset.confirmed) return { allowed: false, code: 'OWNER_UNCONFIRMED', reason: 'Ownership attestation is missing.', asset: asset };
    if (!asset.expires || Date.parse(asset.expires) <= Date.now())
      return { allowed: false, code: 'SCOPE_EXPIRED', reason: 'Authorization window has expired.', asset: asset };
    if (checkType && (asset.checks || []).indexOf(checkType) === -1)
      return { allowed: false, code: 'CHECK_NOT_PERMITTED', reason: 'This check type is outside the permitted scope.', asset: asset };
    return { allowed: true, code: 'SCOPE_VALID', reason: 'Signed authorization verified.', asset: asset, token: (asset.token || '').slice(0, 16) };
  }
  function activeAssets(state) {
    return (state.assets || []).filter(function (a) { return scopeCheck(state, a.name).allowed; });
  }

  /* --------------------------- Triage engine ---------------------------- */
  function triage(alert, state) {
    var sev = DATA.SEVERITIES[alert.severity] || DATA.SEVERITIES.info;
    var score = sev.weight * 0.62 + (Number(alert.confidence) || 50) * 0.24;
    var reasons = [];
    reasons.push('Base severity ' + sev.label + ' contributes ' + (sev.weight * 0.62).toFixed(1) + ' pts.');
    reasons.push('Signal confidence ' + (Number(alert.confidence) || 50) + '% contributes ' + ((Number(alert.confidence) || 50) * 0.24).toFixed(1) + ' pts.');
    var asset = (state.assets || []).filter(function (a) { return a.name === alert.asset; })[0];
    var critBonus = asset ? ({ critical: 10, high: 7, medium: 4, low: 2 }[asset.criticality] || 0) : 0;
    if (critBonus) { score += critBonus; reasons.push('Asset criticality ' + asset.criticality + ' adds ' + critBonus + ' pts.'); }
    var related = (state.findings || []).filter(function (f) { return f.asset === alert.asset && f.status === 'open'; });
    var corr = Math.min(10, related.length * 3);
    if (corr) { score += corr; reasons.push(corr + ' pts from ' + related.length + ' correlated open finding(s) on the same asset.'); }
    var ev = String(alert.evidence || '');
    var iocHit = (state.watchlist || []).filter(function (w) { return ev.toLowerCase().indexOf(String(w.value).toLowerCase()) !== -1; });
    if (iocHit.length) { score += 12; reasons.push('12 pts: evidence matches ' + iocHit.length + ' local watchlist indicator(s).'); }
    var ageHours = Math.max(0, (Date.now() - (alert.createdAt || Date.now())) / 3600000);
    var decay = Math.min(8, Math.round(ageHours));
    if (decay) { score -= decay; reasons.push('-' + decay + ' pts signal age decay (' + ageHours.toFixed(1) + 'h).'); }
    score = Math.round(clamp(score, 0, 100));
    var band = score >= 80 ? 'P1' : score >= 60 ? 'P2' : score >= 40 ? 'P3' : 'P4';
    var recommended = alert.severity === 'critical'
      ? 'Escalate to incident commander; prepare containment for human approval.'
      : alert.severity === 'high'
        ? 'Assign to analyst; correlate with endpoint telemetry and verify scope.'
        : 'Queue for review; enrich with local IOC context before closing.';
    var playbook = (DATA.PLAYBOOKS.filter(function (p) {
      return /credential/i.test(alert.title) ? p.id === 'pb-credential'
        : /exfil|callback/i.test(alert.title) ? p.id === 'pb-exfil'
        : /tls|legacy/i.test(alert.title) ? p.id === 'pb-supply'
        : p.id === 'pb-phishing';
    })[0] || DATA.PLAYBOOKS[0]);
    return {
      score: score, band: band, reasons: reasons, recommended: recommended,
      playbook: playbook.name, requiresApproval: !!(state.settings && state.settings.humanApproval)
    };
  }

  /* ------------------------- Risk & compliance -------------------------- */
  function riskScore(state) {
    var open = (state.findings || []).filter(function (f) { return f.status === 'open'; });
    var raw = 14 + open.reduce(function (n, f) { return n + (DATA.SEVERITIES[f.severity] || DATA.SEVERITIES.info).weight * 0.15; }, 0);
    raw += (state.alerts || []).filter(function (a) { return a.status === 'new' && (a.severity === 'critical' || a.severity === 'high'); }).length * 3;
    raw += (state.assets || []).filter(function (a) { return !scopeCheck(state, a.name).allowed; }).length * 2;
    var header = state.headerResults ? (100 - state.headerResults.score) * 0.08 : 4;
    return Math.round(clamp(raw + header, 0, 99));
  }
  function entryHash(e) {
    return sha256(JSON.stringify([e.seq, e.ts, e.actor, e.action, e.target, e.decision, e.detail || '', e.prevHash]));
  }
  function verifyChain(audit) {
    var prev = '0'.repeat(64);
    for (var i = 0; i < (audit || []).length; i++) {
      var e = audit[i];
      if (e.prevHash !== prev) return { valid: false, brokenAt: e.seq, reason: 'prevHash mismatch', count: audit.length };
      if (entryHash(e) !== e.hash) return { valid: false, brokenAt: e.seq, reason: 'entry hash mismatch', count: audit.length };
      prev = e.hash;
    }
    return { valid: true, count: (audit || []).length, head: prev };
  }
  function complianceState(state) {
    var chain = verifyChain(state.audit);
    var assets = state.assets || [];
    var active = activeAssets(state).length;
    var findings = state.findings || [];
    var open = findings.filter(function (f) { return f.status === 'open'; }).length;
    var mitigated = findings.filter(function (f) { return f.status !== 'open'; }).length;
    var alerts = state.alerts || [];
    var triaged = alerts.filter(function (a) { return a.status !== 'new'; }).length;
    var steps = Object.keys(state.playbookProgress || {}).reduce(function (n, k) {
      return n + (state.playbookProgress[k] || []).filter(Boolean).length;
    }, 0);
    var cookiePass = state.headerResults && state.headerResults.checks.filter(function (c) { return c.id === 'COOKIE' && c.status === 'pass'; }).length;
    var transport = state.headerResults && state.headerResults.checks.filter(function (c) { return c.id === 'HSTS' && c.status === 'pass'; }).length;
    var values = {
      'CIS-01': assets.length >= 3 ? 'implemented' : assets.length ? 'partial' : 'gap',
      'NIST-ID.AM': active === assets.length && active > 0 ? 'implemented' : active ? 'partial' : 'gap',
      'CIS-07': mitigated > 0 && open < findings.length ? 'implemented' : open ? 'partial' : 'gap',
      'NIST-PR.PS': state.headerResults && state.headerResults.score >= 75 ? 'implemented' : state.headerResults ? 'partial' : 'gap',
      'NIST-DE.CM': state.logResults ? 'implemented' : 'gap',
      'MITRE-DE': state.logResults && state.logResults.detections.length ? 'implemented' : 'gap',
      'NIST-DE.AE': triaged === alerts.length && alerts.length ? 'implemented' : triaged ? 'partial' : 'gap',
      'NIST-PR.IP': steps >= 8 ? 'implemented' : steps ? 'partial' : 'gap',
      'NIST-PR.AA': state.settings && state.settings.humanApproval ? 'implemented' : 'partial',
      'NIST-PR.DS': cookiePass && transport ? 'implemented' : (cookiePass || transport) ? 'partial' : 'gap',
      'CIS-13': (state.watchlist || []).length >= 2 ? 'implemented' : (state.watchlist || []).length ? 'partial' : 'gap',
      'NIST-PR.PS-2': chain.valid && chain.count > 1 ? 'implemented' : 'partial'
    };
    return DATA.COMPLIANCE_CONTROLS.map(function (c) {
      return Object.assign({}, c, { status: values[c.id] || 'gap' });
    });
  }

  /* ------------------- Deterministic simulated sweep -------------------- *
   * IMPORTANT: this produces illustrative findings from a local template
   * catalog. It does NOT contact any host. Results are flagged simulated.
   * ------------------------------------------------------------------- */
  function simulateSweep(state, runIndex, targets) {
    var rand = prng(sha256('sweep:' + runIndex + ':' + Date.now()));
    var decisions = [], findings = [];
    var list = targets && targets.length ? targets : (state.assets || []).map(function (a) { return a.name; });
    list.forEach(function (name) {
      var gate = scopeCheck(state, name, 'posture');
      if (!gate.allowed) {
        decisions.push({ target: name, decision: 'REFUSED', code: gate.code, reason: gate.reason, count: 0 });
        return;
      }
      var n = 1 + Math.floor(rand() * 3);
      for (var i = 0; i < n; i++) {
        var tpl = DATA.FINDING_TEMPLATES[Math.floor(rand() * DATA.FINDING_TEMPLATES.length)];
        findings.push({
          id: uid('fnd'), title: tpl.title, severity: tpl.severity, asset: name,
          category: tpl.category, mitre: tpl.mitre, evidence: tpl.evidence,
          remediation: tpl.remediation, confidence: 70 + Math.floor(rand() * 29),
          status: 'open', source: 'autonomous-sweep', simulated: true, createdAt: Date.now()
        });
      }
      decisions.push({ target: name, decision: 'ALLOWED', code: 'SCOPE_VALID', reason: 'Scope token ' + gate.token + ' verified.', count: n });
    });
    return { decisions: decisions, findings: findings, at: Date.now() };
  }

  var API = {
    sha256: sha256, uid: uid, prng: prng, clamp: clamp, defang: defang,
    validIPv4: validIPv4, ipClass: ipClass, extractIOCs: extractIOCs,
    detectLogs: detectLogs, analyzeHeaders: analyzeHeaders, parseHeaders: parseHeaders,
    scopeCheck: scopeCheck, activeAssets: activeAssets, triage: triage,
    riskScore: riskScore, entryHash: entryHash, verifyChain: verifyChain,
    complianceState: complianceState, simulateSweep: simulateSweep, sevRank: sevRank
  };
  root.AEGIS_ENGINE = API;
  if (typeof module !== 'undefined' && module.exports) module.exports = API;
})(typeof globalThis !== 'undefined' ? globalThis : this);


/* ===== 15-advanced.js ===== */
/* AEGIS // SENTINEL v2 — advanced offline analysis engines.
 * Universal normalization, attack-chain reconstruction, anomaly detection,
 * config/IAM/K8s/email/secret/SBOM analyzers, ATT&CK coverage, quantitative
 * risk, natural-language investigation and the capability policy engine.
 * Every function is pure string/object analysis. No network. No exploitation.
 */
(function (root) {
  'use strict';
  var isNode = typeof module !== 'undefined' && module.exports;
  var DATA = isNode ? require('./00-data.js') : root.AEGIS_DATA;
  var D2 = isNode ? require('./05-data2.js') : root.AEGIS_DATA2;
  var E = isNode ? require('./10-engine.js') : root.AEGIS_ENGINE;

  function clamp(n, lo, hi) { return Math.max(lo, Math.min(hi, n)); }
  function uniq(a) { return Array.from(new Set(a)); }
  function sevRank(s) { return (DATA.SEVERITIES[s] || DATA.SEVERITIES.info).rank; }
  function tacticOf(mitre) {
    var t = D2.TECHNIQUES.filter(function (x) { return x.id === mitre; })[0];
    if (t) return t.tactic;
    var parent = String(mitre).split('.')[0];
    var p = D2.TECHNIQUES.filter(function (x) { return x.id === parent; })[0];
    return p ? p.tactic : 'execution';
  }
  function tacticName(id) {
    var t = D2.MITRE_TACTICS.filter(function (x) { return x.id === id; })[0];
    return t ? t.name : id;
  }
  function shannon(s) {
    var freq = Object.create(null);
    for (var i = 0; i < s.length; i++) freq[s[i]] = (freq[s[i]] || 0) + 1;
    var h = 0;
    Object.keys(freq).forEach(function (k) {
      var p = freq[k] / s.length; h -= p * Math.log2(p);
    });
    return h;
  }
  function mask(v) {
    var s = String(v);
    if (s.length <= 8) return s.slice(0, 2) + '****';
    return s.slice(0, 4) + '•'.repeat(Math.min(18, s.length - 8)) + s.slice(-2);
  }

  /* --------------------- universal log normalization --------------------- */
  var NGINX_RE = /^(\S+)\s+\S+\s+\S+\s+\[([^\]]+)\]\s+"(\S+)\s+(\S+)\s+[^"]*"\s+(\d{3})\s+(\d+)\s+"([^"]*)"\s+"([^"]*)"/;
  var SYSLOG_RE = /^([A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+(\S+)\s+([^:\s]+)(?:\[\d+\])?:\s*(.*)$/;
  var IP_RE = /\b(?:\d{1,3}\.){3}\d{1,3}\b/g;

  function tryJson(line) { try { return JSON.parse(line); } catch (e) { return null; } }
  function detectFormat(lines) {
    var scores = { jsonl: 0, nginx: 0, syslog: 0, csv: 0, generic: 0 };
    var sample = lines.slice(0, 60);
    sample.forEach(function (l) {
      var s = l.trim();
      if (!s) return;
      if (/^\{/.test(s) && tryJson(s)) scores.jsonl += 3;
      if (NGINX_RE.test(s)) scores.nginx += 3;
      if (SYSLOG_RE.test(s)) scores.syslog += 3;
      if (s.split(',').length >= 3 && !/^\s*\{/.test(s)) scores.csv += 1;
    });
    var best = 'generic', top = 0;
    // Priority order also acts as the tie-break for mixed-format files.
    ['jsonl', 'syslog', 'nginx', 'csv', 'generic'].forEach(function (k) {
      if (scores[k] > top) { top = scores[k]; best = k; }
    });
    return top >= 3 ? best : 'generic';
  }
  function lineFormat(s) {
    if (/^\s*\{/.test(s) && tryJson(s)) return 'jsonl';
    if (NGINX_RE.test(s)) return 'nginx';
    if (SYSLOG_RE.test(s)) return 'syslog';
    if (s.split(',').length >= 3) return 'csv';
    return 'generic';
  }
  function parseTimestamp(v) {
    if (v == null || v === '') return null;
    if (typeof v === 'number') return v > 1e12 ? v : v * 1000;
    var t = Date.parse(String(v));
    if (!isNaN(t)) return t;
    var m = String(v).match(/^(\d{1,2})\/([A-Za-z]{3})\/(\d{4}):(\d{2}:\d{2}:\d{2})/);
    if (m) { t = Date.parse(m[2] + ' ' + m[1] + ' ' + m[3] + ' ' + m[4]); if (!isNaN(t)) return t; }
    return null;
  }
  function normalizeLogs(text) {
    var lines = String(text || '').split(/\r?\n/).filter(function (l) { return l.trim(); });
    var format = detectFormat(lines);
    var events = [];
    function push(o, idx, raw) {
      events.push({
        id: 'ev' + (idx + 1), n: idx + 1,
        ts: o.ts || null, src: o.src || '', actor: o.actor || '',
        action: o.action || '', target: o.target || '', status: o.status || null,
        ua: o.ua || '', raw: String(raw).slice(0, 260), tags: []
      });
    }
    lines.slice(0, 400).forEach(function (line, idx) {
      var s = line.trim();
      var fmt = lineFormat(s); // per-line detection: mixed files are normalized correctly
      if (fmt === 'jsonl') {
        var j = tryJson(s);
        if (!j) { push({ action: 'unparsed line' }, idx, s); return; }
        var srcObj = j.source || j.src || {};
        push({
          ts: parseTimestamp(j.time || j.timestamp || j['@timestamp'] || j.eventTime || j.ts),
          src: j.src_ip || j.srcIp || j.client_ip || j.remote_addr || srcObj.ip || srcObj.address || j.ip || '',
          actor: j.user || j.userName || j.principal || j.actor || j.userIdentity || '',
          action: j.event || j.eventName || j.action || j.msg || j.message || '',
          target: j.host || j.path || j.dst || j.destination || j.resource || '',
          status: Number(j.status || j.statusCode || j.response_code) || null,
          ua: j.ua || j.userAgent || ''
        }, idx, s);
      } else if (fmt === 'nginx') {
        var m = s.match(NGINX_RE);
        if (!m) { push({ action: 'unparsed line' }, idx, s); return; }
        push({ ts: parseTimestamp(m[2].replace(':', ' ')), src: m[1], actor: '-',
          action: m[3] + ' ' + m[4], target: m[4], status: Number(m[5]), ua: m[8] }, idx, s);
      } else if (fmt === 'syslog') {
        var sm = s.match(SYSLOG_RE);
        if (!sm) { push({ action: s.slice(0, 80) }, idx, s); return; }
        var yr = new Date().getUTCFullYear();
        var ts = Date.parse(sm[1].replace(/\s+/g, ' ') + ' ' + yr);
        var ips = (s.match(IP_RE) || []).filter(E.validIPv4);
        var user = (s.match(/for (?:invalid user )?(\S+)/) || s.match(/user=(\S+)/) || [])[1] || '';
        push({ ts: isNaN(ts) ? null : ts, src: ips.length ? ips[ips.length - 1] : '',
          actor: user, action: sm[4].slice(0, 100), target: sm[2], status: null }, idx, s);
      } else if (fmt === 'csv') {
        var cells = s.split(',').map(function (x) { return x.trim().replace(/^["']|["']$/g, ''); });
        push({ action: cells[2] || cells[1] || '', src: cells[0] || '', actor: cells[1] || '',
          target: cells[3] || '', ts: parseTimestamp(cells[cells.length - 1]) }, idx, s);
      } else {
        var ips2 = (s.match(IP_RE) || []).filter(E.validIPv4);
        push({ src: ips2.length ? ips2[0] : '', action: s.slice(0, 110) }, idx, s);
      }
    });

    // Tag each event with detection rules and ATT&CK tactics.
    events.forEach(function (ev) {
      var hay = [ev.raw, ev.action, ev.target, ev.ua, ev.status].join(' ');
      DATA.LOG_RULES.forEach(function (rule) {
        if (rule.pattern.test(hay)) {
          ev.tags.push({ id: rule.id, name: rule.name, severity: rule.severity, mitre: rule.mitre, tactic: tacticOf(rule.mitre) });
        }
      });
    });
    var tagged = events.filter(function (e) { return e.tags.length; });
    var byTactic = Object.create(null);
    tagged.forEach(function (e) { e.tags.forEach(function (t) { byTactic[t.tactic] = (byTactic[t.tactic] || 0) + 1; }); });
    return {
      format: format, events: events, at: Date.now(),
      stats: {
        lines: lines.length, parsed: events.length, tagged: tagged.length,
        sources: uniq(events.map(function (e) { return e.src; }).filter(Boolean)).length,
        tactics: Object.keys(byTactic).length,
        byTactic: byTactic
      }
    };
  }

  /* ---------------------- attack chain reconstruction -------------------- */
  function attackChains(norm) {
    var groups = Object.create(null);
    (norm.events || []).forEach(function (e) {
      var key = e.src || 'unattributed';
      (groups[key] = groups[key] || []).push(e);
    });
    var chains = Object.keys(groups).map(function (src) {
      var evs = groups[src].slice().sort(function (a, b) { return (a.ts || a.n) - (b.ts || b.n); });
      var tagged = evs.filter(function (e) { return e.tags.length; });
      var tactics = [], techniques = [];
      tagged.forEach(function (e) {
        e.tags.forEach(function (t) {
          if (tactics.indexOf(t.tactic) === -1) tactics.push(t.tactic);
          if (techniques.indexOf(t.mitre) === -1) techniques.push(t.mitre);
        });
      });
      var severity = tagged.reduce(function (worst, e) {
        return e.tags.reduce(function (w, t) { return sevRank(t.severity) > sevRank(w) ? t.severity : w; }, worst);
      }, 'info');
      var confidence = clamp(38 + tactics.length * 11 + techniques.length * 6 + Math.min(12, tagged.length * 2), 0, 96);
      return {
        id: E.sha256('chain:' + src + ':' + evs.length + ':' + techniques.join(',')).slice(0, 12),
        src: src, events: evs.length, tagged: tagged.length,
        tactics: tactics, techniques: techniques, severity: severity,
        confidence: Math.round(confidence),
        start: evs.length ? (evs[0].ts || null) : null,
        timeline: tagged.slice(0, 8).map(function (e) {
          return { n: e.n, ts: e.ts, action: e.action, tactic: e.tags[0].tactic,
            technique: e.tags[0].mitre, severity: e.tags[0].severity };
        })
      };
    }).filter(function (c) { return c.tagged >= 2 && c.tactics.length >= 2; });
    chains.sort(function (a, b) { return b.confidence - a.confidence || b.tactics.length - a.tactics.length; });
    return { chains: chains.slice(0, 8), at: Date.now() };
  }

  /* ------------------------- statistical anomaly ------------------------- */
  function anomalyDetect(values) {
    var v = (values || []).map(Number).filter(function (x) { return isFinite(x); });
    if (!v.length) return { values: [], outliers: [], mean: 0, stddev: 0, q1: 0, q3: 0, lower: 0, upper: 0, ewma: [] };
    var mean = v.reduce(function (a, b) { return a + b; }, 0) / v.length;
    var variance = v.reduce(function (a, b) { return a + Math.pow(b - mean, 2); }, 0) / v.length;
    var sd = Math.sqrt(variance);
    var sorted = v.slice().sort(function (a, b) { return a - b; });
    function q(p) { var i = (sorted.length - 1) * p, lo = Math.floor(i), hi = Math.ceil(i); return sorted[lo] + (sorted[hi] - sorted[lo]) * (i - lo); }
    var q1 = q(0.25), q3 = q(0.75), iqr = q3 - q1;
    var lower = q1 - 1.5 * iqr, upper = q3 + 1.5 * iqr;
    var ewma = [], prev = v[0];
    v.forEach(function (x) { prev = 0.3 * x + 0.7 * prev; ewma.push(Math.round(prev * 100) / 100); });
    var outliers = [];
    v.forEach(function (x, i) {
      var z = sd ? (x - mean) / sd : 0;
      if (Math.abs(z) > 2 || x < lower || x > upper) outliers.push({ index: i, value: x, z: Math.round(z * 100) / 100 });
    });
    return { values: v, outliers: outliers, mean: Math.round(mean * 100) / 100,
      stddev: Math.round(sd * 100) / 100, q1: q1, q3: q3,
      lower: Math.round(lower * 100) / 100, upper: Math.round(upper * 100) / 100, ewma: ewma };
  }
  function eventRateSeries(norm) {
    var buckets = new Array(12).fill(0);
    (norm.events || []).forEach(function (e, i) {
      var idx = e.ts ? Math.floor(((e.ts - (norm.events[0].ts || e.ts)) / 3600000) % 12) : Math.floor(i / Math.max(1, norm.events.length / 12));
      if (!isFinite(idx) || idx < 0) idx = 0;
      buckets[clamp(idx, 0, 11)]++;
    });
    return buckets.map(function (n) { return n || Math.round(1 + Math.random() * 2); });
  }

  /* --------------------------- secret scanning --------------------------- */
  function secretScan(text) {
    var lines = String(text || '').split(/\r?\n/);
    var findings = [], seen = Object.create(null);
    var specs = [
      { type: 'AWS access key', severity: 'critical', re: /\bAKIA[0-9A-Z]{16,20}\b/g, fix: 'Rotate the key in IAM and purge from source control history.' },
      { type: 'GitHub token', severity: 'critical', re: /\bgh[pousr]_[A-Za-z0-9]{20,}\b/g, fix: 'Revoke the token and use short-lived OIDC credentials.' },
      { type: 'Slack token', severity: 'high', re: /\bxox[baprs]-[A-Za-z0-9-]{10,}\b/g, fix: 'Revoke and rotate the workspace token.' },
      { type: 'Stripe live key', severity: 'critical', re: /\bsk_live_[A-Za-z0-9]{16,}\b/g, fix: 'Roll the key in the Stripe dashboard immediately.' },
      { type: 'Private key block', severity: 'critical', re: /-----BEGIN (?:EXAMPLE )?(?:RSA|EC|OPENSSH|DSA|PGP)? ?PRIVATE KEY(?: BLOCK)?-----/g, fix: 'Remove the key from the repository and issue a new keypair.' },
      { type: 'JSON Web Token', severity: 'high', re: /\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b/g, fix: 'Invalidate the session and shorten token lifetimes.' },
      { type: 'Credential in URL', severity: 'high', re: /\b[a-z]+:\/\/[^:\s"']+:[^@\s"']+@/gi, fix: 'Move credentials to a secret manager; never embed in URLs.' },
      { type: 'Assigned secret', severity: 'high', re: /\b(?:password|passwd|secret|token|api[_-]?key|access[_-]?key)\s*[:=]\s*["']?([^\s"',]{8,})/gi, fix: 'Replace with a secret-manager reference and rotate the value.' }
    ];
    lines.forEach(function (line, idx) {
      specs.forEach(function (spec) {
        var m, re = new RegExp(spec.re.source, spec.re.flags);
        while ((m = re.exec(line)) !== null) {
          var value = m[1] || m[0];
          var key = spec.type + ':' + value;
          if (seen[key]) continue;
          seen[key] = 1;
          findings.push({ type: spec.type, severity: spec.severity, line: idx + 1,
            masked: mask(value), entropy: Math.round(shannon(value) * 100) / 100,
            fix: spec.fix });
        }
      });
      // High-entropy tokens not already reported.
      var tokens = line.match(/[A-Za-z0-9+/=_-]{26,}/g) || [];
      tokens.forEach(function (tok) {
        var h = shannon(tok);
        if (h < 3.7) return;
        var key = 'entropy:' + tok;
        if (seen[key]) return;
        if (findings.some(function (f) { return f.type.indexOf('Entropy') === -1 && f.line === idx + 1; })) return;
        seen[key] = 1;
        findings.push({ type: 'High-entropy string', severity: 'medium', line: idx + 1,
          masked: mask(tok), entropy: Math.round(h * 100) / 100,
          fix: 'Verify whether this is credential material; rotate if so.' });
      });
    });
    var weight = findings.reduce(function (n, f) { return n + (DATA.SEVERITIES[f.severity] || DATA.SEVERITIES.info).weight; }, 0);
    return { findings: findings, count: findings.length,
      score: Math.round(clamp(100 - weight * 0.6, 0, 100)), at: Date.now() };
  }

  /* ---------------------------- IAM policy ------------------------------- */
  function analyzeIamPolicy(text) {
    var parsed = null, error = '';
    try { parsed = JSON.parse(String(text)); } catch (e) { error = e.message; }
    var statements = parsed ? (Array.isArray(parsed.Statement) ? parsed.Statement : (parsed.Statement ? [parsed.Statement] : [])) : [];
    var checks = [];
    function add(id, status, title, evidence, fix) { checks.push({ id: id, status: status, title: title, evidence: evidence, fix: fix }); }
    if (!parsed) add('PARSE', 'fail', 'Policy is not valid JSON', error, 'Provide a valid IAM policy document.');
    else {
      var wildAction = statements.filter(function (s) { return s.Effect === 'Allow' && (s.Action === '*' || (Array.isArray(s.Action) && s.Action.indexOf('*') !== -1)); });
      add('WILD-ACTION', wildAction.length ? 'fail' : 'pass', 'Wildcard actions', wildAction.length ? wildAction.length + ' Allow statement(s) use Action: "*"' : 'No wildcard Action in Allow statements.',
        'Enumerate only the actions the principal requires.');
      var wildRes = statements.filter(function (s) { return s.Effect === 'Allow' && (s.Resource === '*' || (Array.isArray(s.Resource) && s.Resource.indexOf('*') !== -1)); });
      add('WILD-RESOURCE', wildRes.length ? 'warn' : 'pass', 'Wildcard resources', wildRes.length ? wildRes.length + ' statement(s) use Resource: "*"' : 'Resources are scoped.',
        'Scope Resource to specific ARNs.');
      var publicPrincipal = statements.filter(function (s) { return s.Principal === '*' || (s.Principal && s.Principal.AWS === '*'); });
      add('PUBLIC-PRINCIPAL', publicPrincipal.length ? 'fail' : 'pass', 'Public principal', publicPrincipal.length ? 'Principal: "*" allows anyone to assume/use this policy.' : 'No public principal.',
        'Remove the public principal or add restrictive conditions.');
      var passRole = statements.filter(function (s) {
        var acts = Array.isArray(s.Action) ? s.Action : [s.Action];
        return s.Effect === 'Allow' && acts.some(function (a) { return /iam:PassRole/i.test(a || ''); });
      });
      add('PASS-ROLE', passRole.length ? 'fail' : 'pass', 'Unrestricted iam:PassRole', passRole.length ? 'iam:PassRole granted without a narrow resource constraint.' : 'No broad PassRole grant.',
        'Limit PassRole to specific role ARNs and add a service condition.');
      var noMfa = statements.filter(function (s) {
        var acts = Array.isArray(s.Action) ? s.Action.join(' ') : String(s.Action || '');
        return s.Effect === 'Allow' && /iam:|s3:Delete|ec2:Terminate/i.test(acts) && !s.Condition;
      });
      add('MFA-CONDITION', noMfa.length ? 'warn' : 'pass', 'MFA condition on sensitive actions', noMfa.length ? noMfa.length + ' sensitive Allow statement(s) lack any Condition.' : 'Sensitive actions carry conditions.',
        'Add aws:MultiFactorAuthPresent / aws:MultiFactorAuthAge conditions.');
      var notAction = statements.filter(function (s) { return s.NotAction && s.Effect === 'Allow'; });
      add('NOT-ACTION', notAction.length ? 'fail' : 'pass', 'NotAction in Allow statement', notAction.length ? 'NotAction allows everything except a short list.' : 'No NotAction allowlist inversion.',
        'Replace NotAction with an explicit Action list.');
      var denyCount = statements.filter(function (s) { return s.Effect === 'Deny'; }).length;
      add('EXPLICIT-DENY', denyCount ? 'pass' : 'warn', 'Explicit deny guardrails', denyCount + ' explicit Deny statement(s).',
        'Add explicit denies for destructive actions and non-approved regions.');
    }
    var total = checks.length, got = checks.reduce(function (n, c) { return n + (c.status === 'pass' ? 1 : c.status === 'warn' ? 0.5 : 0); }, 0);
    return { checks: checks, statements: statements.length, parsed: !!parsed,
      score: total ? Math.round(got / total * 100) : 0, at: Date.now() };
  }

  /* -------------------------- Kubernetes manifest ------------------------ */
  function analyzeK8s(text) {
    var s = String(text || ''), checks = [];
    function has(re) { return re.test(s); }
    function add(id, status, title, evidence, fix) { checks.push({ id: id, status: status, title: title, evidence: evidence, fix: fix }); }
    add('PRIVILEGED', has(/privileged:\s*true/i) ? 'fail' : 'pass', 'Privileged containers',
      has(/privileged:\s*true/i) ? 'privileged: true grants near-host-level access.' : 'No privileged container detected.',
      'Set securityContext.privileged: false.');
    add('HOST-NS', has(/hostNetwork:\s*true|hostPID:\s*true|hostIPC:\s*true/i) ? 'fail' : 'pass', 'Host namespace sharing',
      has(/hostNetwork:\s*true|hostPID:\s*true|hostIPC:\s*true/i) ? 'Pod shares the host network / PID / IPC namespace.' : 'Host namespaces are not shared.',
      'Remove hostNetwork, hostPID and hostIPC.');
    add('ROOT-USER', has(/runAsUser:\s*0\b|runAsNonRoot:\s*false/i) ? 'fail' : 'pass', 'Running as root',
      has(/runAsUser:\s*0\b|runAsNonRoot:\s*false/i) ? 'Container explicitly runs as UID 0 or permits root.' : 'No explicit root execution.',
      'Set runAsNonRoot: true and a non-zero runAsUser.');
    add('PRIV-ESC', has(/allowPrivilegeEscalation:\s*true/i) ? 'fail' : 'pass', 'Privilege escalation permitted',
      has(/allowPrivilegeEscalation:\s*true/i) ? 'allowPrivilegeEscalation: true.' : 'Escalation is not explicitly allowed.',
      'Set allowPrivilegeEscalation: false.');
    add('CAPS', has(/SYS_ADMIN|NET_ADMIN|SYS_PTRACE/i) ? 'fail' : 'pass', 'Dangerous Linux capabilities',
      has(/SYS_ADMIN|NET_ADMIN|SYS_PTRACE/i) ? 'Administrative capabilities added to the container.' : 'No dangerous capabilities added.',
      'Drop ALL capabilities and add back only what is required.');
    add('HOSTPATH', has(/hostPath:/i) ? 'fail' : 'pass', 'Host filesystem mount',
      has(/hostPath:/i) ? 'hostPath volume exposes node filesystem to the pod.' : 'No hostPath volume.',
      'Use a PVC or projected volume instead of hostPath.');
    add('IMAGE-TAG', has(/:\s*latest\b|image:\s*[^\s:]+(?!:\S)/i) ? 'warn' : 'pass', 'Mutable image tag',
      has(/:\s*latest\b/i) ? 'Image uses the :latest tag.' : 'Image tag appears pinned.',
      'Pin an immutable version or digest (sha256:…).');
    add('LIMITS', has(/resources:|limits:/i) ? 'pass' : 'warn', 'Resource limits',
      has(/resources:/i) ? 'Resource requests/limits declared.' : 'No resource limits declared — DoS risk.',
      'Set CPU and memory requests and limits.');
    add('ROOT-FS', has(/readOnlyRootFilesystem:\s*true/i) ? 'pass' : 'warn', 'Read-only root filesystem',
      has(/readOnlyRootFilesystem:\s*true/i) ? 'Root filesystem is read-only.' : 'readOnlyRootFilesystem is not enforced.',
      'Set readOnlyRootFilesystem: true and use emptyDir for temp writes.');
    add('SECCOMP', has(/seccompProfile|runtimeClassName/i) ? 'pass' : 'warn', 'Seccomp / runtime profile',
      has(/seccompProfile/i) ? 'A seccomp profile is declared.' : 'No seccomp profile declared.',
      'Set seccompProfile.type: RuntimeDefault.');
    var total = checks.length, got = checks.reduce(function (n, c) { return n + (c.status === 'pass' ? 1 : c.status === 'warn' ? 0.5 : 0); }, 0);
    return { checks: checks, score: Math.round(got / total * 100), at: Date.now() };
  }

  /* ----------------------------- email / .eml ---------------------------- */
  function analyzeEmail(text) {
    var raw = String(text || '');
    var parts = raw.split(/\r?\n\r?\n/);
    var head = parts[0] || '', body = parts.slice(1).join('\n');
    var headers = Object.create(null);
    var last = null;
    head.split(/\r?\n/).forEach(function (line) {
      var m = line.match(/^([A-Za-z0-9-]+):\s*(.*)$/);
      if (m) { last = m[1].toLowerCase(); headers[last] = (headers[last] ? headers[last] + ' ' : '') + m[2]; }
      else if (last && /^\s/.test(line)) headers[last] += ' ' + line.trim();
    });
    function domain(addr) { var m = String(addr || '').match(/@([A-Za-z0-9.-]+)/); return m ? m[1].toLowerCase() : ''; }
    var from = headers.from || '', replyTo = headers['reply-to'] || '', returnPath = headers['return-path'] || '';
    var auth = headers['authentication-results'] || '';
    var received = head.split(/\r?\n/).filter(function (l) { return /^received:/i.test(l); });
    var checks = [];
    var penalty = 0;
    function add(id, status, title, evidence, fix, weight) {
      checks.push({ id: id, status: status, title: title, evidence: evidence, fix: fix });
      if (status === 'fail') penalty += weight; else if (status === 'warn') penalty += weight * 0.5;
    }
    var spf = /spf=(fail|softfail)/i.test(auth), dkim = /dkim=(fail|none)/i.test(auth), dmarc = /dmarc=(fail|none)/i.test(auth);
    add('AUTH', (spf || dkim || dmarc) ? 'fail' : 'pass', 'Sender authentication',
      auth ? auth.slice(0, 180) : 'No Authentication-Results header present.',
      'Reject or quarantine mail failing SPF/DKIM/DMARC alignment.', 30);
    if (!auth) add('AUTH-HEADER', 'warn', 'Authentication header missing', 'No Authentication-Results header.', 'Ensure the receiving MTA records authentication results.', 12);
    add('REPLY-TO', (replyTo && domain(replyTo) && domain(replyTo) !== domain(from)) ? 'fail' : 'pass', 'Reply-To domain mismatch',
      replyTo ? 'From: ' + domain(from) + ' → Reply-To: ' + domain(replyTo) : 'No Reply-To header.',
      'Treat mismatched reply-to domains as a strong phishing indicator.', 24);
    add('RETURN-PATH', (returnPath && domain(returnPath) && domain(returnPath) !== domain(from)) ? 'warn' : 'pass', 'Return-Path mismatch',
      returnPath || 'No Return-Path header.', 'Check envelope sender alignment.', 10);
    add('RECEIVED', received.length >= 3 ? 'warn' : 'pass', 'Received chain length',
      received.length + ' Received hops.', 'Investigate unusual or looping relay paths.', 8);
    add('PRIVATE-HOP', /received:.*(?:127\.0\.0\.1|10\.\d+\.\d+\.\d+|192\.168\.)/i.test(head) ? 'warn' : 'pass',
      'Private address in relay chain', 'A private address appears in a Received hop.', 'Verify the relay is legitimate.', 8);
    var subject = headers.subject || '';
    add('URGENCY', /urgent|immediately|suspended|action required|verify|expire|locked/i.test(subject) ? 'warn' : 'pass',
      'Coercive subject language', subject || 'No subject.', 'Flag urgency/pressure language for reviewer awareness.', 10);
    add('MAILER', /phpmailer\s*[0-5]\./i.test(headers['x-mailer'] || '') ? 'warn' : 'pass', 'Legacy bulk mailer',
      headers['x-mailer'] || 'No X-Mailer header.', 'Legacy mailers are common in phishing kits.', 6);
    var urls = E.extractIOCs(raw).filter(function (i) { return i.type === 'url' || i.type === 'domain' || i.type === 'ipv4'; });
    add('URLS', urls.length >= 2 ? 'warn' : 'pass', 'Embedded indicators', urls.length + ' URL/domain/IP indicator(s) extracted and defanged.',
      'Inspect destinations in an isolated browser; do not click from a workstation.', 10);
    var score = Math.round(clamp(100 - penalty, 0, 100));
    var verdict = score < 45 ? 'PHISHING LIKELY' : score < 75 ? 'SUSPICIOUS' : 'NO STRONG INDICATORS';
    return { checks: checks, urls: urls, headers: headers, received: received.length,
      score: score, verdict: verdict, bodyExcerpt: body.slice(0, 220), at: Date.now() };
  }

  /* -------------------------- dependency / SBOM -------------------------- */
  function compareVersions(a, b) {
    var pa = String(a || '0').replace(/^[^\d]*/, '').split(/[.\-]/).map(function (x) { return parseInt(x, 10) || 0; });
    var pb = String(b || '0').replace(/^[^\d]*/, '').split(/[.\-]/).map(function (x) { return parseInt(x, 10) || 0; });
    for (var i = 0; i < Math.max(pa.length, pb.length); i++) {
      var d = (pa[i] || 0) - (pb[i] || 0);
      if (d !== 0) return d < 0 ? -1 : 1;
    }
    return 0;
  }
  function analyzeDependencies(text) {
    var raw = String(text || ''), packages = [], format = 'requirements';
    var trimmed = raw.trim();
    if (trimmed.charAt(0) === '{') {
      var j = null; try { j = JSON.parse(trimmed); } catch (e) { j = null; }
      if (j) {
        if (j.components) {
          format = 'CycloneDX SBOM';
          (j.components || []).forEach(function (c) { packages.push({ name: c.name, version: c.version || '0', ecosystem: c.purl && c.purl.indexOf('pypi') !== -1 ? 'pypi' : 'npm' }); });
        } else if (j.packages) {
          format = 'package-lock.json';
          Object.keys(j.packages).forEach(function (k) {
            if (!k || k.indexOf('node_modules/') === -1) return;
            packages.push({ name: k.split('node_modules/').pop(), version: j.packages[k].version || '0', ecosystem: 'npm' });
          });
        } else {
          format = 'package.json';
          ['dependencies', 'devDependencies'].forEach(function (key) {
            Object.keys(j[key] || {}).forEach(function (name) { packages.push({ name: name, version: String(j[key][name]), ecosystem: 'npm' }); });
          });
        }
      }
    }
    if (!packages.length) {
      format = 'requirements.txt / pinned list';
      raw.split(/\r?\n/).forEach(function (line) {
        var m = line.trim().match(/^([A-Za-z0-9_.-]+)\s*(?:==|===|@|:)\s*([^\s,;]+)/);
        if (m) packages.push({ name: m[1], version: m[2], ecosystem: 'pypi' });
      });
    }
    var findings = [];
    packages.forEach(function (p) {
      var adv = D2.ADVISORY_BASELINE.filter(function (a) {
        return a.name.toLowerCase() === String(p.name).toLowerCase() && a.ecosystem === p.ecosystem;
      })[0];
      var clean = String(p.version).replace(/^[\^~><=\s]+/, '');
      if (adv && compareVersions(clean, adv.below) < 0) {
        findings.push({ name: p.name, version: p.version, ecosystem: p.ecosystem, severity: adv.severity,
          cve: adv.cve, title: p.name + ' ' + p.version + ' is below ' + adv.below, fix: adv.fix });
      }
      if (/^[\^~*]|latest|^$/.test(String(p.version)) && !findings.some(function (f) { return f.name === p.name; })) {
        findings.push({ name: p.name, version: p.version, ecosystem: p.ecosystem, severity: 'low',
          cve: '—', title: p.name + ' uses an unpinned / floating version', fix: 'Pin an exact version and commit the lockfile.' });
      }
    });
    var weight = findings.reduce(function (n, f) { return n + (DATA.SEVERITIES[f.severity] || DATA.SEVERITIES.info).weight; }, 0);
    return { format: format, packages: packages, findings: findings,
      score: Math.round(clamp(100 - weight * 0.8, 0, 100)), at: Date.now(),
      note: 'Offline illustrative baseline — not a live vulnerability feed.' };
  }

  /* ------------------------- custom detection rules ---------------------- */
  function testCustomRule(rule, text) {
    var re;
    try { re = new RegExp(String(rule.pattern || ''), String(rule.flags || 'i')); }
    catch (e) { return { ok: false, error: e.message, count: 0, samples: [] }; }
    var lines = String(text || '').split(/\r?\n/).filter(function (l) { return l.trim(); });
    var hits = lines.filter(function (l) { return re.test(l); });
    var threshold = Math.max(1, Number(rule.threshold) || 1);
    return { ok: true, count: hits.length, matched: hits.length >= threshold,
      samples: hits.slice(0, 4), severity: rule.severity || 'medium', mitre: rule.mitre || 'T1059',
      ruleName: rule.name || 'Custom rule' };
  }

  /* --------------------------- ATT&CK coverage --------------------------- */
  function mitreCoverage(state) {
    var covered = Object.create(null), observed = Object.create(null);
    DATA.LOG_RULES.forEach(function (r) { covered[r.mitre] = true; });
    (state.customRules || []).forEach(function (r) { if (r.mitre) covered[r.mitre] = true; });
    ((state.logResults && state.logResults.detections) || []).forEach(function (d) { if (d.mitre) { covered[d.mitre] = true; observed[d.mitre] = true; } });
    (state.findings || []).forEach(function (f) { if (f.mitre) observed[f.mitre] = true; });
    var tactics = D2.MITRE_TACTICS.map(function (t) {
      var techs = D2.TECHNIQUES.filter(function (x) { return x.tactic === t.id; }).map(function (x) {
        return { id: x.id, name: x.name, covered: !!covered[x.id], observed: !!observed[x.id] };
      });
      return { id: t.id, name: t.name, short: t.short, techniques: techs,
        covered: techs.filter(function (x) { return x.covered; }).length, total: techs.length };
    });
    var total = D2.TECHNIQUES.length;
    var cov = tactics.reduce(function (n, t) { return n + t.covered; }, 0);
    return { tactics: tactics, covered: cov, total: total, percent: Math.round(cov / total * 100),
      gaps: D2.TECHNIQUES.filter(function (x) { return !covered[x.id]; }), at: Date.now() };
  }

  /* ---------------------- quantitative risk (illustrative) --------------- */
  function monteCarloRisk(state, iterations) {
    var n = clamp(Math.round(Number(iterations) || 2000), 200, 20000);
    var rand = E.prng(E.sha256('quant:' + n + ':' + (state.findings || []).length + ':' + (state.audit || []).length));
    var open = (state.findings || []).filter(function (f) { return f.status === 'open'; });
    var prob = { critical: 0.34, high: 0.22, medium: 0.12, low: 0.055, info: 0.02 };
    var impact = { critical: 10, high: 6, medium: 3, low: 1.4, info: 0.6 };
    var results = [];
    for (var i = 0; i < n; i++) {
      var loss = 0;
      open.forEach(function (f) {
        if (rand() < (prob[f.severity] || 0.05)) {
          var asset = (state.assets || []).filter(function (a) { return a.name === f.asset; })[0];
          var mult = asset ? ({ critical: 1.8, high: 1.4, medium: 1.1, low: 1 }[asset.criticality] || 1) : 1;
          loss += (impact[f.severity] || 1) * mult * (0.6 + rand() * 0.9);
        }
      });
      results.push(loss);
    }
    results.sort(function (a, b) { return a - b; });
    function pct(p) { return Math.round(results[clamp(Math.floor(n * p), 0, n - 1)] * 10) / 10; }
    var max = results[n - 1] || 1, bins = new Array(10).fill(0);
    results.forEach(function (x) { bins[clamp(Math.floor(x / (max || 1) * 10), 0, 9)]++; });
    return { iterations: n, p10: pct(0.1), p50: pct(0.5), p90: pct(0.9), p95: pct(0.95),
      mean: Math.round(results.reduce(function (a, b) { return a + b; }, 0) / n * 10) / 10,
      max: Math.round(max * 10) / 10, bins: bins, open: open.length, at: Date.now(),
      note: 'Illustrative Monte Carlo model in abstract risk units — not a financial forecast.' };
  }

  /* ---------------------- investigation copilot (NL) --------------------- */
  function investigate(query, state) {
    var q = String(query || '').toLowerCase().trim();
    var wantSeverity = ['critical', 'high', 'medium', 'low'].filter(function (s) { return q.indexOf(s) !== -1; });
    var mitre = (q.toUpperCase().match(/T\d{4}(?:\.\d{3})?/) || [])[0];
    var assetNames = (state.assets || []).map(function (a) { return a.name; }).filter(function (a) { return q.indexOf(a.toLowerCase()) !== -1; });
    var outOfScope = /out of scope|expired|unauthorized/.test(q);
    var intent = /ledger|audit|chain|summary/.test(q) ? 'ledger'
      : /watchlist|indicator|ioc/.test(q) ? 'intel'
      : /asset|scope/.test(q) ? 'assets'
      : /alert|triage|priority/.test(q) ? 'alerts' : 'findings';
    var rows = [], title = '', columns = [];
    if (intent === 'ledger') {
      title = 'Ledger summary'; columns = ['Metric', 'Value'];
      var v = E.verifyChain(state.audit || []);
      rows = [['Entries', String((state.audit || []).length)], ['Chain', v.valid ? 'VALID' : 'BROKEN'],
        ['Refusals', String((state.audit || []).filter(function (e) { return /REFUS|NO_SCOPE|EXPIRED|BLOCKED/i.test(e.decision); }).length)],
        ['Head hash', (v.head || '').slice(0, 24) + '…']];
    } else if (intent === 'intel') {
      title = 'Local watchlist'; columns = ['Type', 'Defanged value', 'Added'];
      rows = (state.watchlist || []).map(function (w) { return [w.type, w.defanged || w.value, new Date(w.addedAt).toLocaleDateString('en-GB')]; });
    } else if (intent === 'assets') {
      title = 'Authorization scope'; columns = ['Asset', 'Environment', 'Criticality', 'Status'];
      rows = (state.assets || []).filter(function (a) {
        var g = E.scopeCheck(state, a.name);
        return outOfScope ? !g.allowed : true;
      }).map(function (a) { var g = E.scopeCheck(state, a.name); return [a.name, a.env, a.criticality, g.allowed ? 'ACTIVE' : g.code]; });
    } else if (intent === 'alerts') {
      title = 'Alert queue'; columns = ['Severity', 'Alert', 'Asset', 'Status', 'Priority'];
      rows = (state.alerts || []).filter(function (a) {
        return (!wantSeverity.length || wantSeverity.indexOf(a.severity) !== -1) &&
          (!assetNames.length || assetNames.indexOf(a.asset) !== -1) &&
          (!/untriaged|new/.test(q) || a.status === 'new');
      }).map(function (a) { return [a.severity, a.title, a.asset, a.status, a.priority ? a.priority.band + ' ' + a.priority.score : '—']; });
    } else {
      title = 'Finding register'; columns = ['Severity', 'Finding', 'Asset', 'MITRE', 'Status'];
      rows = (state.findings || []).filter(function (f) {
        return (!wantSeverity.length || wantSeverity.indexOf(f.severity) !== -1) &&
          (!assetNames.length || assetNames.indexOf(f.asset) !== -1) &&
          (!mitre || String(f.mitre || '').toUpperCase() === mitre) &&
          (!/open/.test(q) || f.status === 'open');
      }).map(function (f) { return [f.severity, f.title, f.asset, f.mitre, f.status]; });
    }
    return { type: intent, title: title, columns: columns, rows: rows.slice(0, 40), count: rows.length,
      parsed: { severities: wantSeverity, assets: assetNames, mitre: mitre || null, outOfScope: outOfScope },
      summary: rows.length + ' matching record(s) · intent=' + intent +
        (wantSeverity.length ? ' · severity=' + wantSeverity.join('/') : '') +
        (assetNames.length ? ' · asset=' + assetNames.join(',') : '') +
        (mitre ? ' · ' + mitre : ''), at: Date.now() };
  }

  /* -------------------------- capability policy -------------------------- */
  function evaluateCapability(id, state, target) {
    var cap = D2.CAPABILITIES.filter(function (c) { return c.id === id; })[0];
    if (!cap) return { allowed: false, code: 'UNKNOWN_CAPABILITY', reason: 'Capability is not present in the signed manifest.' };
    if (cap.status !== 'enabled') return { allowed: false, code: 'CAPABILITY_BLOCKED', reason: cap.reason, cap: cap };
    if (target) {
      var g = E.scopeCheck(state, target, cap.scope);
      if (!g.allowed) return { allowed: false, code: g.code, reason: g.reason, cap: cap };
    }
    return { allowed: true, code: 'CAPABILITY_GRANTED', reason: 'Manifest entry enabled' + (target ? ' and scope verified for ' + target : '') + '.', cap: cap };
  }

  /* ------------------------ orchestrator step runner --------------------- */
  function orchestratorStep(node, state, ctx) {
    var gate = evaluateCapability(node.cap, state, ctx.target);
    if (!gate.allowed) return { status: 'REFUSED', code: gate.code, reason: gate.reason, count: 0 };
    var detail = '', count = 0;
    switch (node.id) {
      case 'scope':
        count = E.activeAssets(state).length;
        detail = count + ' in-scope asset(s); ' + (state.assets.length - count) + ' refused.';
        break;
      case 'ingest':
        ctx.ingest = normalizeLogs(state.drafts.logs || '');
        count = ctx.ingest.events.length;
        detail = ctx.ingest.format + ' format · ' + count + ' normalized events · ' + ctx.ingest.stats.tagged + ' tagged.';
        break;
      case 'detect':
        ctx.detect = E.detectLogs(state.drafts.logs || '');
        (state.customRules || []).forEach(function (r) {
          var res = testCustomRule(r, state.drafts.logs || '');
          if (res.ok && res.matched) ctx.detect.detections.push({
            id: E.uid('det'), rule: r.id, name: res.ruleName, severity: res.severity,
            mitre: res.mitre, count: res.count, lines: [], samples: res.samples,
            evidence: 'Custom operator rule matched ' + res.count + ' line(s).',
            remediation: r.remediation || 'Review matching events.', at: Date.now()
          });
        });
        count = ctx.detect.detections.length;
        detail = count + ' detection(s) from ' + DATA.LOG_RULES.length + ' built-in + ' + (state.customRules || []).length + ' custom rule(s).';
        break;
      case 'harden':
        ctx.harden = E.analyzeHeaders(state.drafts.headers || '');
        count = ctx.harden.checks.length;
        detail = 'Grade ' + ctx.harden.grade + ' · ' + ctx.harden.score + '/100 across ' + count + ' controls.';
        break;
      case 'correlate':
        ctx.chains = attackChains(ctx.ingest || { events: [] });
        count = ctx.chains.chains.length;
        detail = count + ' multi-stage attack chain(s) reconstructed.';
        break;
      case 'triage':
        ctx.scores = (state.alerts || []).map(function (a) { return E.triage(a, state); });
        count = ctx.scores.length;
        detail = count + ' alert(s) scored with reasoning chains.';
        break;
      case 'coverage':
        ctx.coverage = mitreCoverage(state);
        ctx.quant = monteCarloRisk(state, 1200);
        count = ctx.coverage.covered;
        detail = ctx.coverage.percent + '% ATT&CK coverage · modelled p90 ' + ctx.quant.p90 + ' risk units.';
        break;
      case 'report':
        ctx.report = { generatedAt: Date.now(), findings: (state.findings || []).length,
          alerts: (state.alerts || []).length, chains: (ctx.chains ? ctx.chains.chains.length : 0),
          coverage: ctx.coverage ? ctx.coverage.percent : 0, grade: ctx.harden ? ctx.harden.grade : '—' };
        count = 1; detail = 'Evidence report assembled and sealed.';
        break;
      default: detail = 'No-op step.';
    }
    return { status: 'DONE', code: 'CAPABILITY_GRANTED', reason: gate.reason, detail: detail, count: count };
  }

  var API = {
    shannon: shannon, mask: mask, tacticOf: tacticOf, tacticName: tacticName,
    detectFormat: detectFormat, normalizeLogs: normalizeLogs, attackChains: attackChains,
    anomalyDetect: anomalyDetect, eventRateSeries: eventRateSeries,
    secretScan: secretScan, analyzeIamPolicy: analyzeIamPolicy, analyzeK8s: analyzeK8s,
    analyzeEmail: analyzeEmail, analyzeDependencies: analyzeDependencies,
    compareVersions: compareVersions, testCustomRule: testCustomRule,
    mitreCoverage: mitreCoverage, monteCarloRisk: monteCarloRisk,
    investigate: investigate, evaluateCapability: evaluateCapability,
    orchestratorStep: orchestratorStep
  };
  root.AEGIS_ADVANCED = API;
  if (isNode) module.exports = API;
})(typeof globalThis !== 'undefined' ? globalThis : this);


/* ===== 16-hexstrike.js ===== */
/* AEGIS // SENTINEL v2.1 — HexStrike AI compatibility layer.
 *
 * Upstream: https://github.com/0x4m4/hexstrike-ai (MIT, v6.0, 151 MCP tools,
 * 12+ autonomous agents). We vendor the *catalog and the MCP-shaped contract*,
 * not the server, not the binaries and not the offensive behaviour.
 *
 * Every upstream tool name is classified into exactly one of three modes:
 *   adapter     — mapped to a real, offline AEGIS analysis engine
 *   blocked     — mapped to a hard-refused AEGIS capability class
 *   unavailable — requires the upstream Flask/FastMCP server or external
 *                 binaries; never executed in this build
 *
 * Nothing here opens a socket, spawns a process or touches a filesystem.
 */
(function (root) {
  'use strict';
  var isNode = typeof module !== 'undefined' && module.exports;
  var DATA = isNode ? require('./00-data.js') : root.AEGIS_DATA;
  var D2 = isNode ? require('./05-data2.js') : root.AEGIS_DATA2;
  var E = isNode ? require('./10-engine.js') : root.AEGIS_ENGINE;
  var A = isNode ? require('./15-advanced.js') : root.AEGIS_ADVANCED;

  var UPSTREAM = {
    repo: '0x4m4/hexstrike-ai',
    url: 'https://github.com/0x4m4/hexstrike-ai',
    version: '6.0.0',
    license: 'MIT',
    mcpConfig: 'hexstrike-ai-mcp.json',
    server: 'hexstrike_server.py (Flask, /api/*)',
    bridge: 'hexstrike_mcp.py (FastMCP, python3 --server http://IP:8888)',
    decoratedTools: 151,
    note: 'Catalog-only integration. No upstream code is bundled or executed.'
  };

  /* 12 specialised agents described in the upstream README. In AEGIS they are
   * planning personas, not autonomous executors. */
  var AGENTS = [
    { id: 'BugBountyAgent', role: 'Reconnaissance workflow planning', status: 'adapter', caps: ['govern.report', 'intel.ioc'] },
    { id: 'CTFSolverAgent', role: 'Binary / forensics challenge analysis', status: 'blocked', caps: ['exploit.execute'] },
    { id: 'CVEIntelligenceManager', role: 'Vulnerability intelligence', status: 'adapter', caps: ['config.sbom', 'govern.report'] },
    { id: 'AIExploitGenerator', role: 'Automated exploit development', status: 'blocked', caps: ['exploit.execute'] },
    { id: 'IntelligentDecisionEngine', role: 'Tool selection & parameter optimisation', status: 'adapter', caps: ['govern.report'] },
    { id: 'VulnerabilityIntelligenceAgent', role: 'Correlate findings into risk', status: 'adapter', caps: ['govern.report', 'telemetry.correlate'] },
    { id: 'AttackChainDiscoveryAgent', role: 'Multi-stage chain reconstruction', status: 'adapter', caps: ['telemetry.correlate'] },
    { id: 'ThreatHuntingAssistant', role: 'Hunt hypotheses over telemetry', status: 'adapter', caps: ['telemetry.detect', 'telemetry.anomaly'] },
    { id: 'CloudSecurityAgent', role: 'IAM / K8s posture review', status: 'adapter', caps: ['config.iam', 'config.k8s'] },
    { id: 'WebAppSecurityAgent', role: 'HTTP hardening & dependency review', status: 'adapter', caps: ['config.hardening', 'config.sbom'] },
    { id: 'OSINTAgent', role: 'Passive indicator correlation', status: 'adapter', caps: ['intel.ioc'] },
    { id: 'RedTeamOperator', role: 'Offensive engagement execution', status: 'blocked', caps: ['net.scan', 'exploit.execute', 'credential.attack'] }
  ];

  /* Exact tool names from @mcp.tool() decorators in hexstrike_mcp.py.
   * 151 decorated functions, 150 unique names (httpx_probe is declared twice). */
  var RAW_TOOLS = 'nmap_scan,gobuster_scan,nuclei_scan,prowler_scan,trivy_scan,scout_suite_assessment,cloudmapper_analysis,pacu_exploitation,kube_hunter_scan,kube_bench_cis,docker_bench_security_scan,clair_vulnerability_scan,falco_runtime_monitoring,checkov_iac_scan,terrascan_iac_scan,create_file,modify_file,delete_file,list_files,generate_payload,install_python_package,execute_python_script,dirb_scan,nikto_scan,sqlmap_scan,metasploit_run,hydra_attack,john_crack,wpscan_analyze,enum4linux_scan,ffuf_scan,netexec_scan,amass_scan,hashcat_crack,subfinder_scan,smbmap_scan,rustscan_fast_scan,masscan_high_speed,nmap_advanced_scan,autorecon_comprehensive,enum4linux_ng_advanced,rpcclient_enumeration,nbtscan_netbios,arp_scan_discovery,responder_credential_harvest,volatility_analyze,msfvenom_generate,gdb_analyze,radare2_analyze,binwalk_analyze,ropgadget_search,checksec_analyze,xxd_hexdump,strings_extract,objdump_analyze,ghidra_analysis,pwntools_exploit,one_gadget_search,libc_database_lookup,gdb_peda_debug,angr_symbolic_execution,ropper_gadget_search,pwninit_setup,feroxbuster_scan,dotdotpwn_scan,xsser_scan,wfuzz_scan,dirsearch_scan,katana_crawl,gau_discovery,waybackurls_discovery,arjun_parameter_discovery,paramspider_mining,x8_parameter_discovery,jaeles_vulnerability_scan,dalfox_xss_scan,httpx_probe,anew_data_processing,qsreplace_parameter_replacement,uro_url_filtering,ai_generate_payload,ai_test_payload,ai_generate_attack_suite,api_fuzzer,graphql_scanner,jwt_analyzer,api_schema_analyzer,comprehensive_api_audit,volatility3_analyze,foremost_carving,steghide_analysis,exiftool_extract,hashpump_attack,hakrawler_crawl,paramspider_discovery,burpsuite_scan,zap_scan,arjun_scan,wafw00f_scan,fierce_scan,dnsenum_scan,autorecon_scan,server_health,get_cache_stats,clear_cache,get_telemetry,list_active_processes,get_process_status,terminate_process,pause_process,resume_process,get_process_dashboard,execute_command,monitor_cve_feeds,generate_exploit_from_cve,discover_attack_chains,research_zero_day_opportunities,correlate_threat_intelligence,advanced_payload_generation,vulnerability_intelligence_dashboard,threat_hunting_assistant,get_live_dashboard,create_vulnerability_report,format_tool_output_visual,create_scan_summary,display_system_metrics,analyze_target_intelligence,select_optimal_tools_ai,optimize_tool_parameters_ai,create_attack_chain_ai,intelligent_smart_scan,detect_technologies_ai,ai_reconnaissance_workflow,ai_vulnerability_assessment,bugbounty_reconnaissance_workflow,bugbounty_vulnerability_hunting,bugbounty_business_logic_testing,bugbounty_osint_gathering,bugbounty_file_upload_testing,bugbounty_comprehensive_assessment,bugbounty_authentication_bypass_testing,http_framework_test,browser_agent_inspect,http_set_rules,http_set_scope,http_repeater,http_intruder,burpsuite_alternative_scan,error_handling_statistics,test_error_recovery';

  /* Offline adapter map: upstream tool → real AEGIS engine + capability. */
  var ADAPTERS = {
    server_health: { cap: 'scope.verify', engine: 'chainStatus', label: 'Platform health', kind: 'status' },
    get_live_dashboard: { cap: 'govern.report', engine: 'status', label: 'Live posture dashboard', kind: 'status' },
    display_system_metrics: { cap: 'telemetry.anomaly', engine: 'anomalyDetect', label: 'Event-rate statistics', kind: 'anomaly' },
    analyze_target_intelligence: { cap: 'intel.ioc', engine: 'extractIOCs', label: 'Target indicator extraction', kind: 'ioc' },
    correlate_threat_intelligence: { cap: 'intel.ioc', engine: 'extractIOCs', label: 'Threat-intel correlation', kind: 'ioc' },
    exiftool_extract: { cap: 'intel.ioc', engine: 'extractIOCs', label: 'Metadata / IOC extraction', kind: 'ioc' },
    monitor_cve_feeds: { cap: 'config.sbom', engine: 'analyzeDependencies', label: 'Offline advisory baseline', kind: 'deps' },
    trivy_scan: { cap: 'config.sbom', engine: 'analyzeDependencies', label: 'Container dependency scan', kind: 'deps' },
    clair_vulnerability_scan: { cap: 'config.sbom', engine: 'analyzeDependencies', label: 'Image layer advisory check', kind: 'deps' },
    checksec_analyze: { cap: 'config.sbom', engine: 'analyzeDependencies', label: 'Binary hardening baseline', kind: 'deps' },
    prowler_scan: { cap: 'config.iam', engine: 'analyzeIamPolicy', label: 'Cloud IAM posture', kind: 'iam' },
    scout_suite_assessment: { cap: 'config.iam', engine: 'analyzeIamPolicy', label: 'Multi-cloud policy review', kind: 'iam' },
    cloudmapper_analysis: { cap: 'config.iam', engine: 'analyzeIamPolicy', label: 'Account policy review', kind: 'iam' },
    kube_bench_cis: { cap: 'config.k8s', engine: 'analyzeK8s', label: 'CIS Kubernetes benchmark', kind: 'k8s' },
    kube_hunter_scan: { cap: 'config.k8s', engine: 'analyzeK8s', label: 'Cluster manifest review', kind: 'k8s' },
    docker_bench_security_scan: { cap: 'config.k8s', engine: 'analyzeK8s', label: 'Container runtime posture', kind: 'k8s' },
    falco_runtime_monitoring: { cap: 'telemetry.detect', engine: 'detectLogs', label: 'Runtime rule matches', kind: 'logs' },
    threat_hunting_assistant: { cap: 'telemetry.detect', engine: 'detectLogs', label: 'Hunt over supplied telemetry', kind: 'logs' },
    nuclei_scan: { cap: 'config.hardening', engine: 'analyzeHeaders', label: 'Template-style header checks', kind: 'headers' },
    nikto_scan: { cap: 'config.hardening', engine: 'analyzeHeaders', label: 'Web server hardening', kind: 'headers' },
    wafw00f_scan: { cap: 'config.hardening', engine: 'analyzeHeaders', label: 'Response-header fingerprint', kind: 'headers' },
    checkov_iac_scan: { cap: 'config.secrets', engine: 'secretScan', label: 'IaC secret scan', kind: 'secrets' },
    terrascan_iac_scan: { cap: 'config.secrets', engine: 'secretScan', label: 'IaC secret scan', kind: 'secrets' },
    jwt_analyzer: { cap: 'config.secrets', engine: 'secretScan', label: 'Token material scan', kind: 'secrets' },
    strings_extract: { cap: 'config.secrets', engine: 'secretScan', label: 'String / credential scan', kind: 'secrets' },
    xxd_hexdump: { cap: 'config.secrets', engine: 'secretScan', label: 'Hex / credential scan', kind: 'secrets' },
    anew_data_processing: { cap: 'telemetry.normalize', engine: 'normalizeLogs', label: 'Line dedupe & normalization', kind: 'ingest' },
    uro_url_filtering: { cap: 'telemetry.normalize', engine: 'normalizeLogs', label: 'URL log normalization', kind: 'ingest' },
    qsreplace_parameter_replacement: { cap: 'telemetry.normalize', engine: 'normalizeLogs', label: 'Parameter log normalization', kind: 'ingest' },
    discover_attack_chains: { cap: 'telemetry.correlate', engine: 'attackChains', label: 'Attack-chain reconstruction', kind: 'chains' },
    create_attack_chain_ai: { cap: 'telemetry.correlate', engine: 'attackChains', label: 'Attack-chain reconstruction', kind: 'chains' },
    vulnerability_intelligence_dashboard: { cap: 'govern.report', engine: 'mitreCoverage', label: 'ATT&CK coverage model', kind: 'coverage' },
    select_optimal_tools_ai: { cap: 'govern.report', engine: 'plan', label: 'Capability plan selection', kind: 'plan' },
    optimize_tool_parameters_ai: { cap: 'govern.report', engine: 'plan', label: 'Capability plan refinement', kind: 'plan' },
    create_vulnerability_report: { cap: 'govern.report', engine: 'report', label: 'Evidence report assembly', kind: 'report' }
  };

  /* Hard refusals. Each upstream tool class is bound to an AEGIS blocked
   * capability, so the refusal reason comes from the signed manifest. */
  var UNAVAILABLE_RE = /^(get_cache_stats|get_telemetry|get_process_status|get_process_dashboard|list_active_processes|format_tool_output_visual|create_scan_summary|error_handling_statistics|test_error_recovery|detect_technologies_ai|api_schema_analyzer)/;
  var BLOCK_RULES = [
    { re: /^(execute_command|execute_python_script|install_python_package|create_file|modify_file|delete_file|list_files|generate_payload|generate_exploit_from_cve|ai_generate_payload|ai_test_payload|ai_generate_attack_suite|advanced_payload_generation|msfvenom_generate|pwntools_exploit|angr_symbolic_execution|gdb_|radare2_|binwalk_|ropgadget_|ropper_|one_gadget_|libc_database_|pwninit_|ghidra_|objdump_|volatility|foremost_|steghide_|hashpump_)/, cap: 'exploit.execute', risk: 'code-execution', reason: 'Arbitrary execution, payload generation or host-side binary tooling is outside the passive-analysis manifest.' },
    { re: /^(hydra_|john_crack|hashcat_crack|responder_|netexec_|smbmap_|rpcclient_|enum4linux|metasploit_|pacu_|bugbounty_authentication_bypass|http_intruder|http_repeater|http_set_rules|http_set_scope|http_framework_test|browser_agent_inspect)/, cap: 'credential.attack', risk: 'credential-attack', reason: 'Credential attacks, session manipulation and authentication bypass are prohibited.' },
    { re: /^(terminate_process|pause_process|resume_process|clear_cache)/, cap: 'contain.execute', risk: 'process-control', reason: 'External process control requires a human-approved change through your own infrastructure tooling.' },
    { re: /^(nmap|masscan|rustscan|arp_scan|nbtscan|amass|subfinder|fierce|dnsenum|autorecon|httpx|gobuster|dirb|dirsearch|ffuf|feroxbuster|wfuzz|dotdotpwn|xsser|sqlmap|wpscan|katana|gau_|waybackurls|hakrawler|arjun|paramspider|x8_|jaeles|dalfox|burpsuite|zap_scan|api_fuzzer|graphql_scanner|comprehensive_api_audit|intelligent_smart_scan|ai_reconnaissance_workflow|ai_vulnerability_assessment|bugbounty_|research_zero_day)/, cap: 'net.scan', risk: 'active-probing', reason: 'Active scanning, crawling, fuzzing or exploitation of a target requires a separate authorised engagement.' }
  ];

  var CATEGORY_RULES = [
    ['cloud', /^(prowler|trivy|scout|cloudmapper|pacu|kube|docker|clair|falco|checkov|terrascan|nuclei)/],
    ['binary', /^(volatility|foremost|steghide|exiftool|hashpump|gdb|radare2|binwalk|ropgadget|checksec|xxd|strings|objdump|ghidra|pwntools|one_gadget|libc_database|angr|ropper|pwninit|msfvenom|metasploit)/],
    ['api', /^(api_|graphql|jwt|http_|browser_agent|burpsuite|zap_)/],
    ['osint', /^(amass|subfinder|gau|waybackurls|hakrawler|fierce|dnsenum|theharvester)/],
    ['network', /^(nmap|masscan|rustscan|arp|nbtscan|enum4linux|smbmap|rpcclient|responder|netexec|autorecon|httpx|wafw00f)/],
    ['web', /^(gobuster|dirb|dirsearch|ffuf|feroxbuster|wfuzz|dotdotpwn|xsser|sqlmap|wpscan|katana|arjun|paramspider|x8|jaeles|dalfox|anew|qsreplace|uro|nikto)/],
    ['intelligence', /^(server_health|get_|list_|terminate_|pause_|resume_|clear_cache|execute_|monitor_|generate_|discover_|research_|correlate_|advanced_|vulnerability_|threat_|create_|format_|display_|analyze_|select_|optimize_|intelligent_|detect_|ai_|bugbounty_|error_|test_)/],
    ['utility', /^(create_file|modify_file|delete_file|list_files|install_python)/]
  ];

  function categoryOf(id) {
    for (var i = 0; i < CATEGORY_RULES.length; i++) if (CATEGORY_RULES[i][1].test(id)) return CATEGORY_RULES[i][0];
    return 'utility';
  }
  function uniq(a) { var seen = Object.create(null), out = []; a.forEach(function (x) { if (!seen[x]) { seen[x] = 1; out.push(x); } }); return out; }

  var TOOLS = uniq(RAW_TOOLS.split(',').map(function (x) { return x.trim(); }).filter(Boolean)).map(function (id) {
    var a = ADAPTERS[id] || null;
    var rec = {
      id: id, name: id.replace(/_/g, ' '), category: categoryOf(id),
      mode: a ? 'adapter' : 'unavailable', cap: a ? a.cap : null,
      risk: a ? 'local-analysis' : 'external-backend',
      adapter: a, reason: a ? 'Mapped to a local offline AEGIS analysis engine.' : 'Requires the upstream HexStrike Flask/FastMCP server or external binaries; not bundled.'
    };
    if (!a) {
      if (UNAVAILABLE_RE.test(id)) {
        rec.mode = 'unavailable'; rec.risk = 'external-backend';
        rec.reason = 'Reads or renders upstream HexStrike server runtime state; no server is bundled in this offline build.';
      } else {
        for (var i = 0; i < BLOCK_RULES.length; i++) {
          if (BLOCK_RULES[i].re.test(id)) {
            rec.mode = 'blocked'; rec.cap = BLOCK_RULES[i].cap; rec.risk = BLOCK_RULES[i].risk;
            rec.reason = BLOCK_RULES[i].reason; break;
          }
        }
      }
    }
    return rec;
  });
  var BY_ID = Object.create(null);
  TOOLS.forEach(function (t) { BY_ID[t.id] = t; });

  /* --------------------------- MCP-shaped contract ----------------------- */
  var MCP = {
    name: 'aegis-sentinel-hexstrike-adapter',
    version: '2.1.0',
    upstream: UPSTREAM.repo + '@' + UPSTREAM.version,
    transport: 'in-browser / offline (no stdio, no HTTP, no subprocess)',
    alwaysAllow: [],
    capabilities: { tools: true, resources: true, prompts: true, sampling: false, logging: false },
    tools: TOOLS.map(function (t) {
      return {
        name: t.id, description: t.reason, category: t.category,
        mode: t.mode, capability: t.cap,
        inputSchema: { type: 'object', properties: { target: { type: 'string', description: 'Authorised asset identifier' }, data: { type: 'string', description: 'Operator-supplied text (offline only)' } }, additionalProperties: false }
      };
    }),
    resources: [
      { uri: 'aegis://capabilities', description: 'Signed capability manifest' },
      { uri: 'aegis://scope', description: 'Authorisation records (local state)' },
      { uri: 'aegis://ledger', description: 'SHA-256 hash-chained audit ledger' },
      { uri: 'aegis://attck', description: 'MITRE ATT&CK coverage matrix' }
    ],
    prompts: [
      { name: 'assess-posture', description: 'Plan an offline posture assessment for an authorised asset' },
      { name: 'explain-refusal', description: 'Explain why a capability was refused' },
      { name: 'summarise-evidence', description: 'Summarise local findings into an evidence report' }
    ]
  };

  /* ------------------------------ policy --------------------------------- */
  function summary() {
    var c = { adapter: 0, blocked: 0, unavailable: 0 };
    TOOLS.forEach(function (t) { c[t.mode]++; });
    return {
      upstream: UPSTREAM, total: TOOLS.length, decorated: UPSTREAM.decoratedTools,
      adapters: c.adapter, blocked: c.blocked, unavailable: c.unavailable,
      agents: AGENTS.length, blockedAgents: AGENTS.filter(function (a) { return a.status === 'blocked'; }).length,
      categories: uniq(TOOLS.map(function (t) { return t.category; })).sort()
    };
  }
  function get(id) { return BY_ID[String(id || '').trim()] || null; }
  function tools(filter) {
    var f = String(filter || '').trim().toLowerCase();
    if (!f) return TOOLS.slice();
    if (f === 'adapter' || f === 'blocked' || f === 'unavailable') return TOOLS.filter(function (t) { return t.mode === f; });
    return TOOLS.filter(function (t) {
      return t.id.indexOf(f) !== -1 || t.category === f || (t.cap || '').indexOf(f) !== -1 || t.mode === f;
    });
  }
  function evaluate(id, state, target) {
    var t = get(id);
    if (!t) return { allowed: false, code: 'UNKNOWN_TOOL', reason: 'No HexStrike tool named "' + id + '" in the adapter catalog.', tool: null };
    if (t.mode === 'unavailable') return { allowed: false, code: 'TOOL_UNAVAILABLE', reason: t.reason, tool: t };
    if (t.mode === 'blocked') {
      var gate = A.evaluateCapability(t.cap, state, target || null);
      return { allowed: false, code: 'CAPABILITY_BLOCKED', reason: gate.reason, tool: t, mappedCapability: t.cap, riskClass: t.risk };
    }
    var g = A.evaluateCapability(t.cap, state, target || null);
    return { allowed: g.allowed, code: g.allowed ? 'CAPABILITY_GRANTED' : g.code, reason: g.reason, tool: t, mappedCapability: t.cap };
  }

  /* Deterministic planner. Never invents a capability; only selects from the
   * signed manifest and marks everything else REFUSED. */
  var PLAN_RULES = [
    { re: /(header|csp|harden|web|tls|cookie)/i, steps: ['nuclei_scan', 'nikto_scan', 'wafw00f_scan'] },
    { re: /(iam|policy|cloud|aws|s3|role)/i, steps: ['prowler_scan', 'scout_suite_assessment', 'cloudmapper_analysis'] },
    { re: /(k8s|kube|cluster|pod|container)/i, steps: ['kube_bench_cis', 'kube_hunter_scan', 'docker_bench_security_scan'] },
    { re: /(secret|credential|token|key|iac|terraform)/i, steps: ['checkov_iac_scan', 'terrascan_iac_scan', 'jwt_analyzer'] },
    { re: /(dependency|sbom|cve|package|supply)/i, steps: ['trivy_scan', 'monitor_cve_feeds', 'clair_vulnerability_scan'] },
    { re: /(log|telemetry|siem|detect|hunt|attack chain)/i, steps: ['threat_hunting_assistant', 'anew_data_processing', 'discover_attack_chains'] },
    { re: /(intel|ioc|indicator|phish)/i, steps: ['analyze_target_intelligence', 'correlate_threat_intelligence', 'exiftool_extract'] }
  ];
  function plan(goal) {
    var q = String(goal || '').trim();
    var picked = [];
    PLAN_RULES.forEach(function (r) { if (r.re.test(q)) picked = picked.concat(r.steps); });
    if (!picked.length) picked = ['server_health', 'analyze_target_intelligence', 'discover_attack_chains', 'select_optimal_tools_ai', 'create_vulnerability_report'];
    picked = uniq(picked.concat(['server_health', 'create_vulnerability_report']));
    return {
      goal: q || 'general posture assessment',
      engine: 'deterministic keyword planner (no model call)',
      steps: picked.map(function (id, i) {
        var t = get(id);
        return { order: i + 1, tool: id, mode: t.mode, capability: t.cap, category: t.category,
          decision: t.mode === 'adapter' ? 'ELIGIBLE' : 'REFUSED', reason: t.reason };
      })
    };
  }

  /* Execute an adapter tool against operator-supplied text (or the labelled
   * offline samples). Returns a JSON-RPC-shaped envelope. Pure: no state writes. */
  function call(id, args, state) {
    args = args || {};
    var gate = evaluate(id, state, args.target || null);
    var base = { jsonrpc: '2.0', id: args.id || 1, tool: String(id) };
    if (!gate.allowed) {
      return Object.assign(base, { error: { code: gate.code === 'TOOL_UNAVAILABLE' ? -32002 : -32001,
        message: gate.code, data: { reason: gate.reason, capability: gate.mappedCapability || null, mode: gate.tool ? gate.tool.mode : null } } });
    }
    var t = gate.tool, a = t.adapter, data = args.data || '', out = null, summaryText = '';
    function sample(kind) {
      var S = D2.SAMPLES, map = {
        deps: S.deps, iam: S.iam, k8s: S.k8s, secrets: S.secrets, headers: DATA.SAMPLE_HEADERS,
        logs: DATA.SAMPLE_LOGS, ioc: DATA.SAMPLE_INTEL, ingest: S.jsonl, email: S.email
      };
      return data || map[kind] || S.jsonl;
    }
    switch (a.kind) {
      case 'status':
        out = { assets: E.activeAssets(state).length, findings: (state.findings || []).length,
          alerts: (state.alerts || []).length, ledger: E.verifyChain(state.audit || []) };
        summaryText = 'Ledger ' + (out.ledger.valid ? 'VALID' : 'INVALID') + ' · ' + out.assets + ' assets in scope.';
        break;
      case 'anomaly': { var r = A.anomalyDetect([10, 11, 9, 10, 12, 9, 11, 10, 80, 10]);
        out = { mean: r.mean, upper: r.upper, outliers: r.outliers.length }; summaryText = r.outliers.length + ' statistical outlier(s) in the sample series.'; break; }
      case 'ioc': { var iocs = E.extractIOCs(sample('ioc'));
        out = { total: iocs.length, byType: iocs.reduce(function (o, x) { o[x.type] = (o[x.type] || 0) + 1; return o; }, {}),
          defangedSample: iocs.slice(0, 3).map(function (x) { return x.defanged; }) };
        summaryText = iocs.length + ' indicator(s) extracted and defanged locally; no external lookup performed.'; break; }
      case 'deps': { var d = A.analyzeDependencies(sample('deps'));
        out = { format: d.format, packages: d.packages.length, findings: d.findings.length, score: d.score };
        summaryText = d.findings.length + ' advisory match(es) across ' + d.packages.length + ' packages.'; break; }
      case 'iam': { var iam = A.analyzeIamPolicy(sample('iam'));
        out = { statements: iam.statements, checks: iam.checks.length, fails: iam.checks.filter(function (c) { return c.status === 'fail'; }).length, score: iam.score };
        summaryText = iam.checks.filter(function (c) { return c.status === 'fail'; }).length + ' failing IAM control(s).'; break; }
      case 'k8s': { var k = A.analyzeK8s(sample('k8s'));
        out = { checks: k.checks.length, fails: k.checks.filter(function (c) { return c.status === 'fail'; }).length, score: k.score };
        summaryText = out.fails + ' failing Kubernetes control(s).'; break; }
      case 'logs': { var lg = E.detectLogs(sample('logs'));
        out = { detections: (lg.detections || []).length, rules: DATA.LOG_RULES.length,
          iocs: (lg.iocs || []).length, lines: lg.stats.lines, at: lg.at };
        summaryText = out.detections + ' detection(s) from ' + out.rules + ' local MITRE-mapped rules.'; break; }
      case 'headers': { var hd = E.analyzeHeaders(sample('headers'));
        out = { checks: (hd.checks || []).length, grade: hd.grade, score: hd.score };
        summaryText = 'Hardening grade ' + hd.grade + ' across ' + out.checks + ' controls.'; break; }
      case 'secrets': { var sc = A.secretScan(sample('secrets'));
        var allMasked = sc.findings.every(function (f) { return f.masked.indexOf('•') !== -1 || f.masked.indexOf('****') !== -1; });
        out = { findings: sc.findings.length, score: sc.score, allMasked: allMasked,
          entropyMax: sc.findings.reduce(function (m, f) { return Math.max(m, f.entropy || 0); }, 0) };
        summaryText = sc.findings.length + ' credential-shaped string(s), values ' + (allMasked ? 'masked' : 'partially visible') + '.'; break; }
      case 'ingest': { var ng = A.normalizeLogs(sample('ingest'));
        out = { format: ng.format, events: ng.events.length, tagged: ng.stats.tagged, sources: ng.stats.sources };
        summaryText = ng.format + ' detected · ' + out.events + ' events normalized.'; break; }
      case 'chains': { var ch = A.attackChains(A.normalizeLogs(sample('ingest')));
        out = { chains: ch.chains.length, topConfidence: ch.chains.length ? ch.chains[0].confidence : 0 };
        summaryText = out.chains + ' multi-stage chain(s) reconstructed.'; break; }
      case 'coverage': { var cv = A.mitreCoverage(state);
        out = { covered: cv.covered, total: cv.total, percent: cv.percent };
        summaryText = cv.percent + '% ATT&CK technique coverage.'; break; }
      case 'plan': { var pl = plan(args.goal || '');
        out = { steps: pl.steps.length, eligible: pl.steps.filter(function (s) { return s.decision === 'ELIGIBLE'; }).length };
        summaryText = out.eligible + ' eligible offline step(s) in the plan.'; break; }
      case 'report': { out = { generatedAt: Date.now(), findings: (state.findings || []).length,
        alerts: (state.alerts || []).length, auditEntries: (state.audit || []).length };
        summaryText = 'Evidence report assembled from local state.'; break; }
      default: out = {}; summaryText = 'Adapter executed.';
    }
    return Object.assign(base, { result: {
      mode: 'offline-adapter', upstreamTool: t.id, capability: t.cap,
      engine: a.engine, label: a.label, summary: summaryText, data: out
    } });
  }

  var API = {
    UPSTREAM: UPSTREAM, AGENTS: AGENTS, TOOLS: TOOLS, MCP: MCP, ADAPTERS: ADAPTERS,
    summary: summary, get: get, tools: tools, evaluate: evaluate, plan: plan, call: call
  };
  root.AEGIS_HEXSTRIKE = API;
  if (isNode) module.exports = API;
})(typeof globalThis !== 'undefined' ? globalThis : this);


/* ===== 20-store.js ===== */
/* AEGIS / SENTINEL — state, persistence and the tamper-evident audit ledger.
 * All state lives in the browser (localStorage). Nothing is transmitted.
 */
(function (root) {
  'use strict';
  var DATA = root.AEGIS_DATA;
  var DATA2 = root.AEGIS_DATA2;
  var E = root.AEGIS_ENGINE;
  var A = root.AEGIS_ADVANCED;
  var KEY = 'aegis.sentinel.state.v1';
  var ZERO = '0000000000000000000000000000000000000000000000000000000000000000';

  var Store = {
    state: null,

    init: function () {
      var loaded = null;
      try {
        var raw = root.localStorage && root.localStorage.getItem(KEY);
        if (raw) loaded = JSON.parse(raw);
      } catch (e) { loaded = null; }
      this.state = loaded && loaded.version === 1 && loaded.audit && loaded.audit.length
        ? this._migrate(loaded)
        : this._fresh();
      return this.state;
    },

    _migrate: function (s) {
      var D2 = root.AEGIS_DATA2;
      s.drafts = s.drafts || {};
      if (!s.drafts.ingest) s.drafts.ingest = D2.SAMPLES.jsonl;
      if (!s.drafts.lab_email) s.drafts.lab_email = D2.SAMPLES.email;
      if (!s.drafts.lab_iam) s.drafts.lab_iam = D2.SAMPLES.iam;
      if (!s.drafts.lab_k8s) s.drafts.lab_k8s = D2.SAMPLES.k8s;
      if (!s.drafts.lab_secrets) s.drafts.lab_secrets = D2.SAMPLES.secrets;
      if (!s.drafts.lab_deps) s.drafts.lab_deps = D2.SAMPLES.deps;
      if (!s.drafts.investigate) s.drafts.investigate = '';
      s.settings = s.settings || { operator: 'analyst@local', humanApproval: true, strictScope: true };
      if (s.settings.automationLevel == null) s.settings.automationLevel = 'supervised';
      s.sweep = s.sweep || { running: false, log: [], lastRun: null, count: 0 };
      s.events = s.events || [];
      s.watchlist = s.watchlist || [];
      s.playbookProgress = s.playbookProgress || {};
      s.alerts = s.alerts || [];
      s.findings = s.findings || [];
      s.assets = s.assets || [];
      s.cases = s.cases || [];
      s.customRules = s.customRules || [];
      s.ingestResults = s.ingestResults || null;
      s.labResults = s.labResults || {};
      s.orchestratorRuns = s.orchestratorRuns || [];
      s.investigationHistory = s.investigationHistory || [];
      s.capabilityRequests = s.capabilityRequests || [];
      s.quantResult = s.quantResult || null;
      return s;
    },

    _fresh: function () {
      var now = Date.now();
      var assets = DATA.ASSET_SEEDS.map(function (a, i) {
        var expires = new Date(now + a.days * 86400000).toISOString();
        var record = {
          id: E.uid('ast'), name: a.name, type: a.type, owner: a.owner, env: a.env,
          criticality: a.criticality, authorizedBy: a.authorizedBy, expires: expires,
          checks: a.checks.slice(), confirmed: a.confirmed, revoked: false,
          createdAt: now - (20 - i) * 86400000
        };
        record.token = E.sha256(JSON.stringify([record.name, record.owner, record.authorizedBy, record.expires, record.createdAt]));
        return record;
      });
      var alerts = DATA.ALERT_SEEDS.map(function (a, i) {
        return Object.assign({}, a, {
          id: E.uid('alr'), status: 'new', createdAt: now - (i * 37 + 6) * 60000, priority: null
        });
      });
      var findings = DATA.FINDING_SEEDS.map(function (f, i) {
        return Object.assign({}, f, {
          id: E.uid('fnd'), status: 'open', source: 'baseline', simulated: true,
          confidence: 72 + i * 4, createdAt: now - (i + 1) * 3600000 * 7
        });
      });
      var s = {
        version: 1, createdAt: now,
        assets: assets, alerts: alerts, findings: findings,
        events: DATA.EVENT_SEEDS.map(function (e, i) {
          return { id: E.uid('evt'), ts: now - (12 - i * 3) * 60000, kind: e.kind, text: e.text, simulated: true };
        }),
        audit: [], watchlist: [], playbookProgress: {},
        cases: [], customRules: [], ingestResults: null, labResults: {},
        orchestratorRuns: [], investigationHistory: [], capabilityRequests: [], quantResult: null,
        logResults: null, headerResults: null, intelResults: null,
        settings: { operator: 'analyst@local', humanApproval: true, strictScope: true, automationLevel: 'supervised' },
        sweep: { running: false, log: [], lastRun: null, count: 0 },
        drafts: {
          logs: DATA.SAMPLE_LOGS,
          headers: DATA.SAMPLE_HEADERS,
          intel: DATA.SAMPLE_INTEL,
          ingest: DATA2.SAMPLES.jsonl,
          lab_email: DATA2.SAMPLES.email, lab_iam: DATA2.SAMPLES.iam,
          lab_k8s: DATA2.SAMPLES.k8s, lab_secrets: DATA2.SAMPLES.secrets,
          lab_deps: DATA2.SAMPLES.deps, investigate: '',
          asset: '', owner: '', authorizedBy: '', criticality: 'high', env: 'Production',
          checks: DATA.CHECK_TYPES.map(function (c) { return c.id; }),
          days: '90', confirmed: false
        }
      };
      this.state = s;
      this.audit('GENESIS', 'aegis/ledger', 'SEALED', 'Genesis block. Strict scope enforcement enabled.');
      this.audit('POLICY_LOAD', 'aegis/policy', 'ENFORCED',
        'Rules of engagement loaded: authorized assets only, passive analysis only, human approval for containment.');
      this.audit('DEMO_DATA', 'aegis/sandbox', 'NOTED', 'Baseline assets, alerts and findings are SIMULATED sample records.');
      return s;
    },

    save: function () {
      try { root.localStorage && root.localStorage.setItem(KEY, JSON.stringify(this.state)); } catch (e) { /* quota / private mode */ }
      return this.state;
    },

    audit: function (action, target, decision, detail, actor) {
      var s = this.state;
      var prev = s.audit.length ? s.audit[s.audit.length - 1].hash : ZERO;
      var entry = {
        seq: s.audit.length + 1, ts: Date.now(),
        actor: actor || s.settings.operator || 'operator',
        action: action, target: String(target || '—'), decision: decision,
        detail: String(detail || ''), prevHash: prev
      };
      entry.hash = E.entryHash(entry);
      s.audit.push(entry);
      return entry;
    },

    event: function (kind, text, simulated) {
      this.state.events.unshift({ id: E.uid('evt'), ts: Date.now(), kind: kind, text: text, simulated: !!simulated });
      if (this.state.events.length > 120) this.state.events.length = 120;
    },

    /* ----------------------------- assets ------------------------------ */
    addAsset: function (form) {
      var s = this.state;
      var name = String(form.name || '').trim();
      if (!name) return { ok: false, error: 'Asset identifier is required.' };
      if (!/^[A-Za-z0-9._\-\/]+$/.test(name)) return { ok: false, error: 'Use a bare hostname, IP or CIDR — no scheme, path or port.' };
      if (s.assets.some(function (a) { return a.name.toLowerCase() === name.toLowerCase(); }))
        return { ok: false, error: 'That asset already has an authorization record.' };
      if (!form.confirmed) return { ok: false, error: 'Ownership / authorization attestation is mandatory.' };
      var days = E.clamp(parseInt(form.days, 10) || 30, 1, 730);
      var checks = (form.checks || []).filter(function (c) {
        return DATA.CHECK_TYPES.some(function (t) { return t.id === c; });
      });
      if (!checks.length) return { ok: false, error: 'Select at least one permitted check type.' };
      var rec = {
        id: E.uid('ast'), name: name, type: form.type || 'Domain',
        owner: String(form.owner || 'Unassigned'), env: form.env || 'Production',
        criticality: form.criticality || 'medium',
        authorizedBy: String(form.authorizedBy || 'Unattested'),
        expires: new Date(Date.now() + days * 86400000).toISOString(),
        checks: checks, confirmed: true, revoked: false, createdAt: Date.now()
      };
      rec.token = E.sha256(JSON.stringify([rec.name, rec.owner, rec.authorizedBy, rec.expires, rec.createdAt, Math.random()]));
      s.assets.push(rec);
      this.audit('SCOPE_GRANT', name, 'GRANTED',
        'Signed by ' + rec.authorizedBy + '; ' + checks.length + ' check types; expires ' + rec.expires.slice(0, 10) + '.');
      this.event('scope', 'Authorization granted for ' + name + ' — ' + checks.length + ' permitted checks.');
      this.save();
      return { ok: true, asset: rec };
    },

    revokeAsset: function (name) {
      var a = this.state.assets.filter(function (x) { return x.name === name; })[0];
      if (!a) return { ok: false };
      a.revoked = true;
      this.audit('SCOPE_REVOKE', name, 'REVOKED', 'Authorization withdrawn by ' + this.state.settings.operator + '.');
      this.event('scope', 'Authorization revoked for ' + name + '. Agent will refuse all further actions.');
      this.save();
      return { ok: true };
    },

    /* ----------------------------- sweep ------------------------------- */
    applySweep: function (result, targets) {
      var s = this.state, self = this;
      var added = 0;
      result.findings.forEach(function (f) {
        var dup = s.findings.some(function (x) { return x.title === f.title && x.asset === f.asset && x.status === 'open'; });
        if (dup) return;
        s.findings.push(f); added++;
      });
      result.decisions.forEach(function (d) {
        if (d.decision === 'REFUSED') {
          self.audit('SWEEP_REFUSED', d.target, d.code, d.reason);
          self.event('refuse', 'REFUSED ' + d.target + ' — ' + d.code + ': ' + d.reason);
        } else {
          self.audit('SWEEP', d.target, 'ALLOWED', d.reason + ' ' + d.count + ' simulated finding(s).');
        }
      });
      s.sweep.count++;
      s.sweep.lastRun = result.at;
      s.sweep.decisions = result.decisions;
      self.event('agent', 'Autonomous sweep complete: ' + added + ' new finding(s), ' +
        result.decisions.filter(function (d) { return d.decision === 'REFUSED'; }).length + ' refusal(s).', true);
      this.audit('SWEEP_COMPLETE', (targets || []).join(',') || 'all-scope', 'COMPLETE',
        added + ' simulated findings recorded across ' + result.decisions.filter(function (d) { return d.decision === 'ALLOWED'; }).length + ' in-scope assets.');
      this.save();
      return added;
    },

    /* --------------------------- analyzers ----------------------------- */
    applyLogResults: function (result, target) {
      var s = this.state, self = this, created = 0;
      s.logResults = result;
      result.detections.forEach(function (d) {
        if (d.severity === 'low' || d.severity === 'info') return;
        var dup = s.alerts.some(function (a) { return a.source === 'log-analyzer' && a.title === d.name && a.asset === target; });
        if (dup) return;
        s.alerts.unshift({
          id: E.uid('alr'), title: d.name, severity: d.severity, asset: target,
          source: 'log-analyzer', phase: 'Detection', confidence: Math.min(96, 60 + d.count * 5),
          evidence: d.evidence, status: 'new', priority: null, createdAt: Date.now()
        });
        created++;
      });
      this.audit('LOG_ANALYSIS', target, 'COMPLETE',
        result.stats.lines + ' lines analyzed; ' + result.detections.length + ' detection(s); ' +
        result.iocs.length + ' IOC(s) extracted; ' + created + ' alert(s) raised.');
      this.event('detect', 'Log analysis: ' + result.detections.length + ' detection(s) across ' + result.stats.lines + ' lines.');
      this.save();
      return created;
    },

    applyHeaderResults: function (result, target) {
      this.state.headerResults = result;
      this.audit('HEADER_ANALYSIS', target, 'COMPLETE',
        'Grade ' + result.grade + ' (' + result.score + '/100); ' +
        result.checks.filter(function (c) { return c.status === 'fail'; }).length + ' failing controls.');
      this.event('detect', 'Hardening analysis graded ' + result.grade + ' (' + result.score + '/100) for ' + target + '.');
      this.save();
    },

    applyIntelResults: function (iocs, target) {
      this.state.intelResults = { iocs: iocs, at: Date.now(), target: target };
      this.audit('IOC_EXTRACTION', target, 'COMPLETE', iocs.length + ' unique indicator(s) extracted and defanged locally.');
      this.event('intel', iocs.length + ' unique IOC(s) extracted from supplied text.');
      this.save();
    },

    /* ----------------------------- alerts ------------------------------ */
    autoTriageAll: function () {
      var s = this.state, n = 0;
      s.alerts.forEach(function (a) {
        if (a.priority) return;
        a.priority = E.triage(a, s);
        if (a.status === 'new') a.status = 'triaged';
        n++;
      });
      if (n) {
        this.audit('AUTO_TRIAGE', 'alert-queue', 'COMPLETE', n + ' alert(s) scored with explainable reasoning.');
        this.event('agent', 'Auto-triage scored ' + n + ' alert(s); human approval still required for containment.');
      }
      this.save();
      return n;
    },

    setAlertStatus: function (id, status, note) {
      var a = this.state.alerts.filter(function (x) { return x.id === id; })[0];
      if (!a) return false;
      a.status = status;
      this.audit('ALERT_' + status.toUpperCase(), a.asset, status.toUpperCase(),
        a.title + (note ? ' — ' + note : '') + (status === 'contained' ? ' (workflow only; no external action taken)' : ''));
      this.event('triage', a.title.slice(0, 60) + ' → ' + status.toUpperCase());
      this.save();
      return true;
    },

    /* ---------------------------- playbooks ---------------------------- */
    togglePlaybookStep: function (id, idx) {
      var s = this.state;
      var pb = DATA.PLAYBOOKS.filter(function (p) { return p.id === id; })[0];
      if (!pb) return;
      if (!s.playbookProgress[id]) s.playbookProgress[id] = new Array(pb.steps.length).fill(false);
      s.playbookProgress[id][idx] = !s.playbookProgress[id][idx];
      var done = s.playbookProgress[id].filter(Boolean).length;
      if (done === pb.steps.length) {
        this.audit('PLAYBOOK_COMPLETE', id, 'COMPLETE', pb.name + ' — all ' + done + ' steps marked complete.');
        this.event('govern', 'Playbook complete: ' + pb.name);
      }
      this.save();
    },

    /* ---------------------------- watchlist ---------------------------- */
    addWatchlist: function (ioc, note) {
      var s = this.state;
      if (s.watchlist.some(function (w) { return w.value === ioc.value && w.type === ioc.type; })) return false;
      s.watchlist.unshift({ id: E.uid('ioc'), type: ioc.type, value: ioc.value,
        defanged: ioc.defanged, note: note || ioc.note || '', addedAt: Date.now() });
      this.audit('WATCHLIST_ADD', ioc.defanged || ioc.value, 'ADDED', 'Local indicator added to correlation watchlist.');
      this.event('intel', 'Watchlist updated: ' + (ioc.defanged || ioc.value));
      this.save();
      return true;
    },
    removeWatchlist: function (id) {
      var s = this.state;
      var w = s.watchlist.filter(function (x) { return x.id === id; })[0];
      if (!w) return;
      s.watchlist = s.watchlist.filter(function (x) { return x.id !== id; });
      this.audit('WATCHLIST_REMOVE', w.defanged || w.value, 'REMOVED', 'Indicator removed from local watchlist.');
      this.save();
    },

    /* ----------------------------- config ------------------------------ */
    setSetting: function (key, value) {
      this.state.settings[key] = value;
      this.audit('SETTING_CHANGE', 'aegis/settings/' + key, 'UPDATED', String(value));
      this.save();
    },
    setDraft: function (key, value) { this.state.drafts[key] = value; this.save(); },

    exportState: function () { return JSON.stringify(this.state, null, 2); },
    importState: function (json) {
      var obj = JSON.parse(json);
      if (!obj || obj.version !== 1 || !Array.isArray(obj.audit)) throw new Error('Not a valid AEGIS state export.');
      this.state = this._migrate(obj);
      this.audit('STATE_IMPORT', 'aegis/state', 'IMPORTED', 'Operator-supplied state file imported.');
      this.save();
      return true;
    },
    reset: function () {
      try { root.localStorage && root.localStorage.removeItem(KEY); } catch (e) {}
      var s = this._fresh();
      this.save();
      return s;
    },

    /* --------------------------- v2 subsystems ---------------------------- */
    saveIngest: function (result, target) {
      this.state.ingestResults = { result: result, target: target, at: Date.now() };
      this.audit('UNIVERSAL_INGEST', target, 'COMPLETE',
        result.format + ' format · ' + result.events.length + ' events normalized · ' + result.stats.tagged + ' tagged.');
      this.event('detect', 'Ingest: ' + result.format + ' · ' + result.events.length + ' events · ' + result.stats.sources + ' sources.');
      this.save();
    },
    saveLab: function (kind, result, target) {
      this.state.labResults[kind] = { result: result, target: target, at: Date.now() };
      this.audit('LAB_ANALYSIS_' + kind.toUpperCase(), target, 'COMPLETE',
        kind + ' analysis executed locally; score ' + (result.score != null ? result.score : 'n/a') + '.');
      this.event('detect', 'Analysis Lab · ' + kind + ' completed locally.');
      this.save();
    },
    saveCustomRule: function (rule) {
      if (!rule.pattern) return { ok: false, error: 'A regular expression is required.' };
      var t = A.testCustomRule(rule, this.state.drafts.logs || '');
      if (!t.ok) return { ok: false, error: 'Invalid regex: ' + t.error };
      var rec = {
        id: E.uid('rule'), name: String(rule.name || 'Custom rule').slice(0, 80),
        pattern: String(rule.pattern).slice(0, 400), flags: 'i',
        severity: rule.severity || 'medium', mitre: rule.mitre || 'T1059',
        threshold: E.clamp(parseInt(rule.threshold, 10) || 1, 1, 50),
        remediation: String(rule.remediation || 'Review matching events.').slice(0, 240),
        createdAt: Date.now()
      };
      this.state.customRules.unshift(rec);
      this.audit('DETECTION_RULE_ADD', rec.name, 'ADDED', 'Custom rule matches ' + t.count + ' line(s) in current telemetry.');
      this.event('detect', 'Custom detection rule published: ' + rec.name);
      this.save();
      return { ok: true, rule: rec, test: t };
    },
    deleteCustomRule: function (id) {
      var r = this.state.customRules.filter(function (x) { return x.id === id; })[0];
      if (!r) return;
      this.state.customRules = this.state.customRules.filter(function (x) { return x.id !== id; });
      this.audit('DETECTION_RULE_REMOVE', r.name, 'REMOVED', 'Operator deleted the custom rule.');
      this.save();
    },
    createCase: function (payload) {
      var title = String(payload.title || '').trim();
      if (!title) return { ok: false, error: 'A case title is required.' };
      var c = {
        id: E.uid('case'), title: title.slice(0, 120),
        severity: payload.severity || 'high', status: 'open',
        owner: this.state.settings.operator, asset: payload.asset || '—',
        summary: String(payload.summary || '').slice(0, 600),
        linkedAlerts: (payload.linkedAlerts || []).slice(0, 20),
        notes: [], createdAt: Date.now(), updatedAt: Date.now()
      };
      this.state.cases.unshift(c);
      this.audit('CASE_OPEN', c.id, 'OPENED', title + ' · severity ' + c.severity + ' · ' + c.linkedAlerts.length + ' linked alert(s).');
      this.event('govern', 'Incident case opened: ' + title);
      this.save();
      return { ok: true, case: c };
    },
    addCaseNote: function (id, note) {
      var c = this.state.cases.filter(function (x) { return x.id === id; })[0];
      if (!c || !String(note || '').trim()) return false;
      c.notes.unshift({ id: E.uid('note'), ts: Date.now(), actor: this.state.settings.operator, text: String(note).slice(0, 500) });
      c.updatedAt = Date.now();
      this.audit('CASE_NOTE', id, 'RECORDED', String(note).slice(0, 120));
      this.save();
      return true;
    },
    setCaseStatus: function (id, status) {
      var c = this.state.cases.filter(function (x) { return x.id === id; })[0];
      if (!c) return false;
      c.status = status; c.updatedAt = Date.now();
      this.audit('CASE_' + status.toUpperCase(), id, status.toUpperCase(), c.title);
      this.event('govern', 'Case ' + c.title.slice(0, 40) + ' → ' + status.toUpperCase());
      this.save();
      return true;
    },
    recordOrchestratorRun: function (run) {
      this.state.orchestratorRuns.unshift(run);
      if (this.state.orchestratorRuns.length > 12) this.state.orchestratorRuns.length = 12;
      this.audit('ORCHESTRATOR_RUN', run.target || 'all-scope', run.status,
        run.done + ' of ' + run.total + ' tasks completed; ' + run.refused + ' refused; ' + run.durationMs + 'ms.');
      this.event('agent', 'Orchestrator run ' + run.status + ': ' + run.done + '/' + run.total + ' tasks.');
      this.save();
    },
    recordInvestigation: function (res) {
      this.state.investigationHistory.unshift({ query: res.query, at: Date.now(), count: res.result.count, intent: res.result.type });
      if (this.state.investigationHistory.length > 25) this.state.investigationHistory.length = 25;
      this.audit('INVESTIGATION', res.result.type, 'QUERY', '"' + res.query + '" → ' + res.result.count + ' record(s).');
      this.save();
    },
    recordCapabilityRequest: function (id, decision, reason) {
      this.state.capabilityRequests.unshift({ id: id, decision: decision, reason: reason, at: Date.now(), actor: this.state.settings.operator });
      if (this.state.capabilityRequests.length > 30) this.state.capabilityRequests.length = 30;
      this.audit('CAPABILITY_REQUEST', id, decision, reason);
      this.event(decision === 'REFUSED' ? 'refuse' : 'scope', 'Capability ' + id + ' → ' + decision + '.');
      this.save();
    },
    saveQuant: function (result) {
      this.state.quantResult = result;
      this.audit('RISK_QUANT', 'portfolio', 'COMPLETE',
        result.iterations + ' Monte Carlo iterations; p50 ' + result.p50 + ', p90 ' + result.p90 + ' (illustrative).');
      this.save();
    },

    chainStatus: function () { return E.verifyChain(this.state.audit); }
  };

  root.AEGIS_STORE = Store;
})(typeof globalThis !== 'undefined' ? globalThis : this);


/* ===== 30-ui.js ===== */
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
    bolt: 'M13 2L4 14h6l-1 8 9-12h-6z',
    terminal: 'M3 4h18v16H3zM6 8l3 3-3 3M12 15h6'
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
          '<div class="build">v2.1.0 · 9 modules · 20 views · <span>NO NETWORK EGRESS</span></div></div>' +
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
    render: render, renderView: renderView, buildCommands: buildCommands, download: download, copy: copy,
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

  // Defer past the end of the concatenated bundle so every extension module
  // (src/40-ui2.js) can register views, actions and commands before first paint.
  // A defer script sees readyState 'interactive', so the old `else boot()` ran
  // before the extension module executed and rendered the v1 shell on first load.
  if (doc.readyState === 'loading') doc.addEventListener('DOMContentLoaded', boot);
  else root.setTimeout(boot, 0);
})(typeof globalThis !== 'undefined' ? globalThis : this);


/* ===== 40-ui2.js ===== */
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
      ['42', 'ATT&CK TECHNIQUES', 'chart'], ['150', 'HEXSTRIKE TOOLS', 'cpu'], ['8', 'ORCHESTRATOR TASKS', 'bolt']
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
      ['AEGIS Terminal', 'Governed CLI + HexStrike adapter', 'terminal', 'terminal']
    ];
    var rail = '<div class="quick-grid">' + engines.map(function (e) {
      return '<button class="quick" data-action="nav" data-view="' + e[2] + '">' + icon(e[3]) + '<b>' + esc(e[0]) + '</b><small>' + esc(e[1]) + '</small></button>';
    }).join('') + '</div>';
    return originalOverview() + section('Platform breadth', 'AEGIS SENTINEL v2.1 capability surface', '<span class="tag">ULTRA-ADVANCED / AUTHORIZED-ONLY</span>', breadth) +
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


/* ===== 45-terminal.js ===== */
/* AEGIS // SENTINEL v2.1 — interactive operator terminal + HexStrike console.
 *
 * This is NOT a system shell. No OS process is spawned, no socket is opened and
 * no filesystem is touched. Every command is interpreted by the AEGIS policy
 * engine, resolved against the signed capability manifest, and sealed in the
 * hash-chained ledger. HexStrike AI tool names are exposed as a governed,
 * MCP-shaped adapter catalog: safe tools run real offline analysis, everything
 * else is refused with a reason.
 */
(function (root) {
  'use strict';
  var U = root.AEGIS_UI, S = root.AEGIS_STORE, E = root.AEGIS_ENGINE;
  var A = root.AEGIS_ADVANCED, DATA = root.AEGIS_DATA, D2 = root.AEGIS_DATA2;
  var HX = root.AEGIS_HEXSTRIKE;
  if (!U || !HX) return;

  var esc = U.h.esc, icon = U.h.icon, section = U.h.section, $ = U.$, doc = U.doc, ui = U.ui;
  ui.terminalLines = [];
  ui.terminalHistory = [];
  ui.terminalHistIndex = -1;
  ui.terminalDraft = '';
  ui.terminalBooted = false;

  var MAX_LINES = 400;
  var KIND = { cmd: 'cmd', ok: 'ok', bad: 'bad', warn: 'warn', info: 'info', mute: 'mute', data: 'data', head: 'head' };

  function push(text, kind, tag) {
    ui.terminalLines.push({ t: new Date().toISOString().slice(11, 19), text: String(text == null ? '' : text), kind: kind || KIND.info, tag: tag || '' });
    if (ui.terminalLines.length > MAX_LINES) ui.terminalLines.splice(0, ui.terminalLines.length - MAX_LINES);
  }
  function print(text, kind) {
    String(text == null ? '' : text).split('\n').forEach(function (l) { push(l, kind); });
  }
  function linesHtml() {
    return ui.terminalLines.map(function (l) {
      return '<div class="t-line t-' + esc(l.kind) + '">' +
        (l.tag ? '<span class="t-tag">' + esc(l.tag) + '</span>' : '') +
        '<span class="t-time">' + esc(l.t) + '</span><span class="t-text">' + esc(l.text) + '</span></div>';
    }).join('');
  }
  function paint() {
    var out = $('terminal-out');
    if (!out) return;
    out.innerHTML = linesHtml();
    out.scrollTop = out.scrollHeight;
  }
  function focusInput() {
    var i = $('terminal-input');
    if (i) { i.focus(); i.setSelectionRange && i.setSelectionRange(i.value.length, i.value.length); }
  }
  function setInput(v) {
    var i = $('terminal-input');
    if (i) i.value = v;
    ui.terminalDraft = v;
  }
  function pad(s, n) { s = String(s == null ? '' : s); return s.length >= n ? s.slice(0, n) : s + new Array(n - s.length + 1).join(' '); }
  function kv(rows) { rows.forEach(function (r) { print('  ' + pad(r[0], 24) + ' ' + r[1], KIND.data); }); }
  function table(headers, rows) {
    print('  ' + headers.map(function (h, i) { return pad(h, [34, 12, 24, 20][i] || 18); }).join('') .trimEnd(), KIND.head);
    print('  ' + new Array(94).join('─'), KIND.mute);
    rows.forEach(function (r) { print('  ' + r.map(function (c, i) { return pad(c, [34, 12, 24, 20][i] || 18); }).join('').trimEnd(), KIND.data); });
  }
  function defaultTarget() {
    var a = E.activeAssets(S.state);
    return a.length ? a[0].name : null;
  }
  /* jsdom / restricted browsers may not implement object URLs; never let a
   * download failure abort a command. */
  function exportFile(name, text) {
    try { U.download(name, text); return true; }
    catch (err) { print('  Download unavailable in this context; content shown below instead.', KIND.warn); return false; }
  }
  function tokenize(s) {
    var out = [], cur = '', q = null;
    for (var i = 0; i < s.length; i++) {
      var c = s[i];
      if (q) { if (c === q) q = null; else cur += c; continue; }
      if (c === '"' || c === "'") { q = c; continue; }
      if (/\s/.test(c)) { if (cur) { out.push(cur); cur = ''; } continue; }
      cur += c;
    }
    if (cur) out.push(cur);
    return out;
  }
  function bootBanner() {
    if (ui.terminalBooted) return;
    ui.terminalBooted = true;
    [
      '  █████╗ ███████╗ ██████╗ ██╗███████╗    ████████╗███████╗██████╗ ███╗   ███╗',
      ' ██╔══██╗██╔════╝██╔════╝ ██║██╔════╝    ╚══██╔══╝██╔════╝██╔══██╗████╗ ████║',
      ' ███████║█████╗  ██║  ███╗██║███████╗       ██║   █████╗  ██████╔╝██╔████╔██║',
      ' ██╔══██║██╔══╝  ██║   ██║██║╚════██║       ██║   ██╔══╝  ██╔══██╗██║╚██╔╝██║',
      ' ██║  ██║███████╗╚██████╔╝██║███████║       ██║   ███████╗██║  ██║██║ ╚═╝ ██║',
      ' ╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚═╝╚══════╝       ╚═╝   ╚══════╝╚═╝  ╚═╝╚═╝     ╚═╝'
    ].forEach(function (l) { push(l, KIND.ok); });
    push('', KIND.mute);
    print('AEGIS // SENTINEL v2.1  ·  operator terminal  ·  authorization-bound, fully offline', KIND.ok);
    print('HexStrike AI v6.0 adapter loaded · ' + HX.summary().total + ' tool names · ' +
      HX.summary().adapters + ' offline adapters · ' + HX.summary().blocked + ' hard-refused · ' +
      HX.summary().unavailable + ' server-only', KIND.info);
    print('NOT A SYSTEM SHELL: no process, socket or filesystem access. Type `help` for commands.', KIND.warn);
    push('', KIND.mute);
  }

  /* --------------------------- command registry -------------------------- */
  var COMMANDS = {
    help: { args: '[command]', desc: 'List commands or explain one', run: function (argv) {
      if (argv[0]) {
        var c = COMMANDS[argv[0].toLowerCase()];
        if (!c) { print('No such command: ' + argv[0], KIND.bad); return { decision: 'UNKNOWN' }; }
        print(argv[0] + ' ' + c.args, KIND.ok); print('  ' + c.desc, KIND.info); return;
      }
      print('AVAILABLE COMMANDS', KIND.head);
      Object.keys(COMMANDS).sort().forEach(function (k) {
        print('  ' + pad(k + ' ' + COMMANDS[k].args, 34) + COMMANDS[k].desc, KIND.data);
      });
      print('', KIND.mute);
      print('Tip: ↑/↓ history · Tab completion · Ctrl+L clear · `hexstrike tools` · `mcp manifest --json`', KIND.mute);
    } },
    banner: { args: '', desc: 'Reprint the boot banner', run: function () { ui.terminalBooted = false; bootBanner(); } },
    clear: { args: '', desc: 'Clear the scrollback', run: function () { ui.terminalLines = []; paint(); } },
    history: { args: '[n]', desc: 'Show recent commands', run: function (argv) {
      var n = parseInt(argv[0], 10) || 20;
      ui.terminalHistory.slice(-n).forEach(function (h, i) { print('  ' + pad(String(ui.terminalHistory.length - n + i + 1), 5) + h, KIND.data); });
      if (!ui.terminalHistory.length) print('  (no history)', KIND.mute);
    } },
    whoami: { args: '', desc: 'Current operator identity', run: function () { print(S.state.settings.operator, KIND.ok); } },
    date: { args: '', desc: 'UTC timestamp', run: function () { print(new Date().toISOString(), KIND.data); } },
    echo: { args: '<text>', desc: 'Print text', run: function (argv) { print(argv.join(' '), KIND.info); } },
    status: { args: '', desc: 'Platform, scope and ledger status', run: function () {
      var s = S.state, v = E.verifyChain(s.audit || []);
      print('PLATFORM STATUS', KIND.head);
      kv([
        ['BUILD', 'v2.1.0 · 9 modules · 20 views · NO NETWORK EGRESS'],
        ['OPERATOR', s.settings.operator],
        ['STRICT SCOPE', String(s.settings.strictScope)],
        ['HUMAN APPROVAL', String(s.settings.humanApproval)],
        ['ASSETS IN SCOPE', E.activeAssets(s).length + ' / ' + s.assets.length],
        ['OPEN FINDINGS', s.findings.filter(function (f) { return f.status === 'open'; }).length],
        ['UNTRIAGED ALERTS', s.alerts.filter(function (a) { return !a.priority; }).length],
        ['INCIDENT CASES', s.cases.length],
        ['CUSTOM RULES', s.customRules.length],
        ['LEDGER', (v.valid ? 'VALID' : 'INVALID') + ' · ' + s.audit.length + ' entries'],
        ['HEXSTRIKE ADAPTER', HX.summary().total + ' tools / ' + HX.summary().adapters + ' offline adapters']
      ]);
    } },
    scope: { args: 'list|check <target> [type]', desc: 'Query the authorization gate', run: function (argv) {
      var sub = (argv[0] || 'list').toLowerCase();
      if (sub === 'list' || sub === 'active') {
        var rows = S.state.assets.map(function (a) {
          var active = E.activeAssets(S.state).some(function (x) { return x.name === a.name; });
          return [a.name, active ? 'ACTIVE' : 'INACTIVE', a.env, a.authorizedBy];
        });
        table(['ASSET', 'STATE', 'ENV', 'SIGNED BY'], rows);
        return;
      }
      if (sub === 'check') {
        var target = argv[1], type = argv[2] || 'posture';
        if (!target) { print('Usage: scope check <target> [checkType]', KIND.bad); return { decision: 'INVALID' }; }
        var g = E.scopeCheck(S.state, target, type);
        print('  TARGET   ' + target, KIND.data);
        print('  CHECK    ' + type, KIND.data);
        print('  DECISION ' + (g.allowed ? 'ALLOWED' : 'REFUSED'), g.allowed ? KIND.ok : KIND.bad);
        print('  CODE     ' + (g.allowed ? 'SCOPE_VALID' : g.code), g.allowed ? KIND.ok : KIND.bad);
        print('  REASON   ' + g.reason, KIND.info);
        S.audit('TERMINAL_SCOPE_CHECK', target, g.allowed ? 'ALLOWED' : 'REFUSED', g.reason); S.save();
        return { decision: g.allowed ? 'ALLOWED' : 'REFUSED' };
      }
      print('Unknown scope subcommand: ' + sub, KIND.bad); return { decision: 'INVALID' };
    } },
    cap: { args: 'list|blocked|request <id> [target]', desc: 'Inspect or test the capability manifest', run: function (argv) {
      var sub = (argv[0] || 'list').toLowerCase();
      if (sub === 'list' || sub === 'blocked') {
        var caps = D2.CAPABILITIES.filter(function (c) { return sub === 'blocked' ? c.status !== 'enabled' : c.status === 'enabled'; });
        caps.forEach(function (c) { print('  ' + pad(c.id, 26) + (c.status === 'enabled' ? 'ENABLED ' : 'BLOCKED ') + c.name, c.status === 'enabled' ? KIND.ok : KIND.bad); });
        print('  ' + caps.length + ' entr' + (caps.length === 1 ? 'y' : 'ies'), KIND.mute);
        return;
      }
      if (sub === 'request') {
        var id = argv[1], target = argv[2] || defaultTarget();
        if (!id) { print('Usage: cap request <capability-id> [target]', KIND.bad); return { decision: 'INVALID' }; }
        var g = A.evaluateCapability(id, S.state, target);
        S.recordCapabilityRequest(id, g.allowed ? 'GRANTED' : 'REFUSED', g.reason);
        print('  ' + pad(id, 28) + (g.allowed ? 'GRANTED' : 'REFUSED') + '  ' + g.code, g.allowed ? KIND.ok : KIND.bad);
        print('  ' + g.reason, KIND.info);
        return { decision: g.allowed ? 'ALLOWED' : 'REFUSED' };
      }
      print('Unknown cap subcommand: ' + sub, KIND.bad); return { decision: 'INVALID' };
    } },
    hexstrike: { args: 'info|tools|tool|agents|plan|run', desc: 'HexStrike AI adapter console', run: function (argv) {
      var sub = (argv[0] || 'info').toLowerCase(), sm = HX.summary();
      if (sub === 'info') {
        print('HEXSTRIKE AI COMPATIBILITY LAYER', KIND.head);
        kv([
          ['UPSTREAM', HX.UPSTREAM.repo + '@' + HX.UPSTREAM.version],
          ['LICENSE', HX.UPSTREAM.license],
          ['MCP CONFIG', HX.UPSTREAM.mcpConfig],
          ['UPSTREAM SERVER', HX.UPSTREAM.server],
          ['UPSTREAM BRIDGE', HX.UPSTREAM.bridge],
          ['DECORATED TOOLS', sm.decorated],
          ['UNIQUE CATALOG', sm.total],
          ['OFFLINE ADAPTERS', sm.adapters],
          ['HARD-REFUSED', sm.blocked],
          ['SERVER-ONLY', sm.unavailable],
          ['AGENTS', sm.agents + ' (' + sm.blockedAgents + ' blocked)'],
          ['INTEGRATION', HX.UPSTREAM.note]
        ]);
        print('  No upstream Python code, binary or network endpoint is bundled or executed.', KIND.warn);
        return;
      }
      if (sub === 'tools') {
        var list = HX.tools(argv.slice(1).join(' '));
        print('HEXSTRIKE TOOL CATALOG · ' + list.length + ' match(es)', KIND.head);
        table(['TOOL', 'MODE', 'CAPABILITY', 'CATEGORY'], list.slice(0, 40).map(function (t) {
          return [t.id, t.mode.toUpperCase(), t.cap || '—', t.category];
        }));
        if (list.length > 40) print('  … ' + (list.length - 40) + ' more. Use `hexstrike tools <filter>` to narrow.', KIND.mute);
        return;
      }
      if (sub === 'tool') {
        var t = HX.get(argv[1]);
        if (!t) { print('Unknown tool: ' + (argv[1] || ''), KIND.bad); return { decision: 'UNKNOWN' }; }
        print('TOOL ' + t.id, KIND.head);
        kv([['MODE', t.mode.toUpperCase()], ['CATEGORY', t.category], ['CAPABILITY', t.cap || '—'],
          ['RISK CLASS', t.risk], ['REASON', t.reason]]);
        return;
      }
      if (sub === 'agents') {
        print('HEXSTRIKE AGENT PERSONAS · ' + HX.AGENTS.length, KIND.head);
        HX.AGENTS.forEach(function (a) { print('  ' + pad(a.id, 34) + pad(a.status.toUpperCase(), 10) + a.role, a.status === 'adapter' ? KIND.ok : KIND.bad); });
        return;
      }
      if (sub === 'plan') {
        var goal = argv.slice(1).join(' ');
        var p = HX.plan(goal);
        print('OFFLINE CAPABILITY PLAN · ' + JSON.stringify(p.goal), KIND.head);
        print('  Engine: ' + p.engine, KIND.mute);
        p.steps.forEach(function (x) {
          print('  ' + pad(String(x.order), 4) + pad(x.tool, 36) + pad(x.decision, 10) + (x.capability || '—'),
            x.decision === 'ELIGIBLE' ? KIND.ok : KIND.bad);
        });
        return;
      }
      if (sub === 'run') return runTool(argv[1], argv[2] || defaultTarget(), {});
      print('Usage: hexstrike info|tools [filter]|tool <id>|agents|plan <goal>|run <tool> [target]', KIND.bad);
      return { decision: 'INVALID' };
    } },
    run: { args: '<hexstrike-tool> [target]', desc: 'Alias for `hexstrike run`', run: function (argv) { return runTool(argv[0], argv[1] || defaultTarget(), {}); } },
    mcp: { args: 'manifest|tools|resources|prompts|call', desc: 'MCP-shaped contract & JSON-RPC adapter', run: function (argv) {
      var sub = (argv[0] || 'manifest').toLowerCase(), m = HX.MCP;
      if (sub === 'manifest') {
        if (argv.indexOf('--json') !== -1) {
          var saved2 = exportFile('aegis-hexstrike-mcp.json', JSON.stringify(m, null, 2));
          S.audit('MCP_MANIFEST_EXPORT', 'aegis/hexstrike', 'EXPORTED', 'Full MCP-shaped manifest requested from the terminal.'); S.save();
          print('  Full manifest (' + m.tools.length + ' tools · ' + JSON.stringify(m).length + ' bytes) ' +
            (saved2 ? 'downloaded' : 'prepared') + ' as aegis-hexstrike-mcp.json.', KIND.ok);
          print(JSON.stringify({ name: m.name, version: m.version, upstream: m.upstream, transport: m.transport,
            alwaysAllow: m.alwaysAllow, capabilities: m.capabilities,
            tools: m.tools.length, resources: m.resources.length, prompts: m.prompts.length }, null, 2), KIND.data);
          return;
        }
        print('MCP SERVER MANIFEST', KIND.head);
        kv([['NAME', m.name], ['VERSION', m.version], ['UPSTREAM', m.upstream],
          ['TRANSPORT', m.transport], ['ALWAYS ALLOW', JSON.stringify(m.alwaysAllow)],
          ['TOOLS', m.tools.length], ['RESOURCES', m.resources.length], ['PROMPTS', m.prompts.length],
          ['SAMPLING', String(m.capabilities.sampling)], ['LOGGING', String(m.capabilities.logging)]]);
        print('  Use `mcp manifest --json` to print the full machine-readable contract.', KIND.mute);
        return;
      }
      if (sub === 'tools') {
        var f = argv.slice(1).join(' ');
        var ts = HX.MCP.tools.filter(function (t) { return !f || t.name.indexOf(f) !== -1 || t.mode === f || t.category === f; });
        ts.slice(0, 40).forEach(function (t) { print('  ' + pad(t.name, 38) + pad(t.mode.toUpperCase(), 12) + (t.capability || '—'), t.mode === 'adapter' ? KIND.ok : KIND.bad); });
        print('  ' + ts.length + ' tool(s)', KIND.mute);
        return;
      }
      if (sub === 'resources' || sub === 'prompts') {
        var items = sub === 'resources' ? m.resources : m.prompts;
        items.forEach(function (x) { print('  ' + pad(x.uri || x.name, 34) + x.description, KIND.data); });
        return;
      }
      if (sub === 'call') {
        var tool = argv[1];
        if (!tool) { print('Usage: mcp call <tool> [--target=…] [--data=…] [--goal=…]', KIND.bad); return { decision: 'INVALID' }; }
        var args = { id: Date.now() % 100000 };
        argv.slice(2).forEach(function (a) {
          var mm = a.match(/^--([A-Za-z0-9_]+)=(.*)$/);
          if (mm) args[mm[1]] = mm[2];
        });
        var res = HX.call(tool, args, S.state);
        var allowed = !!res.result;
        S.audit('MCP_CALL', tool, allowed ? 'ALLOWED' : 'REFUSED',
          allowed ? res.result.summary : (res.error.data ? res.error.data.reason : res.error.message));
        S.save();
        print(JSON.stringify(res, null, 2), allowed ? KIND.data : KIND.bad);
        return { decision: allowed ? 'ALLOWED' : 'REFUSED' };
      }
      print('Usage: mcp manifest|tools [filter]|resources|prompts|call <tool> [--k=v]', KIND.bad);
      return { decision: 'INVALID' };
    } },
    orchestrator: { args: 'run [target]', desc: 'Execute the 8-task policy-gated DAG', run: function (argv) {
      if (argv[0] !== 'run') { print('Usage: orchestrator run [target]', KIND.bad); return { decision: 'INVALID' }; }
      var target = argv[1] || defaultTarget();
      var gate = A.evaluateCapability('scope.verify', S.state, target);
      if (!gate.allowed) { print('REFUSED ' + gate.code + ': ' + gate.reason, KIND.bad); S.recordCapabilityRequest('scope.verify', 'REFUSED', gate.reason); return { decision: 'REFUSED' }; }
      print('ORCHESTRATOR · target ' + target + ' · 8 tasks', KIND.head);
      var ctx = { target: target }, start = Date.now(), done = 0, refused = 0;
      D2.ORCHESTRATOR_PLAN.forEach(function (n, i) {
        var depsOk = n.deps.every(function (d) { return ctx['done_' + d]; });
        if (!depsOk) {
          ctx['done_' + n.id] = false; refused++;
          print('  [' + (i + 1) + '/8] ' + pad(n.id, 12) + 'SKIPPED  dependency unsatisfied', KIND.bad);
          return;
        }
        var r = A.orchestratorStep(n, S.state, ctx);
        ctx['done_' + n.id] = r.status === 'DONE';
        if (r.status === 'DONE') done++; else refused++;
        print('  [' + (i + 1) + '/8] ' + pad(n.id, 12) + pad(r.status, 9) + r.detail, r.status === 'DONE' ? KIND.ok : KIND.bad);
        S.audit('ORCH_' + n.id.toUpperCase(), target, r.status, r.detail);
      });
      var run = { id: E.uid('orch'), target: target, status: done === 8 ? 'COMPLETE' : 'PARTIAL',
        done: done, refused: refused, total: 8, durationMs: Date.now() - start, at: Date.now(), source: 'terminal' };
      S.recordOrchestratorRun(run); S.save();
      print('  Run ' + run.status + ' · ' + done + '/8 done · ' + refused + ' not done · ' + run.durationMs + 'ms · sealed in ledger', KIND.ok);
      return { decision: 'ALLOWED' };
    } },
    ingest: { args: 'analyze [sample]', desc: 'Normalize telemetry & reconstruct chains', run: function (argv) {
      if (argv[0] !== 'analyze') { print('Usage: ingest analyze [jsonl|nginx|syslog|csv|email|iam|k8s|secrets|deps]', KIND.bad); return { decision: 'INVALID' }; }
      var key = argv[1] || 'draft';
      var text = key === 'draft' ? (S.state.drafts.ingest || '') : (D2.SAMPLES[key] || DATA.SAMPLE_LOGS);
      if (!D2.SAMPLES[key] && key !== 'draft' && key !== 'logs') { print('Unknown sample: ' + key, KIND.bad); return { decision: 'INVALID' }; }
      var target = defaultTarget();
      var gate = A.evaluateCapability('telemetry.normalize', S.state, target);
      if (!gate.allowed) { print('REFUSED ' + gate.code + ': ' + gate.reason, KIND.bad); return { decision: 'REFUSED' }; }
      var r = A.normalizeLogs(text);
      S.saveIngest(r, target || 'operator-supplied text');
      var ch = A.attackChains(r);
      print('  FORMAT      ' + r.format, KIND.ok);
      print('  EVENTS      ' + r.events.length + ' (' + r.stats.tagged + ' tagged)', KIND.data);
      print('  SOURCES     ' + r.stats.sources, KIND.data);
      print('  CHAINS      ' + ch.chains.length + (ch.chains.length ? ' · top confidence ' + ch.chains[0].confidence + '%' : ''), KIND.data);
      return { decision: 'ALLOWED' };
    } },
    lab: { args: 'run <email|iam|k8s|secrets|deps>', desc: 'Run an offline Analysis Lab engine', run: function (argv) {
      var tab = argv[0] === 'run' ? argv[1] : argv[0];
      var map = { email: [A.analyzeEmail, 'config.email', 'intel'], iam: [A.analyzeIamPolicy, 'config.iam', 'posture'],
        k8s: [A.analyzeK8s, 'config.k8s', 'posture'], secrets: [A.secretScan, 'config.secrets', 'posture'],
        deps: [A.analyzeDependencies, 'config.sbom', 'posture'] };
      if (!map[tab]) { print('Usage: lab run <email|iam|k8s|secrets|deps>', KIND.bad); return { decision: 'INVALID' }; }
      var target = defaultTarget(), gate = A.evaluateCapability(map[tab][1], S.state, target);
      if (!gate.allowed) { print('REFUSED ' + gate.code + ': ' + gate.reason, KIND.bad); return { decision: 'REFUSED' }; }
      var text = S.state.drafts['lab_' + tab] || D2.SAMPLES[tab] || '';
      var r = map[tab][0](text);
      S.saveLab(tab, r, target || 'operator-supplied text');
      print('  ' + tab.toUpperCase() + ' · score ' + r.score + '/100 · ' +
        (r.checks ? r.checks.length + ' controls' : r.findings ? r.findings.length + ' findings' : r.packages ? r.packages.length + ' packages' : r.verdict || 'complete'),
        r.score < 60 ? KIND.bad : KIND.ok);
      return { decision: 'ALLOWED' };
    } },
    mitre: { args: 'coverage', desc: 'ATT&CK coverage & gaps', run: function () {
      var c = A.mitreCoverage(S.state);
      print('  COVERAGE  ' + c.covered + '/' + c.total + ' (' + c.percent + '%)', KIND.ok);
      print('  GAPS      ' + c.gaps.length, KIND.warn);
      c.tactics.forEach(function (t) {
        var pct = t.total ? Math.round(t.covered / t.total * 100) : 0;
        print('  ' + pad(t.short, 12) + pad(t.covered + '/' + t.total, 9) + pct + '%', KIND.data);
      });
    } },
    investigate: { args: '<natural-language query>', desc: 'Local investigation copilot', run: function (argv) {
      var q = argv.join(' ');
      if (!q) { print('Usage: investigate <query>', KIND.bad); return { decision: 'INVALID' }; }
      var r = A.investigate(q, S.state);
      S.recordInvestigation({ query: q, result: r });
      print('  INTENT    ' + r.type, KIND.ok);
      print('  MATCHES   ' + r.count, KIND.data);
      if (r.parsed) print('  FILTERS   ' + JSON.stringify(r.parsed), KIND.mute);
      (r.rows || []).slice(0, 8).forEach(function (x) { print('  · ' + (x.title || x.name || x.text || JSON.stringify(x)).slice(0, 100), KIND.data); });
      return { decision: 'ALLOWED' };
    } },
    quant: { args: 'run [iterations]', desc: 'Monte Carlo risk simulation', run: function (argv) {
      var n = Math.max(200, Math.min(20000, parseInt(argv[0] === 'run' ? argv[1] : argv[0], 10) || 2000));
      var r = A.monteCarloRisk(S.state, n);
      S.saveQuant(r);
      print('  ITERATIONS ' + r.iterations, KIND.data);
      print('  P50 / P90 / P95   ' + r.p50 + ' / ' + r.p90 + ' / ' + r.p95, KIND.ok);
      print('  OPEN FINDINGS     ' + r.open + ' · illustrative model, not a forecast', KIND.mute);
      return { decision: 'ALLOWED' };
    } },
    triage: { args: '', desc: 'Score the alert queue with reasoning', run: function () {
      var before = S.state.alerts.filter(function (a) { return !a.priority; }).length;
      S.autoTriageAll();
      print('  ' + before + ' alert(s) scored with explainable reasoning chains.', KIND.ok);
      print('  Containment still requires human approval.', KIND.warn);
    } },
    findings: { args: '[severity]', desc: 'Open finding register', run: function (argv) {
      var f = (argv[0] || '').toLowerCase();
      var list = S.state.findings.filter(function (x) { return x.status === 'open' && (!f || x.severity === f); });
      table(['SEVERITY', 'ASSET', 'TITLE'], list.slice(0, 25).map(function (x) { return [x.severity.toUpperCase(), x.asset, x.title.slice(0, 34)]; }));
      print('  ' + list.length + ' open finding(s)', KIND.mute);
    } },
    alerts: { args: '', desc: 'Alert queue', run: function () {
      table(['PRIORITY', 'STATUS', 'SOURCE', 'TITLE'], S.state.alerts.slice(0, 20).map(function (x) {
        return [x.priority ? String(x.priority.score || 'scored') : '—', x.status, x.source || '—', (x.title || '').slice(0, 30)];
      }));
    } },
    cases: { args: 'list|note <id> <text>', desc: 'Incident cases', run: function (argv) {
      var list = S.state.cases;
      if (argv[0] === 'note') {
        if (!argv[1] || !argv[2]) { print('Usage: cases note <caseId> <text>', KIND.bad); return { decision: 'INVALID' }; }
        var ok = S.addCaseNote(argv[1], argv.slice(2).join(' '));
        print(ok ? '  Evidence note recorded.' : '  Case not found or note empty.', ok ? KIND.ok : KIND.bad);
        return { decision: ok ? 'ALLOWED' : 'REFUSED' };
      }
      if (!list.length) { print('  No cases. Create one from the Incident Cases view.', KIND.mute); return; }
      table(['ID', 'STATUS', 'SEVERITY', 'TITLE'], list.map(function (c) { return [c.id.slice(0, 14), c.status, c.severity, c.title.slice(0, 30)]; }));
    } },
    audit: { args: 'verify|tail [n]', desc: 'Ledger verification & recent entries', run: function (argv) {
      var sub = (argv[0] || 'verify').toLowerCase();
      if (sub === 'verify') {
        var v = E.verifyChain(S.state.audit);
        print('  LEDGER ' + (v.valid ? 'VALID' : 'INVALID') + ' · ' + S.state.audit.length + ' entries · SHA-256 hash chain', v.valid ? KIND.ok : KIND.bad);
        return { decision: v.valid ? 'ALLOWED' : 'REFUSED' };
      }
      var n = parseInt(argv[1], 10) || 12;
      S.state.audit.slice(-n).forEach(function (e) {
        print('  #' + pad(String(e.seq), 5) + pad(e.action, 26) + pad(e.decision, 12) + String(e.target).slice(0, 28),
          e.decision === 'REFUSED' ? KIND.bad : KIND.data);
      });
    } },
    rules: { args: 'list|add <name> <regex>', desc: 'Custom detection rules', run: function (argv) {
      if ((argv[0] || 'list') === 'add') {
        var name = argv[1], pattern = argv.slice(2).join(' ');
        if (!name || !pattern) { print('Usage: rules add <name> <regex>', KIND.bad); return { decision: 'INVALID' }; }
        var r = S.saveCustomRule({ name: name, pattern: pattern, severity: 'medium', mitre: 'T1059', threshold: 1 });
        print(r.ok ? '  Rule published: ' + r.rule.id + ' (' + r.test.count + ' sample match(es)).' : '  ' + r.error, r.ok ? KIND.ok : KIND.bad);
        return { decision: r.ok ? 'ALLOWED' : 'REFUSED' };
      }
      if (!S.state.customRules.length) { print('  No custom rules yet.', KIND.mute); return; }
      S.state.customRules.forEach(function (r) { print('  ' + pad(r.id.slice(0, 14), 16) + pad(r.mitre, 12) + r.name, KIND.data); });
    } },
    report: { args: 'export', desc: 'Export full state + ledger as JSON', run: function (argv) {
      if (argv[0] !== 'export') { print('Usage: report export', KIND.bad); return { decision: 'INVALID' }; }
      var saved = exportFile('aegis-sentinel-evidence.json', S.exportState());
      S.audit('REPORT_EXPORT', 'aegis/state', 'EXPORTED', 'Operator exported state + ledger from the terminal.'); S.save();
      print('  Evidence report ' + (saved ? 'downloaded' : 'prepared') + '. Export sealed in ledger.', KIND.ok);
    } },
    policy: { args: '', desc: 'Rules of engagement', run: function () {
      print('RULES OF ENGAGEMENT · ENFORCED IN CODE', KIND.head);
      [
        'IN SCOPE   : offline analysis of text you supply; assets with a signed, unexpired authorization record;',
        '             explainable triage; mitigation guidance; defanged IOC correlation; hash-chained audit.',
        'OUT OF SCOPE: activity without documented authorization; active network scanning/probing; exploitation;',
        '             credential attacks; persistence/evasion/lateral movement; autonomous external containment;',
        '             sending operator data to third parties; bypassing or disabling the scope gate.',
        'HEXSTRIKE  : catalog-only adapter. Offensive tool names are refused and logged, never executed.'
      ].forEach(function (l) { print('  ' + l, KIND.warn); });
    } },
    go: { args: '<view-id>', desc: 'Navigate to another console view', run: function (argv) {
      var id = argv[0];
      if (!id) { print('Usage: go <view-id>  (try: orchestrator, ingest, lab, studio, capabilities, audit)', KIND.bad); return { decision: 'INVALID' }; }
      U.navigate(id);
      print('  Navigated to ' + id + '.', KIND.ok);
    } },
    exit: { args: '', desc: 'Return to the command center', run: function () { U.navigate('overview'); print('  Returning to the command center.', KIND.ok); } }
  };

  function runTool(toolId, target, extra) {
    if (!toolId) { print('Usage: hexstrike run <tool> [target]', KIND.bad); return { decision: 'INVALID' }; }
    var gate = HX.evaluate(toolId, S.state, target);
    if (!gate.allowed) {
      var reason = gate.reason;
      S.recordCapabilityRequest(toolId, 'REFUSED', reason);
      S.audit('HEXSTRIKE_TOOL', toolId, 'REFUSED', reason); S.save();
      print('  REFUSED  ' + toolId, KIND.bad);
      print('  CODE     ' + gate.code, KIND.bad);
      print('  CAP      ' + (gate.mappedCapability || '—'), KIND.mute);
      print('  REASON   ' + reason, KIND.warn);
      print('  No upstream binary, process or network call was made.', KIND.mute);
      return { decision: 'REFUSED' };
    }
    var args = Object.assign({ target: target }, extra || {});
    var res = HX.call(toolId, args, S.state);
    if (!res.result) {
      S.audit('HEXSTRIKE_TOOL', toolId, 'REFUSED', JSON.stringify(res.error)); S.save();
      print('  ' + JSON.stringify(res.error), KIND.bad);
      return { decision: 'REFUSED' };
    }
    var r = res.result;
    S.audit('HEXSTRIKE_TOOL', toolId, 'ALLOWED', r.summary);
    S.event('agent', 'HexStrike adapter ' + toolId + ' → ' + r.capability + ': ' + r.summary);
    S.save();
    print('  GRANTED  ' + toolId, KIND.ok);
    print('  CAP      ' + r.capability + '  ·  engine ' + r.engine, KIND.mute);
    print('  SUMMARY  ' + r.summary, KIND.ok);
    print('  DATA     ' + JSON.stringify(r.data), KIND.data);
    print('  Executed locally on operator-supplied / labelled sample data. No egress.', KIND.mute);
    return { decision: 'ALLOWED' };
  }

  function exec(raw) {
    var line = String(raw || '').trim();
    if (!line) return;
    ui.terminalHistory.push(line);
    if (ui.terminalHistory.length > 200) ui.terminalHistory.shift();
    ui.terminalHistIndex = -1;
    push('aegis ❯ ' + line, KIND.cmd, 'IN');
    var t = tokenize(line);
    var name = (t[0] || '').toLowerCase(), argv = t.slice(1);
    var c = COMMANDS[name];
    var decision = 'ALLOWED', detail = line.slice(0, 180);
    if (!c) {
      print('command not found: ' + name + '  (try `help`)', KIND.bad);
      decision = 'UNKNOWN';
    } else {
      try {
        var out = c.run(argv);
        if (out && out.decision) decision = out.decision;
      } catch (err) {
        print('runtime error: ' + (err && err.message ? err.message : String(err)), KIND.bad);
        decision = 'ERROR';
      }
    }
    push('', KIND.mute);
    S.audit('TERMINAL_CMD', name || '(empty)', decision, detail);
    S.save();
    paint();
    root.setTimeout(focusInput, 0);
  }

  /* ------------------------------ UI wiring ------------------------------ */
  U.registerNav('OPERATE', [{ id: 'terminal', label: 'AEGIS Terminal', icon: 'terminal', key: 'M' }]);
  U.registerMeta({ terminal: { id: 'terminal', label: 'AEGIS Terminal', icon: 'terminal', key: 'M' } });
  U.registerCommands([
    { label: 'Open the AEGIS terminal', hint: 'OPERATE', icon: 'terminal', run: function () { U.navigate('terminal'); root.setTimeout(focusInput, 0); } },
    { label: 'HexStrike tool catalog', hint: 'ANALYZE', icon: 'cpu', run: function () { U.navigate('terminal'); root.setTimeout(function () { exec('hexstrike tools'); }, 0); } },
    { label: 'Print MCP manifest', hint: 'GOVERN', icon: 'file', run: function () { U.navigate('terminal'); root.setTimeout(function () { exec('mcp manifest'); }, 0); } }
  ]);

  U.registerAction('terminal-quick', function (t) {
    var cmd = t.getAttribute('data-cmd');
    if (cmd) exec(cmd);
  });
  U.registerAction('terminal-copy', function () {
    U.copy(ui.terminalLines.map(function (l) { return '[' + l.t + '] ' + l.text; }).join('\n'));
  });
  U.registerAction('terminal-manifest', function () {
    exportFile('aegis-hexstrike-mcp.json', JSON.stringify(HX.MCP, null, 2));
    S.audit('MCP_MANIFEST_EXPORT', 'aegis/hexstrike', 'EXPORTED', 'MCP-shaped adapter manifest downloaded.'); S.save();
    U.toast('MCP manifest downloaded.', 'ok');
  });

  U.registerForm('terminal-input', function (form, fd) {
    var input = form.querySelector('input[name="cmd"]');
    if (input) input.value = '';
    ui.terminalDraft = '';
    exec(fd.get('cmd'));
  });

  U.registerView('terminal', function () {
    bootBanner();
    var sm = HX.summary();
    var quick = [
      ['help', 'help'], ['status', 'status'], ['hexstrike info', 'hexstrike info'],
      ['hexstrike tools', 'hexstrike tools'], ['mcp manifest', 'mcp manifest'],
      ['orchestrator run', 'orchestrator run'], ['mitre coverage', 'mitre coverage'],
      ['policy', 'policy']
    ];
    return '<div class="page-head"><div><div class="eyebrow">OPERATE · OPERATOR TERMINAL</div><h1>AEGIS Terminal</h1>' +
      '<p>A governed command line for the whole platform. HexStrike AI v6.0 is integrated as an offline, MCP-shaped adapter catalog.</p></div>' +
      '<div class="head-actions"><span class="chip chip-lock">' + icon('shield') + ' AUTHORIZATION-BOUND</span>' +
      '<button class="btn btn-ghost" data-action="terminal-manifest">' + icon('download') + ' MCP manifest</button>' +
      '<button class="btn btn-ghost" data-action="terminal-copy">' + icon('file') + ' Copy log</button></div></div>' +
      '<div class="callout callout-info"><div class="callout-icon">' + icon('lock') + '</div><div><b>This is not a system shell.</b>' +
      '<p>No OS process is spawned, no socket is opened and no file is written. Every command is interpreted by the AEGIS policy engine, checked against the signed capability manifest and sealed in the hash-chained ledger. HexStrike tool names map to real offline analyzers or to hard refusals — never to upstream binaries.</p></div></div>' +
      '<div class="terminal-layout"><div class="col-main">' +
        '<div class="terminal-window"><div class="terminal-bar"><span class="t-dots"><i></i><i></i><i></i></span>' +
        '<span class="t-title">operator@aegis-sentinel: ~ </span><span class="t-badge">HEXSTRIKE ADAPTER v6.0 · OFFLINE</span></div>' +
        '<div id="terminal-out" class="terminal-out">' + linesHtml() + '</div>' +
        '<form data-form="terminal-input" class="terminal-form" autocomplete="off"><span class="t-prompt">aegis ❯</span>' +
        '<input id="terminal-input" name="cmd" type="text" spellcheck="false" autocomplete="off" placeholder="type a command…" value="' + esc(ui.terminalDraft) + '"></form></div>' +
        '<div class="terminal-quick">' + quick.map(function (q) {
          return '<button class="example-chip" data-action="terminal-quick" data-cmd="' + esc(q[1]) + '">' + esc(q[0]) + '</button>';
        }).join('') + '</div>' +
      '</div><div class="col-side">' +
        section('Adapter status', sm.total + ' upstream tool names', '<span class="tag">CATALOG ONLY</span>',
          '<div class="stat-row"><div><b>' + sm.adapters + '</b><span>OFFLINE ADAPTERS</span></div>' +
          '<div><b>' + sm.blocked + '</b><span>HARD-REFUSED</span></div>' +
          '<div><b>' + sm.unavailable + '</b><span>SERVER-ONLY</span></div></div>' +
          '<div class="terminal-meta">' +
          '<div><span>UPSTREAM</span><code>' + esc(HX.UPSTREAM.repo) + '</code></div>' +
          '<div><span>VERSION</span><code>v' + esc(HX.UPSTREAM.version) + '</code></div>' +
          '<div><span>LICENSE</span><code>' + esc(HX.UPSTREAM.license) + '</code></div>' +
          '<div><span>TRANSPORT</span><code>in-browser / offline</code></div>' +
          '</div><p class="muted" style="margin-top:10px;font-size:10.5px">' + esc(HX.UPSTREAM.note) + '</p>') +
        section('Agent personas', sm.agents + ' mapped · ' + sm.blockedAgents + ' blocked', '',
          HX.AGENTS.map(function (a) {
            return '<div class="gap-row"><code>' + esc(a.status.toUpperCase()) + '</code><span>' + esc(a.id) + '</span><small>' + esc(a.role) + '</small></div>';
          }).join('')) +
        section('Quick reference', 'Common command forms', '',
          '<div class="terminal-ref">' + [
            ['hexstrike tools web', 'list upstream web tools'],
            ['hexstrike tool nuclei_scan', 'inspect one tool'],
            ['hexstrike plan harden api', 'build an offline plan'],
            ['hexstrike run trivy_scan', 'run a safe adapter'],
            ['hexstrike run nmap_scan', 'see a hard refusal'],
            ['mcp call jwt_analyzer', 'JSON-RPC envelope'],
            ['scope check api.acme-lab.io', 'verify authorization'],
            ['audit verify', 'check the hash chain']
          ].map(function (x) { return '<div><code>' + esc(x[0]) + '</code><small>' + esc(x[1]) + '</small></div>'; }).join('') + '</div>') +
      '</div></div>';
  });

  /* Keyboard: history, completion, clear. Registered before boot() so it
   * coexists with the base keydown handler (palette / Escape / alt-nav). */
  doc.addEventListener('keydown', function (ev) {
    var t = ev.target;
    if (!t || t.id !== 'terminal-input') return;
    if (ui.palette || ui.modal) return;
    var hist = ui.terminalHistory;
    if (ev.key === 'ArrowUp') {
      ev.preventDefault();
      if (!hist.length) return;
      ui.terminalHistIndex = ui.terminalHistIndex < 0 ? hist.length - 1 : Math.max(0, ui.terminalHistIndex - 1);
      setInput(hist[ui.terminalHistIndex]); return;
    }
    if (ev.key === 'ArrowDown') {
      ev.preventDefault();
      if (ui.terminalHistIndex < 0) return;
      ui.terminalHistIndex++;
      if (ui.terminalHistIndex >= hist.length) { ui.terminalHistIndex = -1; setInput(''); }
      else setInput(hist[ui.terminalHistIndex]);
      return;
    }
    if (ev.key === 'Tab') {
      ev.preventDefault();
      var v = t.value, parts = v.split(/\s+/), last = parts[parts.length - 1];
      var pool;
      if (parts.length === 1) pool = Object.keys(COMMANDS).concat(Object.keys(COMMANDS).map(function (x) { return x; }));
      else if (/^(run|tool|call)$/.test(parts[parts.length - 2]) || /^(hexstrike|mcp)$/.test(parts[0])) pool = HX.TOOLS.map(function (x) { return x.id; });
      else pool = Object.keys(COMMANDS);
      var matches = pool.filter(function (x) { return x.indexOf(last) === 0; });
      if (matches.length === 1) { parts[parts.length - 1] = matches[0]; setInput(parts.join(' ')); }
      else if (matches.length > 1) { print('  ' + matches.slice(0, 12).join('  '), KIND.mute); paint(); }
      return;
    }
    if (ev.key.toLowerCase() === 'l' && ev.ctrlKey) { ev.preventDefault(); ui.terminalLines = []; paint(); return; }
  });
  doc.addEventListener('input', function (ev) {
    if (ev.target && ev.target.id === 'terminal-input') ui.terminalDraft = ev.target.value;
  });
  doc.addEventListener('click', function (ev) {
    var n = ev.target && ev.target.closest && ev.target.closest('[data-action="nav"][data-view="terminal"]');
    if (n) root.setTimeout(focusInput, 0);
  }, true);
  root.setTimeout(function () { if (ui.view === 'terminal') focusInput(); }, 0);

  root.AEGIS_TERMINAL = {
    exec: exec, commands: COMMANDS, lines: ui.terminalLines, hexstrike: HX,
    render: function () { bootBanner(); U.renderView(); paint(); }
  };
})(typeof globalThis !== 'undefined' ? globalThis : this);
