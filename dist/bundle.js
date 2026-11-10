/* AEGIS // SENTINEL — generated bundle. Do not edit directly.
 * Source: src/00-data.js, 10-engine.js, 20-store.js, 30-ui.js  |  Built with scripts/build.mjs
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


/* ===== 20-store.js ===== */
/* AEGIS / SENTINEL — state, persistence and the tamper-evident audit ledger.
 * All state lives in the browser (localStorage). Nothing is transmitted.
 */
(function (root) {
  'use strict';
  var DATA = root.AEGIS_DATA;
  var E = root.AEGIS_ENGINE;
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
      s.drafts = s.drafts || {};
      s.settings = s.settings || { operator: 'analyst@local', humanApproval: true, strictScope: true };
      s.sweep = s.sweep || { running: false, log: [], lastRun: null, count: 0 };
      s.events = s.events || [];
      s.watchlist = s.watchlist || [];
      s.playbookProgress = s.playbookProgress || {};
      s.alerts = s.alerts || [];
      s.findings = s.findings || [];
      s.assets = s.assets || [];
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
        logResults: null, headerResults: null, intelResults: null,
        settings: { operator: 'analyst@local', humanApproval: true, strictScope: true },
        sweep: { running: false, log: [], lastRun: null, count: 0 },
        drafts: {
          logs: DATA.SAMPLE_LOGS,
          headers: DATA.SAMPLE_HEADERS,
          intel: DATA.SAMPLE_INTEL,
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
    alertFilter: 'all', assetQuery: '', toasts: []
  };

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
          '<div class="build">v1.0.0 · offline engine · <span>NO NETWORK EGRESS</span></div></div>' +
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
    ]);
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
