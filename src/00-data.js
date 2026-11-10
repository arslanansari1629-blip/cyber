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
