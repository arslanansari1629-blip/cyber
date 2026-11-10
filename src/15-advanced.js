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
