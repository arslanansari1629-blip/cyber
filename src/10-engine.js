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
