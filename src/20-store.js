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
