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
