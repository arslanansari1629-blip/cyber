/* AEGIS // SENTINEL v2.2 — interactive operator terminal + OpenCode workbench.
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
  var HX = root.AEGIS_HEXSTRIKE, OP = root.AEGIS_OPENCODE;
  if (!U || !HX) return;

  var esc = U.h.esc, icon = U.h.icon, section = U.h.section, $ = U.$, doc = U.doc, ui = U.ui;
  ui.terminalLines = [];
  ui.terminalHistory = [];
  ui.terminalHistIndex = -1;
  ui.terminalDraft = '';
  ui.terminalBooted = false;
  ui.terminalVars = {};
  ui.terminalAliases = {};
  ui.terminalScripts = {};
  ui.terminalPanels = [];
  ui.terminalWorkbenchTab = 'session';
  ui.terminalLast = '';
  ui.opencode = OP ? OP.createSession({ title: 'Operator workbench' }) : null;

  var MAX_LINES = 600;
  var quiet = false, captureSink = null;
  var KIND = { cmd: 'cmd', ok: 'ok', bad: 'bad', warn: 'warn', info: 'info', mute: 'mute', data: 'data', head: 'head' };

  function push(text, kind, tag) {
    var str = String(text == null ? '' : text);
    if (quiet) { if (captureSink) captureSink.push(str); return; }
    ui.terminalLines.push({ t: new Date().toISOString().slice(11, 19), text: str, kind: kind || KIND.info, tag: tag || '' });
    if (ui.terminalLines.length > MAX_LINES) ui.terminalLines.splice(0, ui.terminalLines.length - MAX_LINES);
    if (str.trim()) ui.terminalLast = str.trim();
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
  /* ------------- ultra-advanced shell features (no OS shell) ------------- */
  function builtinVars() {
    return {
      target: defaultTarget() || '—', agent: ui.opencode ? ui.opencode.agent : 'build',
      session: ui.opencode ? ui.opencode.id : '—', last: ui.terminalLast || '',
      goal: ui.opencode ? (ui.opencode.vars.goal || '') : '', date: new Date().toISOString(),
      operator: S.state.settings.operator, tools: HX.summary().total
    };
  }
  function expandVars(line) {
    var b = builtinVars();
    return String(line).replace(/\$\{?([A-Za-z_][A-Za-z0-9_]*)\}?/g, function (m, k) {
      if (Object.prototype.hasOwnProperty.call(ui.terminalVars, k)) return String(ui.terminalVars[k]);
      return Object.prototype.hasOwnProperty.call(b, k) ? String(b[k]) : m;
    });
  }
  function expandAliasOnce(line) {
    var t = tokenize(line), name = (t[0] || '').toLowerCase();
    if (!ui.terminalAliases[name]) return line;
    return ui.terminalAliases[name] + (t.length > 1 ? ' ' + t.slice(1).join(' ') : '');
  }
  function splitOutside(str, sep) {
    var out = [], cur = '', q = null, i = 0;
    while (i < str.length) {
      var ch = str[i];
      if (q) { cur += ch; if (ch === q) q = null; i++; continue; }
      if (ch === '"' || ch === "'") { q = ch; cur += ch; i++; continue; }
      if (str.substr(i, sep.length) === sep) { out.push(cur.trim()); cur = ''; i += sep.length; continue; }
      cur += ch; i++;
    }
    out.push(cur.trim());
    return out.filter(function (x) { return x.length; });
  }
  function splitChain(line) {
    // Returns [{cmd, op}] where op is the operator that preceded this segment.
    var segs = [], cur = '', q = null, i = 0, pendingOp = ';';
    while (i < line.length) {
      var ch = line[i];
      if (q) { cur += ch; if (ch === q) q = null; i++; continue; }
      if (ch === '"' || ch === "'") { q = ch; cur += ch; i++; continue; }
      if (line.substr(i, 2) === '&&') { segs.push({ cmd: cur.trim(), op: pendingOp }); cur = ''; pendingOp = '&&'; i += 2; continue; }
      if (ch === ';') { segs.push({ cmd: cur.trim(), op: pendingOp }); cur = ''; pendingOp = ';'; i++; continue; }
      cur += ch; i++;
    }
    segs.push({ cmd: cur.trim(), op: pendingOp });
    return segs.filter(function (x) { return x.cmd; });
  }
  function applyFilter(lines, expr) {
    var t = tokenize(expr), f = (t[0] || '').toLowerCase(), arg = t.slice(1).join(' '), n = parseInt(t[1], 10);
    switch (f) {
      case 'grep': case 'match': { var re; try { re = new RegExp(arg, 'i'); } catch (e) { return ['Invalid regex: ' + e.message]; }
        return lines.filter(function (l) { return re.test(l); }); }
      case 'exclude': return lines.filter(function (l) { return l.toLowerCase().indexOf(arg.toLowerCase()) === -1; });
      case 'contains': return lines.filter(function (l) { return l.toLowerCase().indexOf(arg.toLowerCase()) !== -1; });
      case 'head': return lines.slice(0, isNaN(n) ? 10 : n);
      case 'tail': return lines.slice(-(isNaN(n) ? 10 : n));
      case 'select': return [lines[(isNaN(n) ? 1 : n) - 1] || ''];
      case 'wc': case 'count': return [lines.length + ' line(s) · ' + lines.join(' ').length + ' chars'];
      case 'sort': return lines.slice().sort();
      case 'uniq': return lines.filter(function (l, i, a) { return i === 0 || l !== a[i - 1]; });
      case 'upper': return lines.map(function (l) { return l.toUpperCase(); });
      case 'lower': return lines.map(function (l) { return l.toLowerCase(); });
      case 'trim': return lines.map(function (l) { return l.trim(); });
      case 'prefix': return lines.map(function (l) { return arg + l; });
      case 'json': {
        var blob = lines.join('\n'), start = blob.indexOf('{');
        if (start === -1) return ['No JSON object in pipeline.'];
        try { return JSON.stringify(JSON.parse(blob.slice(start)), null, 2).split('\n'); }
        catch (e) { return ['JSON parse failed: ' + e.message]; }
      }
      case 'help': return ['Pipeline filters: grep <re> · exclude <text> · contains <text> · head [n] · tail [n] · select <n>',
        '                  wc · sort · uniq · upper · lower · trim · prefix <text> · json'];
      default: return ['Unknown pipeline filter: ' + f + ' (try | help)'];
    }
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
    print('AEGIS // SENTINEL v2.2  ·  operator terminal  ·  authorization-bound, fully offline', KIND.ok);
    print('OpenCode v2.2.7 workbench loaded · ' + (OP ? OP.summary().tools : 0) + ' tools · ' +
      (OP ? OP.summary().agents : 0) + ' agents · ' + (OP ? OP.summary().permissions : 0) +
      ' permission keys · VFS · planner · pipelines · human approval', KIND.ok);
    print('HexStrike AI v6.0 adapter loaded · ' + HX.summary().total + ' tool names · ' +
      HX.summary().adapters + ' offline adapters · ' + HX.summary().blocked + ' hard-refused · ' +
      HX.summary().unavailable + ' server-only', KIND.info);
    print('NOT A SYSTEM SHELL: no process, socket, model call or filesystem access. Type `help` or `oc help`.', KIND.warn);
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
      print('Tip: ↑/↓ history · Tab completion · Ctrl+L clear · `|` pipelines · `&&` chains · $vars · aliases · scripts', KIND.mute);
      print('OpenCode: `oc help` · `oc tools` · `oc run "<goal>"` · `vfs ls` · `sh help` · `panel plan`', KIND.mute);
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
        ['BUILD', 'v2.2.0 · 10 modules · 20 views · NO NETWORK EGRESS'],
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
        'HEXSTRIKE  : catalog-only adapter. Offensive tool names are refused and logged, never executed.',
        'OPENCODE   : contract-only workbench. VFS writes need human approval; webfetch, websearch,',
        '             external_directory and doom_loop are hard-denied. No Bun runtime, LLM or disk I/O.',
        '"ANYTHING" : everything inside the signed offline capability manifest — nothing outside it.'
      ].forEach(function (l) { print('  ' + l, KIND.warn); });
    } },
    go: { args: '<view-id>', desc: 'Navigate to another console view', run: function (argv) {
      var id = argv[0];
      if (!id) { print('Usage: go <view-id>  (try: orchestrator, ingest, lab, studio, capabilities, audit)', KIND.bad); return { decision: 'INVALID' }; }
      U.navigate(id);
      print('  Navigated to ' + id + '.', KIND.ok);
    } },
    exit: { args: '', desc: 'Return to the command center', run: function () { U.navigate('overview'); print('  Returning to the command center.', KIND.ok); } },

    /* ---------------- OpenCode-compatible governed workbench ------------- */
    opencode: { args: '<subcommand>', desc: 'OpenCode adapter: status/tools/agents/plan/run/approve', run: function (argv) {
      return opencodeCmd(argv);
    } },
    oc: { args: '<subcommand>', desc: 'Short alias for `opencode`', run: function (argv) { return opencodeCmd(argv); } },
    vfs: { args: '<ls|cat|grep|glob|read|write|edit|patch|diff|diagnostics|reset>', desc: 'Virtual workspace operations', run: function (argv) {
      return vfsCmd(argv);
    } },
    sh: { args: '<command>', desc: 'Governed virtual shell (help for commands)', run: function (argv) {
      if (!argv.length) { print('Usage: sh <command>   (try `sh help`)', KIND.bad); return { decision: 'INVALID' }; }
      return ocCall('bash', { command: argv.join(' ') });
    } },
    tool: { args: '<tool-id> [json-args]', desc: 'Invoke one OpenCode tool through the policy gate', run: function (argv, raw) {
      if (!argv[0]) { print('Usage: tool <tool-id> [json-args]', KIND.bad); return { decision: 'INVALID' }; }
      var json = raw ? String(raw).replace(/^\s*tool\s+\S+\s*/i, '').trim() : argv.slice(1).join(' ');
      var args = {};
      if (json) {
        try { args = JSON.parse(json); }
        catch (e) { print('Invalid JSON arguments: ' + e.message, KIND.bad); return { decision: 'INVALID' }; }
      }
      return ocCall(argv[0], args);
    } },
    set: { args: '<name> <value>', desc: 'Set a shell variable (use $name)', run: function (argv) {
      if (!argv[0]) { print('Usage: set <name> <value>', KIND.bad); return { decision: 'INVALID' }; }
      ui.terminalVars[argv[0]] = argv.slice(1).join(' ');
      print('  $' + argv[0] + ' = ' + ui.terminalVars[argv[0]], KIND.ok);
    } },
    unset: { args: '<name>', desc: 'Delete a shell variable', run: function (argv) {
      if (!argv[0] || !Object.prototype.hasOwnProperty.call(ui.terminalVars, argv[0])) { print('No such variable.', KIND.bad); return { decision: 'INVALID' }; }
      delete ui.terminalVars[argv[0]]; print('  Variable removed.', KIND.ok);
    } },
    env: { args: '', desc: 'List built-in and user shell variables', run: function () {
      var b = builtinVars();
      print('SHELL VARIABLES', KIND.head);
      Object.keys(b).forEach(function (k) { print('  ' + pad('$' + k, 16) + b[k], KIND.data); });
      Object.keys(ui.terminalVars).forEach(function (k) { print('  ' + pad('$' + k, 16) + ui.terminalVars[k] + '  (user)', KIND.ok); });
    } },
    alias: { args: '<name> <command>', desc: 'Define a terminal alias', run: function (argv) {
      if (!argv[0] || !argv[1]) { print('Usage: alias <name> <command>', KIND.bad); return { decision: 'INVALID' }; }
      ui.terminalAliases[argv[0].toLowerCase()] = argv.slice(1).join(' ');
      print('  Alias ' + argv[0] + ' → ' + argv.slice(1).join(' '), KIND.ok);
    } },
    unalias: { args: '<name>', desc: 'Remove a terminal alias', run: function (argv) {
      delete ui.terminalAliases[(argv[0] || '').toLowerCase()]; print('  Alias removed.', KIND.ok);
    } },
    aliases: { args: '', desc: 'List terminal aliases', run: function () {
      var k = Object.keys(ui.terminalAliases);
      print('ALIASES', KIND.head);
      if (!k.length) print('  (none defined)', KIND.mute);
      k.forEach(function (x) { print('  ' + pad(x, 14) + '→ ' + ui.terminalAliases[x], KIND.data); });
    } },
    script: { args: '<save|run|list|delete>', desc: 'In-memory multi-command macros', run: function (argv) {
      var sub = (argv[0] || 'list').toLowerCase();
      if (sub === 'list') {
        var names = Object.keys(ui.terminalScripts);
        print('SCRIPTS (' + names.length + ')', KIND.head);
        if (!names.length) print('  (none; `script save <name> <cmd>; <cmd>`)', KIND.mute);
        names.forEach(function (n) { print('  ' + pad(n, 16) + ui.terminalScripts[n].join(' ; '), KIND.data); });
        return;
      }
      if (sub === 'save') {
        if (!argv[1] || !argv[2]) { print('Usage: script save <name> "<cmd>; <cmd>"', KIND.bad); return { decision: 'INVALID' }; }
        ui.terminalScripts[argv[1]] = splitChain(argv.slice(2).join(' ')).map(function (x) { return x.cmd; });
        print('  Saved script ' + argv[1] + ' (' + ui.terminalScripts[argv[1]].length + ' steps).', KIND.ok);
        return;
      }
      if (sub === 'run') {
        var sc = ui.terminalScripts[argv[1]];
        if (!sc) { print('No such script: ' + argv[1], KIND.bad); return { decision: 'UNKNOWN' }; }
        return runScript(sc, argv[1]);
      }
      if (sub === 'delete') { delete ui.terminalScripts[argv[1]]; print('  Script deleted.', KIND.ok); return; }
      print('Usage: script <save|run|list|delete>', KIND.bad); return { decision: 'INVALID' };
    } },
    repeat: { args: '<n> <command>', desc: 'Repeat a command up to 10 times', run: function (argv) {
      var n = Math.max(1, Math.min(10, parseInt(argv[0], 10) || 1)), cmd = argv.slice(1).join(' ');
      if (!cmd) { print('Usage: repeat <n> <command>', KIND.bad); return { decision: 'INVALID' }; }
      var last = 'ALLOWED';
      for (var i = 0; i < n; i++) { print('  ── iteration ' + (i + 1) + '/' + n, KIND.mute); last = execLine(cmd); }
      S.audit('TERMINAL_REPEAT', cmd.split(/\s+/)[0], last, n + ' iterations'); S.save();
      return { decision: last };
    } },
    panel: { args: '<session|files|plan|diff|approvals|tools|audit>', desc: 'Switch the live workbench panel', run: function (argv) {
      var tabs = ['session', 'files', 'plan', 'diff', 'approvals', 'tools', 'audit'];
      if (tabs.indexOf(argv[0]) === -1) { print('Usage: panel <' + tabs.join('|') + '>', KIND.bad); return { decision: 'INVALID' }; }
      ui.terminalWorkbenchTab = argv[0]; paintWorkbench();
      print('  Workbench panel → ' + argv[0], KIND.ok);
    } },
    diff: { args: '[virtual-path]', desc: 'Show a unified diff of virtual file changes', run: function (argv) {
      if (!OP) { print('OpenCode adapter unavailable.', KIND.bad); return { decision: 'REFUSED' }; }
      var d = OP.diffText(ui.opencode, argv[0] || null);
      print(d || 'No virtual file changes. Workspace clean.', d ? KIND.data : KIND.mute);
    } },
    diagnostics: { args: '', desc: 'Run LSP-like diagnostics on the virtual workspace', run: function () {
      return ocCall('lsp', {});
    } },
    approvals: { args: '', desc: 'List pending human approvals', run: function () {
      if (!OP) { print('OpenCode adapter unavailable.', KIND.bad); return { decision: 'REFUSED' }; }
      var p = ui.opencode.pending;
      print('PENDING APPROVALS (' + p.length + ')', KIND.head);
      if (!p.length) { print('  (none)', KIND.mute); return; }
      p.forEach(function (x) { print('  ' + pad(x.id, 18) + pad(x.tool, 18) + x.reason, KIND.warn); });
      print('  Use `oc approve <id>` or `oc deny <id>`.', KIND.mute);
    } },
    workbench: { args: '[reset]', desc: 'OpenCode workbench overview / reset session', run: function (argv) {
      if (argv[0] === 'reset') {
        if (!OP) return { decision: 'REFUSED' };
        OP.reset(ui.opencode);
        S.audit('OPENCODE_SESSION', 'workbench', 'RESET', 'Virtual workspace restored.'); S.save();
        print('  Session and virtual workspace reset.', KIND.ok); paintWorkbench(); return;
      }
      return opencodeCmd(['status']);
    } }
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

  /* ------------------ OpenCode workbench terminal helpers ---------------- */
  function ocUnavailable() { print('OpenCode adapter is not loaded in this runtime.', KIND.bad); return { decision: 'REFUSED' }; }
  function printOcResult(res, label) {
    var mark = res.status === 'DONE' ? KIND.ok : res.status === 'PENDING' ? KIND.warn : KIND.bad;
    print('  ' + (label ? label + ' · ' : '') + res.status + '  ' + res.tool + (res.code ? '  (' + res.code + ')' : ''), mark);
    if (res.reason) print('  REASON   ' + res.reason, KIND.mute);
    if (res.cap) print('  CAP      ' + res.cap, KIND.mute);
    (res.output || []).slice(0, 80).forEach(function (l) { print('  │ ' + l, KIND.data); });
    if ((res.output || []).length > 80) print('  │ … ' + (res.output.length - 80) + ' more lines (use vfs cat or a pipeline)', KIND.mute);
    if (res.diff) print('  DIFF     changes written to the virtual workspace; `diff` to review.', KIND.warn);
    if (res.status === 'PENDING') {
      print('  APPROVAL ' + res.approvalId + ' — human decision required.', KIND.warn);
      print('  `oc approve ' + res.approvalId + '` or use the Approvals panel.', KIND.mute);
      ui.terminalWorkbenchTab = 'approvals'; paintWorkbench();
      approvalModal(res.approvalId);
    }
  }
  function ocCall(id, args) {
    if (!OP) return ocUnavailable();
    var res = OP.execute({ tool: id, args: args || {} }, ui.opencode);
    S.audit('OPENCODE_TOOL', String(id), res.status,
      JSON.stringify(args || {}).slice(0, 180) + (res.reason ? ' · ' + res.reason : '')); S.save();
    printOcResult(res);
    paintWorkbench();
    return { decision: res.status === 'DONE' ? 'ALLOWED' : res.status === 'PENDING' ? 'PENDING' : 'REFUSED' };
  }
  function ocPlan(goal) {
    if (!OP) return ocUnavailable();
    var p = OP.plan(goal, ui.opencode);
    print('OPENCODE PLAN · ' + p.goal.toUpperCase(), KIND.head);
    print('  ENGINE   ' + p.engine + ' · ' + p.steps.length + ' steps', KIND.ok);
    p.steps.forEach(function (x, i) { print('  ' + pad(String(i + 1) + '.', 4) + pad(x.title, 42) + '[' + x.tool + ']', KIND.data); });
    print('  No model call, no provider, no network. `oc run "<goal>"` to execute.', KIND.mute);
    S.audit('OPENCODE_PLAN', p.goal || 'workspace', 'GENERATED', p.steps.length + ' deterministic steps.'); S.save();
    ui.terminalWorkbenchTab = 'plan'; paintWorkbench();
  }
  function ocRun(goal) {
    if (!OP) return ocUnavailable();
    var s = ui.opencode, p = OP.plan(goal, s), done = 0, blocked = null;
    print('OPENCODE RUN · ' + (p.goal || 'workspace review'), KIND.head);
    print('  streaming ' + p.steps.length + ' governed steps · agent ' + s.agent, KIND.mute);
    for (var i = 0; i < p.steps.length; i++) {
      var step = p.steps[i], res = OP.execute(step, s);
      S.audit('OPENCODE_TOOL', step.tool, res.status, 'step ' + (i + 1) + '/' + p.steps.length + ' · ' + (p.goal || ''));
      print('  [' + (i + 1) + '/' + p.steps.length + '] ' + pad(step.title, 42) + res.status + '  ' + step.tool,
        res.status === 'DONE' ? KIND.ok : res.status === 'PENDING' ? KIND.warn : KIND.bad);
      if (res.status === 'DONE') {
        done++; if (s.todos[i]) s.todos[i].status = 'done';
        var head = (res.output || [])[0];
        if (head) print('        ' + String(head).slice(0, 120), KIND.mute);
        if (res.diff) print('        VIRTUAL DIFF AVAILABLE · `diff` to review', KIND.warn);
      } else {
        blocked = res;
        print('        ' + (res.reason || res.code || 'stopped'), KIND.warn);
        break;
      }
    }
    S.audit('OPENCODE_RUN', p.goal || 'workspace', blocked ? 'PAUSED' : 'COMPLETED',
      done + '/' + p.steps.length + ' steps · no network · no OS process'); S.save();
    print('  RESULT   ' + done + '/' + p.steps.length + ' steps · ' + (blocked ? 'paused for human decision' : 'complete'),
      blocked ? KIND.warn : KIND.ok);
    if (blocked && blocked.status === 'PENDING') {
      ui.terminalWorkbenchTab = 'approvals'; approvalModal(blocked.approvalId);
    }
    ui.terminalWorkbenchTab = blocked ? 'approvals' : 'plan';
    paintWorkbench();
    return { decision: blocked ? 'PENDING' : 'ALLOWED' };
  }
  function ocApprove(id, decision) {
    if (!OP) return ocUnavailable();
    var r = OP.approve(ui.opencode, id, decision, S.state.settings.operator);
    if (!r.ok) { print('  ' + r.error, KIND.bad); return { decision: 'UNKNOWN' }; }
    S.audit('OPENCODE_APPROVAL', r.pending.tool, decision.toUpperCase(), 'Approval ' + id + ' by human operator.'); S.save();
    print('  APPROVAL ' + id + ' · ' + decision.toUpperCase() + ' · ' + r.pending.tool, decision === 'approve' ? KIND.ok : KIND.warn);
    if (r.result) printOcResult(r.result, 'post-approval');
    U.closeModal();
    ui.terminalWorkbenchTab = 'approvals'; paintWorkbench();
    return { decision: decision === 'approve' ? 'ALLOWED' : 'DENIED' };
  }
  function approvalModal(id) {
    if (!OP) return;
    var p = ui.opencode.pending.filter(function (x) { return x.id === id; })[0];
    if (!p) return;
    var body = '<div class="callout callout-warn"><div class="callout-icon">' + icon('shield') +
      '</div><div><b>Permission policy requires an explicit human decision.</b><p>' + esc(p.reason) + '</p></div></div>' +
      '<div class="terminal-meta" style="margin-top:12px">' +
      '<div><span>APPROVAL</span><code>' + esc(p.id) + '</code></div>' +
      '<div><span>TOOL</span><code>' + esc(p.tool) + '</code></div>' +
      '<div><span>AGENT</span><code>' + esc(p.agent) + '</code></div>' +
      '<div><span>ARGS</span><code>' + esc(JSON.stringify(p.args)) + '</code></div>' +
      '<div><span>BOUNDARY</span><code>virtual workspace only · no OS/network</code></div></div>';
    var footer = '<button class="btn btn-ghost" data-action="close-modal">Cancel</button>' +
      '<button class="btn btn-ghost" data-action="terminal-approve" data-id="' + esc(p.id) + '" data-decision="deny">Deny</button>' +
      '<button class="btn btn-primary" data-action="terminal-approve" data-id="' + esc(p.id) + '" data-decision="approve">Approve</button>';
    U.modal('Human approval required', body, footer);
  }
  function opencodeCmd(argv) {
    if (!OP) return ocUnavailable();
    var s = ui.opencode, sub = (argv[0] || 'status').toLowerCase(), sm = OP.summary(s);
    switch (sub) {
      case 'status': case 'session': case 'info':
        print('OPENCODE COMPATIBILITY LAYER', KIND.head);
        kv([
          ['UPSTREAM', OP.UPSTREAM.repo + '@v' + OP.UPSTREAM.version + ' · ' + OP.UPSTREAM.license],
          ['INTEGRATION', 'contract only · no runtime, model, shell or egress'],
          ['SESSION', s.id + ' · "' + s.title + '"'],
          ['AGENT', s.agent + ' (' + (OP.agent(s.agent) || {}).mode + ')'],
          ['GOAL', s.vars.goal || '(none)'],
          ['TOOLS', sm.tools + ' (' + sm.allow + ' allow · ' + sm.ask + ' ask · ' + sm.deny + ' deny)'],
          ['AGENTS', sm.agents + ' · permission keys ' + sm.permissions],
          ['VIRTUAL FILES', sm.files + ' · changed ' + sm.changed],
          ['APPROVALS', sm.pending + ' pending · tool calls ' + sm.calls]
        ]);
        print('  Hard-denied: webfetch, websearch, external_directory, doom_loop — cannot be relaxed.', KIND.warn);
        print('  Try: `oc tools`, `oc agents`, `oc plan "audit headers"`, `oc run "fix app"`, `panel plan`', KIND.mute);
        return;
      case 'tools': {
        var f = argv.slice(1).join(' '), list = OP.tools(f);
        print('OPENCODE TOOL CATALOG · ' + list.length + ' match(es)' + (f ? ' for "' + f + '"' : ''), KIND.head);
        table(['TOOL', 'ACTION', 'PERMISSION', 'CAPABILITY'], list.slice(0, 60).map(function (t) {
          return [t.id, t.action.toUpperCase(), t.key, t.cap];
        }));
        if (list.length > 60) print('  … ' + (list.length - 60) + ' more; use `oc tools <filter>`', KIND.mute);
        print('  `tool <tool-id> [json-args]` routes through the policy gate.', KIND.mute);
        return;
      }
      case 'tool': {
        var t = OP.get(argv[1]);
        if (!t) { print('No such OpenCode tool: ' + argv[1], KIND.bad); return { decision: 'UNKNOWN' }; }
        var g = OP.evaluate(t.id, s, {});
        print('OPENCODE TOOL · ' + t.id.toUpperCase(), KIND.head);
        kv([['PERMISSION', t.key], ['BASE ACTION', t.action.toUpperCase()], ['EFFECTIVE', g.action.toUpperCase() + ' · ' + g.code],
          ['CAPABILITY', t.cap], ['DESCRIPTION', t.reason]]);
        return;
      }
      case 'agents':
        print('OPENCODE AGENTS', KIND.head);
        table(['AGENT', 'MODE', 'DESCRIPTION'], OP.AGENTS.map(function (a) { return [a.id, a.mode, a.desc.slice(0, 26)]; }));
        print('  `oc agent <id>` applies its permission defaults. Hard-deny keys stay denied.', KIND.mute);
        return;
      case 'agent': {
        if (!argv[1]) { print('Usage: oc agent <build|plan|general|explore|…>', KIND.bad); return { decision: 'INVALID' }; }
        var r = OP.setAgent(s, argv[1]);
        if (!r.ok) { print('  ' + r.error, KIND.bad); return { decision: 'UNKNOWN' }; }
        S.audit('OPENCODE_AGENT', argv[1], 'SELECTED', 'Agent permission defaults applied.'); S.save();
        print('  ACTIVE AGENT ' + argv[1] + ' · ' + r.agent.mode + ' · ' + r.agent.desc, KIND.ok);
        paintWorkbench(); return;
      }
      case 'permissions':
        print('OPENCODE PERMISSION POLICY', KIND.head);
        Object.keys(s.permissions).sort().forEach(function (k) {
          print('  ' + pad(k, 24) + pad(s.permissions[k].toUpperCase(), 10) +
            (OP.HARD_DENY[k] ? 'HARD-DENY · cannot be relaxed' : 'operator-configurable'), OP.HARD_DENY[k] ? KIND.warn : KIND.data);
        });
        return;
      case 'permission': {
        if (!argv[1] || !argv[2]) { print('Usage: oc permission <key> <allow|ask|deny>', KIND.bad); return { decision: 'INVALID' }; }
        var pr = OP.setPermission(s, argv[1], argv[2].toLowerCase());
        if (!pr.ok) { print('  ' + pr.error, KIND.bad); return { decision: 'REFUSED' }; }
        S.audit('OPENCODE_PERMISSION', argv[1], argv[2].toUpperCase(), 'Operator changed permission policy.'); S.save();
        print('  POLICY ' + argv[1] + ' → ' + argv[2].toUpperCase(), KIND.ok);
        paintWorkbench(); return;
      }
      case 'plan': ocPlan(argv.slice(1).join(' ')); return;
      case 'run': return ocRun(argv.slice(1).join(' '));
      case 'approve': return ocApprove(argv[1], 'approve');
      case 'deny': return ocApprove(argv[1], 'deny');
      case 'pending': return COMMANDS.approvals.run([]);
      case 'mcp': {
        var m = OP.mcp();
        print('OPENCODE MCP MANIFEST · ' + m.name, KIND.head);
        kv([['UPSTREAM', m.upstream], ['TRANSPORT', m.transport], ['TOOLS', m.tools.length],
          ['RESOURCES', m.resources.length], ['PROMPTS', m.prompts.length], ['SAMPLING', String(m.capabilities.sampling)],
          ['ALWAYS ALLOW', '[] (every write is reviewed)']]);
        if (argv[1] === '--json') {
          var saved = exportFile('aegis-opencode-mcp.json', JSON.stringify(m, null, 2));
          print('  Manifest ' + (saved ? 'downloaded' : 'prepared') + ' as aegis-opencode-mcp.json (' +
            JSON.stringify(m).length + ' bytes).', KIND.ok);
          S.audit('OPENCODE_MCP_EXPORT', m.name, 'EXPORTED', 'Contract manifest export.'); S.save();
        } else print('  `oc mcp --json` exports the full contract manifest.', KIND.mute);
        return;
      }
      case 'reset': return COMMANDS.workbench.run(['reset']);
      case 'help':
        print('OPENCODE COMMANDS', KIND.head);
        ['status · adapter, agent and session state', 'tools [filter] · list the tool/permission catalog',
          'tool <id> · inspect one tool and its effective policy', 'agents · list built-in agents',
          'agent <id> · apply an agent permission profile', 'permissions · show the permission table',
          'permission <key> <allow|ask|deny> · change a policy (hard-deny stays denied)',
          'plan "<goal>" · deterministic multistep plan', 'run "<goal>" · stream the plan through the gate',
          'approve|deny <id> · human approval decision', 'mcp [--json] · MCP contract manifest',
          'reset · restore the virtual workspace'].forEach(function (l) { print('  ' + l, KIND.data); });
        return;
      default: print('Unknown opencode subcommand: ' + sub + '  (`oc help`)', KIND.bad); return { decision: 'UNKNOWN' };
    }
  }
  function vfsCmd(argv) {
    if (!OP) return ocUnavailable();
    var s = ui.opencode, sub = (argv[0] || 'ls').toLowerCase();
    switch (sub) {
      case 'ls': case 'list': return ocCall('list', {});
      case 'tree': return ocCall('bash', { command: 'tree' });
      case 'cat': case 'read': {
        if (!argv[1]) { print('Usage: vfs cat <path>  (`vfs ls`)', KIND.bad); return { decision: 'INVALID' }; }
        return ocCall('read', { path: argv[1] });
      }
      case 'write': {
        if (!argv[1]) { print('Usage: vfs write <path> <text>', KIND.bad); return { decision: 'INVALID' }; }
        return ocCall('write', { path: argv[1], content: argv.slice(2).join(' ') });
      }
      case 'edit': {
        if (!argv[1] || !argv[2]) { print('Usage: vfs edit <path> <find> <replace>', KIND.bad); return { decision: 'INVALID' }; }
        return ocCall('edit', { path: argv[1], find: argv[2], replace: argv.slice(3).join(' ') });
      }
      case 'patch': {
        if (!argv[1] || !argv[2]) { print('Usage: vfs patch <path> <old-line> <new-line>', KIND.bad); return { decision: 'INVALID' }; }
        return ocCall('apply_patch', { path: argv[1], patch: '-' + argv[2] + '\n+' + argv.slice(3).join(' ') });
      }
      case 'grep': {
        if (!argv[1]) { print('Usage: vfs grep <regex> [glob]', KIND.bad); return { decision: 'INVALID' }; }
        return ocCall('grep', { pattern: argv[1], path: argv[2] || null });
      }
      case 'glob': return ocCall('glob', { pattern: argv[1] || '*' });
      case 'diff': return COMMANDS.diff.run(argv.slice(1));
      case 'diagnostics': case 'lsp': return ocCall('lsp', {});
      case 'reset': return COMMANDS.workbench.run(['reset']);
      case 'help':
        print('VIRTUAL FILE SYSTEM', KIND.head);
        ['ls|tree · list in-memory files', 'cat <path> · numbered read', 'grep <regex> [glob] · regex search',
          'glob <pattern> · path matching', 'write <path> <text> · virtual create (approval required)',
          'edit <path> <find> <replace> · find/replace (approval required)',
          'patch <path> <old-line> <new-line> · unified hunk (approval required)',
          'diff [path] · unified diff', 'diagnostics · LSP-like findings', 'reset · restore seeds'].forEach(function (l) {
          print('  ' + l, KIND.data); });
        return;
      default: print('Unknown vfs subcommand: ' + sub + '  (`vfs help`)', KIND.bad); return { decision: 'UNKNOWN' };
    }
  }
  function runScript(steps, name) {
    print('SCRIPT · ' + name + ' · ' + steps.length + ' step(s)', KIND.head);
    var last = 'ALLOWED';
    for (var i = 0; i < steps.length; i++) {
      print('  ── ' + (i + 1) + '/' + steps.length + '  ' + steps[i], KIND.mute);
      last = execLine(steps[i]);
      if (last === 'REFUSED' || last === 'ERROR' || last === 'UNKNOWN') break;
    }
    S.audit('TERMINAL_SCRIPT', name, last, steps.length + ' in-memory macro steps'); S.save();
    print('  Script finished · last decision ' + last, last === 'ALLOWED' ? KIND.ok : KIND.warn);
    return { decision: last };
  }

  /* --------------------------- workbench panel --------------------------- */
  function workbenchTabs() {
    var tabs = ['session', 'files', 'plan', 'diff', 'approvals', 'tools', 'audit'];
    return '<div class="oc-tabs">' + tabs.map(function (t) {
      return '<button class="oc-tab' + (ui.terminalWorkbenchTab === t ? ' active' : '') +
        '" data-action="terminal-tab" data-tab="' + t + '">' + esc(t.toUpperCase()) + '</button>';
    }).join('') + '</div>';
  }
  function ocChip(cmd, label) {
    return '<button class="example-chip" data-action="terminal-cmd" data-cmd="' + esc(cmd) + '">' + esc(label) + '</button>';
  }
  function workbenchHtml() {
    if (!OP) return '<div class="oc-panel"><p class="muted">Adapter unavailable.</p></div>';
    var s = ui.opencode, sm = OP.summary(s), tab = ui.terminalWorkbenchTab, body = '';
    if (tab === 'session') {
      body = '<div class="oc-stat"><b>' + sm.tools + '</b><span>TOOLS</span></div>' +
        '<div class="oc-stat"><b>' + sm.agents + '</b><span>AGENTS</span></div>' +
        '<div class="oc-stat"><b>' + sm.files + '</b><span>VFS FILES</span></div>' +
        '<div class="oc-stat"><b>' + sm.pending + '</b><span>APPROVALS</span></div>' +
        '<div class="oc-kv"><span>AGENT</span><code>' + esc(s.agent) + '</code></div>' +
        '<div class="oc-kv"><span>SESSION</span><code>' + esc(s.id) + '</code></div>' +
        '<div class="oc-kv"><span>GOAL</span><code>' + esc(s.vars.goal || '—') + '</code></div>' +
        '<div class="oc-kv"><span>CHANGED</span><code>' + sm.changed + ' virtual file(s)</code></div>' +
        '<div class="oc-kv"><span>CALLS</span><code>' + sm.calls + ' sealed in ledger</code></div>' +
        '<div class="oc-actions">' + ocChip('oc plan "audit headers and fix app"', 'Plan') +
        ocChip('oc run "audit headers and fix app"', 'Run') + ocChip('oc permissions', 'Policy') +
        ocChip('vfs diagnostics', 'Diagnostics') + '</div>';
    } else if (tab === 'files') {
      body = '<div class="oc-list">' + OP.files(s).map(function (p) {
        return '<button class="oc-row" data-action="terminal-cmd" data-cmd="vfs cat ' + esc(p) + '">' +
          '<code>' + esc(p) + '</code><small>' + String(s.files[p]).length + ' B</small></button>';
      }).join('') + '</div><div class="oc-actions">' + ocChip('vfs ls', 'List') +
        ocChip('vfs grep eval', 'Grep "eval"') + ocChip('diff', 'Diff') + '</div>';
    } else if (tab === 'plan') {
      body = (s.todos.length ? '<div class="oc-list">' + s.todos.map(function (t, i) {
        return '<div class="oc-row"><code>' + (t.status === 'done' ? '✔' : String(i + 1).padStart(2, ' ')) + '</code><span>' +
          esc(t.text) + '</span><small>' + esc(t.status) + '</small></div>';
      }).join('') + '</div>' : '<p class="muted">No plan yet. Run `oc plan "<goal>"`.</p>') +
        '<div class="oc-actions">' + ocChip('oc plan "review workspace"', 'New plan') +
        ocChip('oc run "review workspace"', 'Execute') + ocChip('tool todowrite', 'Todos') + '</div>';
    } else if (tab === 'diff') {
      var changed = OP.diff(s).filter(function (d) { return d.changed; });
      body = (changed.length ? changed.map(function (d) {
        return '<div class="oc-diff"><code>' + esc(d.file) + '</code><pre>' +
          esc(d.ops.filter(function (o) { return o.t !== ' '; }).slice(0, 14).map(function (o) { return o.t + o.v; }).join('\n')) +
          '</pre></div>';
      }).join('') : '<p class="muted">Virtual workspace clean. Approve a patch to see a diff.</p>') +
        '<div class="oc-actions">' + ocChip('diff', 'Full diff') +
        '<button class="example-chip" data-action="terminal-export-diff">Export diff</button></div>';
    } else if (tab === 'approvals') {
      body = (s.pending.length ? '<div class="oc-list">' + s.pending.map(function (p) {
        return '<div class="oc-row"><code>' + esc(p.tool) + '</code><span>' + esc(p.reason) + '</span></div>' +
          '<div class="oc-actions"><button class="example-chip" data-action="terminal-approve" data-id="' + esc(p.id) +
          '" data-decision="approve">Approve</button><button class="example-chip" data-action="terminal-approve" data-id="' +
          esc(p.id) + '" data-decision="deny">Deny</button></div>';
      }).join('') : '<p class="muted">No pending approvals. Every write is reviewed here first.</p>') +
        '<div class="oc-actions">' + ocChip('approvals', 'List') + ocChip('vfs patch src/app.js "return res.send(eval(html));" "return res.send(safe(html));"', 'Try a patch') + '</div>';
    } else if (tab === 'tools') {
      body = '<div class="oc-list">' + OP.TOOLS.slice(0, 22).map(function (t) {
        return '<button class="oc-row" data-action="terminal-cmd" data-cmd="oc tool ' + esc(t.id) + '">' +
          '<code>' + esc(t.id) + '</code><span>' + esc(t.key) + '</span><small>' + esc(t.action) + '</small></button>';
      }).join('') + '</div><div class="oc-actions">' + ocChip('oc tools', 'All tools') +
        ocChip('oc tools deny', 'Hard-denied') + ocChip('oc agents', 'Agents') + '</div>';
    } else if (tab === 'audit') {
      body = '<div class="oc-list">' + (S.state.audit || []).slice(-12).reverse().map(function (a) {
        return '<div class="oc-row"><code>#' + esc(a.seq) + '</code><span>' + esc(a.action) + ' · ' +
          esc(a.target) + '</span><small>' + esc(a.decision) + '</small></div>';
      }).join('') + '</div><div class="oc-actions">' + ocChip('audit verify', 'Verify chain') +
        ocChip('report export', 'Export evidence') + '</div>';
    }
    return '<div id="terminal-workbench" class="oc-panel">' + workbenchTabs() +
      '<div class="oc-body">' + body + '</div></div>';
  }
  function paintWorkbench() {
    var host = $('terminal-workbench');
    if (!host || !OP) return;
    host.outerHTML = workbenchHtml();
  }

  function dispatch(line) {
    var t = tokenize(line), name = (t[0] || '').toLowerCase(), argv = t.slice(1);
    var c = COMMANDS[name], decision = 'ALLOWED';
    if (!c) { print('command not found: ' + name + '  (try `help`)', KIND.bad); decision = 'UNKNOWN'; }
    else {
      try {
        var out = c.run(argv, line);
        if (out && out.decision) decision = out.decision;
      } catch (err) {
        print('runtime error: ' + (err && err.message ? err.message : String(err)), KIND.bad);
        decision = 'ERROR';
      }
    }
    S.audit('TERMINAL_CMD', name || '(empty)', decision, line.slice(0, 180));
    S.save();
    return decision;
  }
  function runPipeline(parts) {
    quiet = true; captureSink = [];
    var first = 'ALLOWED';
    try { first = dispatch(expandVars(expandAliasOnce(parts[0]))); }
    catch (e) { first = 'ERROR'; }
    var lines = captureSink.slice();
    quiet = false; captureSink = null;
    for (var i = 1; i < parts.length; i++) lines = applyFilter(lines, expandVars(parts[i]));
    if (!lines.length) lines = ['(empty pipeline result)'];
    lines.forEach(function (l) { print(l, KIND.data); });
    print('  pipeline: ' + parts.length + ' stages · ' + lines.length + ' output line(s)', KIND.mute);
    S.audit('TERMINAL_PIPE', parts[0].split(/\s+/)[0] || 'pipe', first,
      parts.length + ' stages · ' + lines.length + ' lines'); S.save();
    return first;
  }
  function execLine(line) {
    var expanded = expandVars(expandAliasOnce(String(line || '').trim()));
    if (!expanded) return 'ALLOWED';
    var pipes = splitOutside(expanded, '|');
    if (pipes.length > 1) return runPipeline(pipes);
    return dispatch(expanded);
  }
  function exec(raw) {
    var line = String(raw || '').trim();
    if (!line) return;
    ui.terminalHistory.push(line);
    if (ui.terminalHistory.length > 200) ui.terminalHistory.shift();
    ui.terminalHistIndex = -1;
    push('aegis ❯ ' + line, KIND.cmd, 'IN');
    var segs = splitChain(line), ok = true;
    segs.forEach(function (s) {
      if (s.op === '&&' && !ok) { print('  skipped (previous && failed)', KIND.mute); return; }
      var d = execLine(s.cmd);
      ok = d !== 'REFUSED' && d !== 'UNKNOWN' && d !== 'ERROR' && d !== 'INVALID';
    });
    push('', KIND.mute);
    paint();
    paintWorkbench();
    root.setTimeout(focusInput, 0);
  }

  /* ------------------------------ UI wiring ------------------------------ */
  U.registerNav('OPERATE', [{ id: 'terminal', label: 'AEGIS Terminal', icon: 'terminal', key: 'M' }]);
  U.registerMeta({ terminal: { id: 'terminal', label: 'AEGIS Terminal', icon: 'terminal', key: 'M' } });
  U.registerCommands([
    { label: 'Open the AEGIS terminal', hint: 'OPERATE', icon: 'terminal', run: function () { U.navigate('terminal'); root.setTimeout(focusInput, 0); } },
    { label: 'HexStrike tool catalog', hint: 'ANALYZE', icon: 'cpu', run: function () { U.navigate('terminal'); root.setTimeout(function () { exec('hexstrike tools'); }, 0); } },
    { label: 'Print MCP manifest', hint: 'GOVERN', icon: 'file', run: function () { U.navigate('terminal'); root.setTimeout(function () { exec('mcp manifest'); }, 0); } },
    { label: 'OpenCode workbench status', hint: 'OPERATE', icon: 'cpu', run: function () { U.navigate('terminal'); root.setTimeout(function () { exec('oc status'); }, 0); } },
    { label: 'Run OpenCode governed plan', hint: 'AGENT', icon: 'bolt', run: function () { U.navigate('terminal'); root.setTimeout(function () { exec('oc run "audit headers and fix app"'); }, 0); } }
  ]);

  U.registerAction('terminal-quick', function (t) {
    var cmd = t.getAttribute('data-cmd');
    if (cmd) exec(cmd);
  });
  U.registerAction('terminal-copy', function () {
    U.copy(ui.terminalLines.map(function (l) { return '[' + l.t + '] ' + l.text; }).join('\n'));
  });
  U.registerAction('terminal-tab', function (t) {
    ui.terminalWorkbenchTab = t.getAttribute('data-tab') || 'session';
    paintWorkbench();
  });
  U.registerAction('terminal-cmd', function (t) {
    var cmd = t.getAttribute('data-cmd');
    if (cmd) exec(cmd);
  });
  U.registerAction('terminal-approve', function (t) {
    var id = t.getAttribute('data-id'), decision = t.getAttribute('data-decision') === 'deny' ? 'deny' : 'approve';
    if (!id) return;
    U.closeModal();
    exec('oc ' + decision + ' ' + id);
  });
  U.registerAction('terminal-export-diff', function () {
    if (!OP) return;
    var text = OP.diffText(ui.opencode) || 'No virtual file changes.\n';
    var saved = exportFile('aegis-opencode-workspace.patch', text);
    S.audit('OPENCODE_DIFF_EXPORT', 'virtual workspace', 'EXPORTED', 'Unified diff export.'); S.save();
    U.toast('Virtual diff ' + (saved ? 'downloaded' : 'prepared') + '.', 'ok');
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
      ['help', 'help'], ['status', 'status'], ['oc status', 'oc status'], ['oc tools', 'oc tools'],
      ['oc run "audit headers and fix app"', 'oc run'],
      ['vfs ls', 'vfs ls'], ['vfs diagnostics', 'diagnostics'], ['sh help', 'sh help'],
      ['hexstrike tools', 'hexstrike tools'], ['mcp manifest', 'mcp manifest'],
      ['orchestrator run', 'orchestrator run'], ['mitre coverage', 'mitre coverage'],
      ['policy', 'policy']
    ];
    var osm = OP ? OP.summary(ui.opencode) : { tools: 0, allow: 0, ask: 0, deny: 0, agents: 0, permissions: 0 };
    return '<div class="page-head"><div><div class="eyebrow">OPERATE · OPERATOR TERMINAL · OPENCODE WORKBENCH</div><h1>AEGIS Terminal</h1>' +
      '<p>An ultra-advanced, governed command line for the whole platform: OpenCode-compatible agents, tools, permissions, a virtual workspace, deterministic planning, pipelines and HexStrike AI v6.0 — all offline.</p></div>' +
      '<div class="head-actions"><span class="chip chip-lock">' + icon('shield') + ' AUTHORIZATION-BOUND</span>' +
      '<button class="btn btn-ghost" data-action="terminal-manifest">' + icon('download') + ' MCP manifest</button>' +
      '<button class="btn btn-ghost" data-action="terminal-copy">' + icon('file') + ' Copy log</button></div></div>' +
      '<div class="callout callout-info"><div class="callout-icon">' + icon('lock') + '</div><div><b>This is not a system shell.</b>' +
      '<p>No OS process is spawned, no socket is opened, no LLM provider is called and no real file is written. Every command is interpreted by the AEGIS policy engine, checked against the signed capability manifest and sealed in the hash-chained ledger. The OpenCode workbench operates on an in-memory virtual workspace; HexStrike tool names map to real offline analyzers or to hard refusals — never to upstream binaries.</p></div></div>' +
      '<div class="terminal-layout"><div class="col-main">' +
        '<div class="terminal-window"><div class="terminal-bar"><span class="t-dots"><i></i><i></i><i></i></span>' +
        '<span class="t-title">operator@aegis-sentinel: ~ </span><span class="t-badge">OPENCODE v2.2 · HEXSTRIKE v6.0 · OFFLINE</span></div>' +
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
        section('OpenCode adapter', OP ? OP.UPSTREAM.repo + '@v' + OP.UPSTREAM.version : 'unavailable', '<span class="tag">CONTRACT ONLY</span>',
          '<div class="stat-row"><div><b>' + osm.tools + '</b><span>TOOLS</span></div>' +
          '<div><b>' + osm.agents + '</b><span>AGENTS</span></div>' +
          '<div><b>' + osm.deny + '</b><span>HARD-DENIED</span></div></div>' +
          '<div class="terminal-meta">' +
          '<div><span>PERMISSIONS</span><code>' + osm.permissions + ' keys · allow / ask / deny</code></div>' +
          '<div><span>PLANNER</span><code>aegis-deterministic-v2</code></div>' +
          '<div><span>WORKSPACE</span><code>in-memory VFS · no disk</code></div>' +
          '<div><span>APPROVAL</span><code>human-in-the-loop for writes</code></div>' +
          '</div><p class="muted" style="margin-top:10px;font-size:10.5px">' + esc(OP ? OP.UPSTREAM.note : '') + '</p>') +
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
      '</div></div>' +
      '<div class="oc-shell"><div class="oc-head"><div><div class="eyebrow">OPENCODE · GOVERNED AGENT WORKBENCH</div>' +
      '<h2>Live workbench</h2><p>Session state, virtual files, plans, diffs, approvals, tool policy and ledger — updated after every command.</p></div>' +
      '<span class="chip chip-lock">' + icon('shield') + ' NO EGRESS · NO OS PROCESS · NO MODEL CALL</span></div>' +
      workbenchHtml() + '</div>';
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
      else if (/^(run|call)$/.test(parts[parts.length - 2]) || /^(hexstrike|mcp)$/.test(parts[0])) pool = HX.TOOLS.map(function (x) { return x.id; });
      else if (/^(tool|cat|read|glob|grep|diff)$/.test(parts[parts.length - 2]) || /^(oc|opencode|vfs)$/.test(parts[0]))
        pool = (OP ? OP.TOOLS.map(function (x) { return x.id; }) : []).concat(OP ? OP.files(ui.opencode) : []);
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
    exec: exec, commands: COMMANDS, lines: ui.terminalLines, hexstrike: HX, opencode: OP,
    session: ui.opencode, vars: ui.terminalVars, aliases: ui.terminalAliases, scripts: ui.terminalScripts,
    render: function () { bootBanner(); U.renderView(); paint(); paintWorkbench(); }
  };
})(typeof globalThis !== 'undefined' ? globalThis : this);
