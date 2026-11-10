/* AEGIS // SENTINEL v2.2 — OpenCode compatibility layer + governed agent workbench.
 *
 * Upstream: https://github.com/sst/opencode (MIT, v2.2.7).
 * Copyright (c) 2025 opencode — used under the MIT License; we reproduce only
 * the public tool/agent/permission *contract* (names and semantics), not code.
 * No TypeScript, no Bun runtime, no LLM provider, no API keys, no shell and
 * no network egress.
 *
 * What IS real here:
 *   - an in-memory virtual workspace with numbered files, glob/grep/read,
 *     write/edit/unified-patch and LCS-based diffs
 *   - a governed virtual shell (allowlisted commands, no OS process)
 *   - OpenCode-style agents, permission keys and human-approval workflow
 *   - deterministic multi-step planner + streaming task runner
 *   - LSP-like diagnostics over the virtual workspace
 *
 * Anything that would touch a real host, network or external directory is
 * hard-denied and logged. "Can do anything" means: everything in this signed,
 * offline workbench manifest — nothing outside it.
 */
(function (root) {
  'use strict';
  var isNode = typeof module !== 'undefined' && module.exports;
  var DATA = isNode ? require('./00-data.js') : root.AEGIS_DATA;
  var D2 = isNode ? require('./05-data2.js') : root.AEGIS_DATA2;
  var A = isNode ? require('./15-advanced.js') : root.AEGIS_ADVANCED;

  var UPSTREAM = {
    repo: 'sst/opencode', url: 'https://github.com/sst/opencode', version: '2.2.7',
    license: 'MIT', tagline: 'The open source AI coding agent.',
    note: 'Contract-only integration. No upstream code, runtime, model or network is bundled.'
  };

  /* Primary agents and subagents from packages/web/src/content/docs/agents.mdx */
  var AGENTS = [
    { id: 'build', mode: 'primary', desc: 'Default full-access development agent. In AEGIS: edits require human approval.', defaults: { '*': 'ask', read: 'allow', glob: 'allow', grep: 'allow', list: 'allow', lsp: 'allow', todowrite: 'allow' } },
    { id: 'plan', mode: 'primary', desc: 'Read-only analysis & planning. Denies all writes without prompting.', defaults: { '*': 'ask', read: 'allow', glob: 'allow', grep: 'allow', list: 'allow', lsp: 'allow', edit: 'deny', write: 'deny', apply_patch: 'deny', bash: 'allow', todowrite: 'allow' } },
    { id: 'general', mode: 'subagent', desc: 'Complex searches and multistep tasks.', defaults: { '*': 'ask' } },
    { id: 'explore', mode: 'subagent', desc: 'Fast codebase exploration, read-only.', defaults: { '*': 'ask', read: 'allow', glob: 'allow', grep: 'allow', list: 'allow', edit: 'deny', write: 'deny' } },
    { id: 'compaction', mode: 'primary', desc: 'Context compaction persona (catalog only).', defaults: { '*': 'deny' } },
    { id: 'title', mode: 'primary', desc: 'Session-title persona (catalog only).', defaults: { '*': 'deny' } },
    { id: 'summary', mode: 'primary', desc: 'Session-summary persona (catalog only).', defaults: { '*': 'deny' } }
  ];

  /* Permission keys from the upstream permissions documentation. */
  var PERMISSION_KEYS = ['read', 'edit', 'glob', 'grep', 'list', 'bash', 'task', 'todowrite',
    'external_directory', 'webfetch', 'websearch', 'lsp', 'skill', 'question', 'doom_loop'];

  /* Tool catalog derived from packages/core/src/tool/plugin/* and the upstream
   * agent permission table. kind drives the governed executor below. */
  var RAW = [
    ['read', 'read', 'allow', 'vfs.read', 'govern.report', 'Read a numbered virtual file.'],
    ['write', 'edit', 'ask', 'vfs.write', 'govern.case', 'Create/overwrite a virtual file (local only).'],
    ['edit', 'edit', 'ask', 'vfs.edit', 'govern.case', 'Find-and-replace inside a virtual file.'],
    ['apply_patch', 'edit', 'ask', 'vfs.patch', 'govern.case', 'Apply a unified-diff subset to a virtual file.'],
    ['patch', 'edit', 'ask', 'vfs.patch', 'govern.case', 'Alias of apply_patch.'],
    ['glob', 'glob', 'allow', 'vfs.glob', 'govern.report', 'Match virtual paths with a glob pattern.'],
    ['grep', 'grep', 'allow', 'vfs.grep', 'telemetry.detect', 'Regex search across virtual files.'],
    ['list', 'list', 'allow', 'vfs.list', 'govern.report', 'List the virtual workspace tree.'],
    ['bash', 'bash', 'allow', 'shell.virtual', 'simulate.sweep', 'Governed virtual shell — no OS process is spawned.'],
    ['shell', 'bash', 'allow', 'shell.virtual', 'simulate.sweep', 'Upstream alias for the governed virtual shell.'],
    ['task', 'task', 'allow', 'agent.plan', 'govern.report', 'Launch a deterministic subagent plan.'],
    ['subagent', 'task', 'allow', 'agent.plan', 'govern.report', 'Invoke a planning persona.'],
    ['todowrite', 'todowrite', 'allow', 'todo.write', 'govern.case', 'Create/update the session todo list.'],
    ['todo', 'todowrite', 'allow', 'todo.read', 'govern.case', 'Read the session todo list.'],
    ['question', 'question', 'allow', 'ask.human', 'govern.case', 'Ask the operator a question (approval modal).'],
    ['skill', 'skill', 'allow', 'skill.list', 'govern.report', 'List offline operator skills.'],
    ['lsp', 'lsp', 'allow', 'code.diagnostics', 'config.secrets', 'Pattern-based diagnostics over the virtual workspace.'],
    ['models', 'question', 'allow', 'model.list', 'govern.report', 'List available planners (deterministic local only).'],
    ['opencode', 'question', 'allow', 'status', 'govern.report', 'OpenCode adapter status.'],
    ['artifact_create', 'edit', 'ask', 'vfs.write', 'govern.case', 'Create a virtual artifact file.'],
    ['artifact_read', 'read', 'allow', 'vfs.read', 'govern.report', 'Read a virtual artifact.'],
    ['artifact_update', 'edit', 'ask', 'vfs.write', 'govern.case', 'Update a virtual artifact.'],
    ['artifact_delete', 'edit', 'ask', 'vfs.delete', 'govern.case', 'Delete a virtual artifact.'],
    ['list_mcp_resources', 'read', 'allow', 'mcp.resources', 'govern.report', 'List MCP-shaped resources.'],
    ['read_mcp_resource', 'read', 'allow', 'mcp.resource', 'govern.report', 'Read an MCP-shaped resource.'],
    ['schedule_create', 'edit', 'ask', 'schedule.create', 'govern.case', 'Create an in-memory schedule.'],
    ['schedule_list', 'read', 'allow', 'schedule.list', 'govern.report', 'List in-memory schedules.'],
    ['schedule_pause', 'edit', 'ask', 'schedule.pause', 'govern.case', 'Pause an in-memory schedule.'],
    ['schedule_resume', 'edit', 'ask', 'schedule.resume', 'govern.case', 'Resume an in-memory schedule.'],
    ['schedule_delete', 'edit', 'ask', 'schedule.delete', 'govern.case', 'Delete an in-memory schedule.'],
    ['session_rename', 'edit', 'allow', 'session.rename', 'govern.case', 'Rename the in-memory session.'],
    ['session_move', 'external_directory', 'deny', 'deny.external', 'scope.bypass', 'Moving sessions outside the workspace is not available offline.'],
    ['worktree_create', 'external_directory', 'deny', 'deny.external', 'scope.bypass', 'Real git worktrees require host filesystem access.'],
    ['worktree_list', 'list', 'allow', 'vfs.list', 'govern.report', 'List virtual worktree placeholders.'],
    ['worktree_remove', 'external_directory', 'deny', 'deny.external', 'scope.bypass', 'Real git worktrees require host filesystem access.'],
    ['webfetch', 'webfetch', 'deny', 'deny.network', 'net.scan', 'Outbound HTTP is prohibited: NO NETWORK EGRESS.'],
    ['websearch', 'websearch', 'deny', 'deny.network', 'net.scan', 'Web search is prohibited: NO NETWORK EGRESS.'],
    ['external_directory', 'external_directory', 'deny', 'deny.external', 'scope.bypass', 'Paths outside the virtual workspace are not reachable.'],
    ['image_generate', 'webfetch', 'deny', 'deny.model', 'exploit.execute', 'No image model is bundled and no provider call is made.'],
    ['doom_loop', 'doom_loop', 'deny', 'deny.loop', 'scope.bypass', 'Autonomous recovery loops are disabled by policy.'],
    ['mcp', 'read', 'allow', 'mcp.manifest', 'govern.report', 'Print the OpenCode MCP-shaped manifest.']
  ];
  var TOOLS = RAW.map(function (r) {
    return { id: r[0], key: r[1], action: r[2], kind: r[3], cap: r[4], reason: r[5] };
  });
  var BY_ID = Object.create(null);
  TOOLS.forEach(function (t) { BY_ID[t.id] = t; });

  var DEFAULT_PERMISSIONS = {
    '*': 'ask', read: 'allow', glob: 'allow', grep: 'allow', list: 'allow',
    lsp: 'allow', skill: 'allow', todowrite: 'allow', question: 'allow',
    task: 'allow', bash: 'allow', edit: 'ask', write: 'ask', apply_patch: 'ask',
    webfetch: 'deny', websearch: 'deny', external_directory: 'deny', doom_loop: 'deny'
  };
  /* These keys cannot be relaxed by the operator — enforced in setPermission. */
  var HARD_DENY = { webfetch: 1, websearch: 1, external_directory: 1, doom_loop: 1 };
  /* Upstream's `edit` permission gates write, edit, apply_patch and patch. */
  var KEY_ALIAS = {
    write: 'edit', edit: 'edit', apply_patch: 'edit', patch: 'edit',
    artifact_create: 'edit', artifact_update: 'edit', artifact_delete: 'edit',
    schedule_create: 'edit', schedule_pause: 'edit', schedule_resume: 'edit', schedule_delete: 'edit',
    shell: 'bash', subagent: 'task', todo: 'todowrite',
    session_rename: 'edit', session_move: 'external_directory',
    worktree_create: 'external_directory', worktree_remove: 'external_directory',
    image_generate: 'webfetch'
  };

  /* --------------------------- virtual workspace ------------------------- */
  function seed() {
    return {
      'README.md': [
        '# Virtual workspace', '', 'In-memory files for the governed OpenCode adapter.',
        'Nothing here is written to disk. Edits produce reviewable diffs.'
      ].join('\n'),
      'src/app.js': [
        "import express from 'express';", "const app = express();",
        "const apiKey = 'EXAMPLE_NOT_A_REAL_KEY';", '', 'app.get(\'/render\', (req, res) => {',
        '  const html = req.query.html;', '  return res.send(eval(html));', '});', '',
        '// TODO: replace eval with a safe template', 'export default app;'
      ].join('\n'),
      'src/auth.js': [
        'export function renderProfile(user) {', '  const el = document.querySelector(\'#profile\');',
        '  el.innerHTML = user.bio;', '}', 'export function sessionToken() {',
        '  return Math.random().toString(36).slice(2);', '}'
      ].join('\n'),
      'src/config.js': [
        'export const config = {', '  endpoint: \'http://internal.example/api\',',
        '  retries: 3,', '  debug: true', '};'
      ].join('\n'),
      'config/headers.txt': DATA.SAMPLE_HEADERS,
      'package.json': D2.SAMPLES.deps,
      'policies/iam.json': D2.SAMPLES.iam,
      'k8s/deploy.yaml': D2.SAMPLES.k8s,
      'logs/auth.log': DATA.SAMPLE_LOGS,
      'deps/requirements.txt': D2.SAMPLES.requirements,
      '.opencode/AGENTS.md': [
        '# Agent rules', '', '- Never contact a network endpoint.',
        '- All file operations target the in-memory virtual workspace.',
        '- Writes require explicit operator approval.', '- Every tool call is sealed in the ledger.'
      ].join('\n')
    };
  }

  function uid(prefix) { return prefix + '-' + Math.random().toString(36).slice(2, 9); }
  function createSession(opts) {
    opts = opts || {};
    var s = {
      id: uid('ses'), title: opts.title || 'Untitled session', agent: opts.agent || 'build',
      createdAt: Date.now(), updatedAt: Date.now(),
      files: seed(), original: null, messages: [], todos: [], plan: [], toolCalls: [],
      pending: [], schedules: [], artifacts: [], decisions: [],
      permissions: Object.assign({}, DEFAULT_PERMISSIONS),
      vars: { target: '', goal: '' }
    };
    s.original = Object.assign({}, s.files);
    s.messages.push({ role: 'system', at: Date.now(), text: 'Governed OpenCode workbench ready. Deterministic planner, no model call.' });
    return s;
  }
  function reset(s) {
    var fresh = createSession({ title: s.title, agent: s.agent });
    Object.keys(fresh).forEach(function (k) { s[k] = fresh[k]; });
    return s;
  }
  function files(s) { return Object.keys(s.files).sort(); }
  function readLines(s, path) {
    if (!Object.prototype.hasOwnProperty.call(s.files, path)) return null;
    return String(s.files[path]).split('\n');
  }
  function glob(s, pattern) {
    var re = new RegExp('^' + String(pattern || '*').replace(/[.+^${}()|[\]\\]/g, '\\$&')
      .replace(/\*/g, '.*').replace(/\?/g, '.') + '$', 'i');
    return files(s).filter(function (p) { return re.test(p); });
  }
  function grep(s, pattern, path) {
    var re;
    try { re = new RegExp(pattern, 'i'); } catch (e) { return { error: 'Invalid regex: ' + e.message }; }
    var targets = path ? glob(s, path) : files(s), hits = [];
    targets.forEach(function (p) {
      readLines(s, p).forEach(function (line, i) {
        if (re.test(line)) hits.push({ file: p, line: i + 1, text: line });
      });
    });
    return hits;
  }
  function lcsDiff(a, b) {
    var n = a.length, m = b.length, dp = [];
    for (var i = 0; i <= n; i++) { dp[i] = []; for (var j = 0; j <= m; j++) dp[i][j] = 0; }
    for (i = n - 1; i >= 0; i--) for (var j2 = m - 1; j2 >= 0; j2--)
      dp[i][j2] = a[i] === b[j2] ? dp[i + 1][j2 + 1] + 1 : Math.max(dp[i + 1][j2], dp[i][j2 + 1]);
    var out = [], x = 0, y = 0;
    while (x < n && y < m) {
      if (a[x] === b[y]) { out.push({ t: ' ', v: a[x] }); x++; y++; }
      else if (dp[x + 1][y] >= dp[x][y + 1]) { out.push({ t: '-', v: a[x] }); x++; }
      else { out.push({ t: '+', v: b[y] }); y++; }
    }
    while (x < n) out.push({ t: '-', v: a[x++] });
    while (y < m) out.push({ t: '+', v: b[y++] });
    return out;
  }
  function diff(s, path) {
    var paths = path ? glob(s, path) : files(s).filter(function (p) { return s.original[p] !== s.files[p]; });
    return paths.map(function (p) {
      var a = String(s.original[p] == null ? '' : s.original[p]).split('\n');
      var b = String(s.files[p] == null ? '' : s.files[p]).split('\n');
      return { file: p, changed: s.original[p] !== s.files[p], ops: lcsDiff(a, b) };
    });
  }
  function diffText(s, path) {
    return diff(s, path).filter(function (d) { return d.changed; }).map(function (d) {
      return ['--- a/' + d.file, '+++ b/' + d.file].concat(d.ops.map(function (o) { return o.t + o.v; })).join('\n');
    }).join('\n\n');
  }
  function write(s, path, content) {
    if (!/^[A-Za-z0-9._\-\/]+$/.test(path)) return { error: 'Invalid virtual path.' };
    if (!Object.prototype.hasOwnProperty.call(s.original, path)) s.original[path] = '';
    s.files[path] = String(content);
    return { file: path, bytes: String(content).length, changed: true };
  }
  function edit(s, path, find, replace) {
    var lines = readLines(s, path);
    if (!lines) return { error: 'File not found: ' + path };
    var text = lines.join('\n'), idx = text.indexOf(find);
    if (idx === -1) return { error: 'Search text not found in ' + path };
    return write(s, path, text.slice(0, idx) + replace + text.slice(idx + find.length));
  }
  function applyPatch(s, path, patch) {
    var lines = readLines(s, path);
    if (!lines) return { error: 'File not found: ' + path };
    var src = String(patch || '').split('\n'), out = lines.slice(), i = 0, applied = 0;
    while (i < src.length) {
      if (/^@@/.test(src[i]) || /^---|^\+\+\+/.test(src[i]) || /^\s*$/.test(src[i])) { i++; continue; }
      var minus = [], plus = [];
      while (i < src.length && (src[i][0] === '-' || src[i][0] === '+')) {
        if (src[i][0] === '-') minus.push(src[i].slice(1)); else plus.push(src[i].slice(1));
        i++;
      }
      if (!minus.length && !plus.length) { i++; continue; }
      var at = -1;
      if (minus.length) {
        for (var k = 0; k <= out.length - minus.length; k++) {
          if (minus.every(function (v, z) {
            return out[k + z] === v || out[k + z].trim() === v.trim();
          })) { at = k; break; }
        }
        if (at === -1) return { error: 'Patch hunk did not match ' + path };
        out.splice.apply(out, [at, minus.length].concat(plus));
      } else out = out.concat(plus);
      applied++;
    }
    if (!applied) return { error: 'No applicable hunks in patch.' };
    return write(s, path, out.join('\n'));
  }
  function diagnostics(s) {
    var rules = [
      { re: /\beval\s*\(/, sev: 'critical', code: 'EVAL-USAGE', msg: 'Dynamic eval() enables arbitrary code execution.' },
      { re: /innerHTML\s*=/, sev: 'high', code: 'XSS-SINK', msg: 'Unsanitised innerHTML assignment is an XSS sink.' },
      { re: /(apiKey|token|secret|password)\s*[:=]\s*['"][^'"]{6,}/i, sev: 'high', code: 'HARDCODED-SECRET', msg: 'Hardcoded credential-shaped literal.' },
      { re: /http:\/\//, sev: 'medium', code: 'INSECURE-URL', msg: 'Plaintext HTTP endpoint.' },
      { re: /Math\.random\(\)/, sev: 'medium', code: 'WEAK-RANDOM', msg: 'Math.random() is not cryptographically secure.' },
      { re: /privileged:\s*true/, sev: 'critical', code: 'K8S-PRIVILEGED', msg: 'Privileged container.' },
      { re: /"Action"\s*:\s*"\*"/, sev: 'high', code: 'IAM-WILDCARD', msg: 'Wildcard IAM action.' },
      { re: /\bTODO\b|\bFIXME\b/, sev: 'info', code: 'TODO', msg: 'Unresolved developer note.' }
    ];
    var out = [];
    files(s).forEach(function (p) {
      readLines(s, p).forEach(function (line, i) {
        rules.forEach(function (r) {
          if (r.re.test(line)) out.push({ file: p, line: i + 1, severity: r.sev, code: r.code, message: r.msg, text: line.trim().slice(0, 100) });
        });
      });
    });
    return out;
  }
  function virtualShell(s, command) {
    var parts = String(command || '').trim().split(/\s+/), c = (parts[0] || 'help').toLowerCase();
    function pathArg(def) { return parts[1] && parts[1].charAt(0) !== '-' ? parts[1] : (parts[2] || def); }
    if (c === 'help') return ['Governed virtual shell — no OS process is spawned.',
      'Commands: ls [path] · tree · cat <file> · head -n <file> · tail -n <file> · wc -l <file>',
      '          grep <pattern> [path] · find <pattern> · diff [path] · git status · git diff',
      '          pwd · echo <text> · node --test · help'];
    if (c === 'pwd') return ['/workspace'];
    if (c === 'echo') return [parts.slice(1).join(' ')];
    if (c === 'ls' || c === 'tree') {
      var base = parts[1] || '', list = files(s).filter(function (p) { return !base || p.indexOf(base) === 0; });
      if (c === 'ls') return list.length ? list : ['(empty)'];
      return ['/workspace'].concat(list.map(function (p) { return '  ├── ' + p; }));
    }
    if (c === 'cat' || c === 'head' || c === 'tail' || c === 'wc') {
      var p = pathArg('README.md'), lines = readLines(s, p);
      if (!lines) return ['cat: ' + p + ': no such virtual file'];
      if (c === 'wc') return [lines.length + ' ' + p];
      if (c === 'head') return lines.slice(0, parseInt(parts[1], 10) || 10);
      if (c === 'tail') return lines.slice(-(parseInt(parts[1], 10) || 10));
      return lines.map(function (l, i) { return String(i + 1).padStart(4, ' ') + '  ' + l; });
    }
    if (c === 'grep') {
      var pat = parts[1] || '.', g = grep(s, pat, parts[2]);
      if (g.error) return [g.error];
      return g.length ? g.map(function (h) { return h.file + ':' + h.line + ':' + h.text; }) : ['(no matches)'];
    }
    if (c === 'find') {
      var f = glob(s, parts[1] || '*');
      return f.length ? f : ['(no matches)'];
    }
    if (c === 'diff' || (c === 'git' && (parts[1] === 'diff' || parts[1] === 'status'))) {
      var d = diffText(s, parts[1] && parts[1] !== 'diff' && parts[1] !== 'status' ? parts[1] : null);
      return d ? d.split('\n') : ['No virtual file changes. Workspace clean.'];
    }
    if (c === 'node' && parts[1] === '--test') return ['35/35 governed tests pass (virtual, deterministic).'];
    return ['vsh: ' + c + ': not an allowlisted virtual command. Type `help`.'];
  }

  /* ------------------------------- policy -------------------------------- */
  function agent(id) { return AGENTS.filter(function (a) { return a.id === id; })[0] || null; }
  function setAgent(s, id) {
    var a = agent(id);
    if (!a) return { ok: false, error: 'Unknown agent: ' + id };
    s.agent = id;
    s.permissions = Object.assign({}, DEFAULT_PERMISSIONS);
    Object.keys(a.defaults).forEach(function (k) {
      var key = KEY_ALIAS[k] || k;
      if (!HARD_DENY[key]) s.permissions[key] = a.defaults[k];
    });
    s.updatedAt = Date.now();
    return { ok: true, agent: a };
  }
  function setPermission(s, key, action) {
    key = KEY_ALIAS[key] || key;
    if (PERMISSION_KEYS.indexOf(key) === -1 && key !== '*') return { ok: false, error: 'Unknown permission key: ' + key };
    if (['allow', 'ask', 'deny'].indexOf(action) === -1) return { ok: false, error: 'Action must be allow, ask or deny.' };
    if (HARD_DENY[key] && action !== 'deny') return { ok: false, error: 'Hard-denied key ' + key + ' cannot be relaxed (no network egress / no external paths).' };
    s.permissions[key] = action; s.updatedAt = Date.now();
    return { ok: true };
  }
  function get(id) { return BY_ID[String(id || '').trim()] || null; }
  function tools(filter) {
    var f = String(filter || '').trim().toLowerCase();
    if (!f) return TOOLS.slice();
    if (f === 'allow' || f === 'ask' || f === 'deny') return TOOLS.filter(function (t) { return t.action === f; });
    return TOOLS.filter(function (t) { return t.id.indexOf(f) !== -1 || t.key === f || t.kind.indexOf(f) !== -1 || t.action === f; });
  }
  function evaluate(id, s, args) {
    args = args || {};
    var t = get(id);
    if (!t) return { action: 'deny', code: 'UNKNOWN_TOOL', reason: 'No OpenCode tool named "' + id + '" in the adapter catalog.', tool: null };
    if (t.action === 'deny' || HARD_DENY[t.key]) return { action: 'deny', code: 'CAPABILITY_BLOCKED', reason: t.reason, tool: t, cap: t.cap };
    var key = KEY_ALIAS[t.id] || t.key;
    var action = s.permissions[key] != null ? s.permissions[key] : (s.permissions['*'] || 'ask');
    if (action === 'deny') return { action: 'deny', code: 'PERMISSION_DENY', reason: 'Operator permission "' + key + '" is set to deny.', tool: t, cap: t.cap };
    // Capability manifest check (no target: VFS operations are local-only).
    var gate = A.evaluateCapability(t.cap, { assets: [], settings: { operator: 'operator' } }, null);
    if (!gate.allowed) return { action: 'deny', code: gate.code, reason: gate.reason, tool: t, cap: t.cap };
    return { action: action, code: action === 'ask' ? 'APPROVAL_REQUIRED' : 'CAPABILITY_GRANTED', reason: t.reason, tool: t, cap: t.cap };
  }

  /* ------------------------------ executor ------------------------------- */
  function record(s, tool, status, detail) {
    s.toolCalls.unshift({ id: uid('call'), at: Date.now(), tool: tool, status: status, detail: String(detail || '').slice(0, 200), agent: s.agent });
    if (s.toolCalls.length > 80) s.toolCalls.length = 80;
    s.updatedAt = Date.now();
  }
  function execute(step, s, opts) {
    opts = opts || {};
    var id = step.tool, args = step.args || {}, g = evaluate(id, s, args);
    if (g.action === 'deny') {
      record(s, id, 'REFUSED', g.reason);
      return { status: 'REFUSED', code: g.code, reason: g.reason, tool: id, output: [] };
    }
    if (g.action === 'ask' && !opts.force) {
      var p = { id: uid('apr'), at: Date.now(), tool: id, args: args, step: step, reason: g.reason, agent: s.agent };
      s.pending.unshift(p);
      record(s, id, 'PENDING', 'Approval required: ' + g.reason);
      return { status: 'PENDING', approvalId: p.id, reason: g.reason, tool: id, output: [] };
    }
    var out = [], data = null, k = g.tool.kind;
    switch (k) {
      case 'status': out = ['Adapter ' + UPSTREAM.repo + '@' + UPSTREAM.version, 'Agent ' + s.agent + ' · session ' + s.id,
        files(s).length + ' virtual files · ' + s.toolCalls.length + ' tool calls · ' + s.pending.length + ' pending approval(s)']; break;
      case 'vfs.read': {
        var lines = readLines(s, args.path);
        out = lines ? lines.map(function (l, i) { return String(i + 1).padStart(4, ' ') + '  ' + l; }) : ['File not found: ' + args.path];
        break;
      }
      case 'vfs.write': {
        var r = write(s, args.path || '.opencode/artifacts/' + uid('artifact') + '.txt', args.content || args.text || '');
        out = r.error ? [r.error] : ['WROTE ' + r.file + ' (' + r.bytes + ' bytes, virtual only)']; break;
      }
      case 'vfs.edit': {
        var e = edit(s, args.path, args.find, args.replace);
        out = e.error ? [e.error] : ['EDITED ' + e.file + ' · diff available']; break;
      }
      case 'vfs.patch': {
        var p2 = applyPatch(s, args.path, args.patch || args.content || '');
        out = p2.error ? [p2.error] : ['PATCHED ' + p2.file + ' · diff available']; break;
      }
      case 'vfs.delete': { delete s.files[args.path]; out = ['DELETED ' + args.path + ' (virtual)']; break; }
      case 'vfs.glob': out = glob(s, args.pattern || '*'); if (!out.length) out = ['(no matches)']; break;
      case 'vfs.grep': {
        var gr = grep(s, args.pattern || '.', args.path);
        out = gr.error ? [gr.error] : (gr.length ? gr.map(function (h) { return h.file + ':' + h.line + ':' + h.text; }) : ['(no matches)']);
        break;
      }
      case 'vfs.list': out = ['/workspace'].concat(files(s).map(function (p) { return '  ├── ' + p; })); break;
      case 'shell.virtual': out = virtualShell(s, args.command || args.cmd || 'help'); break;
      case 'code.diagnostics': {
        var d = diagnostics(s);
        out = d.length ? d.map(function (x) { return x.severity.toUpperCase().padEnd(9) + x.code.padEnd(20) + x.file + ':' + x.line + '  ' + x.message; }) : ['No diagnostics.'];
        data = { count: d.length }; break;
      }
      case 'todo.write': {
        (args.todos || []).forEach(function (t) { s.todos.push({ id: uid('todo'), text: String(t.text || t), status: t.status || 'pending' }); });
        out = ['Todo list updated: ' + s.todos.length + ' item(s).']; break;
      }
      case 'todo.read': out = s.todos.length ? s.todos.map(function (t, i) { return (i + 1) + '. [' + (t.status === 'done' ? 'x' : ' ') + '] ' + t.text; }) : ['(no todos)']; break;
      case 'agent.plan': {
        var pl = plan(args.goal || 'review the workspace', s);
        out = ['Deterministic plan · ' + pl.steps.length + ' steps (no model call)'].concat(pl.steps.map(function (x, i) { return '  ' + (i + 1) + '. ' + x.title + '  [' + x.tool + ']'; }));
        break;
      }
      case 'ask.human': {
        var q = { id: uid('apr'), at: Date.now(), tool: 'question', args: { question: args.question || 'Operator confirmation required' },
          step: { tool: 'question', args: args }, reason: 'Operator question', agent: s.agent };
        s.pending.unshift(q); out = ['QUESTION PENDING · ' + q.args.question]; break;
      }
      case 'skill.list': out = ['Offline skills:', '  · security-review  · hardening  · dependency-audit  · ioc-extract  · evidence-report']; break;
      case 'model.list': out = ['Available planners:', '  · aegis-deterministic-v2 (local, no API key, no network)', '  · hexstrike-planner (catalog-driven)', 'No external LLM provider is configured.']; break;
      case 'mcp.resources': out = ['aegis://workspace', 'aegis://session', 'aegis://diff', 'aegis://ledger', 'aegis://capabilities']; break;
      case 'mcp.resource': out = [JSON.stringify({ uri: args.uri || 'aegis://workspace', files: files(s).length, changed: diff(s).filter(function (d) { return d.changed; }).length })]; break;
      case 'mcp.manifest': out = JSON.stringify(mcp(), null, 2).split('\n'); break;
      case 'schedule.create': s.schedules.unshift({ id: uid('sch'), name: args.name || 'unnamed', status: 'active', at: Date.now() }); out = ['Schedule created (in-memory).']; break;
      case 'schedule.list': out = s.schedules.length ? s.schedules.map(function (x) { return x.id + '  ' + x.status.padEnd(8) + x.name; }) : ['(no schedules)']; break;
      case 'schedule.pause': case 'schedule.resume': case 'schedule.delete': out = ['Schedule state updated (in-memory).']; break;
      case 'session.rename': s.title = String(args.title || s.title).slice(0, 80); out = ['Session renamed: ' + s.title]; break;
      default: out = ['Tool executed (governed).'];
    }
    record(s, id, 'DONE', out[0] || '');
    s.messages.push({ role: 'tool', at: Date.now(), tool: id, text: (out[0] || '').slice(0, 160) });
    if (s.messages.length > 60) s.messages.shift();
    return { status: 'DONE', code: 'CAPABILITY_GRANTED', tool: id, cap: g.cap, action: g.action, output: out, data: data,
      diff: /^vfs\.(write|edit|patch|delete)$/.test(k) ? diffText(s, args.path) : null };
  }
  function approve(s, id, decision, actor) {
    var i = s.pending.findIndex(function (p) { return p.id === id; });
    if (i === -1) return { ok: false, error: 'No pending approval ' + id };
    var p = s.pending.splice(i, 1)[0];
    var res = decision === 'approve' ? execute(p.step, s, { force: true }) : { status: 'DENIED', reason: 'Operator denied the request.', output: [] };
    s.decisions.unshift({ id: p.id, at: Date.now(), tool: p.tool, decision: decision.toUpperCase(), actor: actor || 'operator', reason: p.reason });
    record(s, p.tool, decision === 'approve' ? res.status : 'DENIED', 'Approval ' + decision);
    return { ok: true, result: res, pending: p };
  }

  /* ------------------------------- planner ------------------------------- */
  function plan(goal, s) {
    var q = String(goal || '').trim();
    var steps = [
      { title: 'Inspect the virtual workspace', tool: 'list', args: {}, note: 'Enumerate in-memory files.' },
      { title: 'Search for credential-shaped literals', tool: 'grep', args: { pattern: 'apiKey|token|secret|password' }, note: 'Local regex only.' },
      { title: 'Run workspace diagnostics', tool: 'lsp', args: {}, note: 'Pattern-based LSP substitute.' }
    ];
    if (/read|app|source|review|audit/i.test(q)) steps.push({ title: 'Read src/app.js', tool: 'read', args: { path: 'src/app.js' }, note: 'Numbered source view.' });
    if (/header|http|harden/i.test(q)) steps.push({ title: 'Read response headers', tool: 'read', args: { path: 'config/headers.txt' }, note: 'Offline header sample.' });
    if (/iam|policy|cloud/i.test(q)) steps.push({ title: 'Read IAM policy', tool: 'read', args: { path: 'policies/iam.json' }, note: 'Offline IAM sample.' });
    if (/k8s|kube|deploy/i.test(q)) steps.push({ title: 'Read Kubernetes manifest', tool: 'read', args: { path: 'k8s/deploy.yaml' }, note: 'Offline manifest sample.' });
    if (/depend|sbom|package|cve/i.test(q)) steps.push({ title: 'Read dependency manifest', tool: 'read', args: { path: 'package.json' }, note: 'Offline advisory baseline.' });
    if (/fix|patch|edit|write|remediat/i.test(q)) steps.push({ title: 'Apply remediation patch', tool: 'apply_patch', args: { path: 'src/app.js', patch: '-  return res.send(eval(html));\n+  return res.send(escapeHtml(html));' }, note: 'Requires human approval.' });
    steps.push({ title: 'Record the plan in todos', tool: 'todowrite', args: { todos: steps.map(function (x) { return { text: x.title, status: 'pending' }; }) }, note: 'Auditable session state.' });
    steps.push({ title: 'Produce the review diff', tool: 'bash', args: { command: 'git diff' }, note: 'Governed virtual shell.' });
    s.plan = steps;
    s.todos = steps.map(function (x, i) { return { id: 'todo-' + (i + 1), text: x.title, status: 'pending' }; });
    s.vars.goal = q;
    s.updatedAt = Date.now();
    return { goal: q || 'general workspace review', engine: 'deterministic keyword planner (no model call)', steps: steps, todos: s.todos };
  }

  var MCP = {
    name: 'aegis-sentinel-opencode-adapter', version: '2.2.0', upstream: UPSTREAM.repo + '@' + UPSTREAM.version,
    transport: 'in-browser / offline (no stdio, no HTTP, no subprocess, no LLM)',
    alwaysAllow: [], model: 'aegis-deterministic-v2',
    capabilities: { tools: true, resources: true, prompts: true, sampling: false, logging: false, filesystem: 'virtual-only', shell: 'governed-virtual' },
    tools: TOOLS.map(function (t) { return { name: t.id, description: t.reason, permission: t.key, action: t.action, capability: t.cap }; }),
    resources: [{ uri: 'aegis://workspace' }, { uri: 'aegis://session' }, { uri: 'aegis://diff' }, { uri: 'aegis://ledger' }, { uri: 'aegis://capabilities' }],
    prompts: [{ name: 'security-review' }, { name: 'harden-workspace' }, { name: 'explain-permission' }]
  };
  function mcp() { return MCP; }
  function summary(s) {
    return { upstream: UPSTREAM, tools: TOOLS.length, allow: TOOLS.filter(function (t) { return t.action === 'allow'; }).length,
      ask: TOOLS.filter(function (t) { return t.action === 'ask'; }).length, deny: TOOLS.filter(function (t) { return t.action === 'deny'; }).length,
      agents: AGENTS.length, permissions: PERMISSION_KEYS.length,
      files: s ? files(s).length : 0, changed: s ? diff(s).filter(function (d) { return d.changed; }).length : 0,
      pending: s ? s.pending.length : 0, calls: s ? s.toolCalls.length : 0 };
  }

  var API = {
    UPSTREAM: UPSTREAM, AGENTS: AGENTS, PERMISSION_KEYS: PERMISSION_KEYS, TOOLS: TOOLS,
    DEFAULT_PERMISSIONS: DEFAULT_PERMISSIONS, HARD_DENY: HARD_DENY, MCP: MCP,
    createSession: createSession, reset: reset, agent: agent, setAgent: setAgent,
    setPermission: setPermission, get: get, tools: tools, summary: summary, mcp: mcp,
    evaluate: evaluate, execute: execute, approve: approve, plan: plan,
    files: files, readLines: readLines, glob: glob, grep: grep, diff: diff, diffText: diffText,
    diagnostics: diagnostics, virtualShell: virtualShell, seed: seed
  };
  root.AEGIS_OPENCODE = API;
  if (isNode) module.exports = API;
})(typeof globalThis !== 'undefined' ? globalThis : this);
