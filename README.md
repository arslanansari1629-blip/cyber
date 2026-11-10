# AEGIS // SENTINEL v2.2

An **autonomous, authorization-bound defensive security operations platform** with an ultra-advanced operator terminal that embeds a governed **OpenCode-compatible agent workbench** and a HexStrike AI compatibility layer. Static, zero-dependency, fully offline: all analysis engines execute in the browser (or in the local CLI) on data the operator supplies. No backend, no API keys, no network egress, no exploitation capability.

> **Design boundary:** the agent can do *anything in its signed capability manifest* — and nothing outside it. "Without authorization" operation is the exact failure mode this platform prevents, logs, and makes verifiable in a hash-chained ledger. Every task resolves its capability and re-verifies the target's scope before a single function runs.

---

## What's in v2.2 — OpenCode in the terminal

The upstream [`sst/opencode`](https://github.com/sst/opencode) surface (MIT, v2.2.7) is integrated as a **contract-only, governed workbench** — not a live Bun CLI, LLM provider or server. `src/17-opencode.js` models 41 tools, 7 built-in agents/subagents, 15 permission keys, sessions, todos, MCP-shaped resources/prompts, and a deterministic planner. Nothing is installed, spawned, fetched or written to disk.

What is genuinely implemented and executable **offline**:

| Surface | Implementation |
|---|---|
| **Virtual workspace** | 11 in-memory files. Real numbered `read`, `glob`, regex `grep`, `list`, `write`, `edit`, unified-diff `apply_patch`, LCS diffs and pattern-based LSP-like diagnostics. |
| **Governed virtual shell** | `sh` interprets an allowlisted command set (`ls`, `tree`, `cat`, `head`, `tail`, `wc`, `grep`, `find`, `diff`, `git status`, `pwd`, `echo`, `node --test`, `help`). No OS process exists. |
| **Agents & permissions** | `build`, `plan`, `general`, `explore`, `compaction`, `title`, `summary`; `allow` / `ask` / `deny` keys mirroring upstream. `webfetch`, `websearch`, `external_directory` and `doom_loop` are **hard-denied** and cannot be relaxed. Upstream's `edit` key gates `write`, `edit`, `apply_patch` and `patch`. |
| **Human approval** | Every virtual write creates a pending approval with tool, agent, arguments and reason; a modal or the Approvals panel records APPROVE / DENY in the ledger. |
| **Deterministic planner** | Keyword-driven multistep plans over the virtual workspace. `oc run "<goal>"` streams steps, marks todos and pauses at a write until a human decides. No model call. |
| **Advanced shell** | `|` pipelines (grep/exclude/contains/head/tail/select/wc/sort/uniq/upper/lower/trim/prefix/json), `&&` and `;` chains, `$variables` + built-ins, aliases, in-memory scripts/macros, `repeat`, `panel`, `set`, `env`, `diff`, `diagnostics`, `tool <id> [json]`. |
| **Live workbench UI** | Seven panels — Session, Files, Plan, Diff, Approvals, Tools, Audit — repainted after every command. Export unified diff and MCP contract manifest. |
| **CLI parity** | `tools/aegis-terminal.mjs` exposes the same OpenCode commands, VFS, virtual shell, pipelines, variables, aliases, scripts and approval workflow. |

```bash
# Browser terminal (or local CLI)
aegis ❯ oc help
aegis ❯ oc status
aegis ❯ oc tools deny
aegis ❯ oc agents
aegis ❯ oc plan "audit headers and fix app"
aegis ❯ oc run "audit headers and fix app"     # pauses for human approval
aegis ❯ oc approve <approval-id>
aegis ❯ vfs ls
aegis ❯ vfs cat src/app.js
aegis ❯ vfs patch src/app.js "return res.send(eval(html));" "return res.send(safe(html));"
aegis ❯ diff
aegis ❯ vfs diagnostics
aegis ❯ sh ls
aegis ❯ tool webfetch {"url":"https://example.com"}   # REFUSED — hard-denied
aegis ❯ set target demo && echo $target | upper | prefix "RESULT: "
aegis ❯ alias pstatus status
aegis ❯ script save smoke "vfs ls; oc status"
aegis ❯ script run smoke
aegis ❯ panel plan
aegis ❯ oc mcp --json
aegis ❯ audit verify
```

**Explicitly not wired:** the real `opencode` binary, `opencode serve`, `--auto` approval, model/provider calls, `bash`/`shell` on the host, outbound HTTP, real git worktrees, external filesystem paths, or an MCP server. Registry filtering upstream is catalog visibility, not execution authorization; here both are enforced in the same gate. `--auto` is not implemented: explicit `deny` always wins and writes always require a human decision.

## What's in v2.1

### Interactive terminal

The **AEGIS Terminal** view (20th console view) plus a **real CLI program** you can run in your own shell:

```bash
node tools/aegis-terminal.mjs            # interactive REPL
node tools/aegis-terminal.mjs --no-color # plain output
```

Both are command interpreters, **not system shells**. No OS process is spawned, no socket is opened, no real file is written. Features: command history (↑/↓), Tab completion, Ctrl+L clear, 60+ commands, ANSI output in the CLI, every command sealed in the ledger.

```
aegis ❯ help
aegis ❯ hexstrike tools web
aegis ❯ hexstrike run trivy_scan        # safe offline adapter
aegis ❯ hexstrike run nmap_scan         # hard refusal, logged
aegis ❯ mcp manifest --json
aegis ❯ orchestrator run
aegis ❯ investigate show critical findings
aegis ❯ audit verify
```

### HexStrike AI compatibility layer

The catalog from [`0x4m4/hexstrike-ai`](https://github.com/0x4m4/hexstrike-ai) (MIT, v6.0, 151 `@mcp.tool()` declarations → 150 unique names, 12 agent personas) is integrated as a **governed, MCP-shaped adapter**. No upstream Python code, binary, server or network endpoint is bundled or executed.

| Classification | Count | Behaviour |
|---|---|---|
| `adapter` | 35 | Mapped to a real, offline AEGIS engine (header, IAM, K8s, secret, SBOM, IOC, normalization, attack-chain, coverage, report). Runs locally. |
| `blocked` | 104 | Bound to one of the 6 hard-refused AEGIS capability classes (`net.scan`, `exploit.execute`, `credential.attack`, `contain.execute`, `persistence.install`, `scope.bypass`). Refused with a manifest reason and logged. |
| `unavailable` | 11 | Reads/renders upstream server runtime state; no Flask/FastMCP server is present in the offline build. Never executed. |

Exposed through `hexstrike …`, `mcp …` and `run <tool>` commands, plus a downloadable MCP manifest (`tools:150`, `resources:4`, `prompts:3`, `alwaysAllow:[]`, `sampling:false`). Tool calls return JSON-RPC-shaped envelopes.

### Everything from v2.0 and v1

| Module | What it actually does |
|---|---|
| **Mission Orchestrator** | 8-task dependency-ordered DAG. Each node resolves a capability, re-checks scope, executes real local analysis, and seals its outcome in the ledger. |
| **Universal Ingest** | Per-line format detection for JSONL, nginx/apache, syslog/auth, CSV, generic. Normalizes to a common event schema, tags with detection rules, reconstructs multi-stage ATT&CK chains with confidence, and runs z-score / IQR / EWMA anomaly detection. |
| **Analysis Lab** | Five offline engines: phishing/.eml, IAM policy, Kubernetes manifests, masked secret + Shannon-entropy scan, dependency/SBOM advisory matching. |
| **Detection Studio** | ATT&CK Navigator-style heatmap across 14 tactics / 42 techniques, gap analysis, operator-authored regex rules with live testing. |
| **Investigation Copilot** | Local natural-language query interpreter (intent + severity + asset + MITRE filters). Deterministic, no model call, audited. |
| **Risk Quantification** | Deterministic Monte Carlo simulation with P50/P90/P95 and published assumptions. |
| **Incident Cases** | Link alerts/evidence into an auditable case with append-only notes and status transitions. |
| **Capability Manifest** | 18 enabled operations and 6 explicitly blocked classes, with a request form that logs GRANTED/REFUSED decisions. |
| **Core engines** | Signed authorization scope with SHA-256 tokens and hard refusals, 16 MITRE-mapped log rules, 12 HTTP hardening controls, defanged IOC extraction, explainable triage, six NIST CSF playbooks, CIS/NIST control coverage, executive summary, JSON export, command palette, hash-chained audit ledger. |

**All browser state lives in `localStorage`.** Baseline assets, alerts, findings and the activity chart are simulated sample records and are labelled as such in the UI; every analyzer, the scope gate, triage scoring, orchestrator, coverage model and ledger are real deterministic code. Containment buttons are workflow states only — they never change an external system. The CLI keeps state in memory only.

---

## Repository layout

```
index.html                       App shell (styles.css?v=… + dist/bundle.js?v=…)
styles.css                       Complete visual system, incl. terminal + workbench
src/00-data.js                   Detection rules, playbooks, controls, samples
src/05-data2.js                  ATT&CK matrix, capability manifest, orchestrator plan, samples
src/10-engine.js                 SHA-256, log/header/IOC engines, scope gate, triage, compliance
src/15-advanced.js               Normalization, attack chains, 5 lab engines, coverage, quant, copilot
src/16-hexstrike.js              HexStrike AI v6.0 catalog, MCP manifest, policy gate, offline adapters
src/17-opencode.js               OpenCode v2.2.7 contract: tools, agents, permissions, VFS, planner
src/20-store.js                  State, persistence, append-only audit ledger
src/30-ui.js                     Base console (11 views) + extension API
src/40-ui2.js                    v2 console (8 views) + orchestrator
src/45-terminal.js               Terminal view, command registry, OpenCode workbench UI
scripts/build.mjs                Concatenates sorted src/*.js -> dist/bundle.js (no dependencies)
dist/bundle.js                   Generated bundle (committed so Vercel needs no build step)
tools/aegis-terminal.mjs         Local interactive CLI terminal with OpenCode parity
tests/engine.test.mjs            v1 engine suite (10 tests)
tests/advanced.test.mjs          v2 engine suite (14 tests)
tests/hexstrike.test.mjs         HexStrike adapter suite (11 tests)
tests/opencode.test.mjs          OpenCode workbench suite (8 tests)
vercel.json                      Security headers + no-cache on the app shell
deploy/bootstrap.html            Small files-only deployment fallback (uses __SHA__)
```

> Module load order matters: `src/16-hexstrike.js` and `src/17-opencode.js` must load after `src/15-advanced.js`, and `src/45-terminal.js` after `src/30-ui.js`. The build script sorts `src/*.js` lexicographically. The base UI defers boot with `setTimeout(0)` so every extension module registers before first paint.

## Run locally

```bash
python3 -m http.server 8080 --bind 0.0.0.0
# open http://localhost:8080
node tools/aegis-terminal.mjs
```

Rebuild after editing `src/`, then run all suites:

```bash
node scripts/build.mjs
node --test tests/engine.test.mjs tests/advanced.test.mjs tests/hexstrike.test.mjs tests/opencode.test.mjs
```

43/43 Node tests. A jsdom DOM smoke suite (outside the repo) additionally exercises all 20 views, the defer-boot path, every v2.1 terminal command, and the full v2.2 OpenCode workbench (including approvals, pipelines, aliases, scripts and ledger integrity).

## Deployment

Plain static site on Vercel (`cyber-aegis`). The project uses a no-op build (`true`) with output directory `.`, so the committed `dist/bundle.js` is served directly. `vercel.json` adds `X-Content-Type-Options`, `Referrer-Policy`, `Permissions-Policy`, a CSP, and `Cache-Control: no-cache, no-store, must-revalidate` on `/` and `/index.html` so the canonical URL always picks up the newest versioned assets. No environment variables or secrets are required.

If a Git-connected deployment is unavailable, `deploy/bootstrap.html` is a tiny fallback shell: replace `__SHA__` with the pushed commit SHA and deploy it as `index.html`. It fetches `styles.css` and `dist/bundle.js` from the repository and injects them. The application itself still performs no network analysis.

---

## Rules of engagement (enforced in code)

**In scope:** analyzing text you paste; assessing assets with a signed authorization record; explainable triage; mitigation guidance; defanged IOC correlation; local configuration analysis; virtual-workspace edits after human approval; tamper-evident logging; anything else added to the manifest in a reviewed commit.

**Out of scope:** activity against systems without documented authorization; network scanning/probing; exploitation or payload delivery; credential attacks, persistence, evasion or lateral movement; autonomous external containment; sending operator data to third parties; bypassing the scope gate.

**HexStrike specifically:** catalog-only adapter. Offensive tool names are present so the operator can see *what was refused and why* — they are never executed. Adding an upstream server bridge would require a reviewed manifest change and explicit authorization records; it is intentionally not exposed on the public deployment.

**OpenCode specifically:** contract-only workbench. The virtual workspace is the only "filesystem"; the governed virtual shell is the only "shell"; the deterministic planner is the only "model". `webfetch`, `websearch`, `external_directory`, `doom_loop`, real worktrees and host paths are hard-denied in code and cannot be enabled from the UI or CLI. No upstream binary, provider or MCP server is contacted.

## License

MIT — see `LICENSE`. OpenCode and HexStrike AI upstream are also MIT; their contracts/catalogs are attributed in `src/17-opencode.js` and `src/16-hexstrike.js`. No upstream source code is vendored.
