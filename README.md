# AEGIS // SENTINEL v2.1

An **autonomous, authorization-bound defensive security operations platform** with an interactive operator terminal and a governed HexStrike AI compatibility layer. Static, zero-dependency, fully offline: all analysis engines execute in the browser (or in the local CLI) on data the operator supplies. No backend, no API keys, no network egress, no exploitation capability.

> **Design boundary:** the agent can do *anything in its signed capability manifest* — and nothing outside it. "Without authorization" operation is the exact failure mode this platform prevents, logs, and makes verifiable in a hash-chained ledger. Every task resolves its capability and re-verifies the target's scope before a single function runs.

---

## What's in v2.1

### Interactive terminal

A new **AEGIS Terminal** view (20th console view) plus a **real CLI program** you can run in your own shell:

```bash
node tools/aegis-terminal.mjs            # interactive REPL
node tools/aegis-terminal.mjs --no-color # plain output
```

Both are command interpreters, **not system shells**. No OS process is spawned, no socket is opened, no file is written. Features: command history (↑/↓), Tab completion, Ctrl+L clear, 30+ commands, ANSI output in the CLI, every command sealed in the ledger.

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
styles.css                       Complete visual system, incl. terminal
src/00-data.js                   Detection rules, playbooks, controls, samples
src/05-data2.js                  ATT&CK matrix, capability manifest, orchestrator plan, samples
src/10-engine.js                 SHA-256, log/header/IOC engines, scope gate, triage, compliance
src/15-advanced.js               Normalization, attack chains, 5 lab engines, coverage, quant, copilot
src/16-hexstrike.js              HexStrike AI v6.0 catalog, MCP manifest, policy gate, offline adapters
src/20-store.js                  State, persistence, append-only audit ledger
src/30-ui.js                     Base console (11 views) + extension API
src/40-ui2.js                    v2 console (8 views) + orchestrator
src/45-terminal.js               Terminal view, command registry, HexStrike console
scripts/build.mjs                Concatenates sorted src/*.js -> dist/bundle.js (no dependencies)
dist/bundle.js                   Generated bundle (committed so Vercel needs no build step)
tools/aegis-terminal.mjs         Local interactive CLI terminal
tests/engine.test.mjs            v1 engine suite (10 tests)
tests/advanced.test.mjs          v2 engine suite (14 tests)
tests/hexstrike.test.mjs         HexStrike adapter suite (11 tests)
vercel.json                      Security headers + no-cache on the app shell
deploy/bootstrap.html            Small files-only deployment fallback (uses __SHA__)
```

> Module load order matters: `src/16-hexstrike.js` must load after `src/15-advanced.js`, and `src/45-terminal.js` after `src/30-ui.js`. The build script sorts `src/*.js` lexicographically. The base UI defers boot with `setTimeout(0)` so every extension module registers before first paint.

## Run locally

```bash
python3 -m http.server 8080 --bind 0.0.0.0
# open http://localhost:8080
node tools/aegis-terminal.mjs
```

Rebuild after editing `src/`, then run all suites:

```bash
node scripts/build.mjs
node --test tests/engine.test.mjs tests/advanced.test.mjs tests/hexstrike.test.mjs
```

A jsdom DOM smoke suite (outside the repo) additionally exercises all 20 views, the defer-boot path, and every terminal command.

## Deployment

Plain static site on Vercel (`cyber-aegis`). The project uses a no-op build (`true`) with output directory `.`, so the committed `dist/bundle.js` is served directly. `vercel.json` adds `X-Content-Type-Options`, `Referrer-Policy`, `Permissions-Policy`, a CSP, and `Cache-Control: no-cache, no-store, must-revalidate` on `/` and `/index.html` so the canonical URL always picks up the newest versioned assets. No environment variables or secrets are required.

If a Git-connected deployment is unavailable, `deploy/bootstrap.html` is a tiny fallback shell: replace `__SHA__` with the pushed commit SHA and deploy it as `index.html`. It fetches `styles.css` and `dist/bundle.js` from the repository and injects them. The application itself still performs no network analysis.

---

## Rules of engagement (enforced in code)

**In scope:** analyzing text you paste; assessing assets with a signed authorization record; explainable triage; mitigation guidance; defanged IOC correlation; local configuration analysis; tamper-evident logging; anything else added to the manifest in a reviewed commit.

**Out of scope:** activity against systems without documented authorization; network scanning/probing; exploitation or payload delivery; credential attacks, persistence, evasion or lateral movement; autonomous external containment; sending operator data to third parties.

**HexStrike specifically:** catalog-only adapter. Offensive tool names are present so the operator can see *what was refused and why* — they are never executed. Adding an upstream server bridge would require a reviewed manifest change and explicit authorization records; it is intentionally not exposed on the public deployment.

## License

MIT — see `LICENSE`. HexStrike AI upstream is also MIT; its catalog is attributed in `src/16-hexstrike.js`.
