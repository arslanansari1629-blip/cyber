# AEGIS // SENTINEL v2.0

An **autonomous, authorization-bound defensive security operations platform**. Static, zero-dependency, fully offline: all 20+ analysis engines execute in the browser on data the operator supplies. No backend, no API keys, no network egress, no exploitation capability.

> **Design boundary:** the agent can do *anything in its signed capability manifest* — and nothing outside it. "Without authorization" operation is the exact failure mode this platform prevents, logs, and makes verifiable in a hash-chained ledger. Every task resolves its capability and re-verifies the target's scope before a single function runs.

---

## What v2 adds

| Module | What it actually does |
|---|---|
| **Mission Orchestrator** | An 8-task dependency-ordered DAG. Each node resolves a capability in the signed manifest, re-checks scope, executes real local analysis, and seals its `DONE`/`REFUSED` outcome in the ledger. Live task graph + terminal trace. |
| **Universal Ingest** | Per-line format detection for JSONL, nginx/apache combined, syslog/auth, CSV, generic (plus CloudTrail/Zeek-shaped JSON). Normalizes to a common event schema, tags every event with detection rules, reconstructs **multi-stage attack chains** with MITRE tactic progression and confidence, and runs z-score / IQR / EWMA anomaly detection on event rate. |
| **Analysis Lab** | Five independent offline engines: phishing/.eml (SPF/DKIM/DMARC, Reply-To mismatch, relay chain, defanged URLs), IAM policy (wildcards, public principals, `PassRole`, MFA conditions, `NotAction`), Kubernetes manifests (privileged, host namespaces, root, capabilities, `hostPath`, tags, limits, seccomp), secret & entropy scanning (masked output, Shannon entropy), and dependency/SBOM analysis (package.json, lockfiles, CycloneDX, requirements against an offline advisory baseline). |
| **Detection Studio** | ATT&CK Navigator-style heatmap across 14 tactics / 42 techniques, gap analysis, and an operator-authored regex rule engine with live testing. Custom rules join the orchestrator detection sweep. |
| **Investigation Copilot** | Local natural-language query interpreter (intent + severity + asset + MITRE filter) over session evidence. Deterministic, no model call, audited. |
| **Risk Quantification** | Deterministic Monte Carlo simulation over the open finding register with P50/P90/P95, distribution histogram and fully published assumptions. |
| **Incident Cases** | Link alerts and evidence into an auditable case with append-only notes, status transitions and JSON export. |
| **Capability Manifest** | Machine-readable list of 18 enabled operations and 6 explicitly blocked classes (network scanning, exploitation, credential attacks, persistence, autonomous external containment, scope bypass). A request form evaluates any identifier through the policy engine and logs the decision. |

Plus everything from v1: signed authorization scope with SHA-256 tokens and hard refusals, autonomous sweep, 16 MITRE-mapped log rules, 12 HTTP hardening controls, defanged IOC extraction, explainable triage, six NIST CSF playbooks, CIS/NIST control coverage, executive summary, JSON export, command palette, and a SHA-256 hash-chained audit ledger.

**All state lives in `localStorage`.** Baseline assets, alerts, findings and the activity chart are simulated sample records and are labelled as such in the UI; every analyzer, the scope gate, triage scoring, orchestrator, coverage model and ledger are real deterministic code. Containment buttons are workflow states only — they never change an external system.

---

## Repository layout

```
index.html                  App shell (styles.css + dist/bundle.js)
styles.css                  Complete visual system, incl. v2 modules
src/00-data.js              Detection rules, playbooks, controls, samples
src/05-data2.js             ATT&CK matrix, capability manifest, orchestrator plan, samples
src/10-engine.js            SHA-256, log/header/IOC engines, scope gate, triage, compliance
src/15-advanced.js          Normalization, attack chains, 5 lab engines, coverage, quant, copilot
src/20-store.js             State, persistence, append-only audit ledger, v2 subsystems
src/30-ui.js                Base console (11 views) + extension API
src/40-ui2.js               v2 console (8 views) + orchestrator + command palette entries
scripts/build.mjs           Concatenates src/*.js -> dist/bundle.js (no dependencies)
dist/bundle.js              Generated bundle (committed so Vercel needs no build step)
tests/engine.test.mjs       v1 engine suite (10 tests)
tests/advanced.test.mjs     v2 engine suite (14 tests)
vercel.json                 Security response headers
deploy/bootstrap.html       Small files-only deployment fallback (uses __SHA__)
```

## Run locally

```bash
python3 -m http.server 8080 --bind 0.0.0.0
# open http://localhost:8080
```

Rebuild after editing `src/`, then run both suites:

```bash
node scripts/build.mjs
node --test tests/engine.test.mjs tests/advanced.test.mjs
```

## Deployment

Plain static site on Vercel (`cyber-aegis`). The project uses a no-op build (`true`) with output directory `.`, so the committed `dist/bundle.js` is served directly. `vercel.json` adds `X-Content-Type-Options`, `Referrer-Policy`, `Permissions-Policy` and a CSP. No environment variables or secrets are required.

If a Git-connected deployment is unavailable, `deploy/bootstrap.html` is a tiny fallback shell: replace `__SHA__` with the pushed commit SHA and deploy it as `index.html`. It fetches `styles.css` and `dist/bundle.js` from the repository (GitHub raw, with the GitHub Contents API as a secondary path) and injects them. The application itself still performs no network analysis.

---

## Rules of engagement (enforced in code)

**In scope:** analyzing text you paste; assessing assets with a signed authorization record; explainable triage; mitigation guidance; defanged IOC correlation; local configuration analysis; tamper-evident logging; anything else added to the manifest in a reviewed commit.

**Out of scope:** activity against systems without documented authorization; network scanning/probing; exploitation or payload delivery; credential attacks, persistence, evasion or lateral movement; autonomous external containment; sending operator data to third parties.

## License

MIT — see `LICENSE`.
