# AEGIS // SENTINEL

An **autonomous, authorization-bound defensive security operations console**. Static, zero-dependency, fully offline: all analysis executes in the browser on data the operator supplies. No backend, no API keys, no network egress, no exploitation capability.

> **Design boundary:** the agent is deliberately built to *refuse* anything outside a signed authorization scope. "Without authorization" operation is not a feature here — it is the exact failure mode the platform is designed to prevent, log, and make verifiable.

---

## What it does

| Capability | Implementation |
|---|---|
| **Authorization gate** | Asset registry with owner attestation, accountable approver, expiry, least-privilege check-type allowlist, and a SHA-256 scope token. `scopeCheck()` runs before every agent/analysis action; `REFUSED` outcomes are written to the ledger. |
| **Autonomous agent** | Multi-stage sweep with a live decision trace. Findings are generated **locally from a template catalog** and labelled `SIM` — no host is contacted. Out-of-scope, expired, revoked and unattested targets are refused. A one-click "attempt out-of-scope target" button demonstrates the hard refusal path. |
| **Signal analyzer** | 16 real, MITRE ATT&CK-mapped detection rules over pasted logs: brute-force thresholds, success-after-failure correlation, SQLi, path traversal, XSS, command injection, web shells, scanner user agents, encoded payloads, C2 beacons, defense evasion, ransomware, cryptomining, secret exposure, and status-code anomalies. |
| **Hardening analyzer** | 12 weighted HTTP-header controls (HSTS, CSP, XCTO, framing, referrer, permissions, cookies, version banners, CORS, cache, cross-origin isolation) with an A–F grade and copy-paste remediation. |
| **Explainable triage** | Priority score from severity, confidence, asset criticality, correlated findings, local watchlist hits and signal age — with the full reasoning chain displayed for a human to review. |
| **IOC workbench** | Extracts hashes, URLs, domains, IPs, emails and CVEs; defangs them for safe sharing; maintains a local correlation watchlist. No reputation service is queried. |
| **Response playbooks** | Six NIST CSF-mapped incident checklists with persisted progress. |
| **Control coverage** | Live evaluation against CIS Controls v8, NIST CSF 2.0 and MITRE ATT&CK derived from session evidence. |
| **Audit ledger** | Append-only SHA-256 hash chain. Any edit or deletion breaks verification and is reported. |
| **Operator UX** | Command palette (`Ctrl/⌘+K`), `Alt+1…0/P` navigation, executive summary, JSON export/import, toasts, responsive dark console, SVG charts, terminal trace. |

All state lives in `localStorage` (`aegis.sentinel.state.v1`). Baseline assets, alerts, findings and the activity chart are **simulated sample records** and are labelled as such in the UI; the analyzers, scope enforcement, triage scoring and hash chain are real deterministic code.

Containment buttons are **workflow states only**. They record a human decision — they never block, isolate, or change any external system.

---

## Repository layout

```
index.html                  App shell (loads styles.css + dist/bundle.js)
styles.css                  Complete visual system
src/00-data.js              Rule catalogs, playbooks, controls, sample data
src/10-engine.js            SHA-256, detection, header/IOC engines, scope gate, triage, compliance
src/20-store.js             State, persistence, append-only audit ledger
src/30-ui.js                Console views, charts, dialogs, command palette, actions
scripts/build.mjs           Concatenates src/*.js -> dist/bundle.js (no dependencies)
dist/bundle.js              Generated bundle (committed so Vercel needs no build step)
tests/engine.test.mjs       Node test suite for the offline engine
vercel.json                 Security response headers
deploy/bootstrap.html       Small files-only deployment fallback (uses __SHA__)
```

## Run locally

```bash
python3 -m http.server 8080 --bind 0.0.0.0
# open http://localhost:8080
```

Rebuild after editing anything in `src/`:

```bash
node scripts/build.mjs
node --test tests/engine.test.mjs
```

## Deployment

The project is a plain static site. The Vercel project `cyber-aegis` uses a no-op build (`true`) with output directory `.`, so the committed `dist/bundle.js` is served directly. `vercel.json` adds `X-Content-Type-Options`, `Referrer-Policy`, `Permissions-Policy` and a CSP. No environment variables or secrets are required.

If a Git-connected deployment is unavailable, `deploy/bootstrap.html` is a tiny fallback shell: replace `__SHA__` with the pushed commit SHA and deploy it as `index.html`. It fetches `styles.css` and `dist/bundle.js` from the repository (GitHub raw, with the GitHub Contents API as a secondary path) and injects them. The application itself still performs no network analysis.

---

## Rules of engagement (enforced in code)

**In scope:** analyzing text you paste; assessing assets with a signed authorization record; explainable triage; mitigation guidance; defanged IOC correlation; tamper-evident logging.

**Out of scope:** activity against systems without documented authorization; network scanning/probing; exploitation or payload delivery; credential attacks, persistence, evasion or lateral movement; autonomous external containment; sending operator data to third parties.

## License

MIT — see `LICENSE`.
