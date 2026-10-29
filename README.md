# Prometheus Code — security samples

Curated code samples from **Prometheus Code**, a local-first agentic IDE
(private repository — full source available on request).

These files cover the two areas most worth showing: the authorization
policy that gates every filesystem operation an agent can perform, and
the end-to-end encryption layer behind multi-agent team relay.

## What's here

| File | What it shows |
|---|---|
| `lib/fs-gate.js` | Pure, testable authorization policy for the fs bridge: per-operation root policies, symlink-safe validation (`realpath` on deepest existing ancestor + tail re-attach), credential denylist, anti-DoS caps |
| `lib/team-crypto.js` | Team relay E2E crypto v3: ECDH key agreement, AES-GCM room keys, MAC'd handshakes, anti-replay/downgrade guards |
| `tests/fs-bridge.test.js` | Attack-scenario tests — real tmpdirs + symlinks, no Electron required |
| `tests/team-crypto.test.js` | Crypto round-trip, tamper, replay and downgrade tests |

## Run the tests

```bash
npm test
```

Node 18+. Zero runtime dependencies — `node:test` only.

## Context

Prometheus Code is a local-first agentic IDE (Electron + Python agent
daemon): autonomous agent loop, 15+ policy-gated tools, local LLM serving
via llama.cpp with per-task text↔vision routing, sandboxed IPC and audit
logging. Every mutation an agent proposes passes through a diff/approval
card — `fs-gate.js` is the enforcement layer behind that boundary.

Site: [2-heads.com](https://2-heads.com)
