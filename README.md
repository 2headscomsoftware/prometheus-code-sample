<p align="center">
  <img src="icon.png" width="128" alt="Prometheus Code">
</p>

<h1 align="center">Prometheus Code</h1>

<p align="center">
  <b>Local-first agentic IDE</b> — autonomous agent loops, policy-gated tools,<br>
  local LLM infrastructure and E2E-encrypted team relay. Everything on your machine.
</p>

<p align="center">
  <a href="https://2-heads.com">2-heads.com</a> ·
  <a href="https://github.com/2headscomsoftware">2-Heads Software Solutions</a>
</p>

<p align="center">
  <a href="https://youtu.be/5OQWTTN839M">
    <img src="https://img.youtube.com/vi/5OQWTTN839M/hqdefault.jpg" width="520" alt="Prometheus Code — demo">
  </a>
</p>
<p align="center"><i>▶ Watch the IDE in action</i></p>

---

> **This is a curated public sample.** The full source lives in a private
> repository and is available on request. The files published here cover the
> two areas most worth reading: the authorization policy that gates every
> filesystem operation an agent can perform, and the encryption layer behind
> multi-agent team relay.

## The IDE

Local-first, privacy-respecting AI IDE — local GGUF inference via TurboQuant llama.cpp, bundled OpenCode agents, OWL/CAMEL multi-agent backend, persistent codebase knowledge graph (codebase-memory-mcp), P2P team collaboration, VS Code-compatible extensions. Zero telemetry.

### Agent runtime

- Multi-turn agent loop with parallel vs. dependent tool-call orchestration
- 15+ tools: policy-gated filesystem, terminal, integrated browser, MCP bridge
- Structured `<verify>` and `<terminal>` steps pass through approval cards
- Session memory blocks and audit logging for every agent action

### Local LLM infrastructure

- llama.cpp serving layer with GGUF models on local disk
- Per-task model routing — text↔vision auto-swap (vision via mmproj detection)
- Configurable sampling, thinking budgets and streaming synthesis paths
- RAG over the workspace (ChromaDB embeddings)

### Desktop & editor

- Electron 33 — CodeMirror editor, xterm.js terminal (node-pty)
- VSIX extension host with install-time sanitize
- Sandboxed IPC: preload exposes a whitelisted bridge only
- Auto-update via electron-updater, multi-platform release pipelines

### Team relay

- Multi-agent collaboration over an end-to-end encrypted relay
- v3 protocol: ECDH-wrapped rotating room keys, AES-GCM payloads,
  MAC'd handshakes, anti-replay and anti-downgrade guards

## What's in this sample

| File | What it shows |
|---|---|
| `lib/fs-gate.js` | Pure, testable authorization policy for the fs bridge: per-operation root policies, symlink-safe validation (`realpath` on deepest existing ancestor + tail re-attach), credential denylist, anti-DoS caps |
| `lib/team-crypto.js` | Team relay E2E crypto v3: ECDH key agreement, AES-GCM room keys, MAC'd handshakes, replay/downgrade rejection |
| `tests/fs-bridge.test.js` | Attack-scenario tests — real tmpdirs + symlinks, no Electron required |
| `tests/team-crypto.test.js` | Crypto round-trip, tamper, replay and downgrade tests |

## Run the tests

```bash
npm test
```

Node 18+. Zero runtime dependencies — `node:test` only.

## Architecture at a glance

```
renderer (CodeMirror · xterm.js · agent UI)
    │  sandboxed preload — IPC whitelist only
    ▼
Electron main ──► fs-gate (this repo) ──► approval cards ──► audit log
    │
    ▼
Python agent daemon :18181  (Bearer-token gated)
    │──► llama.cpp server :18180        (text + vision models)
    │──► embeddings :18182              (RAG / ChromaDB)
    └──► team relay ──► team-crypto.js  (E2E ECDH + AES-GCM)
```
