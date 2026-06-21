<p align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="https://raw.githubusercontent.com/writerslogic/cogmem/main/assets/logo-spin-dark.gif">
    <img src="https://raw.githubusercontent.com/writerslogic/cogmem/main/assets/logo-spin.gif" width="200" alt="cogmem">
  </picture>
</p>

# cogmem

[![CI](https://github.com/writerslogic/cogmem/actions/workflows/ci.yml/badge.svg)](https://github.com/writerslogic/cogmem/actions/workflows/ci.yml)
[![License: Apache-2.0](https://img.shields.io/badge/License-Apache--2.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)
[![Python](https://img.shields.io/badge/python-3.12%2B-blue.svg)](https://www.python.org)
[![MCP](https://img.shields.io/badge/MCP-compatible-7c3aed.svg)](https://modelcontextprotocol.io)
[![W3C Verifiable Credentials](https://img.shields.io/badge/W3C-Verifiable%20Credentials-005a9c.svg)](https://www.w3.org/TR/vc-data-model-2.0/)
[![did:key](https://img.shields.io/badge/DID-did%3Akey-005a9c.svg)](https://w3c-ccg.github.io/did-method-key/)
[![SCITT](https://img.shields.io/badge/IETF-SCITT--style%20log-005a9c.svg)](https://datatracker.ietf.org/wg/scitt/about/)
[![Verifiable Agent Memory](https://img.shields.io/badge/Verifiable-Agent%20Memory-16a34a.svg)](./PROVENANCE.md)
[![local-first](https://img.shields.io/badge/local--first-no%20data%20leaves%20your%20machine-111827.svg)](#)

**A self-improving, verifiable memory layer for AI coding agents.**

cogmem learns how you work across sessions so your agent gets more accurate and more
autonomous over time: it stops repeating mistakes, keeps a live model of each
project, and surfaces the right lesson at the right moment. Every memory is
cryptographically signed and tamper-evident, so a poisoned or altered memory can be
detected and rejected before it ever steers the agent.

> Developed by [WritersLogic](https://github.com/writerslogic) -- local-first intelligence with no data leaving your machine.

## Why cogmem is different

Chat-memory systems (Mem0, Letta, Zep) store and retrieve facts. cogmem is built for
coding agents and goes further on three axes nobody else covers:

- **It learns from outcomes.** A feedback loop scores whether a recalled lesson
  actually helped, refines rules that prove wrong, and retires ones that mislead.
- **It models its own failure modes.** cogmem tracks where *the agent itself* tends
  to go wrong in your work and intercepts a known mistake at the tool-call boundary,
  before it happens, not just warns afterward.
- **Its memory is verifiable.** Each memory is a W3C Verifiable Credential signed by
  the agent's `did:key`, recorded in a tamper-evident, SCITT-style transparency log.
  Agent memory is an attack surface; cogmem makes it auditable and poison-resistant.

## Features

- **Two-layer memory** — always-loaded directives (scope-gated, human-approved) plus a
  semantic recall tail (local cross-encoder reranking, no data leaves the machine).
- **Outcome feedback + self-refinement** — memories earn or lose trust based on whether
  they actually helped; contradicted rules are corrected through a safe pipeline.
- **Self-model + guard** — a model of the agent's recurring mistakes, compiled into
  tripwires that intercept them at the `PreToolUse` boundary.
- **Project-state model** — a living per-project state (goal, claims, open questions,
  blockers) that gives situational continuity and reasons across time.
- **Cross-project progress narrative** — momentum, stalls, and dependencies across
  projects, surfaced as alerts.
- **Self-regulation** — recall thresholds tuned automatically against an eval harness.
- **Verifiable Agent Memory** — `did:key` identity, W3C VC-signed memories, COSE_Sign1
  SCITT signed statements (byte-compatible with HMS), a hash-chained transparency log with
  signed Merkle tree head and RFC 6962 inclusion receipts, optional poison-resistance
  enforcement. See [PROVENANCE.md](./PROVENANCE.md).

## Integration

cogmem offers two integration modes:

- **MCP server (universal).** Run `cogmem mcp` to expose cogmem to any MCP client over
  stdio — eight tools (`recall`, `note`, `status`, `verify`, `receipt`, `tree_head`,
  `progress`, `review_pending`) plus read-only resources (the evolving user model and
  each project's live state). Point a client at it with:
  ```json
  { "mcpServers": { "cogmem": { "command": "cogmem", "args": ["mcp"] } } }
  ```
- **Claude Code hooks (automatic).** SessionStart, UserPromptSubmit, Stop, and
  PreToolUse hooks wire the full automatic experience: capture at session end, recall
  at prompt time, and mistake interception during work.

## Quickstart

```bash
cogmem status        # health, metrics, agent DID
cogmem mcp           # run the MCP server (stdio) for any MCP client
cogmem recall "..."  # surface relevant past lessons
cogmem note "..."    # record a decision/finding mid-task
cogmem review list   # approve always-load rules
cogmem verify        # verify every memory's credential + the transparency log
cogmem receipt <id>  # inclusion proof that a memory is committed in the signed log
cogmem statement <id># COSE_Sign1 SCITT signed statement (verifies under HMS too)
```

## Privacy

cogmem is local-first by design. Memories, embeddings, and the identity key live on
your machine; semantic recall runs on a local model. Nothing is sent anywhere.

## License

Apache-2.0. See [LICENSE](./LICENSE).
