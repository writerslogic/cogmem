<p align="center">
  <img src="https://raw.githubusercontent.com/writerslogic/cogmem/main/assets/logo-spin.gif" width="200" alt="cogmem">
</p>

# cogmem

[![CI](https://github.com/writerslogic/cogmem/actions/workflows/ci.yml/badge.svg)](https://github.com/writerslogic/cogmem/actions/workflows/ci.yml)
[![Python](https://img.shields.io/badge/python-3.12%2B-blue.svg)](https://www.python.org)
[![MCP](https://img.shields.io/badge/MCP-compatible-7c3aed.svg)](https://modelcontextprotocol.io)
[![cogmem MCP server](https://glama.ai/mcp/servers/writerslogic/cogmem/badges/score.svg)](https://glama.ai/mcp/servers/writerslogic/cogmem)
[![W3C Verifiable Credentials](https://img.shields.io/badge/W3C-Verifiable%20Credentials-005a9c.svg)](https://www.w3.org/TR/vc-data-model-2.0/)
[![SCITT](https://img.shields.io/badge/IETF-SCITT--style%20log-005a9c.svg)](https://datatracker.ietf.org/wg/scitt/about/)
[![License: Apache-2.0](https://img.shields.io/badge/License-Apache--2.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)
[![local-first](https://img.shields.io/badge/local--first-no%20data%20leaves%20your%20machine-111827.svg)](#)

**A self-improving, verifiable memory layer for AI coding agents.**

cogmem learns how you work across sessions so your agent gets more accurate and more autonomous over time: it stops repeating mistakes, keeps a live model of each project, and surfaces the right lesson at the right moment. Every memory is cryptographically signed and tamper-evident, so a poisoned or altered memory can be detected and rejected before it ever steers the agent.

> Developed by [WritersLogic](https://github.com/writerslogic) — local-first intelligence, no data leaving your machine.

[![cogmem MCP server](https://glama.ai/mcp/servers/writerslogic/cogmem/badges/card.svg)](https://glama.ai/mcp/servers/writerslogic/cogmem)

## Installation

```bash
git clone https://github.com/writerslogic/cogmem.git
cd cogmem
./install.sh
```

Or in one line:

```bash
curl -fsSL https://raw.githubusercontent.com/writerslogic/cogmem/main/install.sh | bash
```

`install.sh` is idempotent — run it again any time to upgrade in place. It sets up
the code under `~/.claude/cogmem`, a self-contained virtualenv with dependencies,
the `cogmem` CLI on your PATH, the Claude Code hooks, and (on macOS) a warm recall
daemon. Requires **Python 3.12+**; semantic recall runs on a local model
(fastembed, no external API). Pass `--no-daemon` or `--no-hooks` to skip those
steps; set `COGMEM_HOME` to install elsewhere.

## Custom Installation

### Install to a different directory

Set `COGMEM_HOME` to place cogmem somewhere other than the default
`~/.claude/cogmem`:

```bash
COGMEM_HOME=/opt/cogmem ./install.sh
```

Or with the one-liner:

```bash
curl -fsSL https://raw.githubusercontent.com/writerslogic/cogmem/main/install.sh | COGMEM_HOME=/opt/cogmem bash
```

The installer copies the code, creates the virtualenv, and symlinks the CLI to
`~/.local/bin/cogmem` (or wherever `COGMEM_BIN` points).

### CLI path

Set `COGMEM_BIN` to control where the `cogmem` CLI symlink is placed:

```bash
COGMEM_BIN=$HOME/.cargo/bin COGMEM_HOME=/opt/cogmem ./install.sh
```

If `COGMEM_BIN` is not on your PATH, the installer prints a warning. You can
always invoke cogmem directly from `$COGMEM_HOME/cogmem`.

### How data directories and identity keys are resolved

At runtime the CLI and engine read `COGMEM_HOME` from the environment. When it is
unset they fall back to `~/.claude/cogmem`. All runtime data lives under the
`vault/` subdirectory:

| Path | Purpose |
|------|---------|
| `$COGMEM_HOME/vault/identity/agent.key` | Ed25519 private key (agent identity, `did:key`) |
| `$COGMEM_HOME/vault/credentials/` | W3C Verifiable Credential storage |
| `$COGMEM_HOME/vault/rules/` | Layer-A (always-load) and Layer-B (recall) rules |
| `$COGMEM_HOME/vault/provenance/log.jsonl` | Append-only hash-chained transparency log |
| `$COGMEM_HOME/vault/provenance/statements/` | COSE_Sign1 SCITT signed statements |
| `$COGMEM_HOME/engine/.venv/` | Python virtualenv with dependencies |
| `$COGMEM_HOME/hooks/` | Claude Code hook scripts |

The identity key is generated on first run (via `cogmem status` or any engine
operation) and persisted at `$COGMEM_HOME/vault/identity/agent.key`. The
corresponding `did:key` is derived from the Ed25519 public key. Moving or
reinstalling cogmem to a new `COGMEM_HOME` creates a fresh identity unless you
migrate the `vault/` directory.

### MCP client with a non-default install

The standard MCP client configuration works regardless of `COGMEM_HOME` because
the `cogmem` CLI resolves the environment variable at runtime:

```json
{
  "mcpServers": {
    "cogmem": { "command": "cogmem", "args": ["mcp"] }
  }
}
```

If the CLI is not on your PATH, use the full path:

```json
{
  "mcpServers": {
    "cogmem": { "command": "/opt/cogmem/cogmem", "args": ["mcp"] }
  }
}
```

Or prefix with `COGMEM_HOME` in a shell wrapper:

```json
{
  "mcpServers": {
    "cogmem": { "command": "env", "args": ["COGMEM_HOME=/opt/cogmem", "cogmem", "mcp"] }
  }
}
```

## Quick Start

```bash
cogmem status           # health check, metrics, agent DID
cogmem recall "..."     # surface relevant past lessons for a task
cogmem note "..."       # record a decision or finding mid-task
cogmem verify           # verify every memory's credential + the transparency log
cogmem receipt <id>     # inclusion proof that a memory is committed in the signed log
cogmem statement <id>   # COSE_Sign1 SCITT signed statement (verifiable by HMS too)
cogmem review list      # approve always-load rules
cogmem mcp              # run the MCP server (stdio) for any MCP client
```

## MCP Integration

Run cogmem as an MCP server and connect any MCP-compatible client:

```json
{
  "mcpServers": {
    "cogmem": { "command": "cogmem", "args": ["mcp"] }
  }
}
```

Eight tools are exposed: `recall`, `note`, `status`, `verify`, `receipt`, `tree_head`, `progress`, `review_pending`, plus read-only resources (the live user model and per-project state).

## Claude Code Integration

`install.sh` wires cogmem into Claude Code automatically (idempotently merged into
`~/.claude/settings.json`) — no manual invocation required. Five hooks make the
memory loop run in the background:

| Event | Hook | What it does |
|---|---|---|
| `SessionStart` | `cogmem-activate.sh` | injects promoted always-load (Layer-A) rules + the self-check |
| `UserPromptSubmit` | `cogmem-recall.sh` | semantic Layer-B recall for the current prompt |
| `PreToolUse(Bash)` | `cogmem-guard.sh` | intercepts known mistakes at the tool-call boundary before they happen |
| `PostToolUse(Edit\|Write)` | `cogmem-context.sh` | tracks which files the session is actively editing |
| `Stop` | `cogmem-capture.sh` | captures the session into memory (acquisition + consolidation) |

Every hook is strictly fail-open: any error, timeout, or cold daemon injects
nothing and never blocks your prompt. The scripts live in `~/.claude/cogmem/hooks/`;
re-run `install.sh` (or `./install.sh --no-daemon`) to refresh the wiring.

<details>
<summary><strong>Why cogmem?</strong> -- learns from outcomes, models failure modes, verifiable memory</summary>

Chat-memory systems (Mem0, Letta, Zep) store and retrieve facts. cogmem is built for coding agents and goes further on three axes:

**It learns from outcomes.** A feedback loop scores whether a recalled lesson actually helped, refines rules that prove wrong, and retires ones that mislead.

**It models its own failure modes.** cogmem tracks where the agent tends to go wrong in your work and intercepts known mistakes at the tool-call boundary — before they happen, not afterward.

**Its memory is verifiable.** Each memory is a W3C Verifiable Credential signed by the agent's `did:key`, recorded in a tamper-evident, SCITT-style transparency log. Agent memory is an attack surface; cogmem makes it auditable and poison-resistant.

</details>

<details>
<summary><strong>Features</strong> -- two-layer memory, outcome feedback, self-model, project state, cross-project narrative, self-regulation, verifiable credentials</summary>

- **Two-layer memory**: always-loaded directives (scope-gated, human-approved) plus a semantic recall tail (local cross-encoder reranking, no data leaves the machine).
- **Outcome feedback and self-refinement**: memories earn or lose trust based on whether they actually helped; contradicted rules are corrected through a safe pipeline.
- **Self-model and guard**: a model of the agent's recurring mistakes, compiled into tripwires that intercept them at the `PreToolUse` boundary.
- **Project-state model**: a living per-project state (goal, claims, open questions, blockers) that gives situational continuity and reasons across time.
- **Cross-project progress narrative**: momentum, stalls, and dependencies across projects, surfaced as alerts.
- **Self-regulation**: recall thresholds tuned automatically against an eval harness.
- **Verifiable Agent Memory**: `did:key` identity, W3C VC-signed memories, COSE_Sign1 SCITT signed statements (byte-compatible with HMS), a hash-chained transparency log with signed Merkle tree head and RFC 6962 inclusion receipts, optional poison-resistance enforcement. See [PROVENANCE.md](./PROVENANCE.md).

</details>

<details>
<summary><strong>Verifiable Memory</strong> -- did:key identity, W3C VC, COSE/SCITT, hash-chained log, poison-resistance</summary>

cogmem treats every stored memory as a signed artifact:

- **`did:key` identity**: each agent gets a persistent Ed25519 identity, exposed as a W3C DID.
- **W3C Verifiable Credentials**: every memory is signed with `eddsa-jcs-2022` Data Integrity proofs.
- **COSE_Sign1 / SCITT signed statements**: byte-identical to the envelope format used by holographic-memory and crosstalk — independently verifiable by any of the three implementations.
- **Hash-chained transparency log**: append-only JSONL with SHA-256 chaining, a signed Merkle tree head, and RFC 6962-style inclusion receipts.
- **Poison-resistance**: altered or injected memories fail verification and are rejected before influencing the agent.

```bash
cogmem verify              # check all memories and the log head
cogmem receipt <memory-id> # prove a memory is in the signed log
```

See [PROVENANCE.md](./PROVENANCE.md) for the full specification.

**Verify the C2PA sample yourself:**

```bash
# examples/c2pa-agent-credential/ is a real signed C2PA manifest
# whose agent identity validates in c2patool
./examples/c2pa-agent-credential/verify.sh
```

This proves the whole chain: agent identity (`cawg.ica.credential_valid`) bound to real cognition — a signed cogmem memory and a signed crosstalk reasoning audit, each an independently verifiable Ed25519 COSE/SCITT statement.

</details>

## Privacy

cogmem is local-first by design. Memories, embeddings, and the identity key live on your machine; semantic recall runs on a local model (fastembed). Nothing is sent anywhere.

## Part of the Agent-Provenance Stack

cogmem is one component of the WritersLogic verifiable agent-provenance pipeline — agent identity, memory, reasoning, and signed output, cryptographically bound end to end.

| Project | Role |
|---|---|
| **cogmem (this repo)** | Agent identity (CAWG credential) + verifiable, tamper-evident memory (COSE/SCITT) |
| [crosstalk](https://github.com/writerslogic/crosstalk) | Multi-model orchestrator; signs each turn's reasoning/orchestration audit |
| [holographic-memory](https://github.com/writerslogic/holographic-memory) | Durable holographic memory store; cross-verifies signed statements and agent identity |
| WritersProof | C2PA producer: binds identity + memory + reasoning to the signed asset |

All four share one substrate — COSE_Sign1 / SCITT signed statements (Ed25519) and W3C DID identity — specified in [UNIFIED-PROVENANCE.md](./UNIFIED-PROVENANCE.md).

## License

Apache-2.0 — see [LICENSE](./LICENSE).
