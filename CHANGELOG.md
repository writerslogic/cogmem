# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- **COSE_Sign1 SCITT signed statements** (`cogmem statement` / `verify-statement`):
  each memory is issued as a COSE_Sign1 signed statement (CBOR, Ed25519) per
  `draft-ietf-scitt-architecture`, byte-compatible with the Holographic Memory System —
  a cogmem statement verifies under HMS's `coset` verifier (shared conformance vector in
  `tests/vectors/`). Adds a `cbor2` dependency.
- **MCP server** (`cogmem mcp`): a stdlib-only stdio JSON-RPC server implementing the
  MCP `tools` and `resources` capabilities — eight tools (`recall`, `note`, `status`,
  `verify`, `receipt`, `tree_head`, `progress`, `review_pending`) with structured
  results, plus the user model and project states as read-only resources. Batch
  requests, `isError` tool semantics, and standard JSON-RPC error codes.
- **SCITT inclusion receipts.** A signed Merkle tree head commits to the whole
  transparency log; `cogmem receipt <id>` issues an RFC 6962-style inclusion proof
  that a memory is in the log, and `verify-receipt` checks it against the signed
  root — third-party-verifiable membership without a full copy of the log. Backed by
  five new tamper-rejection tests in `engine/test_provenance.py`.
- Repository conventions: `.gitignore` (protects the local vault and identity key),
  `.editorconfig`, `CONTRIBUTING.md`, `CODE_OF_CONDUCT.md`, `.github/` templates, and
  a CI workflow.
- New brand identity: a neural-iris logo (recall flow) with static, animated-SVG, and
  light/dark GIF variants.

## [2.4.0] — Verifiable Agent Memory

### Added
- Agent identity as a `did:key` (Ed25519); each memory issued as a W3C Verifiable
  Credential; an append-only, hash-chained, signed SCITT-style transparency log.
- `cogmem verify` / `sign-vault`; optional poison-resistance enforcement that excludes
  tampered or unsigned rules from the recall index.

## [2.3.0] — Active defense + temporal reasoning

### Added
- PreToolUse guard: failure modes carry tripwires that intercept a known mistake at
  the moment of action.
- Cross-project progress narrative (`cogmem progress`): momentum, stalls, dependencies.

## [2.2.0] — Stateful memory

### Added
- Living per-project state model, memory-in-the-loop (`recall` / `note`), artifact
  grounding from git history, and self-regulation (`tune`) against an eval harness.

## [2.1.0] — Learning + quality layer

### Added
- Outcome feedback loop with self-refinement, local cross-encoder recall reranking,
  a self-model of the agent's own failure modes, and a synthesized user model.

## [2.0.0] — Rebuild

### Changed
- Rebuilt from a dead JSON+bash pipeline into a working two-layer learning loop
  (always-load directives + semantic recall tail) over open markdown files.
