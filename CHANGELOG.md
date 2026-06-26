# Changelog

All notable changes to this project are generated from the commit history.
Format: [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) +
[Conventional Commits](https://www.conventionalcommits.org/).
## [2.5.0] - 2026-06-26

### Added
- Bring MCP tools to Glama TDQS 5/5 (titles, param docs, annotations, outputSchema, structuredContent)
- Add idempotent installer, ship Claude Code hooks, and glama.json
- Add did:web-issued sample alongside the offline did:jwk one
- Prove identity-to-cognition binding in the C2PA sample
- AIAgentCredential reference VC + security test coverage (poison-resistance, Merkle, ICA negatives) + CI soft-binding step
- Text-fingerprint soft-binding (char-4-gram SimHash + windowed blocks) with tests and spec
- Add CAWG Identity Claims Aggregation (ICA) agent identity with conformance vector
- COSE_Sign1 SCITT signed statements (cbor2), byte-compatible with HMS
- Initial public release of cogmem

### Changed
- Attest operator via standard cawg.affiliation; retarget AI-agent identity proposal to the identity layer (W3C/DIF)

### Documentation
- Restructure README with collapsible sections
- Rewrite README — fix logo tag, add install/quick start, improve structure
- README advertises the full runnable identity-to-cognition chain
- Regenerate sample manifest with standard cawg.affiliation operator attestation
- Add verifiable C2PA agent-credential sample and CAWG AI-agent identity-type proposal
- Add agent-provenance stack cross-reference to README
- Update changelog [skip ci]

### Fixed
- Restore curated changelog, make it release-triggered, add requirements.txt

### Security
- Move vault gitignore pattern to its own line so the private key is ignored
- Reject non-EdDSA COSE algorithms in _cose_verify (alg confusion); add THREAT-MODEL.md

