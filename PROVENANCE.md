# Verifiable Agent Memory

cogmem's provenance layer makes agent memory **verifiable and tamper-evident**, so a
poisoned or altered memory can be detected — and optionally rejected — before it
steers the agent. It is built on real, recognized standards, and the cryptography is
real (Ed25519), not illustrative.

## Why this exists

Agent memory is an emerging attack surface. cogmem stores rules that directly change
agent behavior and even compile into guards that block tool calls. A single poisoned
rule is an exploit path that no current agent-memory system (Mem0, Letta, Zep)
addresses. Verifiable, tamper-evident memory closes that gap and is a capability the
broader decentralized-identity and content-provenance communities are actively
building toward in 2026.

## What is implemented (MVP, real crypto, tested)

- **Agent identity as `did:key`** (W3C DID method), backed by a real Ed25519 keypair.
  The private key is local-only (`vault/identity/agent.key`, mode 0600); the DID is
  self-certifying. Example: `did:key:z6Mk...`.
- **Memories as W3C Verifiable Credentials** (VC Data Model v2). Each rule is issued
  as an `AgentMemoryCredential` signed by the agent's DID via an `eddsa-jcs-2022`-style
  Data Integrity proof. Stored in `vault/credentials/<id>.jsonld`.
- **SCITT-style transparency log** (`vault/provenance/log.jsonl`): an append-only,
  hash-chained, signed record of memory lifecycle events (created / updated /
  refined / demoted). Tampering with any entry breaks the chain; entries cannot be
  forged without the agent key.
- **Signed Merkle tree head + inclusion receipts** (RFC 6962-style). The log commits
  to a signed Merkle root; `cogmem receipt <id>` issues a compact inclusion proof
  that a memory is in the log, and `verify-receipt` checks it against the signed
  root — third-party-verifiable membership without needing a full copy of the log.
- **COSE_Sign1 SCITT signed statements** (`vault/provenance/statements/<id>.cose`).
  Each memory is also issued as a COSE_Sign1 signed statement (CBOR, Ed25519), the
  encoding used by `draft-ietf-scitt-architecture` — and it is **byte-compatible with
  the Holographic Memory System (HMS)**: a cogmem-produced statement verifies under
  HMS's `coset` verifier, proven by a shared conformance vector in both repos'
  `tests/vectors/`. `cogmem statement <id>` emits one; `verify-statement` checks it.
- **CAWG Identity Claims Aggregation (ICA) credential.** The agent issues a W3C VC v2
  `IdentityClaimsAggregationCredential` (did:jwk / did:web issuer), secured by a tag-18
  COSE_Sign1 over the VC and embedded under the `cawg.identity` assertion. It validates
  in c2patool 0.26.30 as `cawg.ica.credential_valid`. Its `referenced_assertions`
  include the hard binding plus the sibling assertions `cogmem.memory.provenance` and
  `crosstalk.orchestration.audit`, so the agent's signature attests participation in the
  whole C2PA assertion chain (see UNIFIED-PROVENANCE.md).
- **Pinned trust anchor (TOFU).** The trusted agent DID is recorded on first run in
  `$COGMEM_HOME/trust.json` (outside `vault/`, mode 0600). Verification checks each
  artifact's signature **and** that its issuer is the pinned DID, so a memory or log
  re-signed under a *foreign* key — a self-consistent forgery a vault-content attacker
  could otherwise mint — is rejected as an untrusted issuer. Intentional key rotation is
  explicit: `cogmem trust --rotate` re-anchors to the current key and retains the prior
  DID, so history signed by the retired key still verifies. `cogmem trust` shows the
  anchor and warns on a key/anchor mismatch. (Residual: an attacker with write access to
  the whole `$COGMEM_HOME` can re-anchor — see THREAT-MODEL.md §4.3.)
- **Verification + enforcement.** `cogmem verify` checks every credential, confirms
  each rule's statement still matches its signed credential (an unsigned edit is a
  tamper), and verifies the log chain. With `provenance_enforce` enabled, tampered or
  unsigned rules are **excluded from the recall index** — the poison-resistance gate.
- **Tests** (`test_provenance.py`) prove the security properties: tampered credentials
  rejected, cross-key forgery rejected, log tampering detected at the right position,
  forged log entries rejected.

CLI: `cogmem provenance status`, `cogmem sign-vault`, `cogmem verify`,
`cogmem provenance sth`, `cogmem receipt <id>`, `cogmem provenance verify-receipt <file>`,
`cogmem statement <id>`, `cogmem provenance verify-statement <file>`,
`cogmem trust [--rotate]`.

## Standards mapping

| Need | Standard | Status |
|---|---|---|
| Agent identity | W3C DID (`did:key`) | implemented |
| Memory as a verifiable claim | W3C Verifiable Credentials v2 | implemented |
| Signature suite | Data Integrity `eddsa-jcs-2022` (Ed25519) | implemented (JCS-style canonicalization) |
| Signed statements | IETF **SCITT** COSE_Sign1 (CBOR, Ed25519) | implemented; byte-compatible with HMS (`coset`) |
| Tamper-evident provenance | IETF **SCITT** transparency log | implemented, incl. signed tree head + RFC 6962 inclusion receipts |
| Credential encoding | IETF **SD-JWT-VC** | roadmap |
| Federated/agent-to-agent exchange | ToIP **Trust Spanning Protocol** (MCP binding in draft) / DIF **DIDComm** | roadmap |
| Output/content binding | **CAWG** Identity Claims Aggregation (ICA) + **C2PA** | implemented; validates in c2patool 0.26.30 as `cawg.ica.credential_valid` |
| Enterprise identity tier | witnessd-anchored attestation / X.509 (CAWG X.509 path) | roadmap |

## Roadmap

1. **External transparency service**: anchor the signed tree head in an independent,
   append-only log (or witnessd) so inclusion is verifiable beyond the agent's own
   signature. (Inclusion receipts themselves are implemented — see above.)
2. **SD-JWT-VC** encoding for selective disclosure and interop with verifier tooling.
3. **Enterprise identity tier**: a CA-backed / X.509 identity anchored on **witnessd**
   (the attestation protocol), for team/federated memory where "this memory came from
   a certified agent in our trust domain" matters. `did:key` remains the self-sovereign
   default. (WritersProof's app-signing is deliberately not used; it serves a different
   purpose.)
4. **Federated exchange over ToIP TSP**, riding the MCP-over-TSP binding being drafted
   now — cogmem is an MCP server, so a "verifiable agent memory exchanged over TSP"
   reference implementation is directly in reach.
5. **CAWG / C2PA output binding**: attest that an agent's produced artifact was created
   under a given memory/identity provenance.

## Community

This sits exactly where DIF (Trusted AI Agents WG), W3C (Agent Identity Registry
Protocol CG), ToIP (TSP, with its AI-agent and MCP bindings), CAWG and IETF (SCITT,
WIMSE, SD-JWT-VC) are converging in 2026. The intended engagement is as a *builder
with a running implementation* in the DIF Trusted AI Agents Working Group, with the
MCP-over-TSP work as the bridge to ToIP. The MVP above is already a concrete,
demonstrable artifact for that conversation.
