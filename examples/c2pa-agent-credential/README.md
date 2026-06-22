# A verifiable AI-agent identity in a C2PA Content Credential

This is a **real, signed C2PA manifest** in which an AI agent (the cogmem agent) is a
first-class, cryptographically verifiable named actor — via the **standard CAWG Identity
Claims Aggregation (ICA)** path. `c2patool` validates it as `cawg.ica.credential_valid`.

The agent's identity credential **binds to two sibling assertions** carrying the agent's
actual cognition:

| Assertion | What it is |
|---|---|
| `cawg.identity` | The agent's ICA credential — a W3C VC (Ed25519), issuer `did:jwk`, sig_type `cawg.identity_claims_aggregation` |
| `cogmem.memory.provenance` | A **real** cogmem COSE/SCITT signed statement — the memory that steered the output |
| `crosstalk.orchestration.audit` | A **real** crosstalk COSE/SCITT signed statement — the reasoning/orchestration that produced it |
| `c2pa.hash.data` | The hard binding to the asset (`agent-content.txt`) |

The two cognition statements are not placeholders: they are genuine Ed25519 COSE_Sign1
statements on the [shared substrate](../../UNIFIED-PROVENANCE.md), and each
cross-verifies under independent implementations (cogmem and holographic-memory).

## Files
- `agent-content.txt` — the asset the agent produced.
- `agent-content.c2pa` — the signed C2PA 2.4 manifest (standalone sidecar).
- `wp-root.pem` — the X.509 trust anchor for the claim signer (optional, for trust checks).
- `verify.sh` — runs `c2patool` and asserts the agent identity is valid.

## Verify it yourself

You need a `c2patool` that runs the asynchronous **CawgValidator** (the CAWG identity
path). Build it from [contentauth/c2pa-rs](https://github.com/contentauth/c2pa-rs):

```bash
git clone https://github.com/contentauth/c2pa-rs
cd c2pa-rs && cargo build --release -p c2patool
```

Then:

```bash
C2PATOOL=/path/to/c2pa-rs/target/release/c2patool ./verify.sh
```

Expected:

```
PASS: cawg.ica.credential_valid — the AI agent's identity validates.
  issuer: did:jwk:eyJjcnYiOiJFZDI1NTE5Ii…
  type:   IdentityClaimsAggregationCredential
```

Or inspect the full report directly:

```bash
c2patool agent-content.c2pa --detailed
```

You'll see `cawg.ica.credential_valid` in `validation_results.activeManifest.success`,
and the decoded `cawg.identity` credential issued by the agent's DID.

## Honest notes
- The issuer here is `did:jwk` (self-contained, resolves with no network) so this sample
  verifies offline. Production uses `did:web:writersproof.com:agents:cogmem`.
- `validation_state` may report `signingCredential.untrusted` unless you supply
  `wp-root.pem` as a trust anchor — that's about the X.509 *claim signer*, independent of
  the CAWG agent-identity validity shown by `cawg.ica.credential_valid`.
- The agent's operator is attested with the **standard `cawg.affiliation`** verified-identity
  type (provider + `verifiedAt`) — no vendor-namespaced placeholder. The agent itself is a
  named actor identified by the ICA issuer DID, and CAWG's named-actor model already permits
  software actors. What is *not* yet standard is a portable AI-agent **identity credential**
  (what the agent is — nature, operator, model); that is an identity-layer (W3C VC / DIF
  Trusted AI Agents WG) question, not a CAWG/C2PA one. See
  [`docs/proposals/ai-agent-identity-for-content-provenance.md`](../../docs/proposals/ai-agent-identity-for-content-provenance.md).
