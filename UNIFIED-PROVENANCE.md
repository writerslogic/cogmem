# Unified Agent Provenance — cogmem · crosstalk · HMS · WritersProof

One verifiable-provenance substrate across four WritersLogic projects, so an AI agent
is a cryptographically verifiable, first-class actor in a **C2PA Content Credential** —
its identity, the memory that steered it, and the reasoning that produced it all bound
to the signed output and independently cross-verifiable.

This is the coordinating spec. Each repo conforms to the **shared substrate** (below)
so the pieces compose instead of diverging. Where a repo already implements a part, the
status says so; where it doesn't, the work item says what to build.

## The pillars

| Pillar | Project | Signs | Status |
|---|---|---|---|
| WHO — agent identity | **cogmem** | CAWG ICA credential (W3C VC, did:jwk/did:web issuer) | ✅ validates in c2patool 0.26.30 as `cawg.ica.credential_valid` |
| WHAT memory | **cogmem** | COSE/SCITT signed memory statements (+ Merkle receipts) | ✅ implemented, byte-compatible with HMS |
| WHAT reasoning | **crosstalk** | signed + hash-chained orchestration turns | ⚠️ raw Ed25519 today; must also emit a COSE/SCITT audit statement |
| Durability / store | **HMS** | holographic memory; cross-verifies cogmem (and soon crosstalk) statements | ✅ cogmem COSE cross-verify; ICA cross-verify is the open item |
| Packaging | **WritersProof** | the C2PA 2.4 JUMBF manifest binding it all | ✅ two-pass `identityAssertion` producer hook + e2e test |

## The shared substrate

Everything rides **one** signature envelope and **one** identity model, so any pillar's
output verifies under any other pillar's verifier.

### Identity (DID)
- Ed25519 keys. Agent identity is a DID: `did:key` (self-certifying), `did:jwk`
  (self-contained, resolves with no network — used for offline/CI verification), or
  `did:web` (production, hosted, publishes the key as an `assertionMethod` →
  `publicKeyJwk` OKP so the c2pa-rs CAWG ICA resolver accepts it).

### Signed statement — COSE_Sign1, SCITT-style
The unit of cross-verifiable provenance. **Untagged** `COSE_Sign1`, CBOR, EdDSA:
- protected header: `{1: -8 (EdDSA), 3: "application/cbor", 4: <raw 32-byte Ed25519 pubkey as kid>}`
- `external_aad` = empty
- payload: a CBOR claim map (the statement contents)

This is exactly cogmem's `signed_statement` (`engine/provenance.py`) and HMS's
`coset`-based verifier. A conformance vector lives in both repos' `tests/vectors/`
(`cose-signed-statement.json`). **crosstalk's orchestration-audit statement MUST use
this envelope** so HMS verifies it and it can be a C2PA assertion.

### Agent identity credential — CAWG ICA
The agent's identity is an **Identity Claims Aggregation** credential, the path c2pa-rs
ships and c2patool validates:
- a W3C VC v2, `type: [VerifiableCredential, IdentityClaimsAggregationCredential]`,
  context `https://cawg.io/identity/1.1/ica/context/`, `issuer` = the agent DID.
- secured by a **tag-18** `COSE_Sign1`, alg EdDSA, `content_type: "application/vc"`,
  over the VC JSON (note: tag-18 and `application/vc`, distinct from the untagged
  `application/cbor` signed statement above).
- `credentialSubject.c2paAsset` = the `SignerPayload` (referenced-assertion hashes as
  standard base64), cross-checked against the CBOR `signer_payload` in the assertion.
- embedded under the `cawg.identity` assertion label as
  `{signer_payload, signature, pad1}`.

Implemented in cogmem `engine/provenance.py` (`ica_identity_assertion`,
`verify_ica_assertion`, `agent_did_jwk`, `agent_did_web`).

### Critical invariant — referenced-assertion hashes are finalized hashes
A CAWG identity assertion references other assertions (`c2pa.hash.data`,
`cogmem.memory.provenance`, `crosstalk.orchestration.audit`, …) by their **finalized
JUMBF assertion-box hashes**. Those exist only **after** the producer serializes the
assertions. **Pre-baking content hashes fails validation silently** — c2pa-rs's CAWG
validator early-returns on a hash mismatch without logging (it reads as
`cawg.validation_skipped`). Therefore the identity assertion is built in a **two-pass**
producer step: serialize the other assertions → hand their real hashes to the identity
signer → embed → sign the claim. WritersProof's `buildStandaloneManifest` implements
this as the `identityAssertion` hook.

## The C2PA binding

The agent's `cawg.identity` (ICA) credential binds the agent DID to the assertion set:

```
c2pa.claim.v2
├── c2pa.hash.data                  (hard binding — required)
├── c2pa.actions.v2
├── cogmem.memory.provenance        (COSE/SCITT statement: the memory that steered it)
├── crosstalk.orchestration.audit   (COSE/SCITT statement: the reasoning that produced it)  ← new
└── cawg.identity                    (ICA credential; referenced_assertions → the hashes above)
```

`cawg.identity.signer_payload.referenced_assertions` MUST include the hard binding and
SHOULD include the memory + orchestration statements, so the agent's signature attests
participation in the whole chain.

## Cross-verification matrix

| Artifact | Verified by | Status |
|---|---|---|
| cogmem memory statement (COSE) | HMS `coset` verifier | ✅ shared vector |
| crosstalk orchestration audit (COSE) | HMS `coset` verifier | ⬜ once crosstalk emits the statement |
| agent ICA credential | c2patool / c2pa-rs `IcaSignatureVerifier`; HMS `verify_cawg_ica` | ✅ c2patool; ⬜ HMS |
| C2PA manifest | c2patool | ✅ `cawg.ica.credential_valid` proven |

## Work items (segmentable)

1. **cogmem** — drop the superseded `did.cose` vector; keep the ICA emitter + did:jwk/
   did:web + `ica-assertion` CLI (done); add a `crosstalk.orchestration.audit` reference
   path. *(owner: integrator)*
2. **HMS** — add `did:jwk` resolution + `verify_cawg_ica` (parse the embedded
   IdentityAssertion CBOR, verify the tag-18 COSE over the VC under the issuer DID,
   check sig_type + hard binding); migrate the cross-verify test from did.cose to the
   ICA vector. *(parallelizable)*
3. **crosstalk** — emit the signed orchestration-audit head (the hash-chain head +
   session identity) as a COSE/SCITT signed statement on the shared substrate
   (untagged COSE_Sign1, EdDSA, kid = raw pubkey, CBOR claim), so HMS verifies it and it
   becomes the `crosstalk.orchestration.audit` C2PA assertion. *(parallelizable)*
4. **WritersProof** — producer hook + e2e test done; extend the e2e to also reference a
   `crosstalk.orchestration.audit` assertion once #3 lands. *(integrator)*

## Non-divergence rules

- All signed statements use the **untagged COSE_Sign1 / `application/cbor`** envelope
  in *The shared substrate*. The **only** tag-18 / `application/vc` COSE is the ICA
  credential. Do not mix them.
- Assertion labels are stable: `cogmem.memory.provenance`, `crosstalk.orchestration.audit`,
  `cawg.identity`.
- The agent key is Ed25519 everywhere. No ES256 for agent identity (ES256 stays the
  WritersProof X.509 *claim signer*, a separate role).
