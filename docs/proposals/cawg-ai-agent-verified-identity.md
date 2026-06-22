# A `cawg.ai_agent` verified-identity type for AI agents

**Status:** Proposal / RFC for discussion. Not an adopted specification.
**Target:** CAWG Identity Claims Aggregation (ICA), additive to the 1.1 draft.
**Author context:** Surfaced by the cogmem agent-provenance work, which ships a working
AI-agent ICA credential today (validates in c2patool as `cawg.ica.credential_valid`)
but had to use a vendor-namespaced placeholder type for lack of a standard one.

---

## 1. Problem statement

CAWG Identity Claims Aggregation lets an *identity assertion generator* bind one or more
identity-claim attestations about a *named actor* to a C2PA asset, via a W3C Verifiable
Credential whose `credentialSubject.verifiedIdentities[]` array carries the attestations.
Each entry's `type` property "defines the type of verification that was performed by the
identity provider" (per the `VerifiedIdentity` doc comments in c2pa-rs,
`sdk/src/identity/claim_aggregation/ica_credential.rs`).

Every CAWG-defined `type` assumes the named actor is a **human**:

- `cawg.social_media` — the actor's social-media account (`username`, `uri`).
- `cawg.document_verification` — the actor's legal name as found on identity documents.
- `cawg.crypto_wallet` — the actor's wallet `address`.
- `cawg.affiliation` — the actor's affiliation with an organization.

There is no defined type for asserting that **the named actor is a software / AI agent,
operated and attested by party X**. As autonomous agents become first-class actors that
produce signed content, this is a real gap: a C2PA consumer can today learn that a human
named actor was document-verified, but cannot learn — in standard, vendor-neutral terms —
that the actor is an AI agent, what its canonical identity is, or which organization
operates and stands behind it.

The cogmem project ships a complete, validating AI-agent ICA credential. The agent is the
*issuer* of an `IdentityClaimsAggregationCredential` secured by a tag-18 `COSE_Sign1`
(EdDSA, `content_type: application/vc`) over the VC JSON, with
`credentialSubject.c2paAsset` carrying the `SignerPayload` and cross-checked against the
CBOR `signer_payload` in the embedded identity assertion. It validates end-to-end in
c2patool 0.26.30 (`cawg.ica.credential_valid`) and under the c2pa-rs
`IcaSignatureVerifier`. The implementation is sound; the only non-standard element is the
`verifiedIdentities[].type` string. Because no CAWG type fits an agent, the emitter
(`engine/provenance.py`, `agent_verified_identity`) is forced to pass a vendor-namespaced
placeholder, currently `writersproof.ai_agent`:

```python
vi = [agent_verified_identity(
    "cogmem agent", "https://writersproof.com", "WritersProof",
    id_type="writersproof.ai_agent",
    uri="https://writersproof.com/agents/cogmem")]
```

A vendor namespace is the correct stopgap — it does not collide with the `cawg.` reserved
space and it is honest about being non-standard — but it means no two vendors describe
the same fact the same way, and a generic CAWG consumer cannot recognize "this actor is
an AI agent" without out-of-band knowledge of each vendor's string. A single standard
type closes that gap.

## 2. Proposed type: `cawg.ai_agent`

We propose a new CAWG-defined verified-identity type, **`cawg.ai_agent`**.

### 2.1 Name choice

`cawg.ai_agent` parallels the existing `cawg.`-namespaced human types and reads as a
verification *category* ("what was verified: that this is an AI agent"), consistent with
how `cawg.social_media` and `cawg.document_verification` name a category of verification
rather than a data shape. Alternatives considered:

- `cawg.software_agent` — broader; arguably more accurate, since the type asserts an
  *autonomous software* actor whether or not it embeds an ML model. We prefer
  `cawg.ai_agent` for recognizability and because the motivating actors are AI agents,
  but `cawg.software_agent` is a reasonable counter-proposal the community may prefer.
- `cawg.bot` — rejected as imprecise and pejoratively loaded.
- `cawg.machine_identity` — rejected; conflates the agent (an actor) with workload/service
  identity (a key-management concern, e.g. SPIFFE), which is out of scope here.

The semantic decision is the same under any name: **assert that the named actor is an
autonomous software/AI agent, and attest to its operator.** We use `cawg.ai_agent` below.

### 2.2 Semantics

`cawg.ai_agent` asserts that the *identity provider* has verified that the *named actor*
is an autonomous software / AI agent, and attests to the **operator** of that agent — the
organization or party that runs it and stands accountable for its operation. As with every
other CAWG type, the assertion is about *identity and the verification relationship*, not
about the agent's behaviour or the correctness of its outputs (see §4).

The named actor's *operator* is expressed using the existing `provider` object: the
provider is the identity assertion generator and, for this type, is also asserting the
operator relationship. Where the identity provider and the operator are distinct legal
entities, that distinction is out of scope for v1 and can be addressed by a future field;
the common and motivating case is that the operator runs the identity-assertion generator.

### 2.3 Fields

`cawg.ai_agent` reuses the existing `VerifiedIdentity` shape with no structural change.
The following constraints apply for this type (additive: they only tighten optional fields
to REQUIRED for `cawg.ai_agent`, mirroring how `cawg.social_media` makes `username`
REQUIRED and `cawg.document_verification` makes `name` REQUIRED).

| Field | Base rule | For `cawg.ai_agent` | Meaning for an agent |
|---|---|---|---|
| `type` | REQUIRED, non-empty string | `"cawg.ai_agent"` | Names the verification: that the actor is an AI agent. |
| `name` | OPTIONAL | **REQUIRED** | The agent's name as understood by the provider (e.g. `"cogmem agent"`). |
| `uri` | OPTIONAL, valid URI | **REQUIRED** | The agent's canonical, dereferenceable URI: a stable home/identity page, ideally the URL backing its `did:web` (e.g. `https://writersproof.com/agents/cogmem`). |
| `provider.id` | REQUIRED, valid URI, deref → proof of authenticity of the provider | **REQUIRED (unchanged)** | The operator/attestor org's URI; dereferencing it proves the *provider's* authenticity (not the agent's). |
| `provider.name` | REQUIRED, non-empty string | **REQUIRED (unchanged)** | User-visible operator name (e.g. `"WritersProof"`). |
| `verifiedAt` | REQUIRED, RFC 3339 date-time | **REQUIRED (unchanged)** | When the provider verified the agent↔operator relationship. |
| `username`, `address` | OPTIONAL | Not used by this type | Human-oriented; omit. |

#### Proposed agent-specific additions (additive extension fields)

These are **new, OPTIONAL** fields on the `VerifiedIdentity` object, namespaced or added
under CAWG governance. They are purely additive — existing parsers (which deserialize the
defined fields and retain unknown ones, as c2pa-rs does via `extra_properties` on the
credential summary) are unaffected, and nothing here is breaking. Each is justified
conservatively; we propose only what an interoperating consumer can act on.

1. **`agentDid`** (OPTIONAL, string, a DID) — the agent's Decentralized Identifier, e.g.
   `did:web:writersproof.com:agents:cogmem`. **Justification:** the agent's signing key is
   bound to its DID (the ICA credential's `issuer` is that DID). Publishing the DID as a
   verified-identity field lets a consumer connect the asserted identity to the key that
   actually signed, and resolve the DID document independently. This is the single
   highest-value addition. In the common case it equals `issuer`; stating it explicitly in
   `verifiedIdentities[]` keeps the assertion self-describing and survives any future case
   where issuer ≠ subject. If `uri` already points at the `did:web` document, `agentDid`
   MAY be omitted, but stating it is RECOMMENDED.

2. **`model`** (OPTIONAL, object `{ name, version }`) — the underlying model identity and
   version, e.g. `{ "name": "claude-opus-4", "version": "..." }`. **Justification:**
   provenance consumers reasonably want to know what produced the content. We make it
   OPTIONAL and free-form-but-structured rather than required because (a) operators may not
   wish to disclose it, (b) an "agent" may compose several models or none, and (c) the
   provider can only attest what it actually verified. Consumers MUST treat absence as
   "not disclosed," never as "no model."

3. **`capabilityScope`** (OPTIONAL, array of strings) — a coarse declaration of what the
   agent is authorized/intended to do, e.g. `["content-generation", "memory-curation"]`.
   **Justification:** useful for risk assessment, but deliberately advisory. We resist
   encoding fine-grained authorization here; that is the domain of capability/authorization
   tokens, not an identity attestation. If the community judges this premature, it should
   be dropped from v1 with no impact on the rest of the proposal.

We recommend adopting `agentDid` with the type, treating `model` as RECOMMENDED-where-known,
and treating `capabilityScope` as the most negotiable item.

## 3. Mapping to the ICA credential

A `cawg.ai_agent` entry sits in `credentialSubject.verifiedIdentities[]` of the
`IdentityClaimsAggregationCredential`, alongside the existing `c2paAsset` binding. Nothing
about the credential envelope, the tag-18 COSE securing, or the `c2paAsset` cross-check
changes; only the contents of one `verifiedIdentities[]` entry differ from the human types.

Worked example for the real cogmem agent
(`did:web:writersproof.com:agents:cogmem`), matching the structure produced by
`ica_credential` / `agent_verified_identity` in `engine/provenance.py`. The `c2paAsset`
mirrors the CBOR `signer_payload` carried in the embedded identity assertion (hashes shown
as standard, non-URL-safe base64 per the ICA spec; the `c2pa.hash.data` hard binding is
referenced as required):

```json
{
  "@context": [
    "https://www.w3.org/ns/credentials/v2",
    "https://cawg.io/identity/1.1/ica/context/"
  ],
  "type": ["VerifiableCredential", "IdentityClaimsAggregationCredential"],
  "issuer": "did:web:writersproof.com:agents:cogmem",
  "validFrom": "2026-06-21T00:00:00Z",
  "credentialSubject": {
    "verifiedIdentities": [
      {
        "type": "cawg.ai_agent",
        "name": "cogmem agent",
        "uri": "https://writersproof.com/agents/cogmem",
        "verifiedAt": "2026-06-21T00:00:00Z",
        "provider": {
          "id": "https://writersproof.com",
          "name": "WritersProof"
        },
        "agentDid": "did:web:writersproof.com:agents:cogmem",
        "model": { "name": "claude-opus-4", "version": "20260101" },
        "capabilityScope": ["content-generation", "memory-curation"]
      }
    ],
    "c2paAsset": {
      "referenced_assertions": [
        {
          "url": "self#jumbf=c2pa.assertions/c2pa.hash.data",
          "alg": "sha256",
          "hash": "U2FtcGxlSGFyZEJpbmRpbmdIYXNoVmFsdWVCYXNlNjQwMDA="
        },
        {
          "url": "self#jumbf=c2pa.assertions/cogmem.memory.provenance",
          "alg": "sha256",
          "hash": "U2FtcGxlTWVtb3J5UHJvdmVuYW5jZUhhc2hWYWx1ZTAwMDA="
        }
      ],
      "sig_type": "cawg.identity_claims_aggregation"
    }
  }
}
```

This VC is then serialized and secured by the tag-18 `COSE_Sign1` (`_cose_sign1_vc`),
embedded under the `cawg.identity` assertion as `{signer_payload, signature, pad1}`
(`ica_identity_assertion`), and the producer references the finalized JUMBF assertion
hashes — exactly as the existing, validating pipeline does. Swapping
`writersproof.ai_agent` for `cawg.ai_agent` (plus the additive fields) is the only change
to the on-the-wire artifact.

> Note on the hashes above: the `hash` values are illustrative base64 placeholders. In a
> real manifest they are the **finalized** JUMBF assertion-box hashes, available only after
> the producer serializes the referenced assertions; pre-baking them fails ICA validation
> silently. cogmem's emitter takes the real hashes as input (`ica-assertion <label>=<hex>`)
> in the producer's two-pass step. The values here are not from a signed manifest.

## 4. Security & trust considerations

**What the provider attests.** A `cawg.ai_agent` entry attests exactly two things: (1) the
named actor is an autonomous software/AI agent, and (2) the named operator
(`provider.name`, authenticated via `provider.id`) operates that agent and stands
accountable for it. The `provider.id` dereference proves the **provider's** authenticity,
*not* the agent's — this is the same caveat the base spec makes for all types, and it is
especially important here: a consumer must not read operator authenticity as agent-output
authenticity.

**What it does NOT attest.** It makes no claim that the agent's outputs are correct, safe,
non-infringing, or free of hallucination. It is an *identity* attestation, not a quality,
safety, or alignment attestation. `model` and `capabilityScope`, when present, are
declarations the provider chose to make, not guarantees about runtime behaviour.

**Key binding and accountability.** Trust ultimately rests on the agent DID. The ICA
credential's `issuer` is the agent DID, and the tag-18 COSE over the VC is verified under
the key that DID resolves to (`resolve_did_to_key`): for `did:web` this is the
`publicKeyJwk` (OKP/Ed25519) published as an `assertionMethod` in the DID document, for
`did:jwk` it is embedded in the DID itself. So the agent identity asserted in
`verifiedIdentities[]` is bound to the key that actually signed. Proposing `agentDid` as an
explicit field makes that binding legible to consumers rather than implicit in `issuer`.

**Operator accountability.** Because `provider.id` must dereference to a proof of the
operator's authenticity, the operator is a named, locatable party. This is the
accountability anchor: an agent that misbehaves traces to a real operator, and a consumer
can decide trust per operator. Self-asserted operator identity (e.g. an operator vouching
for its own agent) is the expected common case and is legitimate, but consumers should
weigh it as self-attestation — the same way a self-hosted `did:web` is weaker evidence than
one corroborated out-of-band.

**Spoofing / impersonation.** The type does not by itself prevent an operator from claiming
an agent identity it does not control; control is established by possession of the DID's
signing key, not by the string in `name`. Consumers gain assurance by resolving `agentDid`
/ `uri` and confirming the published key matches the signer.

## 5. Relationship to existing work

- **Implementation exists and validates today.** cogmem emits the full ICA credential and
  identity assertion (`engine/provenance.py`: `ica_credential`,
  `ica_identity_assertion`, `agent_verified_identity`, `verify_ica_assertion`). It
  validates in c2patool 0.26.30 as `cawg.ica.credential_valid` and verifies under the
  c2pa-rs `IcaSignatureVerifier`. The *only* non-standard element is the
  `verifiedIdentities[].type` string; this proposal replaces a vendor placeholder with a
  standard type and adds optional fields.
- **Intentionally additive to CAWG 1.1.** Defining `cawg.ai_agent` adds a new permitted
  value of an existing required field (`verifiedIdentities[].type`) and a small set of new
  OPTIONAL object fields. It does not alter the credential envelope, the COSE securing, the
  `c2paAsset` binding, the context IRI, or any existing type. Verifiers that do not
  recognize `cawg.ai_agent` still validate the credential's cryptography and the C2PA
  binding; they simply do not specially interpret the type — exactly as they would treat
  any vendor type today. No change is breaking.
- **Reference structures.** Field semantics in §2 follow the `VerifiedIdentity` /
  `IdentityProvider` doc comments in c2pa-rs
  `sdk/src/identity/claim_aggregation/ica_credential.rs`. The credential mechanics follow
  the cogmem ICA path documented in `UNIFIED-PROVENANCE.md`.

## 6. Framing

This is a proposal/RFC offered to the CAWG community for discussion, not an adopted
specification. The implementation behind it is real and validates today, but the type name
(`cawg.ai_agent` vs. `cawg.software_agent`), the exact set of additive fields, and whether
to model operator-vs-provider distinctions are all open for the working group to decide.
The narrow, defensible claim is: **CAWG ICA has a genuine, demonstrable gap — no verified
identity type describes an AI/software agent — and a single additive `cawg.` type closes
it without breaking anything.**
