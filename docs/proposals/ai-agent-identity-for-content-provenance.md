# AI-agent identity for content provenance: bind it in CAWG, define it at the identity layer

**Status:** Discussion note. The *binding* it describes ships and validates today; the
*identity-credential* it proposes is for W3C / DIF discussion, not an adopted specification.
**Venues:** CAWG Identity Claims Aggregation (ICA) for the binding (no change needed);
W3C Verifiable Credentials, via DIF's Trusted AI Agents Working Group, for the identity
credential.
**Author context:** Surfaced by the cogmem agent-provenance work, which ships a working
AI-agent ICA credential today (validates in c2patool as `cawg.ica.credential_valid`).

---

## 1. Problem statement

An autonomous AI agent that produces signed content needs a **verifiable identity** that
(a) names the agent, (b) conveys its nature as a software agent rather than a human, and
(c) names an accountable operator that stands behind it. A C2PA consumer should be able to
learn, in standard and vendor-neutral terms, *who the agent is, who runs it, and what
produced the content* — and to verify those claims against the key that actually signed.

The question this note answers is **where each of those facts belongs**. The content
layer (C2PA) and the binding layer (CAWG ICA) already cover most of it with no spec
change. The one genuinely missing, standardizable piece — a portable description of *what
a verified AI agent is* — is an **identity-layer** concern (W3C VC), not a CAWG/C2PA one.
The original framing of this note proposed a new `cawg.ai_agent` verified-identity type;
on closer reading that is both unnecessary and out of scope for CAWG. Section 4 gives the
honest reasoning.

## 2. What already works, with no spec change

The cogmem agent is a first-class, cryptographically verifiable named actor today, using
only standard mechanisms. Nothing below requires a new CAWG type or a C2PA change.

- **The agent is a named actor with a DID.** CAWG's named-actor definition does not
  require the actor to be human; a software agent is a valid named actor. The agent is the
  *issuer* of an `IdentityClaimsAggregationCredential`, and `issuer` is the agent's DID
  (`did:web:writersproof.com:agents:cogmem`, or a self-contained `did:jwk` for offline
  samples). The tag-18 `COSE_Sign1` over the VC is verified under the key that DID resolves
  to (`resolve_did_to_key`), so the asserted identity is bound to the key that actually
  signed.
- **The operator is attested with the standard `cawg.affiliation` type.** The
  organization that runs the agent and stands accountable for it is expressed as a
  `verifiedIdentities[]` entry of type `cawg.affiliation` — an existing CAWG type whose
  required fields are `provider` (`id` + `name`) and `verifiedAt`. cogmem's emitter
  (`engine/provenance.py`, `agent_verified_identity`) uses exactly this: provider
  `https://writersproof.com` / `WritersProof`, with a `verifiedAt` timestamp. No
  vendor-namespaced placeholder is used.
- **Lifecycle / role is expressed with `role`.** Where the producer needs to record the
  agent's role in creating the asset, the standard C2PA `role` mechanism carries it; no new
  field is invented.
- **The binding validates today.** The VC is serialized, secured by the tag-18
  `COSE_Sign1` (`_cose_sign1_vc`), embedded under the `cawg.identity` assertion as
  `{signer_payload, signature, pad1}` (`ica_identity_assertion`), and its
  `credentialSubject.c2paAsset` is cross-checked against the CBOR `signer_payload` in the
  embedded identity assertion. It validates end-to-end in c2patool 0.26.30 as
  `cawg.ica.credential_valid` and under the c2pa-rs `IcaSignatureVerifier`.

This is the in-scope, working part. The agent identity is *bound* to the content with
standard CAWG/C2PA machinery, and the accountable operator is *attested* with a standard
CAWG type.

## 3. The actual gap and its correct home

What the standard types above do **not** provide is a single, portable, interoperable
description of the agent *as an AI agent* — its nature, its operator relationship, and
optionally the model and capability behind it — that any verifier can recognize without
out-of-band knowledge. `cawg.affiliation` attests *who the operator is*; it does not assert
*that the subject is an autonomous agent*, nor carry agent-specific facts like the model.

That description is an **identity-layer credential**, and it should be defined as a **W3C
Verifiable Credential** — the natural venue being **DIF's Trusted AI Agents Working
Group** — not as a new CAWG/C2PA type. Sketch of such a credential (`AIAgentCredential`),
issued by the operator, with the agent's DID as subject:

```json
{
  "@context": [
    "https://www.w3.org/ns/credentials/v2",
    "https://identity.foundation/trusted-ai-agents/v1"
  ],
  "type": ["VerifiableCredential", "AIAgentCredential"],
  "issuer": "https://writersproof.com",
  "validFrom": "2026-06-21T00:00:00Z",
  "credentialSubject": {
    "id": "did:web:writersproof.com:agents:cogmem",
    "agentType": "autonomous-software-agent",
    "operator": { "id": "https://writersproof.com", "name": "WritersProof" },
    "model": { "name": "claude-opus-4", "version": "20260101" },
    "capability": ["content-generation", "memory-curation"]
  }
}
```

The exact shape — field names, whether `model` and `capability` are in scope, how operator
authenticity is anchored — is for that working group to decide. The point is only that this
is an **identity** assertion: it says what the subject *is*, independent of any one piece of
content.

**CAWG then aggregates it for free.** CAWG ICA is, by construction, an *aggregator* of
identity claims: its credential accepts any `issuer` DID and any `verifiedIdentities[]`. So
once an `AIAgentCredential` exists at the identity layer, an ICA credential can reference or
embed it with **no change to CAWG and no change to C2PA**. The agent's `did:web` is already
the ICA issuer; whatever DIF/W3C standardize about that DID flows into the C2PA manifest
through the existing aggregation path. The layering is clean: the identity layer says what
the agent is, CAWG binds that identity to content, C2PA carries the manifest.

## 4. Why not a new CAWG type (the honest reasoning)

The earlier draft of this note proposed `cawg.ai_agent`. It is the wrong layer, for four
reasons that are worth stating plainly:

1. **The named-actor definition already permits software actors.** CAWG does not assume a
   named actor is human; a software/AI agent is already a valid named actor. There is no gap
   in CAWG's actor model to fill, only the absence of a standard *identity credential* — and
   that absence is upstream of CAWG.
2. **CAWG attests verified facts, not actor species.** Every CAWG verified-identity type
   names a *verification that was performed* (a social-media account, a document, a wallet,
   an affiliation). "The actor is an AI rather than a human" is a statement about the
   actor's *nature*, not a verification relationship — and tellingly, CAWG defines no
   `cawg.human` either. Attesting an actor's species is simply not a pattern CAWG uses.
3. **AI-generated content is already marked at the content layer.** "This content was
   produced by AI" is expressed by C2PA's `digitalSourceType` on the relevant action, not by
   an identity type. Adding an agent-nature identity type would duplicate, at the wrong
   layer, a fact C2PA already conveys.
4. **It would be out of scope for CAWG.** CAWG deliberately does not *define* identity; it
   *aggregates and binds* identity that other systems define. Defining what an AI-agent
   identity is — its nature, operator, model — is exactly the kind of identity semantics CAWG
   would treat as out of scope and defer to the identity layer.

So the correct move is not to add a CAWG type but to (1) use the existing CAWG mechanisms
for what they already cover (named actor + `cawg.affiliation` + binding), and (2) take the
novel piece — the AI-agent identity credential — to W3C/DIF.

## 5. Worked example

The real cogmem agent (`did:web:writersproof.com:agents:cogmem`), as produced by
`ica_credential` / `agent_verified_identity` in `engine/provenance.py`. The operator is
attested with the standard `cawg.affiliation` type; the agent is identified by the ICA
`issuer` DID. The `c2paAsset` mirrors the CBOR `signer_payload` carried in the embedded
identity assertion (hashes shown as standard, non-URL-safe base64 per the ICA spec; the
`c2pa.hash.data` hard binding is referenced as required):

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
        "type": "cawg.affiliation",
        "name": "cogmem agent",
        "uri": "https://writersproof.com/agents/cogmem",
        "verifiedAt": "2026-06-21T00:00:00Z",
        "provider": {
          "id": "https://writersproof.com",
          "name": "WritersProof"
        }
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

This validates today: the agent DID is the issuer, the operator is a standard
`cawg.affiliation` entry, and the binding cross-checks against the embedded identity
assertion. The **future** identity-layer addition is the `AIAgentCredential` sketched in
§3, issued by the operator with the agent DID as subject; once it exists, an ICA credential
references or embeds it through the same aggregation path, with no CAWG or C2PA change.

> Note on the hashes above: the `hash` values are illustrative base64 placeholders. In a
> real manifest they are the **finalized** JUMBF assertion-box hashes, available only after
> the producer serializes the referenced assertions; pre-baking them fails ICA validation
> silently. cogmem's emitter takes the real hashes as input (`ica-assertion <label>=<hex>`)
> in the producer's two-pass step. The values here are not from a signed manifest.

## 6. Security & trust considerations

**Key binding and accountability.** Trust rests on the agent DID. The ICA credential's
`issuer` is the agent DID, and the tag-18 COSE over the VC is verified under the key that
DID resolves to (`resolve_did_to_key`): for `did:web` this is the `publicKeyJwk`
(OKP/Ed25519) published as an `assertionMethod` in the DID document; for `did:jwk` it is
embedded in the DID itself. So the asserted agent identity is bound to the key that actually
signed.

**Operator accountability.** The `cawg.affiliation` entry's `provider.id` must dereference
to a proof of the operator's authenticity, so the operator is a named, locatable party that
stands accountable for the agent. The `provider.id` dereference proves the *operator's*
authenticity, **not** the agent's — and a consumer must not read operator authenticity as
agent-output authenticity. Self-asserted operator identity (an operator vouching for its own
agent) is the expected common case and is legitimate, but consumers should weigh it as
self-attestation.

**What none of this attests.** Neither the binding nor a future `AIAgentCredential` makes
any claim that the agent's outputs are correct, safe, non-infringing, or free of
hallucination. These are *identity* attestations, not quality, safety, or alignment
attestations. `model` and `capability`, if a future identity credential carries them, are
declarations the operator chose to make, not guarantees about runtime behaviour.

## 7. Status and venues

- **The binding ships and validates today.** cogmem emits the full ICA credential and
  identity assertion (`engine/provenance.py`: `ica_credential`, `ica_identity_assertion`,
  `agent_verified_identity`, `verify_ica_assertion`), validating in c2patool 0.26.30 as
  `cawg.ica.credential_valid` and under the c2pa-rs `IcaSignatureVerifier`. It uses only
  standard CAWG/C2PA mechanisms; there is no non-standard type and no vendor placeholder.
- **No CAWG change is requested.** The named-actor model and `cawg.affiliation` already
  cover the agent-as-actor and operator-attestation cases, and CAWG ICA already aggregates
  any identity-layer credential the agent's DID carries.
- **The identity-credential proposal is for W3C / DIF discussion.** A standard, portable
  `AIAgentCredential` (W3C VC) describing what a verified AI agent is — nature, operator,
  and optionally model and capability — is the genuinely novel, standardizable piece. The
  natural venue is **DIF's Trusted AI Agents Working Group**, feeding the W3C VC ecosystem.
  Whatever it standardizes flows into C2PA through CAWG's existing aggregation, with no
  change to CAWG or C2PA.

The narrow, defensible claim: **AI-agent identity for content provenance is already
bindable with standard CAWG/C2PA mechanisms; the one missing piece is an identity-layer
AI-agent credential, and its correct home is W3C/DIF, not a new CAWG type.**
