# Threat Model — WritersLogic Agent-Provenance Stack

**Scope:** the agent-provenance substrate — cogmem (`engine/provenance.py`), crosstalk
(orchestration audit), holographic-memory (HMS `coset` cross-verifier), and the WritersProof
C2PA producer that packages them. This is the durable design doc: per component, the security
property *claimed*, how it is *enforced* in code, and the *test* that proves it. It complements
the active red-team brief (`REDTEAM-BRIEF.md`), which maps the attack surface for a tester; this
document states what holds and — honestly — what is asserted but unproven.

**Status of the crypto:** real, not illustrative. Ed25519 (W3C `did:key`/`did:jwk`/`did:web`),
RFC 6962 Merkle, RFC 9052 COSE_Sign1, CAWG ICA over a W3C VC v2. The residual risk is not in the
primitives; it is in the *system around* them — soft gates, unkeyed bindings, self-asserted trust
anchors, version-skew, and dev defaults. Those are enumerated in §4 and §5, not buried.

---

## 1. Assets & security goals

| Asset | Security goal | Where it lives |
|---|---|---|
| **Agent identity** (Ed25519 key → DID) | Authenticity: a statement/credential attributed to the agent DID was produced by the holder of that key, and no other DID can mint one for it. | `vault/identity/agent.key` (raw 32-byte, mode 0600); `did_key`/`agent_did_jwk`/`agent_did_web` |
| **Agent memory** (rules as W3C VCs) | Tamper-evidence + poison-resistance: an altered or unsigned rule is detectable, and (under `provenance_enforce`) excluded from recall before it steers the agent. | `vault/credentials/<id>.jsonld`; `issue_credential`/`verify_credential`/`verify_vault` |
| **Memory lifecycle log** | Append-only integrity: the create/update/refine/demote history is hash-chained and signed; any edit breaks the chain at a detectable position. | `vault/provenance/log.jsonl`; `log_append`/`verify_log` |
| **Inclusion proofs** | Independently-verifiable membership: a third party can confirm a memory is committed under a signed Merkle root without a full copy of the log. | `signed_tree_head`/`inclusion_receipt`/`verify_receipt` |
| **Signed statements** (COSE/SCITT) | Cross-implementation conformance: a cogmem memory statement verifies byte-for-byte under the HMS `coset` verifier and vice versa. | `signed_statement`/`verify_signed_statement`; shared vector `tests/vectors/cose-signed-statement.json` |
| **Reasoning audit** (crosstalk) | Same envelope as memory statements, so the orchestration audit is a verifiable C2PA assertion. | crosstalk emitter (⚠️ raw Ed25519 today, COSE statement is a work item per UNIFIED-PROVENANCE.md §"Work items" #3) |
| **C2PA binding** (CAWG ICA) | Binding validity: the agent's `cawg.identity` credential cryptographically binds the agent DID to the finalized assertion set — including the `c2pa.hash.*` hard binding — so the agent signs participation in the whole chain. | `ica_identity_assertion`/`verify_ica_assertion`; validates in c2patool 0.26.30 as `cawg.ica.credential_valid` |

**The core claim these assets defend:** *an AI agent is a cryptographically verifiable actor in a
C2PA Content Credential — its identity, the memory that steered it, and the reasoning that produced
it are bound to the signed output and independently cross-verifiable.*

---

## 2. Trust boundaries & assumptions

### Trusted (not verified by this layer)
- **Local key custody.** `agent.key` is the raw Ed25519 private key, local-only, `chmod 0600`
  (`_load_or_create_key`). Anyone with read access to that file *is* the agent (actor A3 in the
  brief). The OS file-permission boundary is the whole of key protection — there is no
  passphrase, no OS keychain, no HSM. Compromise of the key compromises every property below it.
- **The host process.** The agent runtime that calls `verify_vault` and honors `provenance_enforce`
  is trusted to actually consult the verified set before compiling a rule into a tool-call guard.
  This layer signs and verifies; it does not enforce that the caller acts on the verdict.
- **did:jwk self-resolution.** A `did:jwk` carries its own key; no network, no external anchor.
  Trust is purely that the embedded JWK is the issuer's key — self-certifying, like `did:key`.

### Trusted-after-verification
- **did:web over HTTPS.** `_fetch_did_web` resolves `https://host/<path>/did.json` over plain
  `urllib` with TLS as the only transport guarantee. The published OKP key is taken as the agent's
  key **with no pinning, no TOFU record, no out-of-band fingerprint, no revocation list.** TLS PKI
  and DNS for the did:web host are therefore in the TCB (actor A4: DNS hijack / HTTPS MITM /
  static-hosting takeover substitutes the key). Offline verification can bypass the fetch by
  supplying the DID document to `resolve_did_to_key`/`verify_ica_assertion`, which narrows trust to
  whoever provided that document.
- **The COSE/SCITT substrate.** The untagged COSE_Sign1 (`application/cbor`, EdDSA −8, kid = raw
  32-byte pubkey) and the tag-18 ICA COSE (`application/vc`) are the cross-impl contract. Trust is
  that cogmem's `cbor2`, HMS's `coset`, and c2pa-rs's `IcaSignatureVerifier` decode the same bytes
  to the same meaning. This is asserted by a shared vector for the statement envelope and by
  c2patool validation for the ICA, but **not** by a differential test across all three parsers
  (see §4).

### Explicitly out of the TCB (verified, not trusted)
- Every credential, log entry, receipt, statement, and ICA assertion is signature-checked before
  acceptance. Tamper to any of them is caught by the corresponding `verify_*` function.

---

## 3. Threats → mitigations → evidence

One row per threat. "Mitigation" cites the enforcing code; "Evidence" cites the proving test in
`engine/test_provenance.py` by name, or marks **UNTESTED** where the property is asserted in code
but has no test. UNTESTED rows are the follow-up test backlog (collected in the summary).

| # | Threat | Mitigation (code) | Evidence (test) |
|---|---|---|---|
| T1 | **Memory poisoning** — edit a rule's statement after signing to change agent behavior. | `verify_credential` recomputes the `eddsa-jcs-2022` proof over canonical VC; `verify_vault` additionally requires `credentialSubject.statement == rule body`, so an unsigned edit is a tamper; `provenance_enforce` excludes tampered/unsigned rules from recall. | `test_tampered_credential_rejected` (statement swap → false). **Partial:** `verify_vault`'s body-vs-credential match and the `provenance_enforce` recall exclusion are **UNTESTED** at this layer. |
| T2 | **Credential forgery from another key** — re-issue a memory under a foreign DID. | `verify_credential` verifies the proof under the issuer's key **and** pins the issuer to the trusted agent DID (`_issuer_trusted`, anchored TOFU in `$COGMEM_HOME/trust.json`, outside `vault/`). Swapping the issuer but keeping the old signature breaks the signature; *re-signing* validly under a foreign key is now also rejected as an untrusted issuer. `verify_log`/`verify_sth` pin identically, so a whole chain re-signed under a foreign key fails. | `test_credential_from_other_key_rejected`, `test_self_signed_credential_from_untrusted_issuer_rejected`, `test_forged_log_under_untrusted_key_rejected`, `test_trust_established_on_first_key_use`. |
| T3 | **Log-chain break** — alter or delete a logged lifecycle event. | `verify_log` walks `prevHash` links (`_last_entry_hash` over the full prior line) and verifies each entry's Ed25519 signature over `_entry_signing_input`; reports `broken_at`. | `test_log_tamper_detected` (breaks at position 1), `test_log_chain_intact`. |
| T4 | **Forged log entry** — append an entry without the agent key. | Each entry is signed over its canonical fields; `verify_log` rejects a bad signature. | `test_forged_entry_rejected`. |
| T5 | **Forged inclusion proof** — claim membership for a memory not in the committed tree (tampered leaf, path, or root). | `verify_receipt` checks the STH signature (`verify_sth`), binds `treeSize`, and runs RFC 6962 §2.1.1 inclusion verification (`_verify_inclusion`) with leaf prefix `0x00` / node prefix `0x01`. | `test_inclusion_receipt_verifies`, `test_receipt_single_entry`, `test_receipt_tampered_leaf_rejected`, `test_receipt_tampered_path_rejected`, `test_receipt_forged_root_rejected`. **Gap:** second-preimage via leaf/node domain-prefix confusion, `treeSize`-vs-actual-leaves mismatch, and empty-tree edge cases are **UNTESTED**. |
| T6 | **Key compromise (A3)** — attacker holds `agent.key` and signs arbitrary statements as the DID. | **Not mitigated by design.** The key is the sole authority; file mode 0600 is the only barrier. There is no revocation, no key rotation record, no transparency anchor that would distinguish a compromised-key signature from a legitimate one. | **Out of mitigation scope** — accepted residual risk (§4). No test can prove resistance to an attacker holding the signing key. |
| T7 | **COSE substitution / downgrade** — swap the kid, corrupt the signature, or feed a malformed envelope. | `_cose_verify` requires a 4-element array, reads kid from the protected header, and verifies the signature over the canonical `Signature1` structure binding that kid; a swapped kid fails because the signature no longer matches. | `test_signed_statement_tampered_rejected`, `test_signed_statement_wrong_key_rejected`, `test_cose_malformed_rejected`, `test_signed_statement_structure_is_cose_sign1`. **Gap:** **alg-confusion** (does anything accept a non-EdDSA alg? `_cose_verify` never checks `protected[1]`), **content-type confusion** between `application/cbor` and `application/vc` (also unchecked in `_cose_verify`), and unprotected-header injection are **UNTESTED**. |
| T8 | **did:web takeover (A4/A5)** — substitute the published OKP key via DNS hijack, HTTPS MITM, or hosting/row poisoning. | `_fetch_did_web` relies on TLS only. `resolve_did_to_key` accepts whatever key the document publishes. | **Not mitigated — no test, and none possible without a trust-anchor mechanism.** No key pinning, no TOFU, no revocation list. Accepted residual risk (§4). |
| T9 | **Cross-impl parser differential** — craft a statement/ICA that one of {cogmem `cbor2`, HMS `coset`, c2pa-rs} accepts and another rejects, or all accept with different decoded payloads. | Shared conformance vector for the COSE statement envelope; c2patool 0.26.30 validates the ICA vector as `cawg.ica.credential_valid`. | `test_signed_statement_structure_is_cose_sign1` (envelope shape), `test_ica_assertion_verifies` / `test_ica_assertion_tampered_rejected` (against the shared, c2patool-validated vector). **Gap:** an actual *differential* across parsers — CBOR non-canonical encoding, duplicate map keys, indefinite-length items, big-integer encodings — is **UNTESTED**. Conformance is shown on one good vector, not divergence on adversarial inputs. |
| T10 | **Replay** — re-submit a valid statement/credential/assertion to claim it again. | **Not addressed at this layer.** Statements and credentials carry a `timestampMs`/`validFrom` but no nonce; nothing in cogmem maintains a used-statement ledger. Replay defense is the *caller's* responsibility (mirrors the CPoE packet-verifier nonce design in the brief, H1). | **UNTESTED — no mitigation to test.** Accepted residual risk for this layer; flagged for the consuming verifier. |
| T11 | **ICA binding forgery / hard-binding stripping** — present an ICA whose `c2paAsset` doesn't match the signed `signer_payload`, or that references no hard binding. | `verify_ica_assertion` verifies the tag-18 COSE over the VC under the issuer DID, then cross-checks `c2paAsset.sig_type`/count/url/alg/hash against the CBOR `signer_payload`, and **requires** a `c2pa.hash.*` referenced assertion (else raises). | `test_ica_assertion_verifies`, `test_ica_assertion_tampered_rejected`. **Gap:** the *negative* cases — `c2paAsset`-vs-`signer_payload` mismatch, missing hard binding, count mismatch — each raise in code but are **UNTESTED** individually. |

---

## 4. Known limitations / residual risk

Stated plainly. None of these are bugs to fix silently; they are the honest perimeter of what the
current MVP proves.

1. **Key compromise is unbounded (T6).** The agent key is the sole root of trust, protected only by
   file mode 0600. There is no rotation log, no revocation, and no external anchor, so a stolen key
   produces signatures indistinguishable from legitimate ones. This is the single largest residual
   risk and is inherent to a self-sovereign `did:key`/`did:jwk` design.

2. **did:web is trust-on-first-fetch with no pinning (T8).** `_fetch_did_web` trusts TLS + DNS for
   the did:web host. Anyone controlling either, or the static hosting / Supabase row, substitutes the
   verification key. No pinning, no TOFU record, no out-of-band fingerprint, no DID revocation list.
   The roadmap item "external transparency service" (PROVENANCE.md) would partially address this; it
   is **not implemented**.

3. **Self-asserted, self-signed trust anchors.** `verify_credential`/`verify_log`/`verify_sth` now
   pin the issuer to a TOFU-anchored agent DID (`$COGMEM_HOME/trust.json`), so a memory or chain
   re-signed under a *foreign* key is rejected (T2). This is the meaningful gain: an attacker who can
   write only `vault/` content — the poison/sync threat — can no longer forge a self-consistent chain
   under their own key. **Intentional key rotation** is the only supported way to change the trusted
   identity: `cogmem trust --rotate` re-anchors to the current key and retains the prior DID in the
   anchor's `prior` set, so history signed by the retired key still verifies while a never-trusted
   foreign key stays rejected (`rotate_trust`; `test_rotation_preserves_history_and_accepts_new_key`).
   A vault-content attacker cannot invoke it. **Residual, unchanged:** (a) the anchor lives under
   `$COGMEM_HOME`, so an
   attacker with write access to the *whole* home (including `trust.json` and `agent.key`) re-anchors
   and wins — collapses to T6. This is mitigated by opt-in **macOS Keychain custody** (config
   `keychain: true`): the private key moves out of the 0600 file into the login keychain
   (`_keychain_*`, file migrated then deleted), so a filesystem-write attacker can no longer read or
   replace it without also defeating the keychain ACL. `cogmem doctor` reports where the key lives.
   Linux/headless keep the file backend (a systemd-credential equivalent is the remaining gap). (b)
   The STH is still signed by the agent's own key — there is **no external transparency anchor**
   (PROVENANCE.md roadmap item #1), so an inclusion receipt proves "this memory is in *a* tree the
   agent signed," not "in an independent, witnessed log." The ICA/C2PA claim-signer story similarly
   leans on dev/self-signed certs in the WritersProof producer path (brief H10): **CAWG ICA validity
   is independent of X.509 claim-signer trust**, so an ICA can read "valid" while the claim signer is
   attacker-controlled. cogmem does not close that gap; the consuming verifier must.

4. **Agent-path soft binding is a non-durable SHA-256 placeholder.** The text/soft binding tying the
   agent provenance to document content is, on the agent path, a SHA-256 reference — not a keyed,
   durable binding (cf. the unkeyed `zwc-watermark` in the brief, H3). Its security rests entirely on
   the inner COSE signature plus the `c2pa.hash.*` hard binding, never on the soft binding itself.
   Nothing should treat soft-binding presence as proof.

5. **No replay defense at this layer (T10).** Statements/credentials are not single-use; the
   consuming verifier must maintain its own used-nonce / used-statement ledger.

6. **posme / statement version-skew (brief H4).** There is no algorithm-or-version tag on the wire in
   the COSE statement, and the broader stack has divergent `0.1.0` posme copies across git worktrees.
   A verifier cannot distinguish two differently-coded builds claiming the same version. cogmem's own
   envelope is fixed (EdDSA −8, `application/cbor`), but it carries no explicit version field, so a
   future envelope change is silently ambiguous.

7. **Canonicalization is JCS-*style*, not RFC 8785 (brief H5).** `_canonical` is
   `json.dumps(sort_keys=True, separators=(",",":"))` — sorted-key compact JSON, not certified JCS.
   Duplicate keys, Unicode normalization, and integer/float coercion are not handled the way a strict
   JCS implementation would, opening a canonicalization-differential surface that is **untested**.

8. **`sign_vault` re-signs "legitimately edited" rules.** A rule whose body differs from its stored
   credential is treated as an update and re-signed under the agent key (`sign_vault`, `event="updated"`).
   If an attacker who can write rule files also triggers `sign_vault`, a poisoned rule is laundered
   into a valid credential. This collapses to T6/host-trust but is worth stating explicitly.

9. **crosstalk reasoning audit is not yet on the substrate.** Per UNIFIED-PROVENANCE.md it is raw
   Ed25519 today and must still emit the untagged COSE_Sign1 statement to become a verifiable
   `crosstalk.orchestration.audit` C2PA assertion. Until then the "reasoning" pillar is asserted, not
   cross-verifiable.

---

## 5. Out of scope

- **Denial of service** — volumetric, rate-limit exhaustion, resource starvation. The verifiers are
  not hardened against malicious oversized inputs (e.g. a pathological CBOR/Merkle tree); that is a
  DoS concern, not an integrity one.
- **Third-party dependency internals** — `cryptography`, `cbor2`, c2pa-rs / c2patool, Cloudflare
  Workers / Supabase platform, `@noble/*`. In scope: only how *our* code uses them.
- **Social engineering / physical access** — phishing custodians, coercing key holders, physical
  access to the machine holding `agent.key`.
- **The WritersProof CPoE/CLI evidence layer and web CA** — jitter forgery, the HMAC event store, the
  posme binding crypto, leaf-cert issuance/revocation. Those are the CPoE monorepo's threat surface
  (brief §2 in-scope, H1–H2, H9, H11); this document covers the *agent-provenance* substrate only,
  and references them where the agent path inherits a property (soft binding, version-skew).

---

## Summary

`/Volumes/A/cogmem/THREAT-MODEL.md` — per-component security properties for the agent-provenance
substrate (cogmem identity/memory/log/receipts/COSE/ICA, with crosstalk and HMS cross-verification
and the WritersProof C2PA binding), each tied to its enforcing code in `engine/provenance.py` and
its proving test in `engine/test_provenance.py`. Core claim (identity + memory + reasoning bound to
signed output, independently verifiable) holds for the *signature/chain/receipt tamper* paths that
have tests; it is *overstated* wherever a self-signed anchor, soft gate, or unverified trust fetch
sits underneath (§4 items 1–4 most materially).

**Threats with NO corresponding test (follow-up test backlog):**

- **T1 (partial):** `verify_vault` body-vs-credential match and `provenance_enforce` recall-exclusion
  — the poison-resistance enforcement gate itself is untested.
- **T5 (gaps):** Merkle second-preimage via leaf/node domain-prefix confusion; `treeSize`-vs-actual
  mismatch; empty-tree / single-leaf edge cases.
- **T7 (gaps):** COSE **alg-confusion** (`_cose_verify` never checks `protected[1] == −8`) and
  **content-type confusion** (`protected[3]` unchecked) — both are exploitable parser gaps in code
  with no test.
- **T9:** real cross-parser differential (non-canonical CBOR, duplicate keys, indefinite-length,
  big-int) across cogmem/HMS/c2pa-rs — only single-good-vector conformance exists.
- **T10:** replay — no mitigation and no test at this layer.
- **T11 (negative cases):** `c2paAsset`-vs-`signer_payload` mismatch, missing hard binding, ref-count
  mismatch — each raises in code, none tested.
- Plus the §4 limitations that have no test because they have no mitigation: **T6** key compromise,
  **T8** did:web takeover, **§4.7** canonicalization differential, **§4.8** `sign_vault` re-sign
  laundering.

Not committed.
