#!/usr/bin/env python3
"""Regenerate cawg-ica-credential.json — a deterministic conformance vector for the cogmem
CAWG Identity Claims Aggregation (ICA) credential. Fixed key + fixed timestamps so the
bytes are reproducible and can be checked into the repo. The vector must verify under
c2pa-rs's IcaSignatureVerifier and the HMS coset-based cross-verifier.

Run: python tests/vectors/generate_cawg_ica.py
"""
import json
import os
import sys
import tempfile

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "..", "engine"))

# Fixed Ed25519 test seed (32 bytes) so the issuer key and signature are reproducible.
TEST_SEED = bytes(range(32))
VALID_FROM = "2026-01-01T00:00:00+00:00"
REFS = [
    ("self#jumbf=c2pa.assertions/c2pa.hash.data", "sha256", bytes(range(32))),
    ("self#jumbf=c2pa.assertions/cogmem.memory.provenance", "sha256",
     bytes(range(32, 64))),
]


def main() -> int:
    # Point the engine at a throwaway key file holding the fixed seed, so the emitter
    # signs with a reproducible key instead of the live agent key.
    with tempfile.TemporaryDirectory() as tmp:
        key_path = os.path.join(tmp, "agent.key")
        with open(key_path, "wb") as fh:
            fh.write(TEST_SEED)
        os.chmod(key_path, 0o600)
        import provenance as pv
        pv.KEY_FILE = __import__("pathlib").Path(key_path)
        pv.IDENTITY = __import__("pathlib").Path(tmp)

        issuer = pv.agent_did_jwk()
        vi = [pv.agent_verified_identity(
            "cogmem agent", "https://writersproof.com", "WritersProof",
            id_type="cawg.affiliation", verified_at=VALID_FROM,
            uri="https://writersproof.com/agents/cogmem")]
        assertion, vc = pv.ica_identity_assertion(REFS, issuer, vi, valid_from=VALID_FROM)
        assert pv.verify_ica_assertion(assertion)["issuer"] == issuer
        pub_hex = pv._pub_raw(pv._load_or_create_key()).hex()

    vector = {
        "description": ("cogmem CAWG Identity Claims Aggregation credential (did:jwk issuer, "
                        "EdDSA, COSE_Sign1 tag-18 over the VC, content type application/vc) "
                        "— must verify under c2pa-rs IcaSignatureVerifier and HMS"),
        "issuer": issuer,
        "public_key_hex": pub_hex,
        "referenced_assertions": [{"url": u, "alg": a, "hash_hex": h.hex()} for u, a, h in REFS],
        "identity_assertion_cbor_hex": assertion.hex(),
        "credential": vc,
    }
    out = os.path.join(os.path.dirname(__file__), "cawg-ica-credential.json")
    with open(out, "w") as fh:
        json.dump(vector, fh, indent=2)
        fh.write("\n")
    sys.stdout.write(f"wrote {out} ({len(assertion)}B assertion)\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
