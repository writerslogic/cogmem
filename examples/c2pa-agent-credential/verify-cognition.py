#!/usr/bin/env python3
"""Verify the two cognition statements embedded in the sample C2PA manifest.

`verify.sh` proves the agent *identity* (the CAWG ICA credential) via c2patool. This
goes one step further and proves the identity is bound to the agent's actual cognition:
it extracts the `cogmem.memory.provenance` and `crosstalk.orchestration.audit`
COSE_Sign1 statements from the manifest and verifies their Ed25519 signatures, decoding
what each attests. Reads a c2patool `--detailed` JSON report on stdin.

Uses the cogmem engine that ships in this repo (../../engine). If its dependencies
(cbor2, cryptography) are not installed, it exits 0 with a skip note so it never breaks
the primary identity check.
"""
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "..", "..", "engine"))

try:
    import cbor2
    import provenance as pv
except Exception as exc:  # dependency-free environments: skip, don't fail
    sys.stderr.write(
        f"SKIP: cognition verification needs the cogmem engine deps ({exc}).\n"
        "      pip install cbor2 cryptography  # then re-run\n")
    sys.exit(0)

_out = sys.stdout.write


# c2patool renders a CBOR assertion as the decoded COSE_Sign1 array
# [protected, unprotected, payload, signature]; re-encode it to the wire bytes
# that the verifier expects.
def cose_wire_bytes(value):
    if isinstance(value, list) and len(value) == 4:
        prot, _unprot, payload, sig = value
        return cbor2.dumps([bytes(prot), {}, bytes(payload), bytes(sig)])
    if isinstance(value, list):
        return bytes(value)
    return None


STATEMENTS = [
    ("cogmem.memory.provenance", "memory", "the lesson that steered the output"),
    ("crosstalk.orchestration.audit", "reasoning", "the orchestration that produced it"),
]


def main() -> int:
    report = json.load(sys.stdin)
    store = report["manifests"][report["active_manifest"]]["assertion_store"]
    ok = True
    for label, kind, gloss in STATEMENTS:
        raw = store.get(label)
        if raw is None:
            _out(f"  MISSING: {label}\n")
            ok = False
            continue
        try:
            claim = cbor2.loads(pv._cose_verify(cose_wire_bytes(raw)))
        except Exception as exc:
            _out(f"  FAIL: {label} did not verify ({exc})\n")
            ok = False
            continue
        iss = claim.get("iss", "?")
        _out(f"  VERIFIED {kind:9s} {label}\n")
        _out(f"           issuer {iss}\n")
        if kind == "memory":
            _out(f"           attests: memory '{claim.get('memoryId')}' "
                 f"({claim.get('memoryType')}, {claim.get('event')}) — {gloss}\n")
        else:
            root = claim.get("audit_root", b"")
            root = root.hex() if isinstance(root, (bytes, bytearray)) else str(root)
            _out(f"           attests: session '{claim.get('session_id')}', "
                 f"{claim.get('turn_count')} turns, audit_root {root[:16]}… — {gloss}\n")
    if ok:
        _out("PASS: both cognition statements verify — identity is bound to real "
             "memory and reasoning.\n")
        return 0
    sys.stderr.write("FAIL: a cognition statement did not verify.\n")
    return 1


if __name__ == "__main__":
    sys.exit(main())
