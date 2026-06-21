"""
Cognitive Memory — Verifiable Agent Memory (provenance layer)

Makes agent memory verifiable and tamper-evident, so a poisoned or altered memory
can be detected before it steers the agent. Built on real standards:

- Agent identity is a `did:key` (W3C DID method) backed by a real Ed25519 keypair.
- Each memory is issued as a W3C Verifiable Credential signed by the agent's DID
  (an eddsa-jcs-2022-style Data Integrity proof over the canonical credential).
- Memory lifecycle events (created / refined / demoted) are recorded in an
  append-only, hash-chained, signed transparency log (SCITT-style): tampering with
  any entry breaks the chain, and entries cannot be forged without the agent key.
- A signed Merkle tree head and RFC 6962-style inclusion receipts let anyone verify
  that a given memory is committed in the log, with a compact proof and no full copy.

Scope: this is the MVP core. did:web, SD-JWT-VC encoding, and TSP/DIDComm exchange
are roadmap (see PROVENANCE.md). The crypto here is real and verifiable.

Usage (library): issue_credential, verify_credential, log_append, verify_log.
"""

import hashlib
import json
import logging
from datetime import datetime, timezone
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey, Ed25519PublicKey)
from cryptography.hazmat.primitives import serialization
from cryptography.exceptions import InvalidSignature

from common import VAULT, read_note

log = logging.getLogger("cogmem.provenance")

RULES = VAULT / "rules"
CREDENTIALS = VAULT / "credentials"
IDENTITY = VAULT / "identity"
KEY_FILE = IDENTITY / "agent.key"          # raw 32-byte Ed25519 private key (local only)
LOG_FILE = VAULT / "provenance" / "log.jsonl"
STATEMENTS = VAULT / "provenance" / "statements"   # COSE_Sign1 SCITT signed statements

ED25519_MULTICODEC = b"\xed\x01"           # multicodec prefix for an ed25519 public key
_B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"


def b58encode(data: bytes) -> str:
    n = int.from_bytes(data, "big")
    out = ""
    while n > 0:
        n, r = divmod(n, 58)
        out = _B58[r] + out
    pad = len(data) - len(data.lstrip(b"\x00"))
    return "1" * pad + out


def b58decode(s: str) -> bytes:
    n = 0
    for ch in s:
        n = n * 58 + _B58.index(ch)
    body = n.to_bytes((n.bit_length() + 7) // 8, "big")
    pad = len(s) - len(s.lstrip("1"))
    return b"\x00" * pad + body


def _canonical(obj: dict) -> bytes:
    """Deterministic JSON (sorted keys, compact) — JCS-style for our string data."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


# --- identity (did:key) ---------------------------------------------------------

def _load_or_create_key() -> Ed25519PrivateKey:
    if KEY_FILE.exists():
        return Ed25519PrivateKey.from_private_bytes(KEY_FILE.read_bytes())
    IDENTITY.mkdir(parents=True, exist_ok=True)
    key = Ed25519PrivateKey.generate()
    raw = key.private_bytes(serialization.Encoding.Raw,
                            serialization.PrivateFormat.Raw,
                            serialization.NoEncryption())
    KEY_FILE.write_bytes(raw)
    KEY_FILE.chmod(0o600)
    log.info("Generated new agent identity key.")
    return key


def _pub_raw(key: Ed25519PrivateKey) -> bytes:
    return key.public_key().public_bytes(serialization.Encoding.Raw,
                                         serialization.PublicFormat.Raw)


def did_key(pub_raw: bytes) -> str:
    return "did:key:z" + b58encode(ED25519_MULTICODEC + pub_raw)


def pubkey_from_did(did: str) -> Ed25519PublicKey:
    mb = did.split("did:key:z", 1)[1]
    decoded = b58decode(mb)
    if decoded[:2] != ED25519_MULTICODEC:
        raise ValueError("not an ed25519 did:key")
    return Ed25519PublicKey.from_public_bytes(decoded[2:])


def agent_did() -> str:
    return did_key(_pub_raw(_load_or_create_key()))


# --- verifiable credentials -----------------------------------------------------

def issue_credential(memory_id: str, statement: str, meta: dict) -> dict:
    key = _load_or_create_key()
    did = did_key(_pub_raw(key))
    now = datetime.now(timezone.utc).isoformat()
    vc = {
        "@context": ["https://www.w3.org/ns/credentials/v2"],
        "type": ["VerifiableCredential", "AgentMemoryCredential"],
        "issuer": did,
        "validFrom": now,
        "credentialSubject": {
            "id": f"urn:cogmem:{meta.get('kind', 'rule')}:{memory_id}",
            "memoryType": meta.get("kind", "rule"),
            "layer": meta.get("layer", ""),
            "scope": meta.get("scope", ""),
            "statement": statement,
            "sourceSession": meta.get("source_session", ""),
        },
    }
    proof = {
        "type": "DataIntegrityProof",
        "cryptosuite": "eddsa-jcs-2022",
        "created": now,
        "verificationMethod": f"{did}#{did.split(':')[-1]}",
        "proofPurpose": "assertionMethod",
    }
    signing_input = _canonical({**vc, "proof": proof})
    proof["proofValue"] = "z" + b58encode(key.sign(signing_input))
    vc["proof"] = proof
    return vc


def verify_credential(vc: dict) -> bool:
    try:
        proof = dict(vc["proof"])
        sig = b58decode(proof.pop("proofValue")[1:])
        signing_input = _canonical({**{k: v for k, v in vc.items() if k != "proof"},
                                    "proof": proof})
        pubkey_from_did(vc["issuer"]).verify(sig, signing_input)
        return True
    except (KeyError, ValueError, InvalidSignature, IndexError):
        return False


# --- SCITT-style transparency log ----------------------------------------------

def _entry_signing_input(e: dict) -> bytes:
    return _canonical({k: e[k] for k in ("seq", "ts", "event", "memoryId",
                                         "statementHash", "prevHash", "issuer")})


def _last_entry_hash() -> str:
    if not LOG_FILE.exists():
        return "genesis"
    lines = [l for l in LOG_FILE.read_text().splitlines() if l.strip()]
    if not lines:
        return "genesis"
    return _sha256(lines[-1].encode("utf-8"))


def log_append(event: str, memory_id: str, vc: dict) -> dict:
    key = _load_or_create_key()
    did = did_key(_pub_raw(key))
    LOG_FILE.parent.mkdir(parents=True, exist_ok=True)
    seq = sum(1 for l in LOG_FILE.read_text().splitlines() if l.strip()) if LOG_FILE.exists() else 0
    entry = {
        "seq": seq,
        "ts": datetime.now(timezone.utc).isoformat(),
        "event": event,
        "memoryId": memory_id,
        "statementHash": _sha256(_canonical(vc)),
        "prevHash": _last_entry_hash(),
        "issuer": did,
    }
    entry["signature"] = "z" + b58encode(key.sign(_entry_signing_input(entry)))
    with LOG_FILE.open("a") as fh:
        fh.write(json.dumps(entry, separators=(",", ":")) + "\n")
    return entry


def verify_log() -> dict:
    """Verify the whole chain: signatures valid and prevHash links unbroken."""
    if not LOG_FILE.exists():
        return {"ok": True, "entries": 0}
    lines = [l for l in LOG_FILE.read_text().splitlines() if l.strip()]
    prev = "genesis"
    for i, line in enumerate(lines):
        entry = json.loads(line)
        if entry.get("prevHash") != prev:
            return {"ok": False, "entries": len(lines), "broken_at": i, "reason": "chain break"}
        try:
            sig = b58decode(entry["signature"][1:])
            pubkey_from_did(entry["issuer"]).verify(sig, _entry_signing_input(entry))
        except (KeyError, ValueError, InvalidSignature, IndexError):
            return {"ok": False, "entries": len(lines), "broken_at": i, "reason": "bad signature"}
        prev = _sha256(line.encode("utf-8"))
    return {"ok": True, "entries": len(lines)}


# --- SCITT inclusion receipts (RFC 6962-style Merkle) ---------------------------

def _log_lines() -> list:
    if not LOG_FILE.exists():
        return []
    return [l for l in LOG_FILE.read_text().splitlines() if l.strip()]


def _mth(leaves: list) -> bytes:
    """RFC 6962 Merkle Tree Hash over a list of leaf-data byte strings."""
    n = len(leaves)
    if n == 0:
        return hashlib.sha256(b"").digest()
    if n == 1:
        return hashlib.sha256(b"\x00" + leaves[0]).digest()      # leaf domain prefix
    k = 1
    while k * 2 < n:
        k *= 2                                                    # largest power of 2 < n
    return hashlib.sha256(b"\x01" + _mth(leaves[:k]) + _mth(leaves[k:])).digest()


def _audit_path(m: int, leaves: list) -> list:
    """RFC 6962 inclusion proof (audit path) for leaf index m."""
    n = len(leaves)
    if n <= 1:
        return []
    k = 1
    while k * 2 < n:
        k *= 2
    if m < k:
        return _audit_path(m, leaves[:k]) + [_mth(leaves[k:])]
    return _audit_path(m - k, leaves[k:]) + [_mth(leaves[:k])]


def _verify_inclusion(leaf_hash: bytes, m: int, n: int, path: list, root: bytes) -> bool:
    """RFC 6962 section 2.1.1 inclusion-proof verification."""
    if m >= n:
        return False
    fn, sn, r = m, n - 1, leaf_hash
    for sibling in path:
        if sn == 0:
            return False
        if (fn & 1) or (fn == sn):
            r = hashlib.sha256(b"\x01" + sibling + r).digest()
            while not (fn == 0 or (fn & 1)):
                fn >>= 1
                sn >>= 1
        else:
            r = hashlib.sha256(b"\x01" + r + sibling).digest()
        fn >>= 1
        sn >>= 1
    return sn == 0 and r == root


def signed_tree_head() -> dict:
    """A signed commitment to the current log state (SCITT-style signed statement)."""
    key = _load_or_create_key()
    did = did_key(_pub_raw(key))
    leaves = [l.encode("utf-8") for l in _log_lines()]
    sth = {
        "treeSize": len(leaves),
        "rootHash": _mth(leaves).hex(),
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "issuer": did,
    }
    sth["signature"] = "z" + b58encode(key.sign(_canonical(sth)))
    return sth


def verify_sth(sth: dict) -> bool:
    try:
        body = {k: v for k, v in sth.items() if k != "signature"}
        sig = b58decode(sth["signature"][1:])
        pubkey_from_did(sth["issuer"]).verify(sig, _canonical(body))
        return True
    except (KeyError, ValueError, InvalidSignature, IndexError):
        return False


def inclusion_receipt(memory_id: str):
    """Inclusion receipt for a memory's latest log entry: a compact, independently
    verifiable proof that the entry is committed under the signed Merkle root."""
    lines = _log_lines()
    idx = None
    for i, line in enumerate(lines):
        if json.loads(line).get("memoryId") == memory_id:
            idx = i
    if idx is None:
        return None
    leaves = [l.encode("utf-8") for l in lines]
    return {
        "memoryId": memory_id,
        "leafIndex": idx,
        "treeSize": len(leaves),
        "leaf": lines[idx],
        "auditPath": [p.hex() for p in _audit_path(idx, leaves)],
        "sth": signed_tree_head(),
    }


def verify_receipt(receipt: dict) -> bool:
    """Verify an inclusion receipt: the signed tree head is authentic and the leaf
    is provably included in the committed tree."""
    try:
        sth = receipt["sth"]
        if not verify_sth(sth) or sth["treeSize"] != receipt["treeSize"]:
            return False
        leaf_hash = hashlib.sha256(b"\x00" + receipt["leaf"].encode("utf-8")).digest()
        path = [bytes.fromhex(p) for p in receipt["auditPath"]]
        root = bytes.fromhex(sth["rootHash"])
        return _verify_inclusion(leaf_hash, receipt["leafIndex"], receipt["treeSize"], path, root)
    except (KeyError, ValueError, TypeError):
        return False


# --- COSE_Sign1 SCITT signed statements (CBOR) ----------------------------------
# RFC 9052 untagged COSE_Sign1 over a CBOR claim, EdDSA. The envelope is byte-format
# interoperable with HMS's `coset` signed statements, so a cogmem statement verifies
# under HMS's SCITT verifier and vice versa. Headers: alg=EdDSA(-8), content type
# "application/cbor", kid=raw Ed25519 public key; external_aad is empty.

_COSE_ALG_EDDSA = -8
_COSE_CONTENT_TYPE = "application/cbor"


def _cbor():
    try:
        import cbor2
    except ModuleNotFoundError as exc:                         # graceful: COSE is optional
        raise RuntimeError("cbor2 is required for COSE signed statements "
                           "(pip install cbor2)") from exc
    return cbor2


def _cose_sign1(key: Ed25519PrivateKey, payload: bytes,
                content_type: str = _COSE_CONTENT_TYPE) -> bytes:
    cbor2 = _cbor()
    protected = cbor2.dumps({1: _COSE_ALG_EDDSA, 3: content_type, 4: _pub_raw(key)})
    sig_structure = cbor2.dumps(["Signature1", protected, b"", payload])
    signature = key.sign(sig_structure)
    return cbor2.dumps([protected, {}, payload, signature])


def _cose_verify(cose_bytes: bytes) -> bytes:
    """Verify an untagged COSE_Sign1 against the key id in its protected header,
    returning the payload. Raises on any structural or signature failure."""
    cbor2 = _cbor()
    try:
        arr = cbor2.loads(cose_bytes)
    except cbor2.CBORDecodeError as exc:
        raise ValueError(f"malformed COSE/CBOR: {exc}") from exc
    if not (isinstance(arr, list) and len(arr) == 4):
        raise ValueError("not a COSE_Sign1 structure")
    protected, _unprotected, payload, signature = arr
    pub = cbor2.loads(protected).get(4)
    if not isinstance(pub, (bytes, bytearray)):
        raise ValueError("no key id in protected header")
    sig_structure = cbor2.dumps(["Signature1", protected, b"", payload])
    Ed25519PublicKey.from_public_bytes(bytes(pub)).verify(bytes(signature), sig_structure)
    return payload


def signed_statement(event: str, memory_id: str, vc: dict) -> bytes:
    """A SCITT signed statement (COSE_Sign1) attesting a memory's credential. Its
    statementHash matches the transparency-log entry, linking the two."""
    cbor2 = _cbor()
    key = _load_or_create_key()
    claim = {
        "iss": did_key(_pub_raw(key)),
        "memoryId": memory_id,
        "memoryType": vc.get("credentialSubject", {}).get("memoryType", "rule"),
        "event": event,
        "statementHash": bytes.fromhex(_sha256(_canonical(vc))),
        "timestampMs": int(datetime.now(timezone.utc).timestamp() * 1000),
    }
    return _cose_sign1(key, cbor2.dumps(claim))


def verify_signed_statement(cose_bytes: bytes) -> dict:
    """Verify a signed statement's COSE signature and return its decoded claim.
    Raises if the signature is invalid."""
    return _cbor().loads(_cose_verify(cose_bytes))


def _emit_statement(event: str, memory_id: str, vc: dict) -> None:
    """Write the COSE signed statement for a memory; best-effort so a missing cbor2
    or write error never breaks the core signing pipeline."""
    try:
        STATEMENTS.mkdir(parents=True, exist_ok=True)
        (STATEMENTS / f"{memory_id}.cose").write_bytes(signed_statement(event, memory_id, vc))
    except (RuntimeError, OSError):
        log.debug("COSE signed statement skipped for %s", memory_id)


# --- vault operations (CLI) -----------------------------------------------------

def sign_vault() -> int:
    """Issue a credential for each unsigned active rule and log its creation."""
    CREDENTIALS.mkdir(parents=True, exist_ok=True)
    issued = 0
    for f in sorted(RULES.glob("*.md")):
        meta, body = read_note(f)
        if not body:
            continue
        rid = meta.get("id", f.stem)
        cpath = CREDENTIALS / f"{rid}.jsonld"
        event = "created"
        if cpath.exists():
            try:
                existing = json.loads(cpath.read_text())
            except json.JSONDecodeError:
                existing = {}
            # already signed and unchanged -> skip; legitimately edited -> re-sign
            if existing.get("credentialSubject", {}).get("statement") == body:
                if not (STATEMENTS / f"{rid}.cose").exists():
                    _emit_statement("created", rid, existing)   # backfill missing statement
                continue
            event = "updated"
        vc = issue_credential(rid, body, meta)
        cpath.write_text(json.dumps(vc, indent=2))
        log_append(event, rid, vc)
        _emit_statement(event, rid, vc)
        issued += 1
    return issued


def verify_vault() -> dict:
    """Verify every rule's credential and that its statement still matches the rule
    body (an edit after signing is a tamper), plus the transparency-log chain."""
    total = signed = valid = tampered = unsigned = 0
    for f in sorted(RULES.glob("*.md")):
        meta, body = read_note(f)
        if not body:
            continue
        total += 1
        cpath = CREDENTIALS / f"{meta.get('id', f.stem)}.jsonld"
        if not cpath.exists():
            unsigned += 1
            continue
        signed += 1
        try:
            vc = json.loads(cpath.read_text())
        except json.JSONDecodeError:
            tampered += 1
            continue
        if verify_credential(vc) and vc["credentialSubject"]["statement"] == body:
            valid += 1
        else:
            tampered += 1
    return {"total": total, "signed": signed, "valid": valid, "tampered": tampered,
            "unsigned": unsigned, "chain": verify_log()}


if __name__ == "__main__":
    import sys
    logging.basicConfig(level=logging.INFO, format="%(message)s")
    command = sys.argv[1] if len(sys.argv) > 1 else "status"
    if command == "status":
        log.info("Agent DID:           %s", agent_did())
        r = verify_log()
        log.info("Transparency log:    %d entries, integrity %s", r.get("entries", 0),
                 "OK" if r["ok"] else f"BROKEN ({r.get('reason')})")
        n = len(list(CREDENTIALS.glob("*.jsonld"))) if CREDENTIALS.exists() else 0
        log.info("Signed credentials:  %d", n)
        sth = signed_tree_head()
        log.info("Merkle root:         %s… (tree size %d)", sth["rootHash"][:16], sth["treeSize"])
    elif command == "sign-vault":
        log.info("Issued %d new credential(s).", sign_vault())
    elif command == "verify":
        v = verify_vault()
        log.info("Vault: %d rules | %d signed | %d valid | %d TAMPERED | %d unsigned",
                 v["total"], v["signed"], v["valid"], v["tampered"], v["unsigned"])
        log.info("Transparency log: %s (%d entries)",
                 "OK" if v["chain"]["ok"] else "BROKEN", v["chain"].get("entries", 0))
    elif command == "sth":
        sys.stdout.write(json.dumps(signed_tree_head(), indent=2) + "\n")
    elif command == "receipt":
        if len(sys.argv) < 3:
            log.error("Usage: provenance.py receipt <memory_id>")
            sys.exit(1)
        r = inclusion_receipt(sys.argv[2])
        if r is None:
            log.error("No log entry for memory '%s'", sys.argv[2])
            sys.exit(1)
        sys.stdout.write(json.dumps(r, indent=2) + "\n")
    elif command == "verify-receipt":
        if len(sys.argv) < 3:
            log.error("Usage: provenance.py verify-receipt <receipt.json>")
            sys.exit(1)
        ok = verify_receipt(json.loads(Path(sys.argv[2]).read_text()))
        log.info("Inclusion receipt: %s", "VALID" if ok else "INVALID")
        sys.exit(0 if ok else 1)
    elif command == "statement":
        if len(sys.argv) < 3:
            log.error("Usage: provenance.py statement <memory_id>")
            sys.exit(1)
        mid = sys.argv[2]
        spath = STATEMENTS / f"{mid}.cose"
        if spath.exists():
            cose = spath.read_bytes()
        else:
            cpath = CREDENTIALS / f"{mid}.jsonld"
            if not cpath.exists():
                log.error("No credential for memory '%s' (run sign-vault first)", mid)
                sys.exit(1)
            cose = signed_statement("created", mid, json.loads(cpath.read_text()))
        sys.stdout.write(cose.hex() + "\n")
    elif command == "verify-statement":
        if len(sys.argv) < 3:
            log.error("Usage: provenance.py verify-statement <statement.cose|.hex>")
            sys.exit(1)
        raw = Path(sys.argv[2]).read_bytes()
        try:
            cose = bytes.fromhex(raw.decode().strip())
        except (ValueError, UnicodeDecodeError):
            cose = raw
        try:
            claim = verify_signed_statement(cose)
            log.info("Signed statement: VALID (memory %s, issuer %s)",
                     claim.get("memoryId"), claim.get("iss"))
        except (ValueError, InvalidSignature, RuntimeError):
            log.info("Signed statement: INVALID")
            sys.exit(1)
    else:
        log.error("Usage: provenance.py [status | sign-vault | verify | sth | "
                  "receipt <id> | verify-receipt <file> | statement <id> | "
                  "verify-statement <file>]")
        sys.exit(1)
