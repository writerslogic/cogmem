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

import base64
import hashlib
import json
import logging
import shutil
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives import serialization
from cryptography.exceptions import InvalidSignature

from cogmem.common import VAULT, COGMEM, read_note

log = logging.getLogger("cogmem.provenance")

RULES = VAULT / "rules"
CREDENTIALS = VAULT / "credentials"
IDENTITY = VAULT / "identity"
KEY_FILE = IDENTITY / "agent.key"  # raw 32-byte Ed25519 private key (local only)
LOG_FILE = VAULT / "provenance" / "log.jsonl"
STATEMENTS = VAULT / "provenance" / "statements"  # COSE_Sign1 SCITT signed statements

# Trust anchor: the agent DID pinned on first run. Kept OUTSIDE vault/ (one level
# up, beside it) so an attacker who can only rewrite vault/ content — the stated
# poison threat — cannot also forge a self-consistent chain under their own key and
# have it verify. Verification checks each artifact's signature AND that its issuer
# equals this pinned DID; a foreign-key forgery is rejected as an untrusted issuer.
# Residual gap (documented in THREAT-MODEL.md): an attacker with write access to the
# whole COGMEM_HOME, including this file, can still re-anchor — OS-keychain storage
# is the next hardening step.
TRUST_ANCHOR = COGMEM / "trust.json"

ED25519_MULTICODEC = b"\xed\x01"  # multicodec prefix for an ed25519 public key
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


# --- key custody backends -------------------------------------------------------
# By default the raw key lives in a 0600 file (KEY_FILE). Opt in (config "keychain")
# to store it in the macOS login Keychain instead — the next hardening tier over a
# plain file (THREAT-MODEL §4.3). Dependency-free: shells out to the `security` CLI.
# A `security` keychain item is keyed by (account=$COGMEM_HOME, service).

_KEYCHAIN_SERVICE = "cogmem-agent-key"


def _keychain_available() -> bool:
    return sys.platform == "darwin" and shutil.which("security") is not None and _keychain_enabled()


def _keychain_enabled() -> bool:
    try:
        from cogmem import config

        return bool(config.load().get("keychain", False))
    except Exception:  # noqa: BLE001 — config is optional; default off
        return False


def _keychain_get() -> bytes | None:
    try:
        out = subprocess.run(
            ["security", "find-generic-password", "-a", str(COGMEM), "-s", _KEYCHAIN_SERVICE, "-w"],
            capture_output=True,
            text=True,
            timeout=10,
        )
        if out.returncode != 0 or not out.stdout.strip():
            return None
        return base64.b64decode(out.stdout.strip())
    except (OSError, ValueError, subprocess.SubprocessError):
        return None


def _keychain_put(raw: bytes) -> bool:
    try:
        out = subprocess.run(
            [
                "security",
                "add-generic-password",
                "-U",
                "-a",
                str(COGMEM),
                "-s",
                _KEYCHAIN_SERVICE,
                "-w",
                base64.b64encode(raw).decode("ascii"),
            ],
            capture_output=True,
            text=True,
            timeout=10,
        )
        return out.returncode == 0
    except (OSError, subprocess.SubprocessError):
        return False


def _new_key_raw() -> tuple[Ed25519PrivateKey, bytes]:
    key = Ed25519PrivateKey.generate()
    raw = key.private_bytes(
        serialization.Encoding.Raw,
        serialization.PrivateFormat.Raw,
        serialization.NoEncryption(),
    )
    return key, raw


def _load_or_create_key() -> Ed25519PrivateKey:
    if _keychain_available():
        raw = _keychain_get()
        if raw is not None:
            key = Ed25519PrivateKey.from_private_bytes(raw)
        elif KEY_FILE.exists():
            # Migrate an existing file-based key into the keychain, then remove the
            # plaintext file so the secret no longer sits next to the data.
            raw = KEY_FILE.read_bytes()
            key = Ed25519PrivateKey.from_private_bytes(raw)
            if _keychain_put(raw):
                KEY_FILE.unlink()
                log.info("Migrated agent identity key into the OS keychain.")
        else:
            key, raw = _new_key_raw()
            _keychain_put(raw)
            log.info("Generated new agent identity key (keychain).")
    elif KEY_FILE.exists():
        key = Ed25519PrivateKey.from_private_bytes(KEY_FILE.read_bytes())
    else:
        IDENTITY.mkdir(parents=True, exist_ok=True)
        key, raw = _new_key_raw()
        KEY_FILE.write_bytes(raw)
        KEY_FILE.chmod(0o600)
        log.info("Generated new agent identity key.")
    _establish_trust(did_key(_pub_raw(key)))
    return key


def _pub_raw(key: Ed25519PrivateKey) -> bytes:
    return key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)


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


def key_custody() -> str:
    """Where the agent's private key currently lives, for the doctor surface."""
    if _keychain_available() and _keychain_get() is not None:
        return "macOS keychain"
    if KEY_FILE.exists():
        return "file (0600)"
    return "not yet created"


def _read_anchor() -> dict:
    try:
        return json.loads(TRUST_ANCHOR.read_text())
    except (OSError, json.JSONDecodeError):
        return {}


def trusted_did() -> str | None:
    """The current pinned agent DID, or None if trust has not been established yet."""
    return _read_anchor().get("did") or None


def trusted_dids() -> set[str]:
    """Every DID the operator has ever pinned: the current one plus any retired by a
    rotation. History signed by a retired key still verifies (it was trusted when
    written); only a never-trusted foreign key is rejected."""
    a = _read_anchor()
    dids = set(a.get("prior", []))
    if a.get("did"):
        dids.add(a["did"])
    return dids


def _establish_trust(did: str) -> None:
    """Pin `did` as the trusted issuer on first run (trust-on-first-use). A no-op
    once an anchor exists, so an existing install keeps its original identity."""
    if TRUST_ANCHOR.exists():
        return
    try:
        TRUST_ANCHOR.parent.mkdir(parents=True, exist_ok=True)
        TRUST_ANCHOR.write_text(
            json.dumps(
                {"did": did, "prior": [], "established": datetime.now(timezone.utc).isoformat()}
            )
        )
        TRUST_ANCHOR.chmod(0o600)
    except OSError as e:  # never block signing on an anchor write failure
        log.warning("Could not write trust anchor: %s", e)


def rotate_trust(new_did: str | None = None) -> dict:
    """Re-anchor trust to the current agent key after an intentional key change.
    The previous DID is retained in `prior` (so historical log/credentials it signed
    still verify) and the old anchor is archived to trust.json.prev. Idempotent: a
    no-op when the anchor already matches the current key. This is a deliberate
    operator action — it is the ONLY supported way to change the trusted identity, so
    a vault-content attacker (who cannot run it) still cannot re-root trust."""
    new_did = new_did or did_key(_pub_raw(_load_or_create_key()))
    a = _read_anchor()
    old = a.get("did")
    if old == new_did:
        return {"changed": False, "did": new_did}
    prior = set(a.get("prior", []))
    if old:
        prior.add(old)
    anchor = {
        "did": new_did,
        "prior": sorted(prior),
        "established": a.get("established", datetime.now(timezone.utc).isoformat()),
        "rotated": datetime.now(timezone.utc).isoformat(),
    }
    try:
        TRUST_ANCHOR.parent.mkdir(parents=True, exist_ok=True)
        if TRUST_ANCHOR.exists():
            (TRUST_ANCHOR.parent / "trust.json.prev").write_text(TRUST_ANCHOR.read_text())
        TRUST_ANCHOR.write_text(json.dumps(anchor))
        TRUST_ANCHOR.chmod(0o600)
    except OSError as e:
        log.error("Could not rotate trust anchor: %s", e)
        return {"changed": False, "did": old, "error": str(e)}
    return {"changed": True, "from": old, "to": new_did, "prior": anchor["prior"]}


def _issuer_trusted(issuer: str, expected: str | None) -> bool:
    """True if `issuer` is trusted: the explicitly expected DID, else any DID the
    operator has pinned (current or rotated-out). When no anchor exists yet (first
    run), pinning is skipped so bootstrap is not blocked."""
    if expected is not None:
        return issuer == expected
    trusted = trusted_dids()
    return not trusted or issuer in trusted


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


def verify_credential(vc: dict, expected_issuer: str | None = None) -> bool:
    try:
        proof = dict(vc["proof"])
        sig = b58decode(proof.pop("proofValue")[1:])
        signing_input = _canonical(
            {**{k: v for k, v in vc.items() if k != "proof"}, "proof": proof}
        )
        pubkey_from_did(vc["issuer"]).verify(sig, signing_input)
    except (KeyError, ValueError, InvalidSignature, IndexError):
        return False
    # A valid signature only proves "whoever holds this DID's key signed it"; pin the
    # issuer to the trusted agent so a self-consistent forgery under a foreign key fails.
    return _issuer_trusted(vc["issuer"], expected_issuer)


# --- AI-agent identity credential (DIF identity layer) --------------------------
# The operator-issued (or self-issued) W3C VC v2 asserting *what the agent is*: a
# software agent with an accountable operator and, optionally, the model behind it.
# This is the identity-layer credential sketched in
# docs/proposals/ai-agent-identity-for-content-provenance.md §3 — distinct from the
# CAWG ICA credential, which *binds* such an identity to content. It is secured with
# the same eddsa-jcs-2022 Data Integrity proof as issue_credential. When an operator
# DID issues it the proof is still produced under the agent key here (the reference is
# self-signed by the agent for operators that delegate to the agent's key); a real
# operator-anchored deployment would sign under the operator's own key.

AGENT_CREDENTIAL_TYPE = "AIAgentCredential"
TRUSTED_AI_AGENTS_CONTEXT = "https://identity.foundation/trusted-ai-agents/v1"


def agent_identity_credential(operator_did: str = None, model: dict = None) -> dict:
    """A W3C VC v2 of type AIAgentCredential asserting the agent is an AI agent with an
    accountable operator. `issuer` is the operator DID when given, else the agent DID
    (self-issued). The subject is the agent's did:key. `model`, if given, is carried as
    a credentialSubject.model declaration. Signed with the eddsa-jcs-2022 proof under
    the agent key (the verification method is the agent DID's key)."""
    key = _load_or_create_key()
    did = did_key(_pub_raw(key))
    now = datetime.now(timezone.utc).isoformat()
    operator = operator_did or did
    subject = {
        "id": did,
        "actorType": "ai-agent",
        "operator": {"id": operator},
    }
    if model:
        subject["model"] = model
    vc = {
        "@context": [VC_CONTEXT, TRUSTED_AI_AGENTS_CONTEXT],
        "type": ["VerifiableCredential", AGENT_CREDENTIAL_TYPE],
        "issuer": operator,
        "validFrom": now,
        "credentialSubject": subject,
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


def verify_agent_identity_credential(vc: dict) -> bool:
    """Verify an AIAgentCredential's eddsa-jcs-2022 proof against the key in its
    verification method (the agent DID). Mirrors verify_credential, but the signing key
    is the agent DID embedded in the proof's verificationMethod, not necessarily the
    issuer (which may be an operator DID that delegated to the agent key)."""
    try:
        proof = dict(vc["proof"])
        sig = b58decode(proof.pop("proofValue")[1:])
        signing_input = _canonical(
            {**{k: v for k, v in vc.items() if k != "proof"}, "proof": proof}
        )
        vm = proof["verificationMethod"]
        signer_did = vm.split("#", 1)[0]
        pubkey_from_did(signer_did).verify(sig, signing_input)
        return True
    except (KeyError, ValueError, InvalidSignature, IndexError):
        return False


# --- SCITT-style transparency log ----------------------------------------------


def _entry_signing_input(e: dict) -> bytes:
    return _canonical(
        {k: e[k] for k in ("seq", "ts", "event", "memoryId", "statementHash", "prevHash", "issuer")}
    )


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


def verify_log(expected_issuer: str | None = None) -> dict:
    """Verify the whole chain: signatures valid, prevHash links unbroken, and every
    entry issued by the trusted agent (so a chain re-signed under a foreign key fails)."""
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
        if not _issuer_trusted(entry["issuer"], expected_issuer):
            return {
                "ok": False,
                "entries": len(lines),
                "broken_at": i,
                "reason": "untrusted issuer",
            }
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
        return hashlib.sha256(b"\x00" + leaves[0]).digest()  # leaf domain prefix
    k = 1
    while k * 2 < n:
        k *= 2  # largest power of 2 < n
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


def _sth_body(sth: dict) -> dict:
    """The canonical STH fields both the agent and a witness sign over — everything
    except the signatures themselves."""
    return {k: v for k, v in sth.items() if k not in ("signature", "witness")}


def verify_sth(sth: dict, expected_issuer: str | None = None) -> bool:
    try:
        sig = b58decode(sth["signature"][1:])
        pubkey_from_did(sth["issuer"]).verify(sig, _canonical(_sth_body(sth)))
    except (KeyError, ValueError, InvalidSignature, IndexError):
        return False
    return _issuer_trusted(sth["issuer"], expected_issuer)


# --- external transparency witness ----------------------------------------------
# The agent self-signs its STH, so an inclusion receipt proves "in a tree the agent
# signed", not "in an independently witnessed log". A witness is a SEPARATE keypair —
# meant to live on another machine / under another party — that co-signs the same STH
# body. A relying party then has two independent signatures: the agent can no longer
# fork or rewrite history without the witness also colluding. cogmem provides the
# protocol (cosign + verify + a trusted-witness registry); the witness's independence
# is the operator's to ensure by running it elsewhere.


def witness_cosign(sth: dict, witness_key: Ed25519PrivateKey) -> dict:
    """Return the STH with a witness co-signature over the same body the agent signed."""
    wdid = did_key(_pub_raw(witness_key))
    sig = "z" + b58encode(witness_key.sign(_canonical(_sth_body(sth))))
    return {**sth, "witness": {"issuer": wdid, "signature": sig}}


def verify_witnessed_sth(sth: dict, witness_did: str) -> bool:
    """True only if BOTH the agent signature (trust-pinned) and the witness
    co-signature from `witness_did` verify over the STH body."""
    if not verify_sth(sth):
        return False
    w = sth.get("witness")
    if not isinstance(w, dict) or w.get("issuer") != witness_did:
        return False
    try:
        sig = b58decode(w["signature"][1:])
        pubkey_from_did(witness_did).verify(sig, _canonical(_sth_body(sth)))
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
    except ModuleNotFoundError as exc:  # graceful: COSE is optional
        raise RuntimeError(
            "cbor2 is required for COSE signed statements (pip install cbor2)"
        ) from exc
    return cbor2


def _cose_sign1(
    key: Ed25519PrivateKey, payload: bytes, content_type: str = _COSE_CONTENT_TYPE
) -> bytes:
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
    ph = cbor2.loads(protected)
    if ph.get(1) != _COSE_ALG_EDDSA:
        raise ValueError("unexpected COSE algorithm (only EdDSA is permitted)")
    pub = ph.get(4)
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


# --- did:web / did:jwk resolution -----------------------------------------------
# Resolve an agent DID to its Ed25519 key. did:key/did:jwk are self-contained;
# did:web is fetched (or supplied offline). did:web publishes the key as a JWK so
# the CAWG ICA issuer resolver in c2pa-rs can verify the agent's credential.


def agent_did_web(domain: str, path: str = "agents/cogmem"):
    """Return (did:web identifier, DID document) for the agent anchored at `domain`.
    Host the document at the did:web URL and any Universal Resolver can resolve it
    (`did:web:domain:a:b` resolves to `https://domain/a/b/did.json`). The
    assertionMethod is an embedded verification method publishing the Ed25519 key as a
    `publicKeyJwk` (OKP), the shape the CAWG ICA issuer resolver in c2pa-rs requires."""
    key = _load_or_create_key()
    seg = (":" + path.replace("/", ":")) if path else ""
    did = f"did:web:{domain}{seg}"
    vm = {
        "id": f"{did}#key-1",
        "type": "JsonWebKey2020",
        "controller": did,
        "publicKeyJwk": _agent_jwk_public(key),
    }
    doc = {
        "@context": [
            "https://www.w3.org/ns/did/v1",
            "https://w3id.org/security/suites/jws-2020/v1",
        ],
        "id": did,
        "verificationMethod": [vm],
        "authentication": [vm["id"]],
        "assertionMethod": [vm],
    }
    return did, doc


def _fetch_did_web(did: str) -> dict:
    import urllib.request

    parts = did[len("did:web:") :].split(":")
    host = parts[0]
    sub = "/".join(parts[1:]) if len(parts) > 1 else ".well-known"
    with urllib.request.urlopen(f"https://{host}/{sub}/did.json", timeout=10) as resp:
        return json.loads(resp.read())


def resolve_did_to_key(did: str, document: dict = None) -> bytes:
    """Resolve a DID to its raw 32-byte Ed25519 public key. did:key and did:jwk are
    self-resolving; did:web is resolved from `document` (offline) or fetched over HTTPS."""
    if did.startswith("did:key:"):
        return pubkey_from_did(did).public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw
        )
    if did.startswith("did:jwk:"):
        jwk = json.loads(_b64url_decode(did[len("did:jwk:") :]))
        return _okp_jwk_to_raw(jwk)
    if did.startswith("did:web:"):
        doc = document or _fetch_did_web(did)
        vm = doc["verificationMethod"][0]
        if "publicKeyJwk" in vm:
            return _okp_jwk_to_raw(vm["publicKeyJwk"])
        decoded = b58decode(vm["publicKeyMultibase"][1:])
        if decoded[:2] != ED25519_MULTICODEC:
            raise ValueError("did:web verification method is not ed25519")
        return decoded[2:]
    raise ValueError(f"unsupported DID method: {did}")


# --- CAWG identity claims aggregation (ICA) -------------------------------------
# The production-correct path c2pa-rs ships: the agent is the *issuer* of a W3C
# Verifiable Credential of type IdentityClaimsAggregationCredential, secured by a
# COSE_Sign1 (tag-18, EdDSA, content type `application/vc`) over the VC JSON. The VC's
# credentialSubject.c2paAsset is the SignerPayload (CBOR bytestring hashes rendered as
# standard base64); the same SignerPayload is carried in CBOR in the identity assertion
# and the two are cross-checked. The issuer DID (did:jwk self-contained, or did:web
# resolving to a publicKeyJwk assertionMethod) binds the VC to the signing key.

CAWG_ICA_SIG_TYPE = "cawg.identity_claims_aggregation"
ICA_CONTEXT = "https://cawg.io/identity/1.1/ica/context/"
VC_CONTEXT = "https://www.w3.org/ns/credentials/v2"
ICA_CREDENTIAL_TYPE = "IdentityClaimsAggregationCredential"
_COSE_CONTENT_TYPE_VC = "application/vc"


def _b64url_nopad(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _b64url_decode(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def _okp_jwk_to_raw(jwk: dict) -> bytes:
    if jwk.get("kty") != "OKP" or jwk.get("crv") != "Ed25519":
        raise ValueError("JWK is not an Ed25519 OKP key")
    return _b64url_decode(jwk["x"])


def _agent_jwk_public(key: Ed25519PrivateKey) -> dict:
    return {"kty": "OKP", "crv": "Ed25519", "x": _b64url_nopad(_pub_raw(key))}


def agent_did_jwk() -> str:
    """Self-contained issuer DID: the agent's public JWK embedded in the DID itself, so
    a verifier resolves the key with no network fetch. The method-specific id is
    canonically padded base64url, which c2pa-rs's ICA resolver requires."""
    jwk = _agent_jwk_public(_load_or_create_key())
    enc = base64.urlsafe_b64encode(_canonical(jwk)).decode("ascii")
    return "did:jwk:" + enc


def _cose_sign1_vc(key: Ed25519PrivateKey, payload: bytes) -> bytes:
    """Tag-18 COSE_Sign1 over the VC JSON: protected {alg EdDSA, content type
    application/vc}, empty external_aad, non-detached payload."""
    cbor2 = _cbor()
    protected = cbor2.dumps({1: _COSE_ALG_EDDSA, 3: _COSE_CONTENT_TYPE_VC})
    sig_structure = cbor2.dumps(["Signature1", protected, b"", payload])
    signature = key.sign(sig_structure)
    return cbor2.dumps(cbor2.CBORTag(18, [protected, {}, payload, signature]))


def _ica_signer_payloads(refs: list):
    """Build the SignerPayload twice from `refs` (list of (url, alg, raw_hash)): the CBOR
    form (raw bytestring hashes) for the identity assertion, and the JSON form (standard
    base64 hashes) for the VC's c2paAsset. The two are equal after the verifier decodes."""
    cbor_refs, json_refs = [], []
    for url, alg, raw in refs:
        c = {"url": url, "hash": raw}
        j = {"url": url, "hash": base64.b64encode(raw).decode("ascii")}
        if alg:
            c["alg"] = alg
            j["alg"] = alg
        cbor_refs.append(c)
        json_refs.append(j)
    return (
        {"referenced_assertions": cbor_refs, "sig_type": CAWG_ICA_SIG_TYPE},
        {"referenced_assertions": json_refs, "sig_type": CAWG_ICA_SIG_TYPE},
    )


def agent_verified_identity(
    display_name: str,
    provider_id: str,
    provider_name: str,
    id_type: str,
    verified_at: str = None,
    uri: str = None,
) -> dict:
    """One entry of the VC's verifiedIdentities array. `id_type` names the verification
    performed. The agent's operator is attested with the standard `cawg.affiliation` type
    (provider + verifiedAt); the agent itself is identified by the ICA issuer DID, and
    CAWG's named-actor model already permits software actors. A portable AI-agent *identity*
    credential (what the agent is) is an identity-layer (W3C VC / DIF) concern, not a CAWG
    one -- see docs/proposals/ai-agent-identity-for-content-provenance.md."""
    vi = {
        "type": id_type,
        "name": display_name,
        "verifiedAt": verified_at or datetime.now(timezone.utc).isoformat(),
        "provider": {"id": provider_id, "name": provider_name},
    }
    if uri:
        vi["uri"] = uri
    return vi


def ica_credential(
    issuer_did: str, refs: list, verified_identities: list, valid_from: str = None
) -> dict:
    """The IdentityClaimsAggregationCredential (a W3C VC v2) the agent issues over the
    C2PA asset's SignerPayload."""
    _, sp_json = _ica_signer_payloads(refs)
    return {
        "@context": [VC_CONTEXT, ICA_CONTEXT],
        "type": ["VerifiableCredential", ICA_CREDENTIAL_TYPE],
        "issuer": issuer_did,
        "validFrom": valid_from or datetime.now(timezone.utc).isoformat(),
        "credentialSubject": {
            "verifiedIdentities": verified_identities,
            "c2paAsset": sp_json,
        },
    }


def ica_identity_assertion(
    refs: list, issuer_did: str, verified_identities: list, valid_from: str = None
):
    """The CAWG identity assertion in ICA form, embedded under `cawg.identity`. Returns
    (assertion_cbor, vc): the IdentityAssertion map {signer_payload, signature, pad1}
    where `signature` is the tag-18 COSE_Sign1 over the ICA VC. `refs` MUST include the
    hard binding (a `c2pa.hash.*` assertion)."""
    cbor2 = _cbor()
    key = _load_or_create_key()
    sp_cbor, _ = _ica_signer_payloads(refs)
    vc = ica_credential(issuer_did, refs, verified_identities, valid_from)
    cose = _cose_sign1_vc(key, _canonical(vc))
    assertion = cbor2.dumps(
        {"signer_payload": sp_cbor, "signature": cose, "pad1": b""}, canonical=True
    )
    return assertion, vc


def verify_ica_assertion(assertion_bytes: bytes, did_documents: dict = None) -> dict:
    """Mirror c2pa-rs's IcaSignatureVerifier: decode the assertion, verify the tag-18
    COSE_Sign1 over the VC under the issuer DID's key, and cross-check that the VC's
    c2paAsset equals the SignerPayload carried in the assertion. Returns the VC. Raises
    on any failure. `did_documents` supplies did:web docs offline."""
    cbor2 = _cbor()
    assertion = cbor2.loads(assertion_bytes)
    sp = assertion["signer_payload"]
    if sp.get("sig_type") != CAWG_ICA_SIG_TYPE:
        raise ValueError("signer_payload sig_type is not the ICA type")
    tagged = cbor2.loads(assertion["signature"])
    if not (isinstance(tagged, cbor2.CBORTag) and tagged.tag == 18):
        raise ValueError("signature is not a tag-18 COSE_Sign1")
    protected, _unprotected, payload, signature = tagged.value
    ph = cbor2.loads(protected)
    if ph.get(1) != _COSE_ALG_EDDSA:
        raise ValueError("COSE alg is not EdDSA")
    if ph.get(3) != _COSE_CONTENT_TYPE_VC:
        raise ValueError("COSE content type is not application/vc")
    vc = json.loads(payload)
    pub = resolve_did_to_key(vc["issuer"], (did_documents or {}).get(vc["issuer"]))
    sig_structure = cbor2.dumps(["Signature1", protected, b"", payload])
    Ed25519PublicKey.from_public_bytes(bytes(pub)).verify(bytes(signature), sig_structure)
    c2pa_asset = vc["credentialSubject"]["c2paAsset"]
    if c2pa_asset.get("sig_type") != sp.get("sig_type"):
        raise ValueError("c2paAsset sig_type does not match signer_payload")
    sp_refs, vc_refs = sp["referenced_assertions"], c2pa_asset["referenced_assertions"]
    if len(sp_refs) != len(vc_refs):
        raise ValueError("c2paAsset referenced_assertions count mismatch")
    for s, v in zip(sp_refs, vc_refs):
        if s["url"] != v["url"] or s.get("alg") != v.get("alg"):
            raise ValueError("c2paAsset referenced assertion url/alg mismatch")
        if bytes(s["hash"]) != base64.b64decode(v["hash"]):
            raise ValueError("c2paAsset referenced assertion hash mismatch")
    if not any("c2pa.hash." in r["url"].rsplit("/", 1)[-1] for r in sp_refs):
        raise ValueError("no hard binding assertion referenced")
    return vc


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
                    _emit_statement("created", rid, existing)  # backfill missing statement
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
    return {
        "total": total,
        "signed": signed,
        "valid": valid,
        "tampered": tampered,
        "unsigned": unsigned,
        "chain": verify_log(),
    }


if __name__ == "__main__":
    import sys

    logging.basicConfig(level=logging.INFO, format="%(message)s")
    command = sys.argv[1] if len(sys.argv) > 1 else "status"
    if command == "status":
        log.info("Agent DID:           %s", agent_did())
        r = verify_log()
        log.info(
            "Transparency log:    %d entries, integrity %s",
            r.get("entries", 0),
            "OK" if r["ok"] else f"BROKEN ({r.get('reason')})",
        )
        n = len(list(CREDENTIALS.glob("*.jsonld"))) if CREDENTIALS.exists() else 0
        log.info("Signed credentials:  %d", n)
        sth = signed_tree_head()
        log.info("Merkle root:         %s… (tree size %d)", sth["rootHash"][:16], sth["treeSize"])
    elif command == "trust":
        if "--rotate" in sys.argv:
            r = rotate_trust()
            if r.get("error"):
                sys.exit(1)
            if r["changed"]:
                log.info("Trust re-anchored: %s -> %s", r["from"], r["to"])
                log.info(
                    "Retired DIDs still trusted for history: %s", ", ".join(r["prior"]) or "(none)"
                )
            else:
                log.info("Trust anchor already matches the current key (%s).", r["did"])
        else:
            td = trusted_did()
            log.info("Trusted DID:  %s", td or "(not established)")
            retired = sorted(trusted_dids() - ({td} if td else set()))
            if retired:
                log.info("Retired DIDs: %s", ", ".join(retired))
            cur = agent_did()
            if td and cur != td:
                log.info("WARNING: current key DID %s does NOT match the trusted anchor.", cur)
                log.info("If this key change was intentional, run: cogmem trust --rotate")
    elif command == "witness":
        sub = sys.argv[2] if len(sys.argv) > 2 else ""
        if sub == "keygen" and len(sys.argv) > 3:
            wkey = Ed25519PrivateKey.generate()
            raw = wkey.private_bytes(
                serialization.Encoding.Raw,
                serialization.PrivateFormat.Raw,
                serialization.NoEncryption(),
            )
            kp = Path(sys.argv[3])
            kp.write_bytes(raw)
            kp.chmod(0o600)
            wdid = did_key(_pub_raw(wkey))
            log.info("Witness key written to %s", kp)
            log.info("Witness DID: %s", wdid)
            log.info("Keep this key on a SEPARATE machine, then register it on the agent host:")
            log.info("  cogmem witness trust %s", wdid)
        elif sub == "trust" and len(sys.argv) > 3:
            from cogmem import config

            cfg = config.load()
            cfg["witness_did"] = sys.argv[3]
            config.save(cfg)
            log.info("Trusted witness DID set: %s", sys.argv[3])
        elif sub == "cosign" and len(sys.argv) > 4:
            sth = json.loads(Path(sys.argv[3]).read_text())
            wkey = Ed25519PrivateKey.from_private_bytes(Path(sys.argv[4]).read_bytes())
            sys.stdout.write(json.dumps(witness_cosign(sth, wkey), indent=2) + "\n")
        elif sub == "verify" and len(sys.argv) > 3:
            from cogmem import config

            wdid = config.load().get("witness_did")
            if not wdid:
                log.error("No trusted witness DID set (cogmem witness trust <did>).")
                sys.exit(1)
            ok = verify_witnessed_sth(json.loads(Path(sys.argv[3]).read_text()), wdid)
            log.info("Witnessed STH: %s", "VALID" if ok else "INVALID")
            sys.exit(0 if ok else 1)
        else:
            log.error(
                "Usage: provenance.py witness [keygen <keyfile> | trust <did> | "
                "cosign <sth.json> <keyfile> | verify <sth.json>]"
            )
            sys.exit(1)
    elif command == "sign-vault":
        log.info("Issued %d new credential(s).", sign_vault())
    elif command == "verify":
        v = verify_vault()
        log.info(
            "Vault: %d rules | %d signed | %d valid | %d TAMPERED | %d unsigned",
            v["total"],
            v["signed"],
            v["valid"],
            v["tampered"],
            v["unsigned"],
        )
        log.info(
            "Transparency log: %s (%d entries)",
            "OK" if v["chain"]["ok"] else "BROKEN",
            v["chain"].get("entries", 0),
        )
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
            log.info(
                "Signed statement: VALID (memory %s, issuer %s)",
                claim.get("memoryId"),
                claim.get("iss"),
            )
        except (ValueError, InvalidSignature, RuntimeError):
            log.info("Signed statement: INVALID")
            sys.exit(1)
    elif command == "ica-assertion":
        # ica-assertion <issuer:jwk|web:domain:path> <label>=<hashhex> [<label>=<hashhex> ...]
        # Emits the CAWG identity assertion (ICA form, cawg.identity) as hex, with
        # referenced_assertions carrying the finalized JUMBF hashes the producer passes in.
        if len(sys.argv) < 4:
            log.error(
                "Usage: provenance.py ica-assertion <jwk|web:domain:path> "
                "<label>=<hashhex> [<label>=<hashhex> ...]"
            )
            sys.exit(1)
        spec = sys.argv[2]
        if spec == "jwk":
            issuer = agent_did_jwk()
        elif spec.startswith("web:"):
            domain, _, path = spec[len("web:") :].partition(":")
            issuer, _doc = agent_did_web(domain, path.replace(":", "/") or "agents/cogmem")
        else:
            log.error("issuer must be 'jwk' or 'web:domain:path'")
            sys.exit(1)
        refs = []
        for pair in sys.argv[3:]:
            label, _, hexhash = pair.partition("=")
            if not label or not hexhash:
                log.error("bad ref %r (want label=hashhex)", pair)
                sys.exit(1)
            refs.append((f"self#jumbf=c2pa.assertions/{label}", "sha256", bytes.fromhex(hexhash)))
        vi = [
            agent_verified_identity(
                "cogmem agent",
                "https://writersproof.com",
                "WritersProof",
                id_type="cawg.affiliation",
            )
        ]
        assertion, _vc = ica_identity_assertion(refs, issuer, vi)
        sys.stdout.write(assertion.hex() + "\n")
    else:
        log.error(
            "Usage: provenance.py [status | sign-vault | verify | sth | "
            "receipt <id> | verify-receipt <file> | statement <id> | "
            "verify-statement <file> | ica-assertion <issuer> <label>=<hash>...]"
        )
        sys.exit(1)
