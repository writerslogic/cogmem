"""
Verifiable Agent Memory tests. The tamper-detection cases are the substance of the
poison-resistance claim: an altered credential or log entry must be rejected.

Run:  python test_provenance.py
"""

import hashlib
import json
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import provenance as pv
from common import read_note, write_note


class ProvenanceTest(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        root = Path(self._tmp.name)
        pv.IDENTITY = root / "identity"
        pv.KEY_FILE = pv.IDENTITY / "agent.key"
        pv.LOG_FILE = root / "provenance" / "log.jsonl"

    def tearDown(self):
        self._tmp.cleanup()

    def test_did_key_roundtrip(self):
        did = pv.agent_did()
        self.assertTrue(did.startswith("did:key:z"))
        # the DID's public key must verify a signature from the private key
        key = pv._load_or_create_key()
        sig = key.sign(b"hello")
        pv.pubkey_from_did(did).verify(sig, b"hello")  # raises if wrong

    def test_credential_verifies(self):
        vc = pv.issue_credential("rule-1", "zeroize keys after use",
                                 {"kind": "rule", "layer": "B", "scope": "rust"})
        self.assertTrue(pv.verify_credential(vc))
        self.assertEqual(vc["credentialSubject"]["statement"], "zeroize keys after use")

    def test_tampered_credential_rejected(self):
        vc = pv.issue_credential("rule-1", "use subprocess.run", {"kind": "rule"})
        self.assertTrue(pv.verify_credential(vc))
        vc["credentialSubject"]["statement"] = "use os.system"   # poison the memory
        self.assertFalse(pv.verify_credential(vc))               # must be caught

    def test_credential_from_other_key_rejected(self):
        vc = pv.issue_credential("rule-1", "x", {"kind": "rule"})
        # swap issuer to a different did:key whose key did not sign this
        other = pv.did_key(pv._pub_raw(pv.Ed25519PrivateKey.generate()))
        vc["issuer"] = other
        self.assertFalse(pv.verify_credential(vc))

    # --- AI-agent identity credential (DIF identity layer) -----------------------

    def test_agent_identity_credential_verifies(self):
        vc = pv.agent_identity_credential(
            operator_did="did:web:writersproof.com:agents:cogmem",
            model={"name": "claude-opus-4", "version": "20260101"})
        self.assertTrue(pv.verify_agent_identity_credential(vc))
        self.assertIn("AIAgentCredential", vc["type"])
        self.assertEqual(vc["issuer"], "did:web:writersproof.com:agents:cogmem")
        self.assertEqual(vc["credentialSubject"]["id"], pv.agent_did())
        self.assertEqual(vc["credentialSubject"]["actorType"], "ai-agent")
        self.assertEqual(vc["credentialSubject"]["model"]["name"], "claude-opus-4")

    def test_agent_identity_credential_self_issued(self):
        vc = pv.agent_identity_credential()
        self.assertTrue(pv.verify_agent_identity_credential(vc))
        # no operator given -> issuer is the agent DID (self-issued)
        self.assertEqual(vc["issuer"], pv.agent_did())
        self.assertEqual(vc["credentialSubject"]["operator"]["id"], pv.agent_did())
        self.assertNotIn("model", vc["credentialSubject"])

    def test_agent_identity_credential_tampered_subject_rejected(self):
        vc = pv.agent_identity_credential()
        self.assertTrue(pv.verify_agent_identity_credential(vc))
        vc["credentialSubject"]["actorType"] = "human"     # forge the actor's nature
        self.assertFalse(pv.verify_agent_identity_credential(vc))

    def test_agent_identity_credential_cross_key_forgery_rejected(self):
        vc = pv.agent_identity_credential()
        # swap the verification method to a foreign did:key whose key did not sign this
        other = pv.did_key(pv._pub_raw(pv.Ed25519PrivateKey.generate()))
        vc["proof"]["verificationMethod"] = f"{other}#{other.split(':')[-1]}"
        self.assertFalse(pv.verify_agent_identity_credential(vc))

    def test_log_chain_intact(self):
        for i in range(3):
            vc = pv.issue_credential(f"rule-{i}", f"lesson {i}", {"kind": "rule"})
            pv.log_append("created", f"rule-{i}", vc)
        result = pv.verify_log()
        self.assertTrue(result["ok"])
        self.assertEqual(result["entries"], 3)

    def test_log_tamper_detected(self):
        for i in range(3):
            vc = pv.issue_credential(f"rule-{i}", f"lesson {i}", {"kind": "rule"})
            pv.log_append("created", f"rule-{i}", vc)
        lines = pv.LOG_FILE.read_text().splitlines()
        e = json.loads(lines[1])
        e["memoryId"] = "rule-injected"          # alter a logged event
        lines[1] = json.dumps(e, separators=(",", ":"))
        pv.LOG_FILE.write_text("\n".join(lines) + "\n")
        result = pv.verify_log()
        self.assertFalse(result["ok"])
        self.assertEqual(result["broken_at"], 1)

    def test_forged_entry_rejected(self):
        vc = pv.issue_credential("rule-0", "lesson", {"kind": "rule"})
        pv.log_append("created", "rule-0", vc)
        forged = {"seq": 1, "ts": "2026-01-01T00:00:00Z", "event": "created",
                  "memoryId": "evil", "statementHash": "x",
                  "prevHash": pv._last_entry_hash(), "issuer": pv.agent_did(),
                  "signature": "z" + pv.b58encode(b"not a real signature here....")}
        with pv.LOG_FILE.open("a") as fh:
            fh.write(json.dumps(forged, separators=(",", ":")) + "\n")
        self.assertFalse(pv.verify_log()["ok"])


    def test_inclusion_receipt_verifies(self):
        for i in range(5):
            vc = pv.issue_credential(f"rule-{i}", f"lesson {i}", {"kind": "rule"})
            pv.log_append("created", f"rule-{i}", vc)
        receipt = pv.inclusion_receipt("rule-2")
        self.assertIsNotNone(receipt)
        self.assertTrue(pv.verify_receipt(receipt))

    def test_receipt_single_entry(self):
        vc = pv.issue_credential("rule-0", "only", {"kind": "rule"})
        pv.log_append("created", "rule-0", vc)
        self.assertTrue(pv.verify_receipt(pv.inclusion_receipt("rule-0")))

    def test_receipt_tampered_leaf_rejected(self):
        for i in range(4):
            vc = pv.issue_credential(f"rule-{i}", f"lesson {i}", {"kind": "rule"})
            pv.log_append("created", f"rule-{i}", vc)
        receipt = pv.inclusion_receipt("rule-1")
        receipt["leaf"] = receipt["leaf"].replace("rule-1", "rule-evil")  # forge the leaf
        self.assertFalse(pv.verify_receipt(receipt))

    def test_receipt_tampered_path_rejected(self):
        for i in range(4):
            vc = pv.issue_credential(f"rule-{i}", f"lesson {i}", {"kind": "rule"})
            pv.log_append("created", f"rule-{i}", vc)
        receipt = pv.inclusion_receipt("rule-1")
        sib = bytearray(bytes.fromhex(receipt["auditPath"][0]))
        sib[0] ^= 0xff                                            # corrupt the proof
        receipt["auditPath"][0] = sib.hex()
        self.assertFalse(pv.verify_receipt(receipt))

    def test_receipt_forged_root_rejected(self):
        for i in range(3):
            vc = pv.issue_credential(f"rule-{i}", f"lesson {i}", {"kind": "rule"})
            pv.log_append("created", f"rule-{i}", vc)
        receipt = pv.inclusion_receipt("rule-0")
        bad = bytearray(bytes.fromhex(receipt["sth"]["rootHash"]))
        bad[0] ^= 0xff
        receipt["sth"]["rootHash"] = bad.hex()                    # claim a different root
        self.assertFalse(pv.verify_receipt(receipt))              # STH signature no longer matches

    # --- Merkle / receipt gaps flagged by THREAT-MODEL.md T5 ---------------------

    def test_empty_log_root_stable(self):
        # an empty log must produce a stable root without crashing
        self.assertFalse(pv.LOG_FILE.exists())
        sth = pv.signed_tree_head()
        self.assertEqual(sth["treeSize"], 0)
        self.assertEqual(sth["rootHash"], hashlib.sha256(b"").hexdigest())
        self.assertTrue(pv.verify_sth(sth))                       # signs/verifies cleanly
        self.assertEqual(pv._mth([]).hex(), pv._mth([]).hex())    # deterministic

    def test_receipt_wrong_treesize_rejected(self):
        for i in range(4):
            vc = pv.issue_credential(f"rule-{i}", f"lesson {i}", {"kind": "rule"})
            pv.log_append("created", f"rule-{i}", vc)
        receipt = pv.inclusion_receipt("rule-1")
        # forge sth.treeSize to a value != the real tree size, and re-sign the STH so its
        # signature is *valid*; verify_receipt must still reject (inclusion fails vs root)
        key = pv._load_or_create_key()
        sth = receipt["sth"]
        sth.pop("signature")
        sth["treeSize"] = 99
        receipt["treeSize"] = 99
        sth["signature"] = "z" + pv.b58encode(key.sign(pv._canonical(sth)))
        self.assertTrue(pv.verify_sth(sth))                       # STH signature is genuine
        self.assertFalse(pv.verify_receipt(receipt))              # but the size is a lie

    def test_receipt_second_preimage_rejected(self):
        # feed an internal node's bytes where a leaf is expected: the RFC 6962 0x00/0x01
        # domain prefixes must stop the second-preimage substitution. The attacker hopes
        # the internal node H(0x01||L0||L1) is accepted as a leaf so a shorter forged
        # proof verifies against the real 4-leaf root.
        for i in range(4):
            vc = pv.issue_credential(f"rule-{i}", f"lesson {i}", {"kind": "rule"})
            pv.log_append("created", f"rule-{i}", vc)
        lines = pv._log_lines()
        leaves = [l.encode("utf-8") for l in lines]
        root = pv._mth(leaves)
        internal = hashlib.sha256(
            b"\x01" + hashlib.sha256(b"\x00" + leaves[0]).digest()
            + hashlib.sha256(b"\x00" + leaves[1]).digest()).digest()
        # leaf-prefixed hash of the internal node (what verify_receipt computes from a
        # supplied leaf) must NOT equal the node hash, so it cannot stand in for it
        self.assertNotEqual(hashlib.sha256(b"\x00" + internal).digest(), internal)
        # the substitution fails inclusion verification against the real root, because
        # verify_receipt always re-hashes a supplied leaf under the 0x00 prefix
        sibling = pv._mth(leaves[2:])
        self.assertFalse(pv._verify_inclusion(
            hashlib.sha256(b"\x00" + internal).digest(), 0, 2, [sibling], root))

    def test_signed_statement_verifies(self):
        vc = pv.issue_credential("rule-9", "use subprocess.run", {"kind": "rule"})
        claim = pv.verify_signed_statement(pv.signed_statement("created", "rule-9", vc))
        self.assertEqual(claim["memoryId"], "rule-9")
        self.assertEqual(claim["statementHash"].hex(), pv._sha256(pv._canonical(vc)))

    def test_signed_statement_structure_is_cose_sign1(self):
        import cbor2
        vc = pv.issue_credential("rule-9", "x", {"kind": "rule"})
        arr = cbor2.loads(pv.signed_statement("created", "rule-9", vc))
        self.assertEqual(len(arr), 4)                     # [protected, {}, payload, signature]
        phdr = cbor2.loads(arr[0])
        self.assertEqual(phdr[1], -8)                     # alg = EdDSA  (matches HMS)
        self.assertEqual(phdr[3], "application/cbor")     # content type
        self.assertEqual(len(phdr[4]), 32)                # kid = raw Ed25519 public key

    def test_signed_statement_tampered_rejected(self):
        vc = pv.issue_credential("rule-9", "x", {"kind": "rule"})
        cose = bytearray(pv.signed_statement("created", "rule-9", vc))
        cose[-1] ^= 0xFF                                   # corrupt the signature
        with self.assertRaises(pv.InvalidSignature):
            pv.verify_signed_statement(bytes(cose))

    def test_signed_statement_wrong_key_rejected(self):
        import cbor2
        vc = pv.issue_credential("rule-9", "x", {"kind": "rule"})
        arr = cbor2.loads(pv.signed_statement("created", "rule-9", vc))
        phdr = cbor2.loads(arr[0])
        phdr[4] = pv._pub_raw(pv.Ed25519PrivateKey.generate())   # swap in a foreign kid
        arr[0] = cbor2.dumps(phdr)
        with self.assertRaises(pv.InvalidSignature):
            pv.verify_signed_statement(cbor2.dumps(arr))

    def test_cose_malformed_rejected(self):
        with self.assertRaises(ValueError):
            pv._cose_verify(b"\x00\x01\x02 not cose")

    # --- CAWG ICA conformance (shared vector, c2patool-validated) ----------------

    def _ica_vector(self):
        path = (Path(__file__).resolve().parent.parent
                / "tests" / "vectors" / "cawg-ica-credential.json")
        return json.loads(path.read_text())

    def test_ica_assertion_verifies(self):
        vec = self._ica_vector()
        assertion = bytes.fromhex(vec["identity_assertion_cbor_hex"])
        vc = pv.verify_ica_assertion(assertion)
        self.assertEqual(vc["issuer"], vec["issuer"])
        self.assertIn("IdentityClaimsAggregationCredential", vc["type"])

    def test_ica_assertion_tampered_rejected(self):
        vec = self._ica_vector()
        assertion = bytearray(bytes.fromhex(vec["identity_assertion_cbor_hex"]))
        assertion[-1] ^= 0xFF                    # flip a byte of the assertion
        with self.assertRaises((ValueError, pv.InvalidSignature)):
            pv.verify_ica_assertion(bytes(assertion))

    # --- ICA negative cases flagged by THREAT-MODEL.md T11 -----------------------

    def _build_ica(self, refs):
        issuer = pv.agent_did_jwk()
        vi = [pv.agent_verified_identity("cogmem agent", "https://writersproof.com",
                                         "WritersProof", id_type="cawg.affiliation")]
        return pv.ica_identity_assertion(refs, issuer, vi)

    def _resign_vc(self, assertion, vc):
        import cbor2
        cose = pv._cose_sign1_vc(pv._load_or_create_key(), pv._canonical(vc))
        a = cbor2.loads(assertion)
        a["signature"] = cose                     # rewrap with a freshly-signed VC
        return cbor2.dumps(a, canonical=True)

    def test_ica_referenced_hash_altered_rejected(self):
        # (a) a referenced-assertion hash in c2paAsset altered vs signer_payload
        refs = [("self#jumbf=c2pa.assertions/c2pa.hash.data", "sha256", b"\x11" * 32),
                ("self#jumbf=c2pa.assertions/cogmem.memory.provenance", "sha256", b"\x22" * 32)]
        assertion, vc = self._build_ica(refs)
        self.assertTrue(pv.verify_ica_assertion(assertion))       # baseline good
        import base64
        vc["credentialSubject"]["c2paAsset"]["referenced_assertions"][0]["hash"] = \
            base64.b64encode(b"\x99" * 32).decode("ascii")
        with self.assertRaises(ValueError):
            pv.verify_ica_assertion(self._resign_vc(assertion, vc))

    def test_ica_missing_hard_binding_rejected(self):
        # (b) the hard binding (c2pa.hash.*) is removed
        refs = [("self#jumbf=c2pa.assertions/cogmem.memory.provenance", "sha256", b"\x22" * 32)]
        assertion, _vc = self._build_ica(refs)
        with self.assertRaises(ValueError):
            pv.verify_ica_assertion(assertion)

    def test_ica_referenced_count_mismatch_rejected(self):
        # (c) referenced_assertions counts differ between c2paAsset and signer_payload
        refs = [("self#jumbf=c2pa.assertions/c2pa.hash.data", "sha256", b"\x11" * 32),
                ("self#jumbf=c2pa.assertions/cogmem.memory.provenance", "sha256", b"\x22" * 32)]
        assertion, vc = self._build_ica(refs)
        ra = vc["credentialSubject"]["c2paAsset"]["referenced_assertions"]
        vc["credentialSubject"]["c2paAsset"]["referenced_assertions"] = ra[:1]
        with self.assertRaises(ValueError):
            pv.verify_ica_assertion(self._resign_vc(assertion, vc))



class VaultPoisonTest(unittest.TestCase):
    """THREAT-MODEL.md T1: verify_vault must flag a rule whose body no longer matches
    its signed credential as tampered (memory-poisoning detection)."""

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        root = Path(self._tmp.name)
        pv.IDENTITY = root / "identity"
        pv.KEY_FILE = pv.IDENTITY / "agent.key"
        pv.LOG_FILE = root / "provenance" / "log.jsonl"
        pv.RULES = root / "rules"
        pv.CREDENTIALS = root / "credentials"
        pv.STATEMENTS = root / "provenance" / "statements"
        pv.RULES.mkdir(parents=True)

    def tearDown(self):
        self._tmp.cleanup()

    def test_poisoned_rule_body_detected(self):
        rf = pv.RULES / "rule-x.md"
        write_note(rf, {"id": "rule-x", "layer": "B", "scope": "rust"},
                   "zeroize keys after use")
        self.assertEqual(pv.sign_vault(), 1)
        clean = pv.verify_vault()
        self.assertEqual(clean["valid"], 1)
        self.assertEqual(clean["tampered"], 0)
        # poison: edit the rule body after it was signed, without re-signing
        meta, _body = read_note(rf)
        write_note(rf, meta, "use os.system to run shell")
        poisoned = pv.verify_vault()
        self.assertEqual(poisoned["tampered"], 1)
        self.assertEqual(poisoned["valid"], 0)


class CoseHardeningTest(unittest.TestCase):
    """T7: _cose_verify must reject any algorithm other than EdDSA (alg confusion)."""

    def test_non_eddsa_alg_rejected(self):
        import cbor2
        cose = pv.signed_statement("used", "m", pv.issue_credential("m", "x", {"kind": "rule"}))
        arr = cbor2.loads(cose)
        ph = cbor2.loads(arr[0])
        ph[1] = -7  # forge the protected alg to ES256
        arr[0] = cbor2.dumps(ph)
        with self.assertRaises(ValueError):
            pv._cose_verify(cbor2.dumps(arr))


if __name__ == "__main__":
    unittest.main(verbosity=2)
