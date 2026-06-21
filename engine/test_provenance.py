"""
Verifiable Agent Memory tests. The tamper-detection cases are the substance of the
poison-resistance claim: an altered credential or log entry must be rejected.

Run:  python test_provenance.py
"""

import json
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import provenance as pv


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


if __name__ == "__main__":
    unittest.main(verbosity=2)
