import copy
import hashlib
import hmac
import unittest

from pqc_protocol import (
    OpenSSLBackend, ProtocolAbort, generate_identity, negotiate,
    SIGNATURE_BYTES, CIPHERTEXT_BYTES, SHARED_SECRET_BYTES,
    hkdf, b64, unb64, sha, sign_envelope,
)


class TestPQCProgram3(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.engine = OpenSSLBackend()
        cls.engine.__enter__()
        cls.alice = generate_identity(cls.engine, "Alice")
        cls.bob = generate_identity(cls.engine, "Bob")
        cls.other = generate_identity(cls.engine, "Mallory")

    @classmethod
    def tearDownClass(cls):
        cls.engine.__exit__(None, None, None)

    def test_01_backend(self):
        self.assertIn("OpenSSL 3.5", self.engine.version)

    def test_02_mldsa_sign_verify(self):
        msg = b"authenticated message"
        sig = self.engine.sign(self.alice.signing_private, msg)
        self.assertEqual(len(sig), SIGNATURE_BYTES)
        self.assertIsNone(self.engine.verify(self.alice.signing_public, msg, sig))

    def test_03_modified_message_rejected(self):
        sig = self.engine.sign(self.alice.signing_private, b"original")
        with self.assertRaises(ProtocolAbort):
            self.engine.verify(self.alice.signing_public, b"altered", sig)

    def test_04_wrong_signing_key_rejected(self):
        sig = self.engine.sign(self.alice.signing_private, b"message")
        with self.assertRaises(ProtocolAbort):
            self.engine.verify(self.other.signing_public, b"message", sig)

    def test_05_modified_signature_rejected(self):
        msg = b"message"
        sig = bytearray(self.engine.sign(self.alice.signing_private, msg))
        sig[0] ^= 1
        with self.assertRaises(ProtocolAbort):
            self.engine.verify(self.alice.signing_public, msg, bytes(sig))

    def test_06_mlkem_roundtrip(self):
        sk, pk = self.engine.keypair("ML-KEM-768")
        ct, ss = self.engine.encapsulate(pk)
        self.assertEqual(len(ct), CIPHERTEXT_BYTES)
        self.assertEqual(len(ss), SHARED_SECRET_BYTES)
        self.assertEqual(ss, self.engine.decapsulate(sk, ct))

    def test_07_mlkem_wrong_key(self):
        _, pk1 = self.engine.keypair("ML-KEM-768")
        sk2, _ = self.engine.keypair("ML-KEM-768")
        ct, ss = self.engine.encapsulate(pk1)
        self.assertNotEqual(ss, self.engine.decapsulate(sk2, ct))

    def test_08_mlkem_wrong_ciphertext_length(self):
        sk, _ = self.engine.keypair("ML-KEM-768")
        with self.assertRaises(ProtocolAbort):
            self.engine.decapsulate(sk, b"invalid")

    def test_09_hkdf_rfc5869_case1(self):
        # RFC 5869 Appendix A.1, SHA-256
        ikm = bytes.fromhex("0b" * 22)
        salt = bytes.fromhex("000102030405060708090a0b0c")
        info = bytes.fromhex("f0f1f2f3f4f5f6f7f8f9")
        okm = hkdf(ikm, salt, info, 42)
        self.assertEqual(okm.hex(),
                         "3cb25f25faacd57a90434f64d0362f2a"
                         "2d2d0a90cf1a5a4c5db02d56ecc4c5bf"
                         "34007208d5b887185865")

    def test_10_honest_session_agreement(self):
        result = negotiate(self.engine, self.alice, self.bob)
        self.assertEqual(result.session_key_alice, result.session_key_bob)
        self.assertEqual(len(result.session_key_alice), 32)
        self.assertGreater(result.on_wire_bytes, 1088 + 2*3309)

    def test_11_session_key_freshness(self):
        a = negotiate(self.engine, self.alice, self.bob)
        b = negotiate(self.engine, self.alice, self.bob)
        self.assertNotEqual(a.session_key_alice, b.session_key_alice)
        self.assertNotEqual(a.transcript_hash, b.transcript_hash)

    def test_12_replay_hello_rejected(self):
        seen = set()
        previous = negotiate(self.engine, self.alice, self.bob, replay_cache=seen)
        with self.assertRaises(ProtocolAbort):
            negotiate(self.engine, self.alice, self.bob, replay_cache=seen,
                      replay_hello=previous.envelope_hello)

    def test_12b_default_replay_cache(self):
        previous = negotiate(self.engine, self.alice, self.bob)
        with self.assertRaises(ProtocolAbort):
            negotiate(self.engine, self.alice, self.bob,
                      replay_hello=previous.envelope_hello)

    def _attack(self, stage, modifier):
        def mutator(current, message):
            clone = copy.deepcopy(message)
            if current == stage:
                modifier(clone)
            return clone
        with self.assertRaises(ProtocolAbort):
            negotiate(self.engine, self.alice, self.bob, mutator=mutator)

    def test_13_alice_hello_signature_tamper(self):
        self._attack("client_hello", lambda m: m.__setitem__("signature", b64(b"\0" * 3309)))

    def test_14_alice_mode_tamper(self):
        self._attack("client_hello", lambda m: m["body"].__setitem__("mode", "HYBRID"))

    def test_15_server_signature_tamper(self):
        self._attack("server_hello", lambda m: m.__setitem__("signature", b64(b"\0" * 3309)))

    def test_16_server_kem_key_tamper(self):
        self._attack("server_hello", lambda m: m["body"].__setitem__("kem_public_key", b64(b"fake")))

    def test_17_server_nonce_tamper(self):
        self._attack("server_hello", lambda m: m["body"].__setitem__("server_nonce", b64(b"?"*32)))

    def test_18_client_finish_signature_tamper(self):
        self._attack("client_finish", lambda m: m.__setitem__("signature", b64(b"\0" * 3309)))

    def test_19_client_finish_ciphertext_tamper(self):
        self._attack("client_finish", lambda m: m["body"].__setitem__("kem_ciphertext", b64(b"A"*1088)))

    def test_20_server_confirmation_tamper(self):
        self._attack("server_finished", lambda m: m.__setitem__("mac", b64(b"\0"*32)))

    def test_21_client_confirmation_tamper(self):
        self._attack("client_finished", lambda m: m.__setitem__("mac", b64(b"\0"*32)))

    def test_22_server_identity_tamper(self):
        self._attack("server_hello", lambda m: m["body"].__setitem__("from", "Mallory"))

    def test_23_server_algorithm_tamper(self):
        self._attack("server_hello", lambda m: m["body"].__setitem__("kem_algorithm", "ML-KEM-512"))

    def test_24_wrong_pinned_bob_public_key(self):
        wrong_bob = type(self.bob)(self.bob.name, self.bob.signing_private, self.other.signing_public)
        with self.assertRaises(ProtocolAbort):
            negotiate(self.engine, self.alice, wrong_bob)

    def test_25_invalid_base64_rejected(self):
        with self.assertRaises(ProtocolAbort):
            unb64("%%%")

    def test_26_unsigned_client_hello_extra_field(self):
        self._attack("client_hello", lambda m: m["body"].__setitem__("bogus", "1"))

    def test_27_signed_protocol_mismatch_rejected(self):
        def resign_wrong_version(stage, msg):
            if stage == "client_hello":
                changed = copy.deepcopy(msg)
                changed["body"]["protocol"] = "old-unsupported-version"
                return sign_envelope(self.engine, self.alice.signing_private, changed["body"])
            return msg
        with self.assertRaises(ProtocolAbort):
            negotiate(self.engine, self.alice, self.bob, mutator=resign_wrong_version)


if __name__ == "__main__":
    unittest.main()
