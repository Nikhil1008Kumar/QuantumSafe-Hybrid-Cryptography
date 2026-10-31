"""Tests of the LOCAL SIMULATION and explicitly modeled attack surface."""
import base64
import copy
import unittest
from unittest.mock import patch

from finite_key_bb84 import FiniteKeyConfig, run, run_with_material
from pqc_protocol import OpenSSLBackend, ProtocolAbort, generate_identity, sha
from hybrid_protocol import (Policy, HybridAbort, RecordReceiver, seal_record,
                             run_hybrid, _schedule)


def config(n=50000, noise=0.0, eve=0.0):
    k = round(.18*n)
    return FiniteKeyConfig(transmitted_signals=n,target_key_bits=k,
        target_test_bits=k,noise_probability=noise,intercept_probability=eve)


def alter(stage_to_modify, operation):
    def f(stage, packet):
        if stage != stage_to_modify:
            return packet
        altered = copy.deepcopy(packet)
        operation(altered)
        return altered
    return f


class HybridIntegrationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.backend = OpenSSLBackend()
        cls.backend.__enter__()
        cls.alice = generate_identity(cls.backend,'Alice')
        cls.bob = generate_identity(cls.backend,'Bob')

    @classmethod
    def tearDownClass(cls):
        cls.backend.__exit__(None,None,None)

    def go(self, policy=Policy.HYBRID_REQUIRED, cfg=None, mutator=None,
           handshake_mutator=None, seed=20261024, msg=b'hello'):
        return run_hybrid(self.backend,self.alice,self.bob,cfg or config(), seed,
             policy, plaintext=msg,mutator=mutator,handshake_mutator=handshake_mutator)

    def test_01_program2_original_api_unchanged(self):
        a = run(config(500),1234)
        b, secrets = run_with_material(config(500),1234)
        self.assertEqual(a.status,b.status)
        self.assertIsNone(secrets)

    def test_02_export_only_accepted_key_material(self):
        res, secrets = run_with_material(config(),20261024)
        self.assertEqual(res.status,'ACCEPT')
        self.assertEqual(len(secrets[0]),32)
        self.assertEqual(secrets[0],secrets[1])

    def test_03_hybrid_required_accepts(self):
        result = self.go(msg=b'important message')
        self.assertEqual(result.mode,'HYBRID')
        self.assertEqual(result.qkd_status,'ACCEPT')
        self.assertEqual(result.recovered_plaintext,b'important message')
        self.assertTrue(result.application_keys_match)

    def test_04_pqc_only_no_qkd(self):
        r = self.go(Policy.PQC_ONLY,config(500))
        self.assertEqual(r.mode,'PQC_ONLY')
        self.assertEqual(r.qkd_status,'NOT_RUN')
        self.assertEqual(r.qkd_bound_bits,0)

    def test_05_fallback_on_bad_noise(self):
        r = self.go(Policy.HYBRID_PREFERRED,config(noise=.03))
        self.assertEqual(r.mode,'PQC_ONLY')
        self.assertNotEqual(r.qkd_status,'ACCEPT')

    def test_06_required_policy_blocks_fallback(self):
        with self.assertRaises(HybridAbort) as ex:
            self.go(Policy.HYBRID_REQUIRED, config(noise=.03))
        self.assertEqual(ex.exception.stage,'qkd_admission')

    def test_07_small_sample_does_not_release_qkd(self):
        with self.assertRaises(HybridAbort):
            self.go(Policy.HYBRID_REQUIRED,config(500))

    def test_08_attack_rejected_under_required_mode(self):
        with self.assertRaises(HybridAbort):
            self.go(Policy.HYBRID_REQUIRED,config(n=100000,eve=.2))

    def test_09_attack_falls_back_only_if_authorized(self):
        r = self.go(Policy.HYBRID_PREFERRED,config(n=100000,eve=.2))
        self.assertEqual(r.mode,'PQC_ONLY')
        self.assertNotEqual(r.qkd_status,'ACCEPT')

    def test_10_policy_offer_tampering_rejected(self):
        fn=alter('policy_offer',lambda p:p['body'].__setitem__('policy','PQC_ONLY'))
        with self.assertRaises(ProtocolAbort): self.go(mutator=fn)

    def test_11_policy_ack_tampering_rejected(self):
        fn=alter('policy_ack',lambda p:p['body'].__setitem__('policy','PQC_ONLY'))
        with self.assertRaises(ProtocolAbort): self.go(mutator=fn)

    def test_12_qkd_receipt_tampering_rejected(self):
        fn=alter('qkd_alice',lambda p:p['body'].__setitem__('qkd_status','ACCEPT_UNCHECKED'))
        with self.assertRaises(ProtocolAbort): self.go(mutator=fn)

    def test_13_qkd_ack_tampering_rejected(self):
        fn=alter('qkd_bob',lambda p:p['body'].__setitem__('bound_bits',9999999))
        with self.assertRaises(ProtocolAbort): self.go(mutator=fn)

    def test_14_mode_decision_tampering_rejected(self):
        fn=alter('mode_decision',lambda p:p['body'].__setitem__('mode','PQC_ONLY'))
        with self.assertRaises(ProtocolAbort): self.go(mutator=fn)

    def test_15_mode_ack_tampering_rejected(self):
        fn=alter('mode_agreement',lambda p:p['body'].__setitem__('mode','PQC_ONLY'))
        with self.assertRaises(ProtocolAbort): self.go(mutator=fn)

    def test_16_bob_finished_tampering_rejected(self):
        fn=alter('bob_finished',lambda p:p.__setitem__('mac','AAAA'))
        with self.assertRaises(ProtocolAbort): self.go(mutator=fn)

    def test_17_alice_finished_tampering_rejected(self):
        fn=alter('alice_finished',lambda p:p.__setitem__('mac','AAAA'))
        with self.assertRaises(ProtocolAbort): self.go(mutator=fn)

    def test_18_ciphertext_tampering_rejected(self):
        fn=alter('record',lambda p:p.__setitem__('ciphertext','AAAA'))
        with self.assertRaises(ProtocolAbort): self.go(mutator=fn)

    def test_19_record_sequence_tampering_rejected(self):
        fn=alter('record',lambda p:p.__setitem__('seq',100))
        with self.assertRaises(ProtocolAbort): self.go(mutator=fn)

    def test_20_record_mode_tampering_rejected(self):
        fn=alter('record',lambda p:p.__setitem__('mode','PQC_ONLY'))
        with self.assertRaises(ProtocolAbort): self.go(mutator=fn)

    def test_21_gcm_record_replay_rejected(self):
        key=b'1'*32; prefix=b'1234'; sid='abc'
        receiver=RecordReceiver(key,prefix,sid,'HYBRID','A2B')
        pkt=seal_record(key,prefix,sid,'HYBRID','A2B',0,b'payload')
        self.assertEqual(receiver.open(pkt),b'payload')
        with self.assertRaises(ProtocolAbort): receiver.open(pkt)

    def test_22_record_nonce_tampering_rejected(self):
        key=b'1'*32; prefix=b'1234'; sid='abc'
        receiver=RecordReceiver(key,prefix,sid,'HYBRID','A2B')
        pkt=seal_record(key,prefix,sid,'HYBRID','A2B',0,b'payload')
        pkt['nonce']=base64.b64encode(b'xxxx'+b'\x00'*8).decode()
        with self.assertRaises(ProtocolAbort): receiver.open(pkt)

    def test_23_separate_session_contexts(self):
        r1=self.go(Policy.PQC_ONLY,config(500))
        r2=self.go(Policy.PQC_ONLY,config(500))
        self.assertNotEqual(r1.session_context_hash,r2.session_context_hash)

    def test_24_key_schedule_domain_separated(self):
        pqc=b'k'*32; qkd=b'q'*32;ctx=sha(b'context')
        hybrid=_schedule(pqc,qkd,'HYBRID',ctx)
        plain=_schedule(pqc,None,'PQC_ONLY',ctx)
        self.assertNotEqual(hybrid['A2B_key'],plain['A2B_key'])
        self.assertNotEqual(hybrid['A2B_key'],hybrid['B2A_key'])
        self.assertNotEqual(hybrid['A2B_iv'],hybrid['B2A_iv'])

    def test_25_wrong_qkd_material_causes_key_confirmation_failure(self):
        original = run_with_material
        def corrupt(cfg,seed):
            r, material = original(cfg,seed)
            if material:
                a,b=material
                return r,(a,bytes([b[0]^1])+b[1:])
            return r,material
        with patch('hybrid_protocol.run_with_material', side_effect=corrupt):
            with self.assertRaises(ProtocolAbort): self.go()

    def test_26_handshake_downgrade_rejected(self):
        fn=alter('client_hello',lambda p:p['body'].__setitem__('mode','HYBRID'))
        with self.assertRaises(ProtocolAbort): self.go(handshake_mutator=fn)

    def test_27_unauthenticated_kem_pubkey_rejected(self):
        fn=alter('server_hello',lambda p:p['body'].__setitem__('kem_public_key','AAAA'))
        with self.assertRaises(ProtocolAbort): self.go(handshake_mutator=fn)

    def test_28_invalid_cfg_produces_value_error(self):
        with self.assertRaises(ValueError): config(100,noise=-1)


if __name__=='__main__':
    unittest.main()
