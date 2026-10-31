"""Program 7 protocol tests. Existing Program 2–6 regression suite included."""
import copy
import unittest
import numpy as np
from pqc_protocol import OpenSSLBackend, generate_identity, sign_envelope, ProtocolAbort
from hybrid_protocol import Policy
from finite_key_bb84 import FiniteKeyConfig
from independent_protocol import (Abort,Endpoint,Relay,InteractiveEC,run_session,
                                  kbits)

class IndependentEndpointTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.cm=OpenSSLBackend()
        cls.backend=cls.cm.__enter__()
        cls.alice=generate_identity(cls.backend,'alice')
        cls.bob=generate_identity(cls.backend,'bob')

    @classmethod
    def tearDownClass(cls):
        cls.cm.__exit__(None,None,None)

    def setup_relay(self,policy=Policy.PQC_ONLY):
        a=Endpoint('alice',self.alice,self.bob,np.zeros(100,dtype=np.uint8),np.zeros(100,dtype=np.uint8),None,
                   'f'*64,'12'*16,self.backend)
        b=Endpoint('bob',self.bob,self.alice,np.zeros(100,dtype=np.uint8),np.zeros(100,dtype=np.uint8),
                   np.ones(100,dtype=np.uint8),'f'*64,'12'*16,self.backend)
        a.policy=b.policy=policy
        return Relay(a,b)

    def test_honest_policy_signed_and_bound(self):
        relay=self.setup_relay()
        relay.send('policy_a',{'policy':'PQC_ONLY'})
        relay.send('policy_b',{'policy':'PQC_ONLY'})
        self.assertEqual(relay.alice.last_hash,relay.bob.last_hash)
        self.assertEqual(relay.frames,2)

    def test_out_of_order_rejected_before_signing(self):
        relay=self.setup_relay()
        with self.assertRaises(Abort):
            relay.send('policy_b',{'policy':'PQC_ONLY'})

    def test_wrong_legitimate_role_rejected(self):
        relay=self.setup_relay()
        with self.assertRaises(Abort):
            relay.alice.construct('policy_b',{'policy':'PQC_ONLY'})

    def test_downgrade_policy_detected(self):
        relay=self.setup_relay(Policy.HYBRID_REQUIRED)
        with self.assertRaises(Abort):
            relay.send('policy_a',{'policy':'PQC_ONLY'})

    def test_tampered_signed_body_rejected(self):
        relay=self.setup_relay()
        def mutate(kind,envelope):
            envelope['body']['payload']['policy']='HYBRID_REQUIRED'
            return envelope
        relay.mutator=mutate
        with self.assertRaises(ProtocolAbort):
            relay.send('policy_a',{'policy':'PQC_ONLY'})
        self.assertEqual(relay.frames,0)

    def test_signature_corruption_rejected(self):
        relay=self.setup_relay()
        def mutate(kind,envelope):
            envelope['signature']='AA=='
            return envelope
        relay.mutator=mutate
        with self.assertRaises(ProtocolAbort):
            relay.send('policy_a',{'policy':'PQC_ONLY'})

    def test_cross_session_replay_rejected(self):
        relay=self.setup_relay()
        good=relay.alice.construct('policy_a',{'policy':'PQC_ONLY'})
        second=self.setup_relay()
        second.bob.sid='34'*16
        with self.assertRaises(Abort):
            second.bob.receive(good,'policy_a')

    def test_duplicate_sequence_replay_rejected(self):
        relay=self.setup_relay()
        envelope=relay.alice.construct('policy_a',{'policy':'PQC_ONLY'})
        relay.send('policy_a',{'policy':'PQC_ONLY'})
        with self.assertRaises(Abort):
            relay.bob.receive(envelope,'policy_a')

    def test_forged_bob_signature_by_alice_rejected(self):
        relay=self.setup_relay()
        m={'version':'research-independent-bb84-v1','session':'12'*16,
           'context':'f'*64,'kind':'policy_b','from':'bob','to':'alice',
           'seq':0,'previous':'0'*64,'payload':{'policy':'PQC_ONLY'}}
        env=sign_envelope(self.backend,self.alice.signing_private,m)
        with self.assertRaises(ProtocolAbort):
            relay.alice.receive(env,'policy_b')

    def test_both_endpoint_states_advance(self):
        relay=self.setup_relay()
        relay.send('policy_a',{'policy':'PQC_ONLY'})
        self.assertEqual(relay.alice.flow,'policy_b')
        self.assertEqual(relay.bob.flow,'policy_b')
        relay.send('policy_b',{'policy':'PQC_ONLY'})
        self.assertEqual(relay.alice.flow,'report_a')

    def test_ec_positions_reject_malformed_path(self):
        relay=self.setup_relay()
        ec=InteractiveEC(relay,100,123,passes=2)
        for label in ([0,0,'LRXXXX'],[-1,0,''],[5,0,''],[0,999,''],[0,0,12]):
            with self.assertRaises(Abort):ec.positions(label)

    def test_ec_independent_corrects_single_error(self):
        relay=self.setup_relay(Policy.HYBRID_PREFERRED)
        a,b=relay.alice,relay.bob
        a.raw=np.zeros(100,dtype=np.uint8)
        b.raw=np.zeros(100,dtype=np.uint8)
        b.raw[41]=1
        # Move through expected initial policy and basis/test stages via proper
        # authentic messages, but no raw material crosses the relay.
        relay.send('policy_a',{'policy':Policy.HYBRID_PREFERRED.value})
        relay.send('policy_b',{'policy':Policy.HYBRID_PREFERRED.value})
        for kind in ['detect_b','basis_b','basis_a']:
            relay.send(kind,{'index':0,'chunks':1,'n':0,'bits':''})
        relay.send('sample_a',{'seed':1})
        relay.send('test_a',{'n':0,'bits':''})
        relay.send('test_b',{'n':0,'bits':''})
        relay.send('ec_seed_a',{'seed':123})
        ec=InteractiveEC(relay,100,123,passes=3,block_size=16)
        leaked,queries,flips=ec.reconcile()
        self.assertGreater(queries,0)
        self.assertGreaterEqual(flips,1)
        self.assertEqual(leaked,queries*2)
        self.assertTrue(np.array_equal(a.raw,b.raw))

    def test_clean_large_session_accepted(self):
        cfg=FiniteKeyConfig()
        result=run_session(self.backend,self.alice,self.bob,cfg,2026,Policy.HYBRID_REQUIRED)
        self.assertEqual(result.mode,'HYBRID')
        self.assertEqual(result.qkd_status,'MODEL_ACCEPT')
        self.assertTrue(result.agreement)
        self.assertTrue(result.encrypted_record_ok)
        self.assertGreater(result.ec_queries,0)

    def test_clean_short_required_aborts(self):
        cfg=FiniteKeyConfig(transmitted_signals=1000,target_key_bits=100,target_test_bits=100)
        result=run_session(self.backend,self.alice,self.bob,cfg,2026,Policy.HYBRID_REQUIRED)
        self.assertEqual(result.mode,'ABORT')
        self.assertFalse(result.encrypted_record_ok)

    def test_clean_short_preferred_fallback(self):
        cfg=FiniteKeyConfig(transmitted_signals=1000,target_key_bits=100,target_test_bits=100)
        result=run_session(self.backend,self.alice,self.bob,cfg,2026,Policy.HYBRID_PREFERRED)
        self.assertEqual(result.mode,'PQC_ONLY')
        self.assertTrue(result.encrypted_record_ok)

    def test_eve_parameter_estimation_abort(self):
        cfg=FiniteKeyConfig(intercept_probability=.2)
        result=run_session(self.backend,self.alice,self.bob,cfg,2026,Policy.HYBRID_REQUIRED)
        self.assertEqual(result.mode,'ABORT')
        self.assertEqual(result.qkd_status,'ABORT_PARAMETER_ESTIMATION')

    def test_noise_interactive_correction(self):
        cfg=FiniteKeyConfig(transmitted_signals=12000,target_key_bits=2000,target_test_bits=2000,
                            noise_probability=.01)
        result=run_session(self.backend,self.alice,self.bob,cfg,319,Policy.HYBRID_PREFERRED)
        self.assertGreater(result.ec_flips,0)
        self.assertGreater(result.ec_rounds,0)

    def test_pqc_only_no_parity_exchange(self):
        cfg=FiniteKeyConfig()
        result=run_session(self.backend,self.alice,self.bob,cfg,2026,Policy.PQC_ONLY)
        self.assertEqual(result.mode,'PQC_ONLY')
        self.assertEqual(result.ec_queries,0)
        self.assertTrue(result.encrypted_record_ok)

    def test_reused_session_id_rejected(self):
        cfg=FiniteKeyConfig(transmitted_signals=1000,target_key_bits=100,target_test_bits=100)
        sid='be'*16
        run_session(self.backend,self.alice,self.bob,cfg,123,Policy.PQC_ONLY,sid=sid)
        with self.assertRaises(Abort):
            run_session(self.backend,self.alice,self.bob,cfg,123,Policy.PQC_ONLY,sid=sid)

    def test_attacker_modifies_basis_rejected(self):
        cfg=FiniteKeyConfig(transmitted_signals=1000,target_key_bits=100,target_test_bits=100)
        def mutate(kind,env):
            if kind=='basis_a':env['body']['payload']['bits']='AA=='
            return env
        with self.assertRaises(ProtocolAbort):
            run_session(self.backend,self.alice,self.bob,cfg,123,Policy.HYBRID_PREFERRED,mutator=mutate)

    def test_attacker_modifies_parity_answer_rejected(self):
        cfg=FiniteKeyConfig(transmitted_signals=1000,target_key_bits=100,target_test_bits=100)
        def mutate(kind,env):
            if kind=='parity_answer':env['body']['payload']['parities']=[0]
            return env
        with self.assertRaises(ProtocolAbort):
            run_session(self.backend,self.alice,self.bob,cfg,123,Policy.HYBRID_PREFERRED,mutator=mutate)

if __name__=='__main__':unittest.main()
