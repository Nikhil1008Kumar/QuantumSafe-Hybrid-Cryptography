import copy
import unittest
import numpy as np
from authenticated_bb84 import (AuthenticatedClassicalChannel,ChannelAbort,
  Stage, pack_bits,read_bits, quantum_simulation,run_authenticated_bb84,run_session)
from finite_key_bb84 import FiniteKeyConfig
from hybrid_protocol import Policy
from pqc_protocol import OpenSSLBackend,generate_identity,ProtocolAbort


class TestBitEncoding(unittest.TestCase):
    def test_roundtrip_non_byte_aligned(self):
        for n in (0,1,5,8,9,101):
            bits=(np.arange(n)%2).astype(np.uint8)
            self.assertTrue(np.array_equal(read_bits(pack_bits(bits),n),bits))
    def test_reject_trailing_ones(self):
        from pqc_protocol import b64
        with self.assertRaises(ChannelAbort): read_bits(b64(b'\xff'),1)
    def test_reject_wrong_length(self):
        from pqc_protocol import b64
        with self.assertRaises(ChannelAbort): read_bits(b64(b'\x00\x00'),1)
    def test_model_qber(self):
        cfg=FiniteKeyConfig(transmitted_signals=100_000,intercept_probability=.2,
            target_key_bits=9000,target_test_bits=9000)
        q=quantum_simulation(cfg,400)
        mask=(q.detected==1)&(q.alice_bases==q.bob_bases)
        rate=np.mean(q.alice_bits[mask]!=q.bob_bits[mask])
        self.assertLess(abs(rate-.05),.008)


class TestSignatureStateMachine(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.b=OpenSSLBackend().__enter__()
        cls.a=generate_identity(cls.b,'Alice')
        cls.c=generate_identity(cls.b,'Bob')
    @classmethod
    def tearDownClass(cls): cls.b.__exit__(None,None,None)

    def channel(self,**kwargs):
        return AuthenticatedClassicalChannel(self.b,self.a,self.c,'9'*64,**kwargs)
    def test_wrong_role_rejected(self):
        with self.assertRaises(ChannelAbort):
            self.channel().send('bob','policy_offer',{'policy':'HYBRID_PREFERRED'})
    def test_wrong_state_rejected(self):
        with self.assertRaises(ChannelAbort):
            self.channel().send('alice','alice_basis',{'data':'x'})
    def test_wrong_message_order_rejected(self):
        with self.assertRaises(ChannelAbort):
            self.channel().send('bob','policy_ack',{'data':'x'})
    def test_replayed_session_nonce_rejected(self):
        sid='ab'*16
        a=self.channel(session_id=sid)
        with self.assertRaises(ChannelAbort): self.channel(session_id=sid)
    def test_terminal_state_rejected(self):
        c=self.channel(); c.stage=Stage.FINISHED
        with self.assertRaises(ChannelAbort): c.send('alice','policy_offer',{})
    def test_modified_envelope_rejected(self):
        def attack(stage,env):
            env['body']['payload']['policy']='FAKE'
            return env
        with self.assertRaises(ProtocolAbort):
            self.channel(mutator=attack).send('alice','policy_offer',{'policy':'HYBRID_REQUIRED'})
    def test_signed_policy_turn_order(self):
        c=self.channel()
        c.send('alice','policy_offer',{'policy':'PQC_ONLY'})
        c.send('bob','policy_ack',{'policy':'PQC_ONLY'})
        self.assertEqual(c.next_seq,{'alice':1,'bob':1})
        self.assertEqual(len(c.frames),2)


class TestIntegratedAuthenticatedBB84(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.b=OpenSSLBackend().__enter__()
        cls.a=generate_identity(cls.b,'Alice')
        cls.c=generate_identity(cls.b,'Bob')
        cls.good=FiniteKeyConfig(transmitted_signals=50_000,target_key_bits=9000,
             target_test_bits=9000,q_tolerance=.04)
        cls.short=FiniteKeyConfig(transmitted_signals=500,target_key_bits=90,
             target_test_bits=90,q_tolerance=.04)
    @classmethod
    def tearDownClass(cls): cls.b.__exit__(None,None,None)
    def execute(self,cfg=None,policy=Policy.HYBRID_PREFERRED,attack=None,seed=50):
        return run_session(self.b,self.a,self.c,cfg or self.good,seed,policy,mutator=attack)
    def test_clean_hybrid(self):
        r=self.execute()
        self.assertEqual(r.mode,'HYBRID')
        self.assertEqual(r.qkd_status,'ACCEPT')
        self.assertTrue(r.key_confirmation_ok and r.recovered_ok)
        self.assertGreater(r.classical_frames,12)
    def test_short_fallback(self):
        r=self.execute(self.short)
        self.assertEqual(r.mode,'PQC_ONLY')
        self.assertTrue(r.recovered_ok)
    def test_short_required_abort(self):
        r=self.execute(self.short,Policy.HYBRID_REQUIRED)
        self.assertEqual(r.mode,'ABORT')
        self.assertFalse(r.recovered_ok)
    def test_pqc_only_does_not_run_qkd(self):
        r=self.execute(self.good,Policy.PQC_ONLY)
        self.assertEqual((r.mode,r.qkd_status),('PQC_ONLY','NOT_RUN'))
    def test_noise_fallback(self):
        cfg=FiniteKeyConfig(transmitted_signals=50000,target_key_bits=9000,
            target_test_bits=9000,noise_probability=.03,q_tolerance=.04)
        r=self.execute(cfg)
        self.assertEqual(r.mode,'PQC_ONLY')
    def test_intercept_resend_aborts_required(self):
        cfg=FiniteKeyConfig(transmitted_signals=50000,target_key_bits=9000,
            target_test_bits=9000,intercept_probability=.4,q_tolerance=.04)
        r=self.execute(cfg,Policy.HYBRID_REQUIRED)
        self.assertEqual(r.mode,'ABORT')
    def test_plaintext_not_logged(self):
        marker=b'NOT-TO-APPEAR-IN-CSV'
        r=run_session(self.b,self.a,self.c,self.good,55,Policy.HYBRID_PREFERRED,payload=marker)
        self.assertNotIn('NOT-TO-APPEAR-IN-CSV',str(r))
    def test_wrong_initial_stage(self):
        c=AuthenticatedClassicalChannel(self.b,self.a,self.c,'8'*64)
        with self.assertRaises(ChannelAbort): run_authenticated_bb84(c,self.good,56)

    def test_tamper_every_classical_stage(self):
        stages=('policy_offer','policy_ack','bob_detected','bob_basis','alice_basis',
                'sampling_seed','alice_test_bits','bob_test_bits','ec_seed','ec_batch',
                'verification_seed','alice_verification_tag','bob_verification_tag',
                'privacy_amplification_seed','qkd_report_alice','qkd_report_bob',
                'mode_decision','mode_ack')
        for stage in stages:
            with self.subTest(stage=stage):
                used=[]
                def attack(kind,envelope):
                    if kind==stage:
                        used.append(kind)
                        envelope['body']['payload']['ATTACK']='modified'
                    return envelope
                with self.assertRaises(ProtocolAbort):
                    self.execute(attack=attack)
                self.assertTrue(used,'Attack stage was never reached')

    def test_replay_prior_signed_frame(self):
        captured={}
        def store(stage,envelope):
            if stage=='bob_basis' and 'old' not in captured:
                captured['old']=copy.deepcopy(envelope)
            return envelope
        self.execute(attack=store,seed=94)
        def replay(stage,envelope):
            return copy.deepcopy(captured['old']) if stage=='bob_basis' else envelope
        with self.assertRaises(ProtocolAbort): self.execute(attack=replay,seed=95)


if __name__=='__main__': unittest.main()
