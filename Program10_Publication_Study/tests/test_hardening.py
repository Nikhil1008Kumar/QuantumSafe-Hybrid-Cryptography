"""Program 9 tests: fixed leakage, correction, admitted-key constraints, key schedule."""
import unittest
import numpy as np
from fixed_syndrome import syndrome, leakage_bits, integer_to_bits,bits_to_integer
from finite_key_bb84 import finite_key_bound
from hybrid_protocol import _schedule
from pqc_protocol import OpenSSLBackend, generate_identity
from hardened_independent_protocol import run_session, Abort
from finite_key_bb84 import FiniteKeyConfig
from hybrid_protocol import Policy

class AlgebraTests(unittest.TestCase):
    def test_syndrome_single_errors(self):
        for index in range(31):
            b=np.zeros(31,dtype=np.uint8);b[index]=1
            self.assertEqual(syndrome(b),index+1)
    def test_syndrome_linear(self):
        rng=np.random.default_rng(42)
        for _ in range(20):
            x=rng.integers(0,2,31,dtype=np.uint8)
            y=rng.integers(0,2,31,dtype=np.uint8)
            self.assertEqual(syndrome(x^y),syndrome(x)^syndrome(y))
    def test_syndrome_encoding(self):
        for s in range(32):self.assertEqual(bits_to_integer(integer_to_bits(s)),s)
    def test_fixed_leakage(self):
        self.assertEqual(leakage_bits(31,2),10)
        self.assertEqual(leakage_bits(32,2),20)
        self.assertEqual(leakage_bits(9000,2),2910)
    def test_reject_bad_parameters(self):
        for n,p in [(0,2),(40,0),(-5,3),(40,25)]:
            with self.assertRaises(ValueError):leakage_bits(n,p)
    def test_published_bound_monotone_in_leakage(self):
        inputs=(9000,9000,.04)
        a,_=finite_key_bound(*inputs,2910,1e-10,1e-10)
        b,_=finite_key_bound(*inputs,2910+99,1e-10,1e-10)
        self.assertEqual(a-b,99)
    def test_hybrid_requires_qkd(self):
        with self.assertRaises(Exception):_schedule(bytes(32),None,'HYBRID',bytes(32))
    def test_mode_and_transcript_separation(self):
        pq=bytes(range(32)); q=bytes(range(31,-1,-1)); ctx=bytes(range(32))
        hybrid=_schedule(pq,q,'HYBRID',ctx)
        self.assertNotEqual(hybrid['A2B_key'],hybrid['B2A_key'])
        self.assertNotEqual(hybrid['A2B_key'],_schedule(pq,None,'PQC_ONLY',ctx)['A2B_key'])
        self.assertNotEqual(hybrid['A2B_key'],_schedule(pq,q,'HYBRID',bytes([1])*32)['A2B_key'])
        self.assertNotEqual(hybrid['A2B_key'],_schedule(bytes([42])*32,q,'HYBRID',ctx)['A2B_key'])
        self.assertNotEqual(hybrid['A2B_key'],_schedule(pq,bytes([1])*32,'HYBRID',ctx)['A2B_key'])

class IntegrationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.backend=OpenSSLBackend();cls.backend.__enter__()
        cls.alice=generate_identity(cls.backend,'alice')
        cls.bob=generate_identity(cls.backend,'bob')
    @classmethod
    def tearDownClass(cls):cls.backend.__exit__(None,None,None)
    def cfg(self, signals=50000, noise=0, passes=2, cap=.4):
        n=max(1,round(signals*.18))
        return FiniteKeyConfig(transmitted_signals=signals,target_key_bits=n,
            target_test_bits=n,noise_probability=noise,reconciliation_passes=passes,
            ec_leakage_cap_fraction=cap)
    def test_clean_hybrid_reaches_verified_key(self):
        r=run_session(self.backend,self.alice,self.bob,self.cfg(),21001,Policy.HYBRID_REQUIRED)
        self.assertEqual(r.mode,'HYBRID');self.assertTrue(r.encrypted_record_ok)
        self.assertTrue(r.agreement);self.assertEqual(r.ec_queries,0)
        self.assertEqual(r.public_ec_bits,2910)
    def test_short_key_requires_abort(self):
        r=run_session(self.backend,self.alice,self.bob,self.cfg(signals=500),21002,Policy.HYBRID_REQUIRED)
        self.assertEqual(r.mode,'ABORT')
    def test_noise_prefers_fallback_if_uncorrectable(self):
        r=run_session(self.backend,self.alice,self.bob,self.cfg(noise=.03),21003,Policy.HYBRID_PREFERRED)
        self.assertEqual(r.mode,'PQC_ONLY');self.assertTrue(r.encrypted_record_ok)
    def test_predeclared_leakage_cap_is_enforced(self):
        r=run_session(self.backend,self.alice,self.bob,self.cfg(cap=.1),21004,Policy.HYBRID_REQUIRED)
        self.assertEqual(r.mode,'ABORT');self.assertEqual(r.qkd_status,'ABORT_EC_BUDGET')
    def test_modified_syndrome_signature_rejected(self):
        seen={'changed':False}
        def tamper(kind,env):
            if kind=='ec_syndrome_a':
                env['body']['payload']['pass']=999
                seen['changed']=True
            return env
        with self.assertRaises(Exception):
            run_session(self.backend,self.alice,self.bob,self.cfg(),21005,Policy.HYBRID_PREFERRED,mutator=tamper)
        self.assertTrue(seen['changed'])

if __name__=='__main__': unittest.main()
