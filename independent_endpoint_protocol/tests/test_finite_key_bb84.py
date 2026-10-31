"""Regression + invariant tests for the finite-key BB84 research simulation."""
import math
from pathlib import Path
import sys
import unittest
import numpy as np
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from finite_key_bb84 import (
    FiniteKeyConfig, finite_mu, finite_key_bound, h2, transmit,
    cascade_reconcile, toeplitz_hash, run,
)


class FiniteKeyTests(unittest.TestCase):
    def test_entropy_values(self):
        self.assertEqual(h2(0),0.0)
        self.assertEqual(h2(1),0.0)
        self.assertAlmostEqual(h2(0.5),1.0)
        with self.assertRaises(ValueError):
            h2(-.01)

    def test_theorem_equation_numerical(self):
        n,k=20000,20000
        qtol=.035
        leakage=1200
        e1,e2=1e-10,1e-10
        mu=math.sqrt((n+k)*(k+1)*math.log(2/e1)/(n*k*k))
        predicted=math.floor(n*(1-h2(qtol+mu))-leakage-math.log2(2/(e1**2*e2)))
        observed, deviation=finite_key_bound(n,k,qtol,leakage,e1,e2)
        self.assertEqual(observed,predicted)
        self.assertAlmostEqual(deviation,mu)

    def test_small_blocks_not_automatically_secure(self):
        keylen,mu=finite_key_bound(80,80,.035,0,1e-10,1e-10)
        self.assertEqual(keylen,0)
        self.assertGreater(mu,.5)

    def test_more_ec_disclosure_never_increases_bound(self):
        a,_=finite_key_bound(25000,25000,.03,500,1e-10,1e-10)
        b,_=finite_key_bound(25000,25000,.03,1500,1e-10,1e-10)
        self.assertGreaterEqual(a,b)

    def test_toeplitz_matches_exact_binary_multiplication(self):
        rng=np.random.default_rng(9)
        for n in (1,2,7,29,73):
            for m in (1,3,8,21):
                bits=rng.integers(0,2,n,dtype=np.uint8)
                seed=rng.integers(0,2,n+m-1,dtype=np.uint8)
                got=toeplitz_hash(bits,seed,m)
                expected=np.asarray([
                    sum(int(seed[n-1+i-j])*int(bits[j]) for j in range(n))%2
                    for i in range(m)],dtype=np.uint8)
                np.testing.assert_array_equal(got,expected)

    def test_toeplitz_is_linear_over_gf2(self):
        rng=np.random.default_rng(4)
        n,m=511,128
        a=rng.integers(0,2,n,dtype=np.uint8)
        b=rng.integers(0,2,n,dtype=np.uint8)
        public=rng.integers(0,2,n+m-1,dtype=np.uint8)
        lhs=toeplitz_hash(a ^ b,public,m)
        rhs=toeplitz_hash(a,public,m) ^ toeplitz_hash(b,public,m)
        np.testing.assert_array_equal(lhs,rhs)

    def test_cascade_zero_errors(self):
        rng=np.random.default_rng(100)
        x=rng.integers(0,2,2048,dtype=np.uint8)
        result=cascade_reconcile(x,x,rng,passes=4,initial_block_size=16)
        np.testing.assert_array_equal(x,result.bob_corrected)
        self.assertGreater(result.leakage_bits,0)
        self.assertEqual(result.leakage_bits % 2,0)
        self.assertEqual(result.flipped_bits,0)

    def test_cascade_handplaced_errors_corrected(self):
        rng=np.random.default_rng(111)
        x=rng.integers(0,2,2048,dtype=np.uint8)
        y=x.copy()
        y[[37,100,1001,1555]]^=1
        result=cascade_reconcile(x,y,np.random.default_rng(5),passes=6,initial_block_size=30)
        np.testing.assert_array_equal(x,result.bob_corrected)
        self.assertGreaterEqual(result.flipped_bits,4)

    def test_no_noise_session_accepts_if_resources_sufficient(self):
        config=FiniteKeyConfig(transmitted_signals=60000,target_key_bits=10000,
            target_test_bits=10000,q_tolerance=.035)
        r=run(config,seed=198)
        self.assertEqual(r.status,'ACCEPT')
        self.assertEqual(r.x_errors,0)
        self.assertEqual(r.true_z_errors_after_ec,0)
        self.assertTrue(r.verification_passed)
        self.assertTrue(r.final_keys_match_diagnostic)
        self.assertEqual(r.final_bits,256)
        self.assertGreaterEqual(r.finite_bound_bits,256)
        self.assertLessEqual(r.ec_public_bits,r.ec_leakage_budget_bits)

    def test_eve_detected_with_high_interception(self):
        config=FiniteKeyConfig(transmitted_signals=60000,target_key_bits=10000,
            target_test_bits=10000,intercept_probability=.6,q_tolerance=.04)
        r=run(config,seed=44)
        self.assertEqual(r.status,'ABORT_PARAMETER_ESTIMATION')
        self.assertEqual(r.final_bits,0)

    def test_abort_when_not_enough_detections(self):
        config=FiniteKeyConfig(transmitted_signals=1000,target_key_bits=700,
            target_test_bits=700)
        r=run(config,seed=5)
        self.assertEqual(r.status,'ABORT_INSUFFICIENT_DETECTIONS')
        self.assertEqual(r.final_bits,0)

    def test_small_sample_rejects_even_if_zero_qber(self):
        config=FiniteKeyConfig(transmitted_signals=500,target_key_bits=70,
            target_test_bits=70,q_tolerance=.035)
        r=run(config,seed=17)
        self.assertEqual(r.status,'ABORT_INSUFFICIENT_FINITE_KEY')
        self.assertEqual(r.x_qber,0)
        self.assertEqual(r.final_bits,0)

    def test_reproducibility_except_runtime(self):
        cfg=FiniteKeyConfig(transmitted_signals=15000,target_key_bits=2500,
            target_test_bits=2500,noise_probability=.008,q_tolerance=.035)
        a=run(cfg,24)
        b=run(cfg,24)
        for k in a.__dataclass_fields__:
            if k == 'runtime_ms':
                continue
            va,vb=getattr(a,k),getattr(b,k)
            if isinstance(va,float) and math.isnan(va) and math.isnan(vb):
                continue
            self.assertEqual(va,vb,k)

    def test_ec_disclosure_budget_enforced(self):
        config=FiniteKeyConfig(transmitted_signals=60000,target_key_bits=10000,
            target_test_bits=10000,noise_probability=.03,q_tolerance=.04,
            ec_leakage_cap_fraction=.02)
        r=run(config,seed=100)
        self.assertEqual(r.status,'ABORT_EC_LEAKAGE_BUDGET')
        self.assertGreater(r.ec_public_bits,r.ec_leakage_budget_bits)

    def test_verification_rejects_unreconciled_errors(self):
        cfg=FiniteKeyConfig(transmitted_signals=20000,
            target_key_bits=3000,target_test_bits=3000,
            noise_probability=.04,q_tolerance=.20,
            reconciliation_passes=1,reconciliation_block_size=200,
            ec_leakage_cap_fraction=1)
        r=run(cfg,seed=44)
        self.assertEqual(r.status,'ABORT_KEY_VERIFICATION')
        self.assertGreater(r.true_z_errors_after_ec,0)
        self.assertFalse(r.verification_passed)
        self.assertEqual(r.final_bits,0)

    def test_loss_can_prevent_predeclared_quota(self):
        cfg=FiniteKeyConfig(transmitted_signals=10000,target_key_bits=1500,
            target_test_bits=1500,loss_probability=.8)
        r=run(cfg,seed=81)
        self.assertEqual(r.status,'ABORT_INSUFFICIENT_DETECTIONS')
        self.assertEqual(r.final_bits,0)

    def test_qber_under_tolerance_can_still_abort_due_to_leakage(self):
        cfg=FiniteKeyConfig(transmitted_signals=100000,
            target_key_bits=18000,target_test_bits=18000,
            intercept_probability=.10,q_tolerance=.04)
        r=run(cfg,seed=2026)
        self.assertLess(r.x_qber,cfg.q_tolerance)
        self.assertEqual(r.status,'ABORT_EC_LEAKAGE_BUDGET')
        self.assertEqual(r.final_bits,0)

    def test_bad_configs_rejected(self):
        for kwargs in (dict(q_tolerance=.5),dict(p_z=0),
                       dict(eps_secrecy=1),dict(target_key_bits=0),
                       dict(reconciliation_passes=0)):
            with self.assertRaises(ValueError):
                FiniteKeyConfig(**kwargs)

    def test_empirical_x_error_matches_theory(self):
        cfg=FiniteKeyConfig(transmitted_signals=100000,target_key_bits=15000,
            target_test_bits=15000,intercept_probability=.2,noise_probability=.01)
        tx=transmit(cfg,np.random.default_rng(72))
        expected=.01+(1-2*.01)*(.2/4)
        self.assertLess(abs(np.mean(tx.x_alice[:15000]!=tx.x_bob[:15000])-expected),.012)


if __name__=='__main__':
    unittest.main()
