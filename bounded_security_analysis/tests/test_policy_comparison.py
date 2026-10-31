import unittest
from dataclasses import replace
from policy_comparison import (Strategy, Mode, VerifiedContext, QKDObservation,
                               decide, mutate_context)
from hybrid_protocol import Policy

ADMITTED = QKDObservation('ACCEPT', .01, 3000, 729, 256, True, 100, 1800)
SHORT = QKDObservation('ABORT_INSUFFICIENT_FINITE_KEY', .0, 100, 0, 0, True, 20, 40)
HIGH_NOISE = QKDObservation('ABORT_EC_LEAKAGE_BUDGET', .03, 3000, 729, 0, True, 2000, 1800)
HIGH_QBER = QKDObservation('ABORT_PARAMETER_ESTIMATION', .15, 3000, 0, 0, False, 0, 0)

class TestPolicyComparison(unittest.TestCase):
    def test_accepted_hybrid_is_selected(self):
        for policy in [Policy.HYBRID_REQUIRED, Policy.HYBRID_PREFERRED]:
            self.assertEqual(decide(Strategy.PROPOSED, policy, ADMITTED).mode, Mode.HYBRID)
    def test_qber_only_wrong_for_short(self):
        d=decide(Strategy.QBER_ONLY, Policy.HYBRID_PREFERRED, SHORT)
        self.assertEqual(d.mode, Mode.HYBRID)
        self.assertTrue(d.model_invalid_hybrid)
    def test_qber_only_wrong_when_ec_overbudget(self):
        self.assertTrue(decide(Strategy.QBER_ONLY, Policy.HYBRID_REQUIRED, HIGH_NOISE).model_invalid_hybrid)
    def test_proposed_fallback_short(self):
        d=decide(Strategy.PROPOSED, Policy.HYBRID_PREFERRED, SHORT)
        self.assertEqual(d.mode, Mode.PQC_ONLY)
        self.assertFalse(d.model_invalid_hybrid)
    def test_required_never_downgrades(self):
        for evidence in [SHORT,HIGH_NOISE,HIGH_QBER]:
            self.assertEqual(decide(Strategy.PROPOSED, Policy.HYBRID_REQUIRED,evidence).mode,Mode.ABORT)
    def test_pqc_only(self):
        for strategy in Strategy:
            self.assertEqual(decide(strategy,Policy.PQC_ONLY,None).mode,Mode.PQC_ONLY)
    def test_baseline_respects_required(self):
        self.assertEqual(decide(Strategy.PQC_ONLY,Policy.HYBRID_REQUIRED,ADMITTED).mode,Mode.ABORT)
    def test_no_fallback(self):
        self.assertEqual(decide(Strategy.FINITE_NO_FALLBACK,Policy.HYBRID_PREFERRED,SHORT).mode,Mode.ABORT)
    def test_model_certification_requires_256_bits(self):
        self.assertFalse(replace(ADMITTED,output_bits=128).finite_key_admitted)
    def test_model_certification_requires_correctness(self):
        self.assertFalse(replace(ADMITTED,key_verification_passed=False).finite_key_admitted)
    def test_model_certification_requires_ec_budget(self):
        self.assertFalse(replace(ADMITTED,ec_leakage_bits=2000).finite_key_admitted)
    def test_model_certification_requires_status(self):
        self.assertFalse(replace(ADMITTED,status='ABORT').finite_key_admitted)
    def test_model_certification_requires_positive_sample(self):
        self.assertFalse(replace(ADMITTED,x_bits=0).finite_key_admitted)
    def test_nan_qber_fails_baseline(self):
        self.assertFalse(replace(ADMITTED,x_qber=float('nan')).qber11_admitted)
    def test_missing_qkd_receipt_aborts(self):
        for strategy in Strategy:
            self.assertEqual(decide(strategy,Policy.HYBRID_PREFERRED,None).mode,Mode.ABORT)
    def test_all_preconditions_abort_for_all_policies(self):
        base=VerifiedContext()
        for fld in base.__dataclass_fields__:
            for pol in Policy:
                for strategy in Strategy:
                    d=decide(strategy,pol,ADMITTED,mutate_context(base,fld))
                    self.assertEqual(d.mode,Mode.ABORT,f'{fld}: {pol}, {strategy}')
    def test_invalid_precondition_name_raises(self):
        with self.assertRaises(ValueError): mutate_context(VerifiedContext(),'bad')
    def test_bad_policy_type_raises(self):
        with self.assertRaises(TypeError): decide(Strategy.PROPOSED,'HYBRID_REQUIRED',ADMITTED)
    def test_qber_boundary(self):
        self.assertTrue(replace(ADMITTED,x_qber=.11).qber11_admitted)
        self.assertFalse(replace(ADMITTED,x_qber=.110001).qber11_admitted)
    def test_outcomes_invariants(self):
        for qkd in [ADMITTED,SHORT,HIGH_NOISE,HIGH_QBER]:
            for pol in Policy:
                d=decide(Strategy.PROPOSED,pol,qkd)
                self.assertFalse(d.model_invalid_hybrid)
                if d.mode is Mode.HYBRID: self.assertTrue(qkd.finite_key_admitted)
                if d.mode is Mode.PQC_ONLY: self.assertNotEqual(pol, Policy.HYBRID_REQUIRED)

if __name__=='__main__': unittest.main()
