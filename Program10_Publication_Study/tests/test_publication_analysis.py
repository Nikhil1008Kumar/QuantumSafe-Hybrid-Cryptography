"""Program 10 regression tests (no external network, no secret keys logged)."""
import math
import unittest
from publication_analysis import (
    SCENARIOS,POLICIES,STRATEGIES,Scenario, trial_seed, expected_qber,
    wilson,paired_bootstrap_difference,simulate,summarize_qkd,
    summarize_decisions,paired_strategy_contrasts,model_config,
)
from run_experiments import integration_summary

class TestPublicationAnalysis(unittest.TestCase):
    def test_01_distinct_scenarios(self):
        self.assertEqual(len(SCENARIOS),10)
        self.assertEqual(len(set(s.name for s in SCENARIOS)),len(SCENARIOS))

    def test_02_trial_seeds_deterministic(self):
        self.assertEqual(trial_seed(101,'clean',3),trial_seed(101,'clean',3))
        self.assertNotEqual(trial_seed(101,'clean',3),trial_seed(101,'noise',3))
        self.assertNotEqual(trial_seed(101,'clean',3),trial_seed(101,'clean',4))

    def test_03_invalid_seed(self):
        for args in ((-1,'case',0),(1,'',0),(1,'case',-1)):
            with self.assertRaises(ValueError):trial_seed(*args)

    def test_04_qber_theory(self):
        self.assertAlmostEqual(expected_qber(.6,0),.15)
        self.assertAlmostEqual(expected_qber(.4,.02),.116)
        with self.assertRaises(ValueError):expected_qber(-.1,0)

    def test_05_wilson_zero_one(self):
        a,b=wilson(0,100)
        self.assertEqual(a,0)
        self.assertLess(b,.04)
        c,d=wilson(100,100)
        self.assertEqual(d,1)
        self.assertGreater(c,.96)

    def test_06_wilson_half(self):
        a,b=wilson(50,100)
        self.assertLess(a,.5)
        self.assertGreater(b,.5)

    def test_07_wilson_rejects_invalid(self):
        for args in ((-1,10),(11,10),(0,0),(1,1.2)):
            with self.assertRaises(ValueError):wilson(*args)

    def test_08_bootstrap_paired_deterministic(self):
        x=[1,0,1,1,0];y=[0,0,1,0,0]
        a=paired_bootstrap_difference(x,y,seed=23,draws=100)
        self.assertEqual(a,paired_bootstrap_difference(x,y,seed=23,draws=100))
        self.assertAlmostEqual(a[0],.4)
        self.assertLessEqual(a[1],a[0])
        self.assertLessEqual(a[0],a[2])

    def test_09_bootstrap_rejects_mismatch(self):
        with self.assertRaises(ValueError):paired_bootstrap_difference([1],[1,0])

    def test_10_parameter_configuration(self):
        cfg=model_config(Scenario('t',50_000,noise=.01))
        self.assertEqual(cfg.target_key_bits,9000)
        self.assertEqual(cfg.target_test_bits,9000)
        self.assertEqual(cfg.reconciliation_passes,2)

    def test_11_trial_fields_and_replay(self):
        scenario=Scenario('testcase',500)
        r,d=simulate(scenario,0)
        r2,d2=simulate(scenario,0)
        for field in ('seed','qkd_status','qkd_model_admitted','qber_only_admitted'):
            self.assertEqual(r[field],r2[field])
        self.assertEqual(d,d2)
        self.assertEqual(len(d),len(POLICIES)*len(STRATEGIES))
        self.assertNotIn('secret_key',r)

    def test_12_short_key_not_admitted(self):
        r,d=simulate(Scenario('short_test',500),0)
        self.assertEqual(r['qkd_model_admitted'],0)
        row=next(x for x in d if x['policy']=='HYBRID_REQUIRED' and x['strategy']=='FINITE_KEY_POLICY')
        self.assertEqual(row['mode'],'ABORT')

    def test_13_qkd_and_decision_summaries(self):
        c=next(s for s in SCENARIOS if s.name=='clean_50000')
        raw,dec=[],[]
        for rep in range(3):
            r,d=simulate(c,rep)
            raw.append(r);dec+=d
        s=summarize_qkd(raw)
        self.assertEqual(len(s),1)
        self.assertEqual(s[0]['n_trials'],3)
        x=summarize_decisions(dec)
        self.assertEqual(len(x),len(POLICIES)*len(STRATEGIES))
        self.assertTrue(all(v['n_trials']==3 for v in x))

    def test_14_proposed_never_invalid_under_model(self):
        for case in (SCENARIOS[0],SCENARIOS[2],SCENARIOS[5]):
            for rep in (0,1):
                _,dec=simulate(case,rep)
                self.assertTrue(all(x['in_model_invalid_hybrid']==0 for x in dec if x['strategy']=='FINITE_KEY_POLICY'))

    def test_15_paired_contrasts_keys(self):
        case=SCENARIOS[0]
        dec=[]
        for rep in range(4):dec+=simulate(case,rep)[1]
        contrasts=paired_strategy_contrasts(dec,draws=60)
        self.assertEqual(len(contrasts),len(POLICIES)*3)
        self.assertTrue(all(x['paired_n']==4 for x in contrasts))

    def test_16_integration_summary_empty(self):
        self.assertEqual(integration_summary([]),[])

    def test_17_no_qber_sample_is_not_zero_qber(self):
        r,_=simulate(Scenario('loss_all',500,loss=1),0)
        self.assertEqual(r['x_qber'],'')
        self.assertEqual(r['qber_only_admitted'],0)

if __name__=='__main__':unittest.main()
