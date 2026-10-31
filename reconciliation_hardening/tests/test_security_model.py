import unittest
from dataclasses import replace
from security_model import (Guards,State,intended_mode,transition,explore,
                            negative_controls,POLICIES,STAGES,ACTIONS)

class TestExplicitStateModel(unittest.TestCase):
    def test_all_scenarios_explored(self):
        result=explore()
        self.assertEqual(result['scenarios'],24)
        self.assertEqual(result['max_protocol_frames'],8)
        self.assertGreater(result['states_explored'],1000)
        self.assertEqual(result['violations'],{})
    def test_more_bounded_attacks(self):
        r=explore(max_attacks=2)
        self.assertEqual(r['violations'],{})
        self.assertGreaterEqual(r['states_explored'],explore()['states_explored'])  # under intact guards every deviation terminates
    def test_policy_matrix(self):
        self.assertEqual(intended_mode('HYBRID_REQUIRED',False,True),'ABORT')
        self.assertEqual(intended_mode('HYBRID_REQUIRED',True,True),'HYBRID')
        self.assertEqual(intended_mode('HYBRID_PREFERRED',False,True),'PQC_ONLY')
        self.assertEqual(intended_mode('PQC_ONLY',True,True),'PQC_ONLY')
        self.assertEqual(intended_mode('HYBRID_PREFERRED',True,False),'ABORT')
    def test_replay_rejected(self):
        s=State('HYBRID_PREFERRED',True,True,True)
        self.assertEqual(transition(s,'cross_session_replay').status,'REJECT')
        self.assertEqual(transition(s,'replay_prior').status,'REJECT')
    def test_tampering_rejected(self):
        s=State('HYBRID_PREFERRED',True,True,True)
        self.assertEqual(transition(s,'forge').status,'REJECT')
        self.assertEqual(transition(s,'reorder').status,'REJECT')
    def test_drop_only_stalls(self):
        s=State('HYBRID_PREFERRED',True,True,True)
        self.assertEqual(transition(s,'drop').status,'STALLED')
    def test_outside_attack_alphabet_rejected(self):
        with self.assertRaises(ValueError):
            transition(State('HYBRID_REQUIRED',True,True,True),'quantum_side_channel')
    def test_negative_controls_all_find_counterexamples(self):
        found=negative_controls()
        self.assertEqual(len(found),6)
        for name,result in found.items():
            with self.subTest(name=name):
                self.assertTrue(result['violations'])
                self.assertTrue(all(x['trace'] for x in result['violations'].values()))
    def test_attack_bound_validation(self):
        with self.assertRaises(ValueError):
            explore(max_attacks=3)

if __name__=='__main__': unittest.main()
