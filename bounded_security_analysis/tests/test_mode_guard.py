"""Local mode-selection checks added in Program 8."""
import unittest
from independent_protocol import Endpoint,Abort
from hybrid_protocol import Policy

class TestLocallyCheckedMode(unittest.TestCase):
    def role(self,policy,status,key):
        e=Endpoint.__new__(Endpoint)
        e.flow='mode_a';e.bitmap_next=0;e.policy=policy;e.status=status;e.final=key
        return e
    def payload(self,policy,mode,status):
        return {'policy':policy.value,'mode':mode,'qkd_status':status}
    def test_hybrid_required_accepts_valid_key(self):
        p=Policy.HYBRID_REQUIRED;s='MODEL_ACCEPT'
        self.role(p,s,b'x'*32).allowed('mode_a',self.payload(p,'HYBRID',s))
    def test_hybrid_required_does_not_silently_downgrade(self):
        p=Policy.HYBRID_REQUIRED;s='ABORT_EC_BUDGET'
        with self.assertRaises(Abort):
            self.role(p,s,None).allowed('mode_a',self.payload(p,'PQC_ONLY',s))
    def test_hybrid_preferred_explicit_fallback(self):
        p=Policy.HYBRID_PREFERRED;s='ABORT_EC_BUDGET'
        self.role(p,s,None).allowed('mode_a',self.payload(p,'PQC_ONLY',s))
    def test_hybrid_preferred_rejects_uncertified_hybrid(self):
        p=Policy.HYBRID_PREFERRED;s='ABORT_FINITE_KEY'
        with self.assertRaises(Abort):
            self.role(p,s,None).allowed('mode_a',self.payload(p,'HYBRID',s))
    def test_pqc_only_rejects_hybrid(self):
        p=Policy.PQC_ONLY;s='NOT_RUN'
        with self.assertRaises(Abort):
            self.role(p,s,None).allowed('mode_a',self.payload(p,'HYBRID',s))
    def test_policy_mismatch_rejected_even_if_signed(self):
        p=Policy.HYBRID_REQUIRED;s='MODEL_ACCEPT'
        with self.assertRaises(Abort):
            self.role(p,s,b'x'*32).allowed('mode_a',self.payload(Policy.HYBRID_PREFERRED,'HYBRID',s))
    def test_status_mismatch_rejected(self):
        p=Policy.HYBRID_PREFERRED
        with self.assertRaises(Abort):
            self.role(p,'ABORT_FINITE_KEY',None).allowed('mode_a',self.payload(p,'PQC_ONLY','MODEL_ACCEPT'))
    def test_second_party_checks_mode_too(self):
        p=Policy.HYBRID_REQUIRED;s='ABORT_FINITE_KEY'
        e=self.role(p,s,None);e.flow='mode_b'
        with self.assertRaises(Abort):
            e.allowed('mode_b',self.payload(p,'PQC_ONLY',s))
if __name__=='__main__':unittest.main()
