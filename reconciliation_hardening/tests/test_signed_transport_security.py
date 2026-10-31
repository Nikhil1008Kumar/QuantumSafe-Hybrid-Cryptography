"""Check several signed-frame attacks against the actual OpenSSL-backed relay."""
import copy
import unittest
import numpy as np
from pqc_protocol import OpenSSLBackend, generate_identity,ProtocolAbort
from independent_protocol import Endpoint,Relay,Abort
from hybrid_protocol import Policy

class TestRealSignedFrames(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.backend=OpenSSLBackend().__enter__()
        cls.a=generate_identity(cls.backend,'alice')
        cls.b=generate_identity(cls.backend,'bob')
    @classmethod
    def tearDownClass(cls):
        cls.backend.__exit__(None,None,None)
    def setUp(self):
        bits=np.zeros(20,dtype=np.uint8)
        self.alice=Endpoint('alice',self.a,self.b,bits,bits,None,'ctx','01'*16,self.backend)
        self.bob=Endpoint('bob',self.b,self.a,bits,bits,bits,'ctx','01'*16,self.backend)
        self.alice.policy=self.bob.policy=Policy.HYBRID_PREFERRED
        self.relay=Relay(self.alice,self.bob)
        self.payload={'policy':Policy.HYBRID_PREFERRED.value,'cfg_sha256':'test'}
    def test_untampered_policy_is_delivered(self):
        self.relay.send('policy_a',self.payload)
        self.assertEqual(self.alice.trace,self.bob.trace)
        self.assertEqual(self.bob.seq_in,1)
    def test_modified_signed_payload_rejected(self):
        def mutate(k,e):
            e['body']['payload']['policy']='HYBRID_REQUIRED'
            return e
        self.relay.mutator=mutate
        with self.assertRaises(ProtocolAbort):self.relay.send('policy_a',self.payload)
    def test_cross_session_replay_is_rejected(self):
        self.relay.send('policy_a',self.payload)
        old=self.relay.history[0][1]
        bits=np.zeros(20,dtype=np.uint8)
        new_bob=Endpoint('bob',self.b,self.a,bits,bits,bits,'ctx','02'*16,self.backend)
        new_bob.policy=Policy.HYBRID_PREFERRED
        with self.assertRaises(ProtocolAbort):new_bob.receive(old,'policy_a')
    def test_duplicate_signed_frame_is_rejected(self):
        self.relay.send('policy_a',self.payload)
        old=self.relay.history[0][1]
        with self.assertRaises(ProtocolAbort):self.bob.receive(old,'policy_a')
    def test_wrong_stage_rejected_before_commit(self):
        self.relay.send('policy_a',self.payload)
        self.assertEqual(self.bob.flow,'policy_b')
        old=self.relay.history[0][1]
        with self.assertRaises(ProtocolAbort):self.bob.receive(old,'policy_a')
        self.assertEqual(len(self.bob.trace),1)
    def test_different_context_is_rejected(self):
        self.relay.send('policy_a',self.payload)
        old=self.relay.history[0][1]
        bits=np.zeros(20,dtype=np.uint8)
        new_bob=Endpoint('bob',self.b,self.a,bits,bits,bits,'different-context','01'*16,self.backend)
        new_bob.policy=Policy.HYBRID_PREFERRED
        with self.assertRaises(ProtocolAbort):new_bob.receive(old,'policy_a')
if __name__=='__main__':unittest.main()
