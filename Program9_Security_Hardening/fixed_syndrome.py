"""Fixed-length Hamming(31) syndrome reconciliation for a *simulated* BB84 study.

This deliberately trades coding efficiency for auditable leakage: the entire
error-correction disclosure consists of exactly 5*ceil(n/31)*passes public
syndrome bits, sent on a fixed schedule independent of raw bits and decoding
outcome. For multiple errors in a block, verification can fail and must abort.

No proof of a deployed QKD system is implied: quantum source, randomness,
authentication and other conditions must satisfy the adopted theorem.
"""
from __future__ import annotations
import math
import numpy as np
from quantum_channel_model import pack_bits,read_bits

BLOCK=31
SYNDROME_BITS=5


def leakage_bits(n:int, passes:int)->int:
    if type(n) is not int or type(passes) is not int or n<1 or not 1<=passes<=20:
        raise ValueError('invalid fixed reconciliation dimensions')
    return math.ceil(n/BLOCK)*SYNDROME_BITS*passes


def syndrome(bits:np.ndarray)->int:
    a=np.asarray(bits,dtype=np.uint8)
    if a.ndim!=1 or len(a)>BLOCK or np.any(a>1):
        raise ValueError('syndrome expects at most 31 bits')
    value=0
    for i,bit in enumerate(a):
        if int(bit):
            value ^= i+1
    return value


def integer_to_bits(value:int)->np.ndarray:
    return np.array([(value >> j)&1 for j in range(SYNDROME_BITS)],dtype=np.uint8)


def bits_to_integer(bits:np.ndarray)->int:
    if len(bits)!=SYNDROME_BITS or np.any(bits>1):
        raise ValueError('not a five-bit syndrome')
    return sum(int(v)<<j for j,v in enumerate(bits))


class FixedSyndromeEC:
    """One authenticated syndrome frame per pass, no adaptive parity queries.

    All block permutations and transmitted lengths are chosen without reference
    to the key or observed errors. The remote endpoint sees only Alice's
    syndrome bits. Bob's local correction pattern is never transmitted.
    """
    def __init__(self, relay, n:int, seed:int, passes:int):
        if not 1<=passes<=20 or n<1: raise ValueError('invalid syndrome configuration')
        self.relay=relay
        self.n=n
        self.passes=passes
        rng=np.random.default_rng(seed)
        self.orders=[rng.permutation(n) for _ in range(passes)]
        self.disclosures=leakage_bits(n,passes)
        self.queries=0
        self.rounds=passes
        self.flips=0

    def reconcile(self):
        alice=self.relay.alice
        bob=self.relay.bob
        if alice.raw is None or bob.raw is None or len(alice.raw)!=self.n or len(bob.raw)!=self.n:
            raise ValueError('raw bits missing or mismatched')
        for pass_id,order in enumerate(self.orders):
            blocks=[order[j:j+BLOCK] for j in range(0,self.n,BLOCK)]
            alice_bits=np.concatenate([integer_to_bits(syndrome(alice.raw[idx])) for idx in blocks])
            frame={'pass':pass_id,'n':int(len(alice_bits)),'blocks':len(blocks),'bits':pack_bits(alice_bits)}
            received=self.relay.send('ec_syndrome_a',frame)
            public=read_bits(received['bits'],received['n'])
            if len(public)!=SYNDROME_BITS*len(blocks) or received['blocks']!=len(blocks):
                raise ValueError('noncanonical syndrome payload')
            for block_index,positions in enumerate(blocks):
                a_syn=bits_to_integer(public[block_index*SYNDROME_BITS:(block_index+1)*SYNDROME_BITS])
                delta=a_syn^syndrome(bob.raw[positions])
                if 1<=delta<=len(positions):
                    bob.raw[int(positions[delta-1])] ^= np.uint8(1)
                    self.flips+=1
        return self.disclosures,self.queries,self.flips
