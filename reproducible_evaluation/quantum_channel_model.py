from __future__ import annotations
from dataclasses import dataclass
import numpy as np
from finite_key_bb84 import FiniteKeyConfig
from pqc_protocol import b64,unb64,ProtocolAbort
class ChannelAbort(ProtocolAbort): pass
def pack_bits(bits:np.ndarray)->str:
    return b64(np.packbits(np.asarray(bits,dtype=np.uint8),bitorder='big').tobytes())


def read_bits(value:str,count:int)->np.ndarray:
    if type(count) is not int or count<0 or count>1_000_000:
        raise ChannelAbort('Invalid public bit count')
    raw=unb64(value,(count+7)//8+1)
    if len(raw)!=(count+7)//8:
        raise ChannelAbort('Public bits have incorrect byte length')
    arr=np.unpackbits(np.frombuffer(raw,dtype=np.uint8),bitorder='big')
    if np.any(arr[count:]):
        raise ChannelAbort('Noncanonical nonzero trailing bits')
    return arr[:count].copy()


@dataclass
class RawExchange:
    alice_bits: np.ndarray
    alice_bases: np.ndarray
    bob_bits: np.ndarray
    bob_bases: np.ndarray
    detected: np.ndarray


def quantum_simulation(cfg:FiniteKeyConfig,seed:int)->RawExchange:
    """Reproducible BB84 measurement model; seeded NumPy is NOT a CSPRNG."""
    rng=np.random.default_rng(seed)
    n=cfg.transmitted_signals
    alice_bits=rng.integers(0,2,n,dtype=np.uint8)
    alice_bases=(rng.random(n)<cfg.p_z).astype(np.uint8)
    bob_bases=(rng.random(n)<cfg.p_z).astype(np.uint8)
    detected=(rng.random(n)>=cfg.loss_probability).astype(np.uint8)
    attacked=(rng.random(n)<cfg.intercept_probability)&(detected==1)
    eve_base=rng.integers(0,2,n,dtype=np.uint8)
    eve_rand=rng.integers(0,2,n,dtype=np.uint8)
    eve_bit=np.where(eve_base==alice_bases,alice_bits,eve_rand)
    forward_bit=np.where(attacked,eve_bit,alice_bits)
    forward_basis=np.where(attacked,eve_base,alice_bases)
    bob_rand=rng.integers(0,2,n,dtype=np.uint8)
    bob_bits=np.where(bob_bases==forward_basis,forward_bit,bob_rand).astype(np.uint8)
    bob_bits^=(rng.random(n)<cfg.noise_probability).astype(np.uint8)
    return RawExchange(alice_bits,alice_bases,bob_bits,bob_bases,detected)


