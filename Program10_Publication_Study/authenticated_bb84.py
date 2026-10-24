"""Program 6: signed classical BB84 stage messages and experimental hybrid handoff.

Research-only single-process simulator. NOT a deployed/authentic two-party
QKD system. Error-correction parity exchanges are *batched and signed after*
the simulator computes them; this is not a live authenticated Cascade network.
Finite-key bounds retain the assumptions documented in finite_key_bb84.py.
"""
from __future__ import annotations
import base64
import copy
import hashlib
import hmac
import math
import os
import time
from dataclasses import asdict, dataclass
from enum import Enum
from typing import Callable, Optional
import numpy as np
from finite_key_bb84 import FiniteKeyConfig, cascade_reconcile, finite_key_bound, toeplitz_hash
from pqc_protocol import (OpenSSLBackend, Identity, ProtocolAbort, b64, unb64,
                          encode, sha, sign_envelope, verify_envelope, negotiate)
from hybrid_protocol import Policy, _schedule, seal_record, RecordReceiver

PROTOCOL='research-auth-bb84-v1'
FRAMES={'policy_offer','policy_ack','bob_detected','bob_basis','alice_basis',
        'sampling_seed','alice_test_bits','bob_test_bits','ec_seed',
        'ec_batch','verification_seed','alice_verification_tag','bob_verification_tag',
        'privacy_amplification_seed','qkd_report_alice','qkd_report_bob',
        'mode_decision','mode_ack'}
Mutator=Callable[[str,dict],dict]

# Role and state are checked even for a cryptographically valid signature.
FRAME_RULES={
 'policy_offer':('alice',{'INIT'}), 'policy_ack':('bob',{'INIT'}),
 'bob_detected':('bob',{'BASIS'}), 'bob_basis':('bob',{'BASIS'}),
 'alice_basis':('alice',{'BASIS'}),
 'sampling_seed':('alice',{'TEST'}), 'alice_test_bits':('alice',{'TEST'}),
 'bob_test_bits':('bob',{'TEST'}),
 'ec_seed':('alice',{'EC'}), 'ec_batch':('bob',{'EC'}),
 'verification_seed':('alice',{'VERIFY'}),
 'alice_verification_tag':('alice',{'VERIFY'}),
 'bob_verification_tag':('bob',{'VERIFY'}),
 'privacy_amplification_seed':('alice',{'PA'}),
 'qkd_report_alice':('alice',{'BASIS','TEST','VERIFY','PA'}),
 'qkd_report_bob':('bob',{'BASIS','TEST','VERIFY','PA'}),
 'mode_decision':('alice',{'DECIDED'}), 'mode_ack':('bob',{'DECIDED'})
}
EXPECTED_PREDECESSORS={
 'policy_offer':None, 'policy_ack':'policy_offer',
 'bob_detected':'policy_ack','bob_basis':'bob_detected',
 'alice_basis':'bob_basis', 'sampling_seed':'alice_basis',
 'alice_test_bits':'sampling_seed','bob_test_bits':'alice_test_bits',
 'ec_seed':'bob_test_bits','verification_seed':None,
 'alice_verification_tag':'verification_seed',
 'bob_verification_tag':'alice_verification_tag',
 'privacy_amplification_seed':'bob_verification_tag',
 'qkd_report_bob':'qkd_report_alice',
 'mode_ack':'mode_decision'
}


class ChannelAbort(ProtocolAbort):
    pass


class Stage(str,Enum):
    INIT='INIT'
    AUTHENTICATED='AUTHENTICATED'
    BASIS='BASIS'
    TEST='TEST'
    EC='EC'
    VERIFY='VERIFY'
    PA='PA'
    DECIDED='DECIDED'
    FINISHED='FINISHED'
    ABORT='ABORT'


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


class AuthenticatedClassicalChannel:
    """Two role-aware signature-verifying transcript endpoints.

    The sender signs each canonical frame and the receiver verifies it against a
    provisioned trusted public identity key. Both senders have distinct ordered
    hash chains, session nonce, strict frame names, and monotonically increasing
    sequence numbers. Messages in this simulator are delivered synchronously.
    """
    def __init__(self, backend:OpenSSLBackend,alice:Identity,bob:Identity,
                 context_hash:str, session_id:str|None=None,
                 mutator:Mutator|None=None, replay_cache:set[str]|None=None):
        self.backend=backend
        self.identities={'alice':alice,'bob':bob}
        self.context_hash=context_hash
        self.session_id=session_id or os.urandom(16).hex()
        if len(bytes.fromhex(self.session_id))!=16:
            raise ValueError('Invalid session ID')
        self.mutator=mutator
        self.next_seq={'alice':0,'bob':0}
        self.last={'alice':'0'*64,'bob':'0'*64}
        self.stage=Stage.INIT
        self.frames=[]
        self.bytes=0
        self.last_kind=None
        self.next_ec_batch=0
        self._cache=replay_cache if replay_cache is not None else backend.replay_cache
        cache_id='bb84-session:'+self.session_id
        if cache_id in self._cache:
            raise ChannelAbort('Replayed QKD session identifier')
        self._cache.add(cache_id)

    def advance(self, old:Stage,new:Stage):
        if self.stage!=old:
            raise ChannelAbort(f'Illegal state transition {self.stage} -> {new}')
        self.stage=new

    def send(self, role:str,kind:str,payload:dict)->dict:
        if role not in self.identities or kind not in FRAMES or not isinstance(payload,dict):
            raise ChannelAbort('Invalid sender, frame kind, or payload')
        if self.stage in (Stage.ABORT,Stage.FINISHED):
            raise ChannelAbort('Session already terminal')
        expected_role, allowed_stages=FRAME_RULES[kind]
        if role!=expected_role or self.stage.value not in allowed_stages:
            raise ChannelAbort('Wrong role or invalid protocol phase')
        preceding=EXPECTED_PREDECESSORS.get(kind)
        if preceding is not None and self.last_kind!=preceding:
            raise ChannelAbort('Unexpected protocol-message order')
        if kind=='ec_batch':
            if self.last_kind not in ('ec_seed','ec_batch') or payload.get('index')!=self.next_ec_batch:
                raise ChannelAbort('Unexpected or replayed EC batch')
        if kind=='verification_seed' and self.last_kind not in ('ec_seed','ec_batch'):
            raise ChannelAbort('Verification before error correction')
        if kind=='qkd_report_alice' and self.last_kind in ('qkd_report_alice','qkd_report_bob'):
            raise ChannelAbort('Duplicate QKD report')
        if kind=='mode_decision' and self.last_kind not in ('policy_ack','qkd_report_bob'):
            raise ChannelAbort('Mode cannot be decided before reports')
        body={'protocol':PROTOCOL,'kind':kind,'sender':role,
              'receiver':'bob' if role=='alice' else 'alice',
              'session_id':self.session_id,'context_hash':self.context_hash,
              'seq':self.next_seq[role],'previous_hash':self.last[role],
              'payload':payload}
        identity=self.identities[role]
        envelope=sign_envelope(self.backend,identity.signing_private,body)
        received=self.mutator(kind,copy.deepcopy(envelope)) if self.mutator else envelope
        if not isinstance(received,dict):
            raise ChannelAbort('Dropped or malformed signed frame')
        wire=encode(received)
        self.bytes+=len(wire)
        if len(wire)>20000:
            raise ChannelAbort('Signed frame exceeds research transport limit')
        verified=verify_envelope(self.backend,identity.signing_public,received)
        if verified!=body:
            raise ChannelAbort('Signed frame changed or reused')
        # Independent checks, important even if a foreign trusted key signs a
        # syntactically valid but wrong-role or out-of-session payload.
        if (verified['seq']!=self.next_seq[role] or
            verified['previous_hash']!=self.last[role] or
            verified['session_id']!=self.session_id or
            verified['context_hash']!=self.context_hash or
            verified['sender']!=role or verified['kind']!=kind):
            raise ChannelAbort('Sequence, role, or context violation')
        self.last[role]=sha(wire).hex()
        self.next_seq[role]+=1
        self.last_kind=kind
        if kind=='ec_batch':
            self.next_ec_batch+=1
        self.frames.append({'kind':kind,'role':role,'digest':self.last[role],
                            'bytes':len(wire)})
        return verified['payload']

    def digest(self)->str:
        return sha(encode({'protocol':PROTOCOL,'session_id':self.session_id,
                           'context':self.context_hash,'last':self.last,
                           'frames':self.frames})).hex()


@dataclass
class QKDResult:
    status:str
    x_qber:float|None
    raw_z:int
    test_x:int
    ec_leakage_bits:int
    ec_budget_bits:int
    finite_key_bound_bits:int
    final_key_bits:int
    signed_frames:int
    signed_bytes:int
    transcript_hash:str
    runtime_ms:float
    endpoint_keys_match:bool
    classical_state:str


def _report(channel:AuthenticatedClassicalChannel,status:str,xq:float|None,n:int,k:int,
            leakage:int,cap:int,bound:int,keys:tuple[bytes,bytes]|None,t0:int)->tuple[QKDResult,tuple[bytes,bytes]|None]:
    payload={'status':status,'raw_z':n,'test_x':k,'ec_leakage_bits':leakage,
             'ec_budget_bits':cap,'finite_bound_bits':bound,
             'output_key_bits':len(keys[0])*8 if keys else 0,
             'x_qber_ppm':round(xq*1e6) if xq is not None else None}
    r1=channel.send('alice','qkd_report_alice',payload)
    r2=channel.send('bob','qkd_report_bob',{**payload,'alice_report_sha256':sha(encode(r1)).hex()})
    if r2['alice_report_sha256']!=sha(encode(r1)).hex():
        raise ChannelAbort('Report agreement failed')
    channel.advance(channel.stage,Stage.DECIDED)
    return (QKDResult(status,xq,n,k,leakage,cap,bound,len(keys[0])*8 if keys else 0,
                      len(channel.frames),channel.bytes,channel.digest(),
                      (time.perf_counter_ns()-t0)/1e6,
                      bool(keys is not None and hmac.compare_digest(*keys)),
                      channel.stage.value),keys)


def run_authenticated_bb84(channel:AuthenticatedClassicalChannel,
                            cfg:FiniteKeyConfig,seed:int)->tuple[QKDResult,tuple[bytes,bytes]|None]:
    """Public-basis/test/EC/verification/PA data are actually signed on channel.

    No raw Z key or final QKD material is written to signed/public messages.
    EC calculations occur within a privileged simulator. EC query records are
    batch-authenticated after computation, before key verification/admission.
    """
    start=time.perf_counter_ns()
    if channel.stage!=Stage.AUTHENTICATED:
        raise ChannelAbort('QKD cannot start before mutual policy authentication')
    tx=quantum_simulation(cfg,seed)
    nsignals=cfg.transmitted_signals
    channel.advance(Stage.AUTHENTICATED,Stage.BASIS)
    bd=channel.send('bob','bob_detected',{'count':nsignals,'bits':pack_bits(tx.detected)})
    bb=channel.send('bob','bob_basis',{'count':nsignals,'bits':pack_bits(tx.bob_bases)})
    ab=channel.send('alice','alice_basis',{'count':nsignals,'bits':pack_bits(tx.alice_bases)})
    detected=read_bits(bd['bits'],bd['count'])
    bob_bases=read_bits(bb['bits'],bb['count'])
    alice_bases=read_bits(ab['bits'],ab['count'])
    if any(len(x)!=nsignals for x in (detected,bob_bases,alice_bases)):
        raise ChannelAbort('Basis framing mismatch')
    selected=(detected==1)&(alice_bases==bob_bases)
    zpos=np.flatnonzero(selected&(alice_bases==1))
    xpos=np.flatnonzero(selected&(alice_bases==0))
    n=cfg.target_key_bits
    k=cfg.target_test_bits
    if len(zpos)<n or len(xpos)<k:
        return _report(channel,'ABORT_INSUFFICIENT_DETECTIONS',None,0,0,0,0,0,None,start)
    channel.advance(Stage.BASIS,Stage.TEST)
    # Simulation-only deterministic sampler; seed is a publicly authenticated
    # uniform draw. Separate Z/X samples without replacement.
    rng=np.random.default_rng(seed+918273)
    sample_seed=int(rng.integers(0,2**63-1))
    sb=channel.send('alice','sampling_seed',{'seed':sample_seed,'key_count':n,'test_count':k})
    srng=np.random.default_rng(sb['seed'])
    zi=srng.choice(len(zpos),n,replace=False)
    xi=srng.choice(len(xpos),k,replace=False)
    alice_z=tx.alice_bits[zpos[zi]]
    bob_z=tx.bob_bits[zpos[zi]]
    alice_x=tx.alice_bits[xpos[xi]]
    bob_x=tx.bob_bits[xpos[xi]]
    at=channel.send('alice','alice_test_bits',{'count':k,'bits':pack_bits(alice_x)})
    bt=channel.send('bob','bob_test_bits',{'count':k,'bits':pack_bits(bob_x)})
    a_test=read_bits(at['bits'],at['count'])
    b_test=read_bits(bt['bits'],bt['count'])
    if len(a_test)!=k or len(b_test)!=k:
        raise ChannelAbort('Test-size disagreement')
    errs=int(np.count_nonzero(a_test!=b_test))
    qber=errs/k
    if qber>cfg.q_tolerance:
        return _report(channel,'ABORT_PARAMETER_ESTIMATION',qber,n,k,0,0,0,None,start)
    channel.advance(Stage.TEST,Stage.EC)
    ec_seed=int(rng.integers(0,2**63-1))
    ec_msg=channel.send('alice','ec_seed',{'seed':ec_seed,
        'passes':cfg.reconciliation_passes,'block_size':cfg.reconciliation_block_size})
    events:list[dict]=[]
    ec=cascade_reconcile(alice_z,bob_z,np.random.default_rng(ec_msg['seed']),
                         passes=cfg.reconciliation_passes,
                         initial_block_size=cfg.reconciliation_block_size,
                         public_log=events)
    if len(events)*2!=ec.leakage_bits:
        raise ChannelAbort('EC public disclosure accounting mismatch')
    # Batches bind the actual parity decisions used by the local reconciling
    # routine. Not equivalent to authenticating each *interactive* query live.
    for j in range(0,len(events),60):
        block=events[j:j+60]
        got=channel.send('bob','ec_batch',{'index':j//60,'events':block})
        if got['index']!=j//60 or got['events']!=block:
            raise ChannelAbort('EC batch disagreement')
    channel.advance(Stage.EC,Stage.VERIFY)
    vbits=math.ceil(math.log2(1/cfg.eps_correctness))
    vseed=rng.integers(0,2,n+vbits-1,dtype=np.uint8)
    sent=channel.send('alice','verification_seed',{'count':len(vseed),'bits':pack_bits(vseed)})
    agreed_seed=read_bits(sent['bits'],sent['count'])
    tag_a=toeplitz_hash(alice_z,agreed_seed,vbits)
    tag_b=toeplitz_hash(ec.bob_corrected,agreed_seed,vbits)
    tag_a_msg=channel.send('alice','alice_verification_tag',{'count':vbits,'bits':pack_bits(tag_a)})
    tag_b_msg=channel.send('bob','bob_verification_tag',{'count':vbits,'bits':pack_bits(tag_b)})
    va=read_bits(tag_a_msg['bits'],tag_a_msg['count'])
    vb=read_bits(tag_b_msg['bits'],tag_b_msg['count'])
    cap=math.ceil(cfg.ec_leakage_cap_fraction*n)
    bound,_=finite_key_bound(n,k,cfg.q_tolerance,cap,cfg.eps_secrecy,cfg.eps_correctness)
    if ec.leakage_bits>cap:
        return _report(channel,'ABORT_EC_LEAKAGE_BUDGET',qber,n,k,ec.leakage_bits,cap,bound,None,start)
    if not np.array_equal(va,vb):
        return _report(channel,'ABORT_KEY_VERIFICATION',qber,n,k,ec.leakage_bits,cap,bound,None,start)
    if bound<cfg.min_final_key_bits or bound<cfg.output_key_bits:
        return _report(channel,'ABORT_INSUFFICIENT_FINITE_KEY',qber,n,k,ec.leakage_bits,cap,bound,None,start)
    channel.advance(Stage.VERIFY,Stage.PA)
    pa_seed=rng.integers(0,2,n+cfg.output_key_bits-1,dtype=np.uint8)
    pa=channel.send('alice','privacy_amplification_seed',{'count':len(pa_seed),'bits':pack_bits(pa_seed)})
    pa_public=read_bits(pa['bits'],pa['count'])
    alice_final=toeplitz_hash(alice_z,pa_public,cfg.output_key_bits)
    bob_final=toeplitz_hash(ec.bob_corrected,pa_public,cfg.output_key_bits)
    keys=(np.packbits(alice_final,bitorder='big').tobytes(),
          np.packbits(bob_final,bitorder='big').tobytes())
    if not hmac.compare_digest(*keys):
        raise ChannelAbort('Final QKD key disagreement after verification')
    return _report(channel,'ACCEPT',qber,n,k,ec.leakage_bits,cap,bound,keys,start)


@dataclass
class SessionResult:
    mode:str
    policy:str
    qkd_status:str
    qkd_bound_bits:int
    qkd_test_qber:float|None
    classical_frames:int
    classical_bytes:int
    qkd_transcript_hash:str
    handshake_ms:float
    total_ms:float
    record_bytes:int
    key_confirmation_ok:bool
    recovered_ok:bool


def run_session(backend:OpenSSLBackend,alice:Identity,bob:Identity,
                cfg:FiniteKeyConfig,seed:int,policy:Policy,
                payload:bytes=b'Program 6 authenticated session',
                mutator:Mutator|None=None,
                qkd_session_id:str|None=None)->SessionResult:
    """PQC handshake -> dual-signed policy -> signed QKD transcript ->
    dual-signed mode decision -> transcript-bound hybrid/PQC-only traffic keys.
    All cryptography is real except idealized QKD and NumPy-sampled bits.
    """
    start=time.perf_counter_ns()
    if not isinstance(policy,Policy) or len(payload)>1_000_000:
        raise ValueError('Invalid policy or record size')
    p=negotiate(backend,alice,bob)
    if not hmac.compare_digest(p.session_key_alice,p.session_key_bob):
        raise ChannelAbort('PQC bootstrap disagreement')
    cfg_hash=sha(encode(asdict(cfg))).hex()
    channel=AuthenticatedClassicalChannel(backend,alice,bob,
                   context_hash=sha(encode({'bootstrap':p.transcript_hash,
                                            'config':cfg_hash,'policy':policy.value})).hex(),
                   session_id=qkd_session_id,mutator=mutator)
    channel.send('alice','policy_offer',{'policy':policy.value,'cfg_hash':cfg_hash,
             'bootstrap_hash':p.transcript_hash})
    channel.send('bob','policy_ack',{'policy':policy.value,'cfg_hash':cfg_hash,
             'bootstrap_hash':p.transcript_hash})
    channel.advance(Stage.INIT,Stage.AUTHENTICATED)
    if policy==Policy.PQC_ONLY:
        qkd=QKDResult('NOT_RUN',None,0,0,0,0,0,0,0,0,channel.digest(),0,False,Stage.DECIDED.value)
        keys=None
        channel.advance(Stage.AUTHENTICATED,Stage.DECIDED)
    else:
        qkd,keys=run_authenticated_bb84(channel,cfg,seed)
    if qkd.status=='ACCEPT' and keys is not None:
        mode='HYBRID'
    elif policy==Policy.HYBRID_PREFERRED or policy==Policy.PQC_ONLY:
        mode='PQC_ONLY'
    else:
        mode='ABORT'
    assert channel.stage==Stage.DECIDED
    descriptor={'policy':policy.value,'mode':mode,'qkd_status':qkd.status,
                'qkd_transcript_hash':channel.digest(),'bootstrap_hash':p.transcript_hash}
    d=channel.send('alice','mode_decision',descriptor)
    a=channel.send('bob','mode_ack',{**descriptor,'alice_decision_hash':sha(encode(d)).hex()})
    if a['alice_decision_hash']!=sha(encode(d)).hex():
        raise ChannelAbort('Mode decision inconsistency')
    if mode=='ABORT':
        channel.stage=Stage.ABORT
        return SessionResult('ABORT',policy.value,qkd.status,qkd.finite_key_bound_bits,
              qkd.x_qber,len(channel.frames),channel.bytes,channel.digest(),
              (time.perf_counter_ns()-start)/1e6,
              (time.perf_counter_ns()-start)/1e6,0,False,False)
    context=sha(encode({'bootstrap_hash':p.transcript_hash,
                        'classical_transcript':channel.digest(),
                        'session_id':channel.session_id,
                        'policy':policy.value,'mode':mode}))
    qa,qb=keys if mode=='HYBRID' else (None,None)
    ka=_schedule(p.session_key_alice,qa,mode,context)
    kb=_schedule(p.session_key_bob,qb,mode,context)
    for label,sender,receiver in [('bob',kb,ka),('alice',ka,kb)]:
        sig=hmac.new(sender[f'{label}_confirm'],b'P6-FINISHED'+context+label.encode(),hashlib.sha256).digest()
        expected=hmac.new(receiver[f'{label}_confirm'],b'P6-FINISHED'+context+label.encode(),hashlib.sha256).digest()
        if not hmac.compare_digest(sig,expected):
            raise ChannelAbort('Hybrid key confirmation failed')
    handshake_ms=(time.perf_counter_ns()-start)/1e6
    sid=context.hex()
    record=seal_record(ka['A2B_key'],ka['A2B_iv'],sid,mode,'A2B',0,payload)
    rr=RecordReceiver(kb['A2B_key'],kb['A2B_iv'],sid,mode,'A2B')
    recovered=rr.open(record)
    if recovered!=payload:
        raise ChannelAbort('Application record mismatch')
    channel.advance(Stage.DECIDED,Stage.FINISHED)
    return SessionResult(mode,policy.value,qkd.status,qkd.finite_key_bound_bits,
        qkd.x_qber,len(channel.frames),channel.bytes,channel.digest(),
        handshake_ms,(time.perf_counter_ns()-start)/1e6,
        len(unb64(record['ciphertext'],1_100_000)),True,True)
