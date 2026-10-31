"""Program 7: independently stateful Alice/Bob, signed public messages and
interactive, parity-query reconciliation over an in-memory untrusted relay.
Research simulator; NOT a QKD security proof or a network implementation.
"""
from __future__ import annotations
import hashlib
import hmac
import math
import os
import time
import copy
from dataclasses import dataclass
from typing import Callable
import numpy as np
from finite_key_bb84 import FiniteKeyConfig, finite_key_bound, toeplitz_hash
from pqc_protocol import (OpenSSLBackend, Identity, ProtocolAbort, encode, sha, b64, unb64,
                          sign_envelope, verify_envelope, negotiate)
from hybrid_protocol import Policy, _schedule, seal_record, RecordReceiver
from quantum_channel_model import quantum_simulation, pack_bits, read_bits

VERSION = 'research-independent-bb84-v1'
ROLE_OF = {
    'policy_a':'alice','policy_b':'bob', 'detect_b':'bob', 'basis_b':'bob','basis_a':'alice',
    'sample_a':'alice','test_a':'alice','test_b':'bob','ec_seed_a':'alice',
    'parity_query':'bob','parity_answer':'alice','verification_seed_a':'alice',
    'verification_tag_a':'alice','verification_tag_b':'bob',
    'pa_seed_a':'alice','report_a':'alice','report_b':'bob',
    'mode_a':'alice','mode_b':'bob',
}

class Abort(ProtocolAbort):
    pass


def kbits(seed:int, count:int)->np.ndarray:
    """Only simulator randomness, not cryptographically appropriate in deployment."""
    return np.random.default_rng(seed).integers(0,2,count,dtype=np.uint8)


class Endpoint:
    """The only holder of its own raw-key bits and private signing key."""
    def __init__(self, role:str, identity:Identity, peer:Identity,
                 bits:np.ndarray, bases:np.ndarray, detected:np.ndarray|None,
                 context:str, sid:str, backend:OpenSSLBackend):
        self.role=role
        self.identity=identity
        self.peer_public=peer.signing_public
        self.bits=bits.copy()
        self.bases=bases.copy()
        self.detected=None if detected is None else detected.copy()
        self.context=context
        self.sid=sid
        self.backend=backend
        self.seq_out=0
        self.seq_in=0
        self.last_hash='0'*64
        self.trace=[]
        self.raw:np.ndarray|None=None
        self.final:bytes|None=None
        self.qber:float|None=None
        self.status=None
        self.ec_passes=[]
        self.ec_seed=None
        self.verify_ok=False
        self.mode=None
        self.policy=None
        self.flow='policy_a'
        self.bitmap_next=0

    def allowed(self,kind:str,payload:dict):
        choices={
            'post_basis':{'sample_a','report_a'},
            'post_test':{'ec_seed_a','report_a'},
            'post_ec':{'parity_query','verification_seed_a'},
            'post_verify':{'pa_seed_a','report_a'},
        }
        allowed=choices.get(self.flow,{self.flow})
        if kind not in allowed:
            raise Abort(f'Wrong stage: {kind} at {self.flow}')
        if kind in ('detect_b','basis_b','basis_a'):
            if (type(payload.get('index')) is not int or
                payload['index']!=self.bitmap_next or
                type(payload.get('chunks')) is not int or payload['chunks']<1 or
                payload['index']>=payload['chunks'] or
                type(payload.get('n')) is not int or payload['n']<0):
                raise Abort('Bitmap chunk order invalid')
        if kind in ('policy_a','policy_b') and self.policy is not None:
            if payload.get('policy')!=self.policy.value:
                raise Abort('Policy mismatch')

    def update_flow(self,kind:str,payload:dict):
        if kind in ('detect_b','basis_b','basis_a'):
            self.bitmap_next+=1
            if self.bitmap_next<payload['chunks']:
                return
            self.bitmap_next=0
            self.flow={'detect_b':'basis_b','basis_b':'basis_a',
                       'basis_a':'post_basis'}[kind]
            return
        self.flow={
            'policy_a':'policy_b',
            'policy_b':'report_a' if self.policy==Policy.PQC_ONLY else 'detect_b',
            'sample_a':'test_a','test_a':'test_b','test_b':'post_test',
            'ec_seed_a':'post_ec','parity_query':'parity_answer',
            'parity_answer':'post_ec','verification_seed_a':'verification_tag_a',
            'verification_tag_a':'verification_tag_b',
            'verification_tag_b':'post_verify',
            'pa_seed_a':'report_a','report_a':'report_b',
            'report_b':'mode_a','mode_a':'mode_b','mode_b':'DONE',
        }.get(kind,'DONE')

    def construct(self, kind:str, payload:dict)->dict:
        if ROLE_OF.get(kind)!=self.role:
            raise Abort('Wrong signing role for message')
        if not isinstance(payload,dict):
            raise Abort('Wrong payload type')
        self.allowed(kind,payload)
        return sign_envelope(self.backend,self.identity.signing_private,{
            'version':VERSION,'session':self.sid,'context':self.context,
            'kind':kind,'from':self.role,'to':'bob' if self.role=='alice' else 'alice',
            'seq':self.seq_out,'previous':self.last_hash,'payload':payload})

    def receive(self, envelope:dict, expected_kind:str)->dict:
        body=verify_envelope(self.backend,self.peer_public,envelope)
        expected_sender='bob' if self.role=='alice' else 'alice'
        if (body.get('version')!=VERSION or body.get('session')!=self.sid or
            body.get('context')!=self.context or body.get('kind')!=expected_kind or
            body.get('from')!=expected_sender or body.get('to')!=self.role or
            body.get('seq')!=self.seq_in or body.get('previous')!=self.last_hash):
            raise Abort('Authenticated role/order/context mismatch')
        if ROLE_OF.get(expected_kind)!=expected_sender:
            raise Abort('Unauthorized message type for role')
        if not isinstance(body.get('payload'),dict):
            raise Abort('Invalid authenticated payload')
        self.allowed(expected_kind,body['payload'])
        return body['payload']

    def commit(self, envelope:dict):
        digest=sha(encode(envelope)).hex()
        self.last_hash=digest
        self.trace.append(digest)


Mutator=Callable[[str,dict],dict]

class Relay:
    """Tamperable public relay. Each recipient verifies using its pinned peer key.

    Signature verification succeeds before BOTH endpoints commit the same frame.
    A sender's message never bypasses the recipient's independent validation.
    """
    def __init__(self, alice:Endpoint,bob:Endpoint,mutator:Mutator|None=None):
        self.alice=alice
        self.bob=bob
        self.mutator=mutator
        self.frames=0
        self.bytes=0
        self.last_kind=None
        self.history=[]

    def send(self,kind:str,payload:dict)->dict:
        role=ROLE_OF.get(kind)
        if role is None:
            raise Abort('Unknown message')
        sender=self.alice if role=='alice' else self.bob
        recipient=self.bob if role=='alice' else self.alice
        env=sender.construct(kind,payload)
        altered=self.mutator(kind,copy.deepcopy(env)) if self.mutator else env
        if not isinstance(altered,dict):
            raise Abort('Frame dropped or corrupt')
        wire=encode(altered)
        if len(wire)>20_000:
            raise Abort('Oversized signed frame')
        verified=recipient.receive(altered,kind)
        # Reconfirm sender's payload before updating both independent endpoints.
        if verified != payload:
            raise Abort('Delivered payload changed')
        sender.seq_out+=1
        recipient.seq_in+=1
        sender.commit(altered)
        recipient.commit(altered)
        sender.update_flow(kind,verified)
        recipient.update_flow(kind,verified)
        self.history.append((kind,copy.deepcopy(altered)))
        self.frames+=1
        self.bytes+=len(wire)
        self.last_kind=kind
        return verified

    def digest(self)->str:
        if self.alice.last_hash!=self.bob.last_hash or self.alice.trace!=self.bob.trace:
            raise Abort('Endpoint transcript disagreement')
        return sha(encode(self.alice.trace)).hex()


class InteractiveEC:
    """True query/answer interactivity, NOT original Cascade look-back.

    Bob decides each next query using ONLY his local corrected bits and
    authenticated Alice parity answers. Positions derive from public seed.
    One signed query batch and one signed reply batch per round. The query
    list is constructed BEFORE the answer arrives.
    """
    def __init__(self, relay:Relay, n:int, seed:int, passes:int=3,block_size:int=24):
        self.relay=relay
        self.n=n
        self.rng=np.random.default_rng(seed)
        self.passes=passes
        self.block_size=block_size
        self.disclosures=0
        self.queries=0
        self.rounds=0
        self.flips=0
        self.permutations=[]
        for p in range(passes):
            perm=self.rng.permutation(n)
            size=min(n,block_size*(2**p))
            self.permutations.append([perm[j:j+size].copy() for j in range(0,n,size)])

    def positions(self, label:list)->np.ndarray:
        if not (isinstance(label,list) and len(label)==3):
            raise Abort('Wrong EC query label')
        p,b,path=label
        if type(p)!=int or type(b)!=int or type(path)!=str or p<0 or p>=self.passes:
            raise Abort('Illegal EC block reference')
        blocks=self.permutations[p]
        if b<0 or b>=len(blocks) or len(path)>32:
            raise Abort('Illegal EC block index')
        positions=blocks[b]
        for c in path:
            if c not in 'LR' or len(positions)<2:
                raise Abort('Invalid bisection path')
            m=len(positions)//2
            positions=positions[:m] if c=='L' else positions[m:]
        return positions

    def roundtrip(self, labels:list[list])->list[int]:
        if not labels: return []
        responses=[]
        for start in range(0,len(labels),95):
            chunk=labels[start:start+95]
            msg=self.relay.send('parity_query',{'labels':chunk})
            accepted=msg['labels']
            if accepted!=chunk:
                raise Abort('EC query disagreement')
            # Alice reads only Alice's own raw bits, computing the public parities.
            alice_raw=self.relay.alice.raw
            assert alice_raw is not None
            parities=[int(np.bitwise_xor.reduce(alice_raw[self.positions(tag)])) for tag in accepted]
            received=self.relay.send('parity_answer',{'parities':parities})
            if received['parities']!=parities or len(parities)!=len(chunk):
                raise Abort('EC answer inconsistency')
            responses.extend(parities)
            self.queries+=len(chunk)
            self.rounds+=1
            # Each Alice parity reveals <= 1 bit; each adaptive branch
            # reveals <= 1 additional binary choice. Treat all as 2 bits,
            # subject to stronger full-transcript leakage analysis.
            self.disclosures+=2*len(chunk)
        return responses

    def reconcile(self)->tuple[int,int,int]:
        alice=self.relay.alice
        bob=self.relay.bob
        if alice.raw is None or bob.raw is None or len(alice.raw)!=len(bob.raw):
            raise Abort('No independent raw strings')
        for p,blocks in enumerate(self.permutations):
            labels=[[p,b,''] for b in range(len(blocks))]
            answers=self.roundtrip(labels)
            odd=[]
            for label,answer in zip(labels,answers):
                bp=int(np.bitwise_xor.reduce(bob.raw[self.positions(label)]))
                if bp!=answer:
                    odd.append(label)
            # Bob narrows odd blocks to one discrepant position; branching
            # is based on his LOCAL parity and authenticated Alice's answer.
            while odd:
                done=[]
                pending=[]
                for label in odd:
                    pos=self.positions(label)
                    if len(pos)==1:
                        bob.raw[int(pos[0])] ^= np.uint8(1)
                        self.flips+=1
                        done.append(label)
                    else:
                        pending.append(label)
                if not pending: break
                left_queries=[[p,b,path+'L'] for p,b,path in pending]
                left_answers=self.roundtrip(left_queries)
                odd=[]
                for label,ans,left in zip(pending,left_answers,left_queries):
                    local=int(np.bitwise_xor.reduce(bob.raw[self.positions(left)]))
                    p_,b_,path=label
                    odd.append(left if local!=ans else [p_,b_,path+'R'])
        return self.disclosures,self.queries,self.flips


@dataclass
class Result:
    mode:str
    qkd_status:str
    qkd_bound_bits:int
    x_qber:float|None
    public_ec_bits:int
    ec_queries:int
    ec_rounds:int
    ec_flips:int
    messages:int
    public_bytes:int
    agreement:bool
    encrypted_record_ok:bool
    transcript_hash:str
    elapsed_ms:float


def run_session(backend:OpenSSLBackend,alice_identity:Identity,bob_identity:Identity,
                cfg:FiniteKeyConfig,seed:int,policy:Policy,
                mutator:Mutator|None=None,
                sid:str|None=None)->Result:
    """Execute independent endpoint state on a synchronous hostile relay.

    Simulator (trusted quantum source model) creates separate role-specific
    local observations. No participant obtains the other party's raw bits.
    Neither final key is exported to the result files.
    """
    t0=time.perf_counter()
    pqc=negotiate(backend,alice_identity,bob_identity)
    if not hmac.compare_digest(pqc.session_key_alice,pqc.session_key_bob):
        raise Abort('PQC bootstrap mismatch')
    from quantum_channel_model import quantum_simulation
    q=quantum_simulation(cfg,seed)
    session_id=sid or os.urandom(16).hex()
    if len(bytes.fromhex(session_id))!=16:
        raise Abort('Invalid session identifier')
    if not hasattr(backend,'p7_cache'):
        backend.p7_cache=set()
    if session_id in backend.p7_cache:
        raise Abort('Replayed session ID')
    backend.p7_cache.add(session_id)
    ctx=sha(encode({'version':VERSION,'pqc_hash':pqc.transcript_hash,
                    'cfg':cfg.__dict__,'policy':policy.value})).hex()
    a=Endpoint('alice',alice_identity,bob_identity,q.alice_bits,q.alice_bases,
               None,ctx,session_id,backend)
    b=Endpoint('bob',bob_identity,alice_identity,q.bob_bits,q.bob_bases,
               q.detected,ctx,session_id,backend)
    a.policy=b.policy=policy
    relay=Relay(a,b,mutator)
    def message(kind,pl): return relay.send(kind,pl)

    def bitmap(kind:str,source:np.ndarray)->np.ndarray:
        # Chunked to respect both 20 KB signed-message limits and frame order.
        full=[]
        total=len(source)
        chunks=(total+11999)//12000
        for index in range(chunks):
            bits=source[index*12000:(index+1)*12000]
            received=message(kind,{'index':index,'chunks':chunks,'n':len(bits),
                                   'bits':pack_bits(bits)})
            full.append(read_bits(received['bits'],received['n']))
        return np.concatenate(full)

    message('policy_a',{'policy':policy.value,'cfg_sha256':sha(encode(cfg.__dict__)).hex()})
    message('policy_b',{'policy':policy.value,'cfg_sha256':sha(encode(cfg.__dict__)).hex()})
    bound=leak=queries=rounds=flips=0
    xq=None
    status='NOT_RUN'
    if policy!=Policy.PQC_ONLY:
        detected=bitmap('detect_b',b.detected)
        b_basis=bitmap('basis_b',b.bases)
        a_basis=bitmap('basis_a',a.bases)
        # Alice and Bob calculate the same positions from signed public values.
        mask=(detected==1)&(a_basis==b_basis)
        zpos=np.flatnonzero(mask&(a_basis==1))
        xpos=np.flatnonzero(mask&(a_basis==0))
        n,k=cfg.target_key_bits,cfg.target_test_bits
        if len(zpos)<n or len(xpos)<k:
            status='ABORT_DETECTION'
        else:
            # Public sampler is committed through a signed message.
            sample_seed=seed+813741
            message('sample_a',{'seed':sample_seed,'z_count':n,'x_count':k})
            rng=np.random.default_rng(sample_seed)
            zi=rng.choice(len(zpos),n,replace=False)
            xi=rng.choice(len(xpos),k,replace=False)
            a.raw=a.bits[zpos[zi]].copy()
            b.raw=b.bits[zpos[zi]].copy()
            ax=a.bits[xpos[xi]]
            bx=b.bits[xpos[xi]]
            sent_a=message('test_a',{'n':k,'bits':pack_bits(ax)})
            sent_b=message('test_b',{'n':k,'bits':pack_bits(bx)})
            public_ax=read_bits(sent_a['bits'],k)
            public_bx=read_bits(sent_b['bits'],k)
            xq=float(np.count_nonzero(public_ax!=public_bx)/k)
            a.qber=b.qber=xq
            if xq>cfg.q_tolerance:
                status='ABORT_PARAMETER_ESTIMATION'
            else:
                ecseed=seed+392823
                message('ec_seed_a',{'seed':ecseed,'passes':cfg.reconciliation_passes,
                                    'block_size':cfg.reconciliation_block_size})
                ec=InteractiveEC(relay,n,ecseed,cfg.reconciliation_passes,cfg.reconciliation_block_size)
                leak,queries,flips=ec.reconcile()
                rounds=ec.rounds
                # Universal hash verification is public and independent of EC.
                vbits=math.ceil(math.log2(1/cfg.eps_correctness))
                v_seed=kbits(seed+11411,n+vbits-1)
                vmsg=message('verification_seed_a',{'n':len(v_seed),'bits':pack_bits(v_seed)})
                vs=read_bits(vmsg['bits'],len(v_seed))
                tag_a=toeplitz_hash(a.raw,vs,vbits)
                tag_b=toeplitz_hash(b.raw,vs,vbits)
                va=message('verification_tag_a',{'n':vbits,'bits':pack_bits(tag_a)})
                vb=message('verification_tag_b',{'n':vbits,'bits':pack_bits(tag_b)})
                agree=hmac.compare_digest(pack_bits(read_bits(va['bits'],vbits)),
                                          pack_bits(read_bits(vb['bits'],vbits)))
                budget=math.ceil(cfg.ec_leakage_cap_fraction*n)
                bound,_=finite_key_bound(n,k,cfg.q_tolerance,budget,
                                         cfg.eps_secrecy,cfg.eps_correctness)
                if leak>budget:
                    status='ABORT_EC_BUDGET'
                elif not agree:
                    status='ABORT_VERIFICATION'
                elif bound<max(256,cfg.output_key_bits,cfg.min_final_key_bits):
                    status='ABORT_FINITE_KEY'
                else:
                    pa_seed=kbits(seed+72883,n+cfg.output_key_bits-1)
                    pmsg=message('pa_seed_a',{'n':len(pa_seed),'bits':pack_bits(pa_seed)})
                    ps=read_bits(pmsg['bits'],len(pa_seed))
                    a.final=np.packbits(toeplitz_hash(a.raw,ps,cfg.output_key_bits),bitorder='big').tobytes()
                    b.final=np.packbits(toeplitz_hash(b.raw,ps,cfg.output_key_bits),bitorder='big').tobytes()
                    if not hmac.compare_digest(a.final,b.final):
                        raise Abort('Independent final key disagreement')
                    status='MODEL_ACCEPT'
    # Two independently generated status reports. Do not expose raw key strings.
    for endpoint,kind in [(a,'report_a'),(b,'report_b')]:
        endpoint.status=status
        message(kind,{'status':endpoint.status,'x_qber_ppm':round(xq*1e6) if xq is not None else None,
                      'ec_disclosure_upper_bits':leak,'bound':bound,
                      'has_key':bool(endpoint.final)})
    qkd_ok=(a.final is not None and b.final is not None and status=='MODEL_ACCEPT')
    mode=('HYBRID' if qkd_ok else 'PQC_ONLY' if policy!=Policy.HYBRID_REQUIRED else 'ABORT')
    # Signed decision binds the policy and all previously exchanged frames.
    pre_mode_digest=relay.digest()
    d={'mode':mode,'policy':policy.value,'qkd_status':status,'pre_mode_digest':pre_mode_digest}
    da=message('mode_a',d)
    db=message('mode_b',{**d,'alice_mode_hash':sha(encode(da)).hex()})
    if db['alice_mode_hash']!=sha(encode(da)).hex():
        raise Abort('Mode inconsistency')
    a.mode=b.mode=mode
    confirmed=False
    if mode!='ABORT':
        digest=bytes.fromhex(relay.digest())
        aq=a.final if mode=='HYBRID' else None
        bq=b.final if mode=='HYBRID' else None
        akeys=_schedule(pqc.session_key_alice,aq,mode,digest)
        bkeys=_schedule(pqc.session_key_bob,bq,mode,digest)
        for label in ('alice','bob'):
            mac1=hmac.new(akeys[f'{label}_confirm'],b'P7-MODE-CONFIRM'+digest,hashlib.sha256).digest()
            mac2=hmac.new(bkeys[f'{label}_confirm'],b'P7-MODE-CONFIRM'+digest,hashlib.sha256).digest()
            if not hmac.compare_digest(mac1,mac2):
                raise Abort('Hybrid key confirmation mismatch')
        sid_record=digest.hex()
        rec=seal_record(akeys['A2B_key'],akeys['A2B_iv'],sid_record,mode,'A2B',0,
                        b'Program 7: independent endpoint test record')
        receive=RecordReceiver(bkeys['A2B_key'],bkeys['A2B_iv'],sid_record,mode,'A2B')
        confirmed=(receive.open(rec)==b'Program 7: independent endpoint test record')
        if not confirmed: raise Abort('Record mismatch')
    return Result(mode,status,bound,xq,leak,queries,rounds,flips,relay.frames,
                  relay.bytes,(a.final is not None and hmac.compare_digest(a.final,b.final)) if qkd_ok else False,
                  confirmed,relay.digest(),round((time.perf_counter()-t0)*1000,3))
