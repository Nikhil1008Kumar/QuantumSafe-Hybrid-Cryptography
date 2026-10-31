"""Program 8: bounded, explicit-state model of the authenticated mode handshake.

MODEL scope, not a cryptographic proof: signatures are ideal authentication tags;
QKD certification and ML-KEM security are assumptions supplied as booleans;
network attacker actions are enumerated, one attack per trace (max 8 steps).
No quantitative quantum entropy or hybrid combiner secrecy is verified here.
"""
from __future__ import annotations
from dataclasses import dataclass, replace, asdict
from collections import deque, Counter
from itertools import product
from typing import Iterable

STAGES = ('policy_a', 'policy_b', 'report_a', 'report_b',
          'mode_a', 'mode_b', 'confirm_a', 'confirm_b')
AUTHORS = ('alice','bob','alice','bob','alice','bob','alice','bob')
POLICIES = ('HYBRID_REQUIRED', 'HYBRID_PREFERRED', 'PQC_ONLY')
ACTIONS = ('deliver', 'forge', 'cross_session_replay', 'replay_prior',
           'reorder', 'drop', 'peer_mode_conflict')

@dataclass(frozen=True)
class Guards:
    auth: bool = True
    session: bool = True
    sequence_stage: bool = True
    policy: bool = True
    role_agreement: bool = True
    key_confirmation: bool = True

@dataclass(frozen=True)
class State:
    policy: str
    certified_qkd: bool
    kem_ok: bool
    keys_equal: bool
    index: int = 0
    mode_alice: str = ''
    mode_bob: str = ''
    status: str = 'RUNNING'
    accepted_forgery: bool = False
    accepted_cross_session: bool = False
    accepted_out_of_stage: bool = False
    trace: tuple[str, ...] = ()

@dataclass(frozen=True)
class Outcome:
    valid: bool
    reason: str
    state: State


def intended_mode(policy: str, qkd_ok: bool, kem_ok: bool) -> str:
    if not kem_ok:
        return 'ABORT'
    if policy == 'PQC_ONLY':
        return 'PQC_ONLY'
    if qkd_ok:
        return 'HYBRID'
    return 'PQC_ONLY' if policy == 'HYBRID_PREFERRED' else 'ABORT'


def transition(s: State, action: str, guards: Guards = Guards()) -> State:
    """Deliver one attacker-controlled network action at current signed frame.

    Replay_prior/forged/cross-session are symbolic messages: attacker cannot
    generate a valid signature from a pinned uncompromised key; prior frames
    have authentic signatures but stale stage/session. Mode conflict represents
    a validly signed, incorrectly configured Bob, checked against local policy.
    """
    if s.status != 'RUNNING':
        return s
    if s.index >= len(STAGES):
        raise ValueError('invalid state index')
    if action not in ACTIONS:
        raise ValueError('unsupported attack action')
    msg = STAGES[s.index]
    trace = s.trace + (f'{msg}:{action}',)
    if action == 'drop':
        return replace(s, status='STALLED', trace=trace)
    if action == 'forge' and guards.auth:
        return replace(s, status='REJECT', trace=trace)
    if action == 'cross_session_replay' and guards.session:
        return replace(s, status='REJECT', trace=trace)
    if action in ('replay_prior','reorder') and guards.sequence_stage:
        return replace(s, status='REJECT', trace=trace)
    if action == 'peer_mode_conflict' and msg != 'mode_b':
        return replace(s, status='REJECT', trace=trace)

    s = replace(s,
      accepted_forgery=s.accepted_forgery or action == 'forge',
      accepted_cross_session=s.accepted_cross_session or action == 'cross_session_replay',
      accepted_out_of_stage=s.accepted_out_of_stage or action in ('replay_prior','reorder'),
      trace=trace)

    if msg == 'mode_a':
        if guards.policy:
            mode = intended_mode(s.policy, s.certified_qkd, s.kem_ok)
        else:
            # Deliberately faulty controller: silent PQC downgrade is allowed.
            mode = 'HYBRID' if s.certified_qkd and s.kem_ok else ('PQC_ONLY' if s.kem_ok else 'ABORT')
        return replace(s, mode_alice=mode, index=s.index+1)
    if msg == 'mode_b':
        bob_mode = intended_mode(s.policy,s.certified_qkd,s.kem_ok)
        if not guards.policy:
            bob_mode = s.mode_alice
        if action == 'peer_mode_conflict':
            bob_mode = 'PQC_ONLY' if s.mode_alice != 'PQC_ONLY' else 'HYBRID'
        if guards.role_agreement and (bob_mode != s.mode_alice or
                                      bob_mode != intended_mode(s.policy,s.certified_qkd,s.kem_ok)):
            return replace(s,mode_bob=bob_mode,status='REJECT',trace=trace)
        return replace(s,mode_bob=bob_mode,index=s.index+1)
    if msg == 'confirm_b':
        if guards.key_confirmation and not s.keys_equal and s.mode_alice != 'ABORT':
            return replace(s,status='REJECT',trace=trace)
        if guards.role_agreement and s.mode_bob != s.mode_alice:
            return replace(s,status='REJECT',trace=trace)
        finish = 'ABORT' if s.mode_alice=='ABORT' else 'ACCEPT'
        return replace(s,status=finish,index=s.index+1)
    return replace(s,index=s.index+1)


def invariant_violations(s: State) -> list[str]:
    failures=[]
    if s.accepted_forgery:
        failures.append('Forged payload was accepted as authentic')
    if s.accepted_cross_session:
        failures.append('Signed message from a different session was accepted')
    if s.accepted_out_of_stage:
        failures.append('A replayed or out-of-order signed message was accepted')
    if s.mode_alice=='HYBRID' and (not s.certified_qkd or not s.kem_ok):
        failures.append('Hybrid selected without both authorized key inputs')
    if s.status=='ACCEPT':
        if not s.kem_ok:
            failures.append('Accepted without KEM establishment')
        if s.policy=='HYBRID_REQUIRED' and s.mode_alice!='HYBRID':
            failures.append('Silent fallback violates QKD-required policy')
        if s.policy=='PQC_ONLY' and s.mode_alice!='PQC_ONLY':
            failures.append('PQC-only policy selected another mode')
        if s.mode_alice != s.mode_bob:
            failures.append('Alice/Bob finished with different modes')
        if not s.keys_equal:
            failures.append('Accepted despite failed key confirmation')
    return failures


def scenarios() -> Iterable[State]:
    for p,q,k,a in product(POLICIES,(False,True),(False,True),(False,True)):
        yield State(p,q,k,a)


def explore(guards: Guards = Guards(), max_attacks: int = 1) -> dict:
    """Exhaustive exploration of enumerated traces with <=max_attacks deviations.

    The state space is finite and bounded. No symbolic Dolev-Yao closure or
    arbitrary concurrency is claimed. `max_attacks` may be 0,1 or 2.
    """
    if not 0 <= max_attacks <= 2:
        raise ValueError('allowed deviation count: 0..2')
    count = Counter()
    violations={}
    outcomes=[]
    visited=0
    for starting in scenarios():
        queue=deque([(starting,0)])
        seen={(starting,0)}
        while queue:
            s,num_attacks=queue.popleft()
            visited+=1
            found=invariant_violations(s)
            for failure in found:
                violations.setdefault(failure, {'policy':s.policy,'qkd':s.certified_qkd,
                    'kem':s.kem_ok,'keys_equal':s.keys_equal,
                    'trace':list(s.trace),'status':s.status})
            if s.status!='RUNNING':
                count[s.status]+=1
                outcomes.append(s)
                continue
            for action in ACTIONS:
                delta=int(action!='deliver')
                if num_attacks+delta>max_attacks:
                    continue
                nxt=transition(s,action,guards)
                key=(nxt,num_attacks+delta)
                if key not in seen:
                    seen.add(key);queue.append((nxt,num_attacks+delta))
    return {'scenarios':len(tuple(scenarios())),
            'max_protocol_frames':len(STAGES),
            'max_attacks_per_trace':max_attacks,
            'states_explored':visited,
            'completed_trace_counts':dict(count),
            'violations':violations,
            'model_guards':asdict(guards),
            'note':'Bounded symbolic-state exploration; NOT an unbounded cryptographic or QKD secrecy proof.'}


def negative_controls() -> dict:
    variants = {
        'no_authentication_check': replace(Guards(),auth=False),
        'no_session_binding': replace(Guards(),session=False),
        'no_sequence_or_stage_check': replace(Guards(),sequence_stage=False),
        'no_policy_check': replace(Guards(),policy=False,role_agreement=False),
        'no_mode_agreement_check': replace(Guards(),role_agreement=False),
        'no_key_confirmation': replace(Guards(),key_confirmation=False),
    }
    return {name:explore(g,1) for name,g in variants.items()}
