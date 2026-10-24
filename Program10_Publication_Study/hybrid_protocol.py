"""Program 4: simulated finite-key BB84 + authenticated ML-KEM/ML-DSA + AES-256-GCM.

Research demonstration only. QKD classical exchange is modeled in a trusted
single-process simulator, not an actual message-by-message authenticated network.
BB84 simulation randomness is seeded for reproducibility, NOT suitable for
cryptographic operation. HKDF's concatenated-secret construction has not been
formally established as a robust hybrid combiner under arbitrary compromise.
This module makes no end-to-end composable-security or hardware claims.
"""
from __future__ import annotations

import hashlib
import hmac
import os
import time
from dataclasses import dataclass, asdict
from enum import Enum
from typing import Any, Callable
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from finite_key_bb84 import FiniteKeyConfig, FiniteKeyResult, run_with_material
from pqc_protocol import (OpenSSLBackend, Identity, ProtocolAbort, b64, unb64,
                          encode, sha, hkdf, negotiate, sign_envelope,
                          verify_envelope)

VERSION = 'research-bb84-pqc-aead-v1'


class Policy(str, Enum):
    HYBRID_REQUIRED = 'HYBRID_REQUIRED'
    HYBRID_PREFERRED = 'HYBRID_PREFERRED'
    PQC_ONLY = 'PQC_ONLY'


class HybridAbort(ProtocolAbort):
    def __init__(self, message: str, stage: str, qkd_status: str = 'NOT_RUN'):
        super().__init__(message)
        self.stage = stage
        self.qkd_status = qkd_status


TransportMutator = Callable[[str, dict], dict]


@dataclass
class HybridResult:
    mode: str
    policy: str
    qkd_status: str
    qkd_bound_bits: int
    qkd_observed_x_qber: float | None
    qkd_ec_leakage_bits: int
    qkd_runtime_ms: float
    handshake_runtime_ms: float
    complete_runtime_ms: float
    ciphertext_bytes: int
    on_wire_bytes: int
    session_context_hash: str
    recovered_plaintext: bytes  # local assertion only, never written to CSV/logs
    application_keys_match: bool


def _validated_envelope(backend: OpenSSLBackend, pinned: bytes,
                        envelope: dict, expect: dict) -> dict:
    body = verify_envelope(backend, pinned, envelope)
    if set(body) != set(expect) or any(body[k] != v for k, v in expect.items()):
        raise ProtocolAbort('Signed message fields or content disagree')
    return body


def _bytes_to_b64tag(data: bytes, label: bytes, key: bytes) -> str:
    return b64(hmac.new(key, label + data, hashlib.sha256).digest())


class RecordReceiver:
    """One-direction AES-GCM record receiver with replay rejection.

    Uses 96-bit deterministic nonce = 4-byte HKDF-derived prefix || 8-byte
    sequence. A distinct traffic key and prefix exist for each direction.
    Rejects duplicates and only records a sequence after successful AEAD check.
    Sequence uniqueness relies on session key freshness and no counter rollback.
    """
    def __init__(self, key: bytes, prefix: bytes, session_id: str,
                 mode: str, direction: str):
        if len(key) != 32 or len(prefix) != 4 or direction not in ('A2B', 'B2A'):
            raise ValueError('Invalid GCM record parameters')
        self.key, self.prefix = key, prefix
        self.session_id, self.mode, self.direction = session_id, mode, direction
        self.seen: set[int] = set()

    def _aad(self, seq: int) -> bytes:
        return encode({'protocol':VERSION, 'session_id':self.session_id,
                       'mode':self.mode, 'direction':self.direction, 'seq':seq})

    def open(self, record: dict) -> bytes:
        if not isinstance(record, dict) or set(record) != {
                'protocol','session_id','mode','direction','seq','nonce','ciphertext'}:
            raise ProtocolAbort('Malformed encrypted record')
        seq = record['seq']
        if type(seq) is not int or seq < 0 or seq >= 2**64 or seq in self.seen:
            raise ProtocolAbort('Invalid or replayed record sequence')
        if (record['protocol'] != VERSION or record['session_id'] != self.session_id or
                record['mode'] != self.mode or record['direction'] != self.direction):
            raise ProtocolAbort('Record authenticated context mismatch')
        expected_nonce = self.prefix + seq.to_bytes(8, 'big')
        if unb64(record['nonce'], 20) != expected_nonce:
            raise ProtocolAbort('Unexpected record nonce')
        ciphertext = unb64(record['ciphertext'], 1_100_000)
        try:
            plaintext = AESGCM(self.key).decrypt(expected_nonce, ciphertext, self._aad(seq))
        except InvalidTag as exc:
            raise ProtocolAbort('AES-GCM authentication tag rejected') from exc
        self.seen.add(seq)
        return plaintext


def seal_record(key: bytes, prefix: bytes, session_id: str,
                mode: str, direction: str, seq: int, plaintext: bytes) -> dict:
    if type(seq) is not int or not 0 <= seq < 2**64 or len(plaintext) > 1_000_000:
        raise ValueError('Unsupported sequence/record length')
    if len(key) != 32 or len(prefix) != 4 or direction not in ('A2B','B2A'):
        raise ValueError('Invalid record key/IV/direction')
    nonce = prefix + seq.to_bytes(8,'big')
    aad = encode({'protocol':VERSION, 'session_id':session_id,
                  'mode':mode, 'direction':direction, 'seq':seq})
    ciphertext = AESGCM(key).encrypt(nonce, plaintext, aad)
    return {'protocol':VERSION,'session_id':session_id,'mode':mode,
            'direction':direction,'seq':seq,'nonce':b64(nonce),
            'ciphertext':b64(ciphertext)}


def _schedule(pqc_secret: bytes, qkd_secret: bytes | None, mode: str,
              context: bytes) -> dict[str, bytes]:
    """Experimental domain-separated HKDF schedule; NOT a proved robust combiner."""
    if len(pqc_secret) != 32:
        raise ProtocolAbort('Wrong KEM-derived bootstrap key length')
    if mode == 'HYBRID':
        if qkd_secret is None or len(qkd_secret) != 32:
            raise ProtocolAbort('Missing accepted 256-bit QKD key')
        ikm = b'P4-HYBRID\x00' + pqc_secret + qkd_secret
    elif mode == 'PQC_ONLY':
        if qkd_secret is not None:
            raise ProtocolAbort('PQC-only may not claim QKD contribution')
        ikm = b'P4-PQC-ONLY\x00' + pqc_secret
    else:
        raise ProtocolAbort('Unknown mode')
    salt = sha(b'Program4/v1/transcript-salt\x00' + context)
    labels = ('A2B_key', 'B2A_key', 'A2B_iv', 'B2A_iv',
              'alice_confirm', 'bob_confirm')
    return {label: hkdf(ikm, salt, b'Program4/v1/' + label.encode() + b'/' + mode.encode()
                        + b'/' + context, 4 if label.endswith('_iv') else 32)
            for label in labels}


def run_hybrid(backend: OpenSSLBackend, alice: Identity, bob: Identity,
               cfg: FiniteKeyConfig, qkd_seed: int, policy: Policy,
               plaintext: bytes = b'Confidential research message',
               mutator: TransportMutator | None = None,
               handshake_mutator: TransportMutator | None = None) -> HybridResult:
    if not isinstance(policy, Policy):
        raise ValueError('policy must be an explicit Policy enum')
    if not isinstance(plaintext, bytes) or len(plaintext) > 1_000_000:
        raise ValueError('Plaintext must be <=1MB bytes')
    start = time.perf_counter_ns()
    wire_bytes = 0

    def transfer(stage: str, message: dict) -> dict:
        nonlocal wire_bytes
        sent = mutator(stage, message) if mutator else message
        if not isinstance(sent, dict):
            raise ProtocolAbort('Transport message must be a dictionary')
        wire_bytes += len(encode(sent))
        return sent

    # Bootstrap authenticated ML-KEM/ML-DSA exchange from Program 3.
    bootstrap = negotiate(backend, alice, bob, mutator=handshake_mutator)
    if bootstrap.session_key_alice != bootstrap.session_key_bob:
        raise ProtocolAbort('PQC bootstrap key disagreement')
    wire_bytes += bootstrap.on_wire_bytes
    bootstrap_digest = bootstrap.transcript_hash

    # Application policy is signed by BOTH sides and binds the bootstrap and
    # predeclared QKD configuration before QKD simulation starts.
    cfg_digest = sha(encode(asdict(cfg))).hex()
    offer = {'protocol':VERSION, 'type':'policy_offer', 'alice':alice.name,
             'bob':bob.name, 'policy':policy.value, 'qkd_cfg_sha256':cfg_digest,
             'bootstrap_sha256':bootstrap_digest}
    alice_offer = transfer('policy_offer',sign_envelope(backend,alice.signing_private,offer))
    _validated_envelope(backend,alice.signing_public,alice_offer,offer)
    ack = {'protocol':VERSION, 'type':'policy_ack', 'alice':alice.name,
           'bob':bob.name,'policy':policy.value,
           'offer_sha256':sha(encode(alice_offer)).hex(),
           'bootstrap_sha256':bootstrap_digest}
    bob_ack = transfer('policy_ack',sign_envelope(backend,bob.signing_private,ack))
    _validated_envelope(backend,bob.signing_public,bob_ack,ack)

    qkd_status = 'NOT_RUN'
    qkd_bound = 0
    qkd_qber = None
    qkd_ec = 0
    qkd_elapsed = 0.0
    qkd_a = qkd_b = None
    if policy != Policy.PQC_ONLY:
        # Privileged single-process QKD model: DOES NOT exchange real classical
        # BB84 messages. This is a simulation bridge, with authenticated
        # end-of-run receipts; QKD classical transcript is an assumption.
        qkd_result, secrets = run_with_material(cfg, qkd_seed)
        qkd_status = qkd_result.status
        qkd_bound = qkd_result.finite_bound_bits
        qkd_ec = qkd_result.ec_public_bits
        qkd_qber = (qkd_result.x_qber if qkd_result.test_x_used else None)
        qkd_elapsed = qkd_result.runtime_ms
        if qkd_status == 'ACCEPT':
            if not secrets or qkd_result.final_bits != 256:
                raise ProtocolAbort('QKD accepted without 256-bit material')
            qkd_a, qkd_b = secrets

    report = {'protocol':VERSION,'type':'qkd_report', 'qkd_status':qkd_status,
              'bound_bits':qkd_bound,'key_bits':256 if qkd_a is not None else 0,
              'parameter_config_sha256':cfg_digest, 'bootstrap_sha256':bootstrap_digest}
    signed_a_report = transfer('qkd_alice',sign_envelope(backend,alice.signing_private,report))
    _validated_envelope(backend,alice.signing_public,signed_a_report,report)
    report_b = dict(report, type='qkd_report_ack',
                    alice_report_sha256=sha(encode(signed_a_report)).hex())
    signed_b_report = transfer('qkd_bob',sign_envelope(backend,bob.signing_private,report_b))
    _validated_envelope(backend,bob.signing_public,signed_b_report,report_b)

    if policy == Policy.PQC_ONLY:
        mode = 'PQC_ONLY'
    elif qkd_a is not None:
        mode = 'HYBRID'
    elif policy == Policy.HYBRID_PREFERRED:
        mode = 'PQC_ONLY'
    else:
        raise HybridAbort('Hybrid required but QKD admission failed', 'qkd_admission',qkd_status)

    decision = {'protocol':VERSION,'type':'mode_decision', 'policy':policy.value,
                'mode':mode,'bootstrap_sha256':bootstrap_digest,
                'qkd_receipts_sha256':sha(encode([signed_a_report,signed_b_report])).hex()}
    dec_a = transfer('mode_decision', sign_envelope(backend,alice.signing_private,decision))
    _validated_envelope(backend,alice.signing_public,dec_a,decision)
    agreement = dict(decision,type='mode_agreement',
                     decision_sha256=sha(encode(dec_a)).hex())
    dec_b = transfer('mode_agreement', sign_envelope(backend,bob.signing_private,agreement))
    _validated_envelope(backend,bob.signing_public,dec_b,agreement)
    context = sha(encode([bootstrap_digest,alice_offer,bob_ack,
                          signed_a_report,signed_b_report,dec_a,dec_b]))
    session_id = context.hex()

    # Each endpoint derives its keys from its own (simulated) QKD material.
    alice_keys = _schedule(bootstrap.session_key_alice,
                           qkd_a if mode == 'HYBRID' else None, mode, context)
    bob_keys = _schedule(bootstrap.session_key_bob,
                         qkd_b if mode == 'HYBRID' else None, mode, context)

    def confirm(stage: str, sender_keys: dict, receiver_keys: dict, label: str):
        keylabel = label + '_confirm'
        msg = {'protocol':VERSION, 'type':stage, 'session_id':session_id,
               'mac':_bytes_to_b64tag(context,stage.encode(),sender_keys[keylabel])}
        received = transfer(stage, msg)
        if set(received) != set(msg) or received.get('type') != stage or received.get('session_id') != session_id:
            raise ProtocolAbort('Finished frame mismatch')
        if not hmac.compare_digest(unb64(received['mac'],64),
                                   unb64(_bytes_to_b64tag(context,stage.encode(),receiver_keys[keylabel]),64)):
            raise ProtocolAbort('Session confirmation failed')

    confirm('bob_finished',bob_keys,alice_keys,'bob')
    confirm('alice_finished',alice_keys,bob_keys,'alice')
    handshake_ms = (time.perf_counter_ns()-start)/1e6
    sender_record = seal_record(alice_keys['A2B_key'],alice_keys['A2B_iv'],
                                session_id, mode, 'A2B',0,plaintext)
    received_record = transfer('record',sender_record)
    receiver = RecordReceiver(bob_keys['A2B_key'],bob_keys['A2B_iv'],
                              session_id,mode,'A2B')
    decrypted = receiver.open(received_record)
    if decrypted != plaintext:
        raise ProtocolAbort('Application plaintext integrity mismatch')
    # Do not serialize session keys or plaintext in result CSVs.
    return HybridResult(mode=mode,policy=policy.value,qkd_status=qkd_status,
            qkd_bound_bits=qkd_bound,qkd_observed_x_qber=qkd_qber,
            qkd_ec_leakage_bits=qkd_ec,qkd_runtime_ms=qkd_elapsed,
            handshake_runtime_ms=handshake_ms,
            complete_runtime_ms=(time.perf_counter_ns()-start)/1e6,
            ciphertext_bytes=len(unb64(received_record['ciphertext'],1_100_000)),
            on_wire_bytes=wire_bytes,session_context_hash=session_id,
            recovered_plaintext=decrypted,
            application_keys_match=hmac.compare_digest(alice_keys['A2B_key'],bob_keys['A2B_key']))
