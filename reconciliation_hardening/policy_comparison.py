"""Program 5: paired QKD admission policy comparisons on identical simulations.

All QKD outcomes are obtained with finite_key_bb84.run(), with seeds held equal
across controller comparisons. This models a privileged simulator, NOT a
networked QKD public-message protocol. It does not implement a cryptographic
security proof or a novel robust KEM combiner.
"""
from __future__ import annotations
from dataclasses import dataclass, replace
from enum import Enum
import math
from finite_key_bb84 import FiniteKeyResult
from hybrid_protocol import Policy

class Mode(str, Enum):
    HYBRID = 'HYBRID'
    PQC_ONLY = 'PQC_ONLY'
    ABORT = 'ABORT'

class Strategy(str, Enum):
    PROPOSED = 'FINITE_KEY_POLICY'
    QBER_ONLY = 'QBER_11_PERCENT'
    FINITE_NO_FALLBACK = 'FINITE_KEY_NO_FALLBACK'
    PQC_ONLY = 'PQC_ONLY_BASELINE'

@dataclass(frozen=True)
class VerifiedContext:
    """Indicators for earlier authenticated checks, NOT substitutes for signatures.

    Program 4 verifies real signed envelopes and transcript MACs. Program 5
    studies the *decision layer only*: it assumes those prior checks were
    performed and rejects when any check fails. A random bit toggle of these
    fields is NOT a cryptographic forgery experiment.
    """
    authenticated_identities: bool = True
    signed_policy_verified: bool = True
    signed_qkd_receipts_verified: bool = True
    transcript_consistent: bool = True
    fresh_session: bool = True
    kem_ready: bool = True

    @property
    def valid(self) -> bool:
        return (self.authenticated_identities and self.signed_policy_verified and
                self.signed_qkd_receipts_verified and self.transcript_consistent and
                self.fresh_session and self.kem_ready)

@dataclass(frozen=True)
class QKDObservation:
    status: str
    x_qber: float | None
    x_bits: int
    bound_bits: int
    output_bits: int
    key_verification_passed: bool
    ec_leakage_bits: int
    ec_budget_bits: int

    @classmethod
    def from_result(cls, result: FiniteKeyResult) -> 'QKDObservation':
        return cls(status=result.status,
                   x_qber=result.x_qber if result.test_x_used else None,
                   x_bits=result.test_x_used,
                   bound_bits=result.finite_bound_bits,
                   output_bits=result.final_bits,
                   key_verification_passed=result.verification_passed,
                   ec_leakage_bits=result.ec_public_bits,
                   ec_budget_bits=result.ec_leakage_budget_bits)

    @property
    def finite_key_admitted(self) -> bool:
        """Model-certificate admission: not an independent security oracle."""
        return (self.status == 'ACCEPT' and self.output_bits == 256 and
                self.bound_bits >= 256 and self.key_verification_passed and
                self.ec_leakage_bits <= self.ec_budget_bits and self.x_bits > 0)

    @property
    def qber11_admitted(self) -> bool:
        # Intentionally naive baseline: ignores finite key length, EC leakage,
        # correctness, privacy amplification and the predeclared 4% tolerance.
        return (self.x_qber is not None and math.isfinite(self.x_qber) and
                self.x_bits > 0 and self.x_qber <= 0.11)

@dataclass(frozen=True)
class Decision:
    strategy: Strategy
    policy: Policy
    mode: Mode
    qkd_qualified: bool
    model_invalid_hybrid: bool
    reason: str


def _mode(qualified: bool, policy: Policy) -> Mode:
    if policy is Policy.PQC_ONLY:
        return Mode.PQC_ONLY
    if qualified:
        return Mode.HYBRID
    if policy is Policy.HYBRID_PREFERRED:
        return Mode.PQC_ONLY
    return Mode.ABORT


def decide(strategy: Strategy, policy: Policy, observation: QKDObservation | None,
           checks: VerifiedContext = VerifiedContext()) -> Decision:
    """Compare strategies under identical authenticated precondition checks.

    Any session marked HYBRID by the QBER-only baseline but failing our
    finite-key simulator's certificate is counted as an *in-model invalid
    QKD admission*. It is NOT evidence that any real-world key was leaked.
    """
    if not isinstance(strategy, Strategy) or not isinstance(policy, Policy):
        raise TypeError('Use Strategy and Policy enum values')
    if not isinstance(checks, VerifiedContext):
        raise TypeError('Expected VerifiedContext')
    if not checks.valid:
        return Decision(strategy, policy, Mode.ABORT, False, False,
                        'FAILED_AUTHENTICATED_PRECONDITION')
    if observation is None and policy is not Policy.PQC_ONLY:
        # A non-PQC-only policy expects QKD to have been attempted. An
        # explicit failure observation is needed even for fallback.
        return Decision(strategy, policy, Mode.ABORT, False, False,
                        'MISSING_QKD_REPORT')
    finite = observation.finite_key_admitted if observation else False
    qber = observation.qber11_admitted if observation else False
    if strategy is Strategy.PROPOSED:
        selected = _mode(finite, policy)
    elif strategy is Strategy.QBER_ONLY:
        selected = _mode(qber, policy)
    elif strategy is Strategy.FINITE_NO_FALLBACK:
        selected = (Mode.PQC_ONLY if policy is Policy.PQC_ONLY else
                    Mode.HYBRID if finite else Mode.ABORT)
    elif strategy is Strategy.PQC_ONLY:
        # Baseline respects HYBRID_REQUIRED: it cannot satisfy the policy
        # by pretending a PQC-only session contains accepted QKD material.
        selected = Mode.ABORT if policy is Policy.HYBRID_REQUIRED else Mode.PQC_ONLY
    else:
        raise AssertionError('Unhandled strategy')
    invalid_hybrid = (selected is Mode.HYBRID and not finite)
    return Decision(strategy, policy, selected, selected is Mode.HYBRID and finite,
                    invalid_hybrid,
                    'CERTIFIED_QKD' if selected is Mode.HYBRID and finite else
                    'UNCERTIFIED_QKD_MODE' if invalid_hybrid else
                    'PERMITTED_PQC' if selected is Mode.PQC_ONLY else 'POLICY_ABORT')


def mutate_context(base: VerifiedContext, field: str) -> VerifiedContext:
    if field not in base.__dataclass_fields__:
        raise ValueError('Unknown precondition')
    return replace(base, **{field: False})
