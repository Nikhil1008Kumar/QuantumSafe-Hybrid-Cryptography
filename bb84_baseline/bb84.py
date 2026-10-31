"""Educational BB84 prepare-and-measure Monte Carlo simulator.

Scope: ideal BB84 state/basis measurement, optional intercept-resend attack,
independent post-measurement bit-flip noise, independent loss, random public
parameter-estimation sample. No authenticated classical channel, error
correction, privacy amplification, source/detector imperfections, or security
proof. Output retained bits are UNRECONCILED RAW BITS, NOT SECRET KEYS.

Reproducibility: NumPy Generator with caller-specified RNG seed.
"""

from __future__ import annotations

from dataclasses import dataclass
import math
import time
import numpy as np


@dataclass(frozen=True)
class BB84Config:
    transmitted_signals: int = 10_000
    intercept_probability: float = 0.0
    noise_probability: float = 0.0
    loss_probability: float = 0.0
    test_fraction: float = 0.20

    def __post_init__(self) -> None:
        if self.transmitted_signals < 1:
            raise ValueError('transmitted_signals must be >= 1')
        for name in ('intercept_probability', 'noise_probability',
                     'loss_probability'):
            value = getattr(self, name)
            if not math.isfinite(value) or not (0 <= value <= 1):
                raise ValueError(f'{name} must be finite and within [0, 1]')
        if not math.isfinite(self.test_fraction) or not (0 < self.test_fraction <= 1):
            raise ValueError('test_fraction must be finite and within (0, 1]')


@dataclass(frozen=True)
class BB84Result:
    transmitted_signals: int
    received_signals: int
    sifted_bits: int
    publicly_revealed_bits: int
    publicly_revealed_errors: int
    estimated_qber: float
    retained_raw_bits: int
    retained_raw_mismatches_diagnostic: int
    complete_sifted_qber_diagnostic: float
    runtime_ms: float


def expected_qber(intercept_probability: float, noise_probability: float = 0.0) -> float:
    """Expected sifted QBER in the *specific* independent-noise model.

    Assumes independent intercept-resend with Eve's random Z/X basis,
    independent bit flips with probability noise_probability *after* Bob's
    quantum-basis measurement, and basis-independent losses.
    """
    for name, value in [('intercept_probability', intercept_probability),
                        ('noise_probability', noise_probability)]:
        if not math.isfinite(value) or not 0 <= value <= 1:
            raise ValueError(f'{name} must be in [0,1]')
    q_eve = intercept_probability / 4.0
    return noise_probability + (1 - 2 * noise_probability) * q_eve


def simulate(config: BB84Config, seed: int) -> BB84Result:
    """Run one full BB84 transmission and publicly sample sifted positions.

    Alice's and Bob's bases are independent and unbiased. All unreceived
    signals are discarded. Eve intercepts independently with configured
    probability; if Eve uses the wrong basis her measurement is uniform.
    Bob's measurement is uniform if his basis does not match the forwarded
    state. Testing positions are sampled *uniformly without replacement*.

    complete_sifted_qber_diagnostic and retained_raw_mismatches_diagnostic
    require privileged simulator access to both sides' private bits; neither
    value is available to a deployed BB84 endpoint without disclosure.
    """
    rng = np.random.default_rng(seed)
    t0 = time.perf_counter_ns()
    n = config.transmitted_signals
    alice_bits = rng.integers(0, 2, size=n, dtype=np.uint8)
    alice_bases = rng.integers(0, 2, size=n, dtype=np.uint8)
    bob_bases = rng.integers(0, 2, size=n, dtype=np.uint8)

    # Physical-independent channel losses; Bob obtains no bit when lost.
    received = rng.random(n) >= config.loss_probability

    eve_intercepts = (rng.random(n) < config.intercept_probability) & received
    eve_bases = rng.integers(0, 2, size=n, dtype=np.uint8)
    eve_random_outcomes = rng.integers(0, 2, size=n, dtype=np.uint8)
    eve_bits = np.where(eve_bases == alice_bases, alice_bits, eve_random_outcomes)

    forwarded_bits = np.where(eve_intercepts, eve_bits, alice_bits)
    forwarded_bases = np.where(eve_intercepts, eve_bases, alice_bases)
    bob_random_outcomes = rng.integers(0, 2, size=n, dtype=np.uint8)
    bob_bits = np.where(bob_bases == forwarded_bases, forwarded_bits, bob_random_outcomes)
    noise_flips = rng.random(n) < config.noise_probability
    bob_bits = np.bitwise_xor(bob_bits, noise_flips.astype(np.uint8))

    sifted_positions = np.flatnonzero(received & (alice_bases == bob_bases))
    count_sifted = int(sifted_positions.size)
    count_received = int(np.count_nonzero(received))
    if count_sifted == 0:
        return BB84Result(n, count_received, 0, 0, 0, float('nan'), 0, 0,
                          float('nan'), (time.perf_counter_ns() - t0) / 1e6)

    # A genuine random subset, not the first entries. Leave at least one raw
    # bit when possible, but never label it a secret/final key.
    public_count = min(max(1, math.floor(count_sifted * config.test_fraction)),
                       count_sifted - 1 if count_sifted > 1 else 1)
    public_indices_in_sift = rng.choice(count_sifted, size=public_count,
                                        replace=False)
    publicly_revealed_positions = sifted_positions[public_indices_in_sift]
    errors_public = int(np.count_nonzero(
        alice_bits[publicly_revealed_positions] != bob_bits[publicly_revealed_positions]))

    retained_mask_in_sift = np.ones(count_sifted, dtype=bool)
    retained_mask_in_sift[public_indices_in_sift] = False
    retained_positions = sifted_positions[retained_mask_in_sift]
    retained_mismatches = int(np.count_nonzero(
        alice_bits[retained_positions] != bob_bits[retained_positions]))
    all_sift_mismatch_count = int(np.count_nonzero(
        alice_bits[sifted_positions] != bob_bits[sifted_positions]))

    return BB84Result(
        transmitted_signals=n,
        received_signals=count_received,
        sifted_bits=count_sifted,
        publicly_revealed_bits=public_count,
        publicly_revealed_errors=errors_public,
        estimated_qber=errors_public / public_count,
        retained_raw_bits=int(retained_positions.size),
        retained_raw_mismatches_diagnostic=retained_mismatches,
        complete_sifted_qber_diagnostic=all_sift_mismatch_count / count_sifted,
        runtime_ms=(time.perf_counter_ns() - t0) / 1e6,
    )
