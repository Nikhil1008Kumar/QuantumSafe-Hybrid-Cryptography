"""Program 2: finite-key-aware *simulated* ideal single-qubit BB84.

Educational / research prototype; no actual quantum devices, no classical-channel
implementation, no hardware-security guarantee. Classical messages are assumed
to arrive on an authenticated channel, as required by the cited finite-key
security theorem. NumPy's seeded generator is a simulator, NOT a production
cryptographic random-number generator.

Uses the bound in Tomamichel, Lim, Gisin & Renner, Nat Commun 3, 634 (2012),
Eq. (2):
  ell <= n(q-h2(Q_tol+mu)) - leak_EC - log2(2/(eps_sec^2 eps_cor)),
  mu = sqrt((n+k)(k+1) ln(2/eps_sec)/(n k^2)).
Here n is the preselected number of key-basis detections, k is the
preselected number of test-basis detections, q=1 for the ideal preparation.
The fixed (predeclared) acceptance tolerance Q_tol is NOT set after seeing the
sample. The theorem's assumptions remain prerequisites; a numerical check
is not a stand-alone quantum-security proof.
"""

from __future__ import annotations

from collections import deque
from dataclasses import dataclass
import hashlib
import math
import time
from typing import Optional
import numpy as np
from scipy.signal import fftconvolve


@dataclass(frozen=True)
class FiniteKeyConfig:
    transmitted_signals: int = 100_000
    target_key_bits: int = 20_000
    target_test_bits: int = 20_000
    p_z: float = 0.5
    intercept_probability: float = 0.0
    noise_probability: float = 0.0
    loss_probability: float = 0.0
    q_tolerance: float = 0.04
    eps_secrecy: float = 1e-10
    eps_correctness: float = 1e-10
    min_final_key_bits: int = 256
    reconciliation_passes: int = 6
    reconciliation_block_size: int = 24
    ec_leakage_cap_fraction: float = 0.40
    output_key_bits: int = 256

    def __post_init__(self):
        if self.transmitted_signals < 1 or self.target_key_bits < 1 or self.target_test_bits < 1:
            raise ValueError('Signal count and target bit counts must be >= 1')
        if self.min_final_key_bits < 1 or self.output_key_bits < 1:
            raise ValueError('Key length thresholds must be positive')
        if self.reconciliation_passes < 1 or self.reconciliation_block_size < 2:
            raise ValueError('Invalid reconciliation configuration')
        if not math.isfinite(self.ec_leakage_cap_fraction) or not (0 < self.ec_leakage_cap_fraction <= 1):
            raise ValueError('EC leakage cap fraction must be in (0,1]')
        for name in ('p_z', 'intercept_probability', 'noise_probability',
                     'loss_probability', 'q_tolerance', 'eps_secrecy', 'eps_correctness'):
            x = getattr(self, name)
            if not math.isfinite(x):
                raise ValueError(f'{name} must be finite')
        if not 0 < self.p_z < 1:
            raise ValueError('p_z must be in (0,1)')
        if not 0 <= self.q_tolerance < 0.5:
            raise ValueError('q_tolerance must be in [0,0.5)')
        for name in ('noise_probability','loss_probability','intercept_probability'):
            if not 0 <= getattr(self, name) <= 1:
                raise ValueError(f'{name} must be in [0,1]')
        for name in ('eps_secrecy','eps_correctness'):
            if not 0 < getattr(self, name) < 1:
                raise ValueError(f'{name} must be in (0,1)')


@dataclass
class Transmission:
    z_alice: np.ndarray
    z_bob: np.ndarray
    x_alice: np.ndarray
    x_bob: np.ndarray
    detected: int
    sifted_z: int
    sifted_x: int


@dataclass
class Reconciliation:
    bob_corrected: np.ndarray
    leakage_bits: int
    flipped_bits: int
    passes: int


@dataclass
class FiniteKeyResult:
    status: str
    transmitted: int
    detected: int
    observed_z: int
    observed_x: int
    raw_z_used: int
    test_x_used: int
    x_errors: int
    x_qber: float
    # Special privileged diagnostic; not available to a real BB84 endpoint.
    true_z_errors_before_ec: int
    true_z_errors_after_ec: int
    ec_public_bits: int
    ec_leakage_budget_bits: int
    verification_bits: int
    verification_passed: bool
    finite_mu: float
    finite_bound_bits: int
    final_bits: int
    final_keys_match_diagnostic: bool
    runtime_ms: float


def h2(p: float) -> float:
    """Binary entropy on [0,1]."""
    if not 0.0 <= p <= 1.0:
        raise ValueError('p outside [0,1]')
    if p in (0.0, 1.0):
        return 0.0
    return -p * math.log2(p) - (1-p) * math.log2(1-p)


def finite_mu(n: int, k: int, eps_sec: float) -> float:
    if n < 1 or k < 1 or not (0 < eps_sec < 1):
        raise ValueError('invalid n/k/secrecy budget')
    return math.sqrt((n+k)*(k+1)*math.log(2/eps_sec)/(n*k*k))


def finite_key_bound(n: int, k: int, q_tol: float, leakage_ec: int,
                     eps_sec: float, eps_cor: float) -> tuple[int, float]:
    """Maximum extractable bits permitted by the published Eq. 2 bound.

    Only applicable when the source and measurement assumptions of the paper
    hold, a fixed Q_tol is chosen *before* parameter estimation, and the
    authentic-classical-channel prerequisite holds. leak_EC is a fixed
    predeclared upper bound on ALL public error-correction information;
    the verification hash is covered by the published correctness term. Returns (nonnegative bound, mu).
    """
    if not (0 <= q_tol < 0.5) or leakage_ec < 0 or not (0 < eps_cor < 1):
        raise ValueError('invalid tolerance/leakage/correctness budget')
    mu = finite_mu(n, k, eps_sec)
    if q_tol + mu >= 0.5:
        return 0, mu
    cost = math.log2(2/(eps_sec**2 * eps_cor))
    max_len = math.floor(n*(1-h2(q_tol+mu)) - leakage_ec - cost)
    return max(0, max_len), mu


def transmit(cfg: FiniteKeyConfig, rng: np.random.Generator) -> Transmission:
    """Ideal states, same measurement model as Program 1, but separated bases.

    Z=1, X=0. Coin choices are independent for Alice and Bob; detected
    events do not depend on their basis (a prerequisite in the ideal model).
    """
    n = cfg.transmitted_signals
    a = rng.integers(0, 2, n, dtype=np.uint8)
    a_base = (rng.random(n) < cfg.p_z).astype(np.uint8)
    b_base = (rng.random(n) < cfg.p_z).astype(np.uint8)
    detected = rng.random(n) >= cfg.loss_probability
    attacked = (rng.random(n) < cfg.intercept_probability) & detected
    eve_base = rng.integers(0, 2, n, dtype=np.uint8)
    eve_rand = rng.integers(0, 2, n, dtype=np.uint8)
    eve_measured = np.where(eve_base == a_base, a, eve_rand)
    forwarded_bit = np.where(attacked, eve_measured, a)
    forwarded_basis = np.where(attacked, eve_base, a_base)
    b_rand = rng.integers(0, 2, n, dtype=np.uint8)
    b = np.where(b_base == forwarded_basis, forwarded_bit, b_rand)
    b = np.bitwise_xor(b, (rng.random(n) < cfg.noise_probability).astype(np.uint8))
    mask = detected & (a_base == b_base)
    z_idx = np.flatnonzero(mask & (a_base == 1))
    x_idx = np.flatnonzero(mask & (a_base == 0))
    return Transmission(a[z_idx], b[z_idx], a[x_idx], b[x_idx],
                        int(np.count_nonzero(detected)), int(len(z_idx)),int(len(x_idx)))


def cascade_reconcile(a: np.ndarray, b: np.ndarray, rng: np.random.Generator,
                      passes: int = 6, initial_block_size: int = 24,
                      public_log: list[dict] | None = None) -> Reconciliation:
    """Research reference implementation of multi-pass Cascade-like EC.

    Conservatively counts Alice AND Bob parity disclosures (two public
    bits per parity comparison), including repeat queries. Corrects bits via parity
    bisection and revisits affected blocks from earlier passes. This is a
    leakage-conservative implementation, not a production Cascade package.
    Residual errors may remain; independent universal-hash verification in
    the caller detects mismatched reconciled keys with bounded probability.
    """
    alice = np.asarray(a, dtype=np.uint8)
    bob = np.asarray(b, dtype=np.uint8).copy()
    if alice.shape != bob.shape or alice.ndim != 1:
        raise ValueError('reconciliation requires two equal 1D raw strings')
    n = len(alice)
    if n == 0 or passes < 1 or initial_block_size < 2:
        raise ValueError('invalid reconciliation arguments')
    leakage = 0
    corrected = 0
    pass_blocks: list[list[np.ndarray]] = []
    memberships: list[np.ndarray] = []
    pending: deque[tuple[int,int]] = deque()
    queued: set[tuple[int,int]] = set()

    def query_alice_parity(pos: np.ndarray) -> int:
        nonlocal leakage
        leakage += 2  # Alice parity, Bob parity (both observable publicly)
        result = int(np.bitwise_xor.reduce(alice[pos]))
        if public_log is not None:
            # Include the identity of the queried positions.  They are public.
            # A compact hash binds their ordered encoding; it does not replace
            # a live interactive Cascade exchange.
            ordered = np.asarray(pos, dtype='<u4')
            public_log.append({'positions_sha256': hashlib.sha256(ordered.tobytes()).hexdigest(),
                               'alice_parity': result, 'bob_parity': None})
        return result

    def bob_parity(pos: np.ndarray) -> int:
        result = int(np.bitwise_xor.reduce(bob[pos]))
        if public_log is not None:
            if not public_log or public_log[-1]['bob_parity'] is not None:
                raise RuntimeError('Parity message order invalid')
            public_log[-1]['bob_parity'] = result
        return result

    def put(pass_id: int, block_id: int) -> None:
        tag = (pass_id, block_id)
        if tag not in queued:
            queued.add(tag)
            pending.append(tag)

    for pass_id in range(passes):
        order = rng.permutation(n)
        block_size = min(n, initial_block_size * (2**pass_id))
        groups = [order[i:i+block_size] for i in range(0,n,block_size)]
        which_block = np.empty(n, dtype=np.int32)
        for bi, group in enumerate(groups):
            which_block[group] = bi
        pass_blocks.append(groups)
        memberships.append(which_block)
        for bi in range(len(groups)):
            put(pass_id,bi)
        while pending:
            cur_pass, cur_bi = pending.popleft()
            queued.discard((cur_pass,cur_bi))
            pos = pass_blocks[cur_pass][cur_bi]
            if query_alice_parity(pos) == bob_parity(pos):
                continue
            # At least one odd error in pos; binary search for an odd half.
            while len(pos) > 1:
                middle = len(pos) // 2
                left = pos[:middle]
                if query_alice_parity(left) != bob_parity(left):
                    pos = left
                else:
                    pos = pos[middle:]
            bit_pos = int(pos[0])
            bob[bit_pos] ^= 1
            corrected += 1
            # Revisit every constructed permutation: a correction in an old
            # block can change the parity of a previously checked newer block.
            for prev_pass in range(len(pass_blocks)):
                if prev_pass == cur_pass:
                    continue  # parity of current group now matches
                put(prev_pass,int(memberships[prev_pass][bit_pos]))
    return Reconciliation(bob, leakage, corrected, passes)


def toeplitz_hash(bits: np.ndarray, public_seed: np.ndarray, output_len: int) -> np.ndarray:
    """Universal_2 Toeplitz hashing over GF(2), FFT-accelerated.

    T[i,j] = seed[n-1+i-j]. The seed is PUBLIC and chosen independently of
    input; therefore fresh independent seeds are required for verification
    and for privacy amplification. Float64 FFT results are rounded before
    reducing modulo 2, which is validated against exact binary arithmetic
    for small vectors in the automated tests. This is NOT hardware-hardened.
    """
    x = np.asarray(bits, dtype=np.uint8)
    seed = np.asarray(public_seed, dtype=np.uint8)
    if x.ndim != 1 or output_len < 1 or len(x) < 1 or seed.shape != (len(x)+output_len-1,):
        raise ValueError('invalid Toeplitz dimensions')
    if np.any(x > 1) or np.any(seed > 1):
        raise ValueError('Toeplitz inputs must be bits')
    convolution = fftconvolve(seed.astype(np.float64), x.astype(np.float64),mode='full')
    coeff = np.rint(convolution[len(x)-1:len(x)-1+output_len]).astype(np.int64)
    return (coeff & 1).astype(np.uint8)


def _result(status: str, cfg: FiniteKeyConfig, tx: Transmission,
            t0: int, *, nx=0, x_err=0, nz=0, z_bad_before=0, z_bad_after=0,
            leakage=0, ec_cap=0, vbits=0, verified=False, mu=float('nan'),
            bound=0, final=0, match=False) -> FiniteKeyResult:
    return FiniteKeyResult(status, cfg.transmitted_signals, tx.detected,
        tx.sifted_z, tx.sifted_x, nz, nx, x_err,
        (x_err/nx if nx else float('nan')),
        z_bad_before, z_bad_after, leakage, ec_cap, vbits, verified,
        mu, bound, final, match,
        (time.perf_counter_ns()-t0)/1e6)


def run_with_material(cfg: FiniteKeyConfig, seed: int) -> tuple[FiniteKeyResult, tuple[bytes, bytes] | None]:
    """Run one idealized simulated session, optionally returning accepted key bytes.

    Non-cryptographic reproducible randomness: NEVER deploy these key bytes.
    Aborts export NO key material. Both parties are modeled in one process.
    """
    t0 = time.perf_counter_ns()
    rng = np.random.default_rng(seed)
    tx = transmit(cfg,rng)
    if tx.sifted_z < cfg.target_key_bits or tx.sifted_x < cfg.target_test_bits:
        return _result('ABORT_INSUFFICIENT_DETECTIONS',cfg,tx,t0), None
    # Uniform selection without replacement *after* sifting, as required
    # for a random, time-independent sample of the accepted detections.
    z_positions = rng.choice(tx.sifted_z,size=cfg.target_key_bits,replace=False)
    x_positions = rng.choice(tx.sifted_x,size=cfg.target_test_bits,replace=False)
    az = tx.z_alice[z_positions]
    bz = tx.z_bob[z_positions]
    ax = tx.x_alice[x_positions]
    bx = tx.x_bob[x_positions]
    n,k = len(az),len(ax)
    xerrors = int(np.count_nonzero(ax != bx))
    zerrors = int(np.count_nonzero(az != bz))  # simulator diagnostic only
    if xerrors/k > cfg.q_tolerance:
        return _result('ABORT_PARAMETER_ESTIMATION',cfg,tx,t0,nx=k,
                       x_err=xerrors,nz=n,z_bad_before=zerrors), None
    ec = cascade_reconcile(az,bz,rng,cfg.reconciliation_passes,
                           cfg.reconciliation_block_size)
    uncorrected = int(np.count_nonzero(az != ec.bob_corrected))
    # Correctness verification: universal2 tag; tag seed is public.
    vbits = math.ceil(math.log2(1/cfg.eps_correctness))
    v_seed = rng.integers(0,2,n+vbits-1,dtype=np.uint8)
    tag_a = toeplitz_hash(az,v_seed,vbits)
    tag_b = toeplitz_hash(ec.bob_corrected,v_seed,vbits)
    verified = bool(np.array_equal(tag_a,tag_b))
    # The published bound assumes a PREDECLARED maximum EC disclosure.
    # Avoid plugging a post-hoc observed transcript length into the theorem.
    ec_cap=math.ceil(cfg.ec_leakage_cap_fraction*n)
    bound,mu=finite_key_bound(n,k,cfg.q_tolerance,ec_cap,
                              cfg.eps_secrecy,cfg.eps_correctness)
    common=dict(nx=k,x_err=xerrors,nz=n,z_bad_before=zerrors,
                z_bad_after=uncorrected,leakage=ec.leakage_bits,
                ec_cap=ec_cap,vbits=vbits,
                verified=verified,mu=mu,bound=bound)
    if ec.leakage_bits > ec_cap:
        return _result('ABORT_EC_LEAKAGE_BUDGET',cfg,tx,t0,**common), None
    if not verified:
        return _result('ABORT_KEY_VERIFICATION',cfg,tx,t0,**common), None
    if bound < cfg.min_final_key_bits or bound < cfg.output_key_bits:
        return _result('ABORT_INSUFFICIENT_FINITE_KEY',cfg,tx,t0,**common), None
    # Fresh public universal2 hash. Output a FIXED 256-bit example key for
    # controlled numerical study, never output raw/key bytes in reports.
    pa_seed = rng.integers(0,2,n+cfg.output_key_bits-1,dtype=np.uint8)
    final_alice=toeplitz_hash(az,pa_seed,cfg.output_key_bits)
    final_bob=toeplitz_hash(ec.bob_corrected,pa_seed,cfg.output_key_bits)
    same=bool(np.array_equal(final_alice,final_bob))  # diagnostic only
    return (_result('ACCEPT',cfg,tx,t0,final=cfg.output_key_bits,
                    match=same,**common),
            (np.packbits(final_alice, bitorder='big').tobytes(),
             np.packbits(final_bob, bitorder='big').tobytes()))


def run(cfg: FiniteKeyConfig, seed: int) -> FiniteKeyResult:
    """Preserve the original Program 2 diagnostic API without exporting keys."""
    return run_with_material(cfg, seed)[0]
