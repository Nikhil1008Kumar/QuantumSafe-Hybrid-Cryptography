# Program 5 — Paired Security-Policy Comparison for Finite-Key BB84 + PQC

**Status:** completed local research simulation; not a quantum-security proof or an independently networked QKD implementation.

## Purpose

Tests whether a **finite-key-gated controller** avoids declaring QKD usable when a QBER-only controller would accept, and how application policy changes session availability. All four strategies are evaluated on the **same** simulated BB84 observations (paired design) so differences are due to the policy, not different random-channel outcomes.

The four strategies:

1. `FINITE_KEY_POLICY` (proposed candidate): if the Program 2 simulator admits a 256-bit key, label HYBRID; else allow `PQC_ONLY` **only** for `HYBRID_PREFERRED`, otherwise ABORT.
2. `QBER_11_PERCENT`: a deliberately incomplete benchmark that labels HYBRID whenever the sample X-QBER is at most 11%, regardless of finite-key or error-correction eligibility. **A HYBRID label does not mean a usable cryptographic key exists.**
3. `FINITE_KEY_NO_FALLBACK`: same finite-key admission check but abort whenever unavailable.
4. `PQC_ONLY_BASELINE`: no QKD assistance; policy `HYBRID_REQUIRED` cannot be satisfied and must abort. Explicit `HYBRID_PREFERRED` permits PQC-only.

Each strategy uses identical hypothetical prior checks for trusted ML-DSA identities, signed policy, signed QKD receipts, transcript consistency, freshness, and availability of the ML-KEM key. Security-critical failures always abort in the comparison. Actual ML-DSA/ML-KEM/AEAD operations are exercised in the **unmodified Program 4 integration module**, including five additional smoke checks during the default experimental run. The comparison controller itself is a policy evaluator, **not a network endpoint or cryptographic protocol**.

## Setup: Windows Git Bash / VS Code

Extract the ZIP and change into the directory containing this README, `requirements.txt`, and `run_experiments.py`. Example, if extracted to the same directory as previous programs:

```bash
cd ~/OneDrive/Desktop/Quantum_Project/Program5_Policy_Comparison
pwd
ls
openssl version
python -m pip install -r requirements.txt
python -m unittest discover -s tests -v
python run_experiments.py
```

Requires Python 3.11+, OpenSSL >= 3.5 on `PATH` with ML-KEM-768 and ML-DSA-65 support, NumPy, SciPy, cryptography and Matplotlib from `requirements.txt`. You previously ran Program 4 with OpenSSL 3.5.7, which meets this requirement.

**Expected:** `Ran 95 tests` and `OK`; then 180 paired QKD observations from nine predeclared scenarios, 1,440 controller decisions (four strategies × two policies × 180 observations), and **five** successful Program 4 integration spot checks. Your exact timing may differ substantially.

Additional commands:

```bash
python run_experiments.py --repetitions 100
python run_experiments.py --repetitions 20 --skip-integration
```

`--skip-integration` runs a **policy-only** study and needs no OpenSSL execution; the 75 inherited P2–P4 unit tests may still require OpenSSL. Larger repetitions improve exploratory precision but must not be treated as a universal security proof.

## What each output means

- `results/qkd_observations.csv` — one row per QKD simulation; status, QBER, model bound, public leakage, etc. No cryptographic key bytes.
- `results/paired_policy_decisions.csv` — one row per simulated observation, application policy, and strategy. A `HYBRID` choice by the QBER-only baseline is a **hypothetical** decision, not successful encryption.
- `results/policy_summary.csv` — aggregated counts plus Wilson 95% intervals for *modeled policy-compliant session outcomes*.
- `results/integration_smoke.csv` — five genuine ML-DSA/ML-KEM/AES-GCM Program 4 spot checks; OpenSSL timings include file I/O and subprocess startup.
- `results/authorized_availability.png` — authorized success under preferred policy, counting a QKD-labeled mode as invalid if the finite-key simulator did not admit it.
- `results/invalid_qkd_admissions.png` — rate of model-invalid QKD labels under preferred policy.
- `results/policy_required_vs_preferred.png` — proposed controller operating under the two application policies.
- `results/experiment_manifest.json` — runtime, parameters and limitations.
- `METHODS_AND_LIMITATIONS.md`, `RESULTS_INTERPRETATION.md` — research interpretation, mathematical definitions, and boundary of evidence.

### Protocol invariants asserted by tests

- Invalid authenticated prerequisites abort irrespective of chosen policy.
- HYBRID from the finite-key controller implies the Program 2 result meets a 256-bit admission certificate.
- `HYBRID_REQUIRED` never silently yields `PQC_ONLY`.
- `PQC_ONLY` requires no QKD-run observation.
- A low X-QBER alone cannot cause the finite-key controller to release a QKD-labelled session.
- Mode choice with high QBER, failed reconciliation budget, insufficient input bits, stale checks and altered policy is tested.

**Important:** The Program 4 code still authenticates only a signed high-level QKD receipt rather than independently verifying every *actual* public BB84 message; source and detector imperfections and a robust combiner security proof remain out of scope. See methods document.

## Why this experiment alone is not novel

QKD/PQC hybrids, finite-key analysis, authenticated post-quantum key exchange, and adaptive fallback have extensive prior art. In particular, Agalya & Priyadarsini (2026) investigate trust-aware QKD/PQC fallback, while Gupta et al. (2026) explicitly analyze finite-key QKD–PQC hybrids. The measured differences here are **preliminary benchmarks against simple representative controllers**, not an established original scientific theorem. Before writing a journal manuscript, we need a rigorous threat model, authenticated on-wire classical BB84 exchange, formalized combiner, stronger independent baselines, and enough repeated trials for statistical confidence.

## Sources

- Tomamichel et al., *Tight finite-key analysis for quantum cryptography* (2012), https://www.nature.com/articles/ncomms1631
- NIST FIPS 203, ML-KEM, https://csrc.nist.gov/pubs/fips/203/final
- NIST FIPS 204, ML-DSA, https://csrc.nist.gov/pubs/fips/204/final
- NIST SP 800-227 (2025), https://csrc.nist.gov/pubs/sp/800/227/final
- Agalya & Priyadarsini (2026), https://www.frontiersin.org/journals/communications-and-networks/articles/10.3389/frcmn.2026.1929455/abstract
- Gupta et al., *Combined Quantum and Post-Quantum Security Performance Under Finite Keys* (QCNC 2026), https://arxiv.org/abs/2512.04429
- Alotaibi et al., *Combining PQC and QKD*, October 2026, https://arxiv.org/abs/2610.19039
