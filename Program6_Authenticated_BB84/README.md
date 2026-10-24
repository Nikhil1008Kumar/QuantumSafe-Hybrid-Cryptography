# Program 6 — Authenticated BB84 Classical Communication (Research Prototype)

**Purpose:** Move beyond Program 4's signed end-of-session QKD receipts toward a reproducible classical BB84 transcript with *real* ML-DSA-65 signatures on the public protocol stages, authenticated policy negotiation, finite-key admission, ML-KEM bootstrap, and AES-256-GCM record protection.

**Read `METHODS_AND_LIMITATIONS.md` before citing this project.** This simulator is neither a deployed QKD network nor a security proof. The Cascade-like parity calculations still run in one privileged process; **parity-event batches are authenticated *after* computation**, so the implementation does not yet demonstrate a live independently authenticated interactive reconciliation over a hostile network.

## Requirements

- Python 3.11+ (tested on Python 3.13; previous project run on Windows Python 3.11)
- OpenSSL **3.5+** CLI on `PATH`, with ML-KEM-768 and ML-DSA-65 providers
- NumPy, SciPy, Matplotlib, `cryptography` (see `requirements.txt`)

## Git Bash on Windows

Extract `Program6_Authenticated_BB84` inside `Quantum_Project`:

```bash
cd ~/OneDrive/Desktop/Quantum_Project/Program6_Authenticated_BB84
openssl version
python -m pip install -r requirements.txt
python -m unittest discover -s tests -v
python run_experiments.py
```

Optional longer experiments:

```bash
python run_experiments.py --repetitions 20 --attack-repetitions 10
```

**Expected test count:** 116; it may rise if tests are extended. Exact run times differ substantially across machines because OpenSSL is started repeatedly through a subprocess and temporary files are used.

## Files

- `authenticated_bb84.py`: independent signed stage messages, role and sequence checks, quantum-channel simulation, error-correction trace batches, and a policy-bound hybrid/PQC-only application handoff.
- `finite_key_bb84.py`: inherited Program 2 implementation, with optional trace logging of EC parity comparisons; **original Program 2 source is unchanged**.
- `pqc_protocol.py`: inherited Program 3 ML-DSA-65/ML-KEM-768 implementation.
- `hybrid_protocol.py`: inherited Program 4 AES-GCM and experimental key schedule.
- `policy_comparison.py`: inherited Program 5 policy comparison.
- `tests/`: original tests and Program 6 attack/state-machine tests.
- `run_experiments.py`: reproducible scenario runner and CSV/PNG generation.
- `PROTOCOL_SPEC.md`: message sequence and mathematically specified checks.
- `METHODS_AND_LIMITATIONS.md`: assumptions, weaknesses, and publication boundaries.
- `results/`: experiments, manifest, figures and interpretation.

## Quick result check

Default script settings: 9 scenarios × 5 independent simulated sessions = **45 integrated sessions** and 16 mutation stages × 3 trials = **48 tampering trials**.

In the provided reference run, the modes were:

| Scenario | Hybrid | PQC-only | Abort |
|---|---:|---:|---:|
| clean_preferred | 5 | 0 | 0 |
| noise1_preferred | 5 | 0 | 0 |
| noise3_preferred | 0 | 5 | 0 |
| eve20_preferred | 0 | 5 | 0 |
| short_preferred | 0 | 5 | 0 |
| clean_required | 5 | 0 | 0 |
| noise3_required | 0 | 0 | 5 |
| short_required | 0 | 0 | 5 |
| pqc_only | 0 | 5 | 0 |

All 48 explicitly modified frames were rejected. These are deterministic and limited *test observations*, not a guarantee against all attacks.

## Reproducibility and privacy

QKD experiments use NumPy's seeded random generator so comparisons can be rerun. **These outputs are not cryptographically secure random keys** and must not be used to protect real data. The underlying PQC algorithms are executed with OpenSSL; production identity enrollment and long-term key storage are not implemented. Source code, datasets, timing charts, and the manifest are included. No raw QKD keys or ML-KEM shared secrets are saved to CSV files.
