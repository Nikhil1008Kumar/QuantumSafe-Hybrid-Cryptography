# Program 2 — Finite-key-aware BB84 simulation

This is the **second research prototype** following `bb84_baseline`. It implements a **predeclared finite-key admission rule** for an idealized single-qubit, prepare-and-measure BB84 simulation.

> **Research-use disclaimer:** No quantum hardware or authenticated network is implemented. Seeded NumPy randomness is deliberately reproducible and must **never** be used for actual cryptographic keys. The finite-key formula is drawn from an existing theorem, not a new proof. The theorem's source/measurement/authentication assumptions must hold; tests passing do not independently prove unconditional security.

## Quick start

Open a terminal in this folder:

```bash
python -m pip install -r requirements.txt
python -m unittest discover -s tests -v
python run_experiments.py
```

The test suite currently contains **19 tests**. `run_experiments.py` runs 400 independently seeded simulated sessions and saves CSV files, five PNG charts, and a JSON manifest in `results/`.

A single demonstration can be run with:

```python
from finite_key_bb84 import FiniteKeyConfig, run
cfg = FiniteKeyConfig(
    transmitted_signals=100_000,
    target_key_bits=18_000,
    target_test_bits=18_000,
    noise_probability=0.01,
    q_tolerance=0.04,
)
result = run(cfg, seed=1234)
print(result.status, result.x_qber, result.finite_bound_bits)
```

## Program sequence

1. Alice chooses qubit bits and bases; Bob chooses independent measurement bases.
2. Simulate ideal BB84 measurement, intercept-resend intervention, background bit flips, and basis-independent loss.
3. Obtain detected `Z`-basis raw-key candidates and `X`-basis error-test candidates. Select fixed target sizes by uniform sampling without replacement.
4. Disclose the X-basis test results over an **assumed authenticated** classical channel. Abort when `X_QBER > Q_tol`, where `Q_tol` is fixed **before** data collection.
5. Run a multi-pass, Cascade-like parity/binary-search reconciler. Account for **two public parity bits per comparison** (one Alice and one Bob) and abort if the disclosed EC information exceeds the **predeclared leakage cap**.
6. Compare an independent universal2 Toeplitz verification tag. Abort if mismatched; correctness failure probability from the tag is bounded under the ideal uniform-hash model.
7. Compute the extractable-length bound from Equation (2) of Tomamichel et al. The maximum error-correction disclosure, **not the observed disclosure**, is charged against the bound.
8. Release a fixed-length *simulated example* 256-bit key via a newly seeded public Toeplitz hash **only when** all security checks pass. Report only summary statistics and privileged simulator diagnostics, not key bytes.

## Exact mathematical rule implemented

Under the ideal single-qubit source preparation model (`q=1`) and all the theorem's other prerequisites:

```
h2(u) = -u*log2(u)-(1-u)*log2(1-u)
mu = sqrt( (n+k)*(k+1) * ln(2/eps_sec) / (n*k*k) )
ell_max = floor( n*(1-h2(Q_tol+mu))
                 - leak_EC_budget
                 - log2(2/(eps_sec**2*eps_cor)) )
```

`n` is the predeclared number of Z-basis raw-key bits; `k` is the predeclared number of X-basis test bits. The tolerance `Q_tol`, the maximum allowed EC disclosure (`leak_EC_budget`), and the security budgets are fixed in advance. If `Q_tol+mu >= 0.5`, or the computed length is less than 256, the simulation rejects key extraction.

The validation budget used in these preliminary trials is `eps_sec=10^-10` and `eps_cor=10^-10`. These are **conditional mathematical bounds**, not measurements of security of a real optical device.

### Interpretation of the fixed budget

For clarity and conservatism, the experiment predeclares `leak_EC_budget = ceil(0.40*n)`. The actual reconciliation transcript is counted separately; each Alice/Bob parity comparison costs two public bits. The 40% fraction is a **baseline design parameter**, *not* an optimal security rule. Some noisy runs have sufficient potential entropy but must abort because this communication limit is exceeded. We will vary this parameter and compare reconciliation algorithms in subsequent work.

Since the budget and `Q_tol` are fixed, `ell_max` is identical across noise rates at a fixed `n`, even though **acceptance outcomes and actual EC disclosures vary**. This is intentional, not a statistical anomaly.

## Results

The file `results/RESULTS_INTERPRETATION.md` explains the data. Each grid configuration has only 20 independent repetitions. Values of 0% or 100% observed acceptance are **preliminary sample proportions**, not population certainties.

## Files

- `finite_key_bb84.py`: BB84 channel, entropic bound, Cascade-like reconciliation, Toeplitz hashing, abort checks
- `tests/test_finite_key_bb84.py`: correctness/invariant/attack tests
- `run_experiments.py`: seeded repeated simulations, CSV aggregation, figures
- `results/session_trials.csv`: individual trial data and abort codes
- `results/summary.csv`: aggregate statistics, acceptance, leakage, and sample QBER
- `results/experiment_manifest.json`: reproducibility configuration
- `results/*.png`: graphs
- `METHODS_AND_LIMITATIONS.md`: assumptions and open issues before journal submission

## Scientific reference

Tomamichel, M., Lim, C. C. W., Gisin, N., and Renner, R. (2012). **Tight finite-key analysis for quantum cryptography.** *Nature Communications* **3**, 634. DOI: [10.1038/ncomms1631](https://doi.org/10.1038/ncomms1631). See Eq. (2) and Box 1 for the matched protocol and prerequisites.
