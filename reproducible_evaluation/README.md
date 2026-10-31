# Reproducible Evaluation — Hybrid BB84–Post-Quantum Communication

**Status:** completed research-simulation and reproducibility package. It is **not** evidence that a composably secure deployed QKD network has been built; see `SECURITY_LIMITATIONS.md`.

## 1. Running on Windows / VS Code (Git Bash)

Extract `reproducible_evaluation` inside your `Quantum_Project` folder and run:

```bash
cd ~/OneDrive/Desktop/Quantum_Project/reproducible_evaluation
openssl version
python -m pip install -r requirements.txt
python -m unittest discover -s tests -v
python run_experiments.py
```

Reference environment: **190 tests passed**. The default experiment performs **1,000 independently seeded stochastic BB84 trials** (100 across each of 10 predeclared channel conditions), **8,000 paired controller decisions** (2 policies × 4 controllers per QKD observation), and **10 OpenSSL-backed integration sessions** (1 repetition × 5 scenarios × 2 variants). Your local runtime and timing results will differ.

For a larger **Monte Carlo** study without the slower OpenSSL handshakes:

```bash
python run_experiments.py --repetitions 500 --no-integration
```

For a more extensive end-to-end integration study (substantially slower):

```bash
python run_experiments.py --repetitions 500 --integration-repetitions 10
```

For repeatable experiments with another chosen seed:

```bash
python run_experiments.py --repetitions 500 --no-integration --master-seed 20261025
```

**Warning:** each run replaces the data files in `results/`; copy the folder first if retaining an older run. Never publish or reuse the deterministic key bytes for real cryptography.

## 2. What is compared?

- **Software QKD model:** idealized BB84 with interception, noise, loss, parameter estimation, Cascade-like reconciliation, key verification and candidate finite-key privacy amplification.
- **Policies:** hybrid-preferred and hybrid-required.
- **Controllers:** model finite-key admission, QBER ≤ 11% only, finite-key with no fallback, PQC-only.
- **Integration spot check:** Adaptive P8 interactive reconciliation versus Fixed P9 public-syndrome reconciliation, each using actual OpenSSL-backed ML-DSA/ML-KEM signed handshakes and AES-GCM.

The **same QKD observations** are given to each controller, permitting paired comparisons without different simulated channels acting as confounders. The QBER-only controller is an intentionally oversimplified negative control.

## 3. Outputs

| File | What it contains |
|---|---|
| `results/qkd_trial_data.csv` | One row per QKD session: channel, QBER, admission, candidate length, leakage proxy, duration |
| `results/decision_trial_data.csv` | All strategy/policy decisions for every QKD observation |
| `results/qkd_summary.csv` | Model admission with Wilson 95% confidence intervals and theoretical QBER |
| `results/controller_summary.csv` | Mode counts, in-model invalid decisions, model-compliant counts, Wilson intervals |
| `results/paired_controller_contrasts.csv` | Paired bootstrap confidence intervals for differences between strategies |
| `results/integration_trial_data.csv` | Full OpenSSL-backed trial data: signed frames, bytes, time, mode |
| `results/integration_summary.csv` | Per-scenario integration medians and mode proportions |
| `results/RESULTS_REPORT.md` | Automatically generated preliminary paper tables and caveats |
| `results/experiment_manifest.json` | Python/platform/OpenSSL versions, model configurations, seeds, design |
| `results/01_...png` through `05_...png` | Figures derived directly from CSV data |

## 3A. Instrumented communication accounting

The supplementary integration dataset is stored in
`results/integration_accounting_v2/`. It contains 100 OpenSSL-backed
executions forming 50 matched Adaptive P8 / Fixed P9 pairs across
five scenarios.

The new modeled serialized communication metric is:

`modeled_total_serialized_bytes = pqc_handshake_bytes + on_wire_bytes + record_encoded_bytes`

Here `on_wire_bytes` retains its original meaning: successfully
processed authenticated-relay frame bytes. PQC handshake bytes and
locally encoded application-record bytes are reported separately.
These totals are software serialization estimates, not measured
physical network traffic.

In the clean condition, the median modeled communication volumes
were 252,639 bytes for Adaptive P8 and 198,587 bytes for Fixed P9
(10 paired trials). Timing results are host-dependent; the fixed
execution order and small sample size limit generalization.
At 1% noise, protocol modes differed in four matched pairs.

The instrumented dataset preserves the original experiment's
policy decisions, QKD statuses, reconciliation quantities,
frame counts and relay-byte counts for all 100 matched execution
identifiers.

## 4. Statistical methods

For a success proportion \(\hat p=k/n\), the two-sided 95% Wilson score interval uses \(z=1.9599639845\):

\[
\left(\frac{\hat p+z^2/(2n)}{1+z^2/n}\right)
\pm\frac{z}{1+z^2/n}
\sqrt{\frac{\hat p(1-\hat p)}{n}+\frac{z^2}{4n^2}}.
\]

The paired controller differences use resampling of matched runs, **never independent bootstrap samples for the two strategies**. Percentile intervals are exploratory Monte Carlo uncertainty estimates; neither type of 95% interval is a QKD secrecy parameter.

The theoretical intercept-resend QBER with independent bit-flip noise \(q_0\) is:

\[
Q_{\rm expected}=q_0+(1-2q_0)\frac{p_{\rm Eve}}{4}.
\]

This equation is appropriate for the implemented idealized channel model, **not** a universal hardware channel law.

## 5. Source files

- `publication_analysis.py`: scenario design, Monte Carlo trials, paired policy decisions and statistical calculations.
- `run_experiments.py`: full experiment orchestration, CSVs, figures, machine manifest and result report.
- `tests/test_publication_analysis.py`: 17 evaluation tests; 190 tests in the complete regression suite.
- `SECURITY_LIMITATIONS.md`: open security-proof questions and permitted wording for the manuscript.
- `EXPERIMENTAL_DESIGN.md`: conditions and reporting specifications.
- Supporting Python modules: protocols, signatures, KEM, authenticated record encryption, checker, EC alternatives.

## 6. Source references

- Tomamichel, Lim, Gisin and Renner, *Tight finite-key analysis for quantum cryptography*, Nature Communications 3, 634 (2012), https://doi.org/10.1038/ncomms1631
- NIST SP 800-227 (final 2025), https://csrc.nist.gov/pubs/sp/800/227/final
- RFC 5869 HKDF, https://www.rfc-editor.org/rfc/rfc5869
