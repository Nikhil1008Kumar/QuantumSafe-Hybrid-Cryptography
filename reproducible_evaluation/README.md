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

<!-- ISSUE5-SENSITIVITY:START -->
## Issue 5: archived finite-key sensitivity and robustness results

**Design.** 22 predeclared configurations × 100 seeded simulations = **2,200 trials**. This is an idealized BB84 model-admission study, distinct from the existing 5,000-trial QKD policy comparison and the separate 100 protocol-integration executions. The primary experiment varies transmitted-signal/target-bit allocations, test-sample allocation, channel noise and loss, predeclared EC leakage budgets, and secrecy/correctness parameters. Configuration overrides are in [`manifest.json`](results/finite_key_sensitivity_full100/manifest.json).

**Reproduce.** From the `reproducible_evaluation/` directory, run `python finite_key_sensitivity_v1.py --repetitions 100 --run-label YOUR_UNIQUE_LABEL`. The script refuses an existing output directory; use a fresh label to preserve the archived study. To reproduce the *exact* existing `figures_v3`, see [`plot_finite_key_sensitivity_v2.py`](plot_finite_key_sensitivity_v2.py), which currently selects the archived `full100` input and `figures_v3` output and intentionally refuses to overwrite that folder. Generate figures in a separate working copy or select a **new output directory** in that script. Do not delete archived results simply to rerun the plots.

**Archived evidence.** [`trial_data.csv`](results/finite_key_sensitivity_full100/trial_data.csv), [`summary.csv`](results/finite_key_sensitivity_full100/summary.csv), [`manifest.json`](results/finite_key_sensitivity_full100/manifest.json), [`SHA256SUMS.txt`](results/finite_key_sensitivity_full100/SHA256SUMS.txt), and final [`figures_v3/`](results/finite_key_sensitivity_full100/figures_v3/) (PNG, PDF, checksums). Both the on-disk files and the committed Git versions were checked against the recorded SHA-256 values; `.gitattributes` preserves exact bytes for the archived results.

**Observed admission rates and first terminal outcomes** (95% Wilson intervals in fractional units):

| Configuration | Model-admitted | Wilson 95% interval | Terminal status counts |
|---|---:|---:|---|
| `baseline_clean` | 100/100 | 0.963–1.000 | ACCEPT: 100 |
| `block_20000` | 0/100 | 0.000–0.037 | finite-key shortfall: 100 |
| `block_35000` | 0/100 | 0.000–0.037 | finite-key shortfall: 100 |
| `block_70000` | 100/100 | 0.963–1.000 | ACCEPT: 100 |
| `test_3000` | 0/100 | 0.000–0.037 | finite-key shortfall: 100 |
| `test_6000` | 100/100 | 0.963–1.000 | ACCEPT: 100 |
| `test_11000` | 100/100 | 0.963–1.000 | ACCEPT: 100 |
| `noise_1pct` | 100/100 | 0.963–1.000 | ACCEPT: 100 |
| `noise_2pct` | 99/100 | 0.946–0.998 | EC leakage: 1, ACCEPT: 99 |
| `noise_3pct` | 0/100 | 0.000–0.037 | EC leakage: 100 |
| `noise_4pct` | 0/100 | 0.000–0.037 | EC leakage: 51, parameter estimation: 49 |
| `loss_10pct` | 100/100 | 0.963–1.000 | ACCEPT: 100 |
| `loss_20pct` | 100/100 | 0.963–1.000 | ACCEPT: 100 |
| `loss_30pct` | 0/100 | 0.000–0.037 | insufficient detections: 100 |
| `noise1_cap20` | 0/100 | 0.000–0.037 | EC leakage: 100 |
| `noise1_cap30` | 100/100 | 0.963–1.000 | ACCEPT: 100 |
| `noise1_cap45` | 100/100 | 0.963–1.000 | ACCEPT: 100 |
| `noise1_cap50` | 0/100 | 0.000–0.037 | finite-key shortfall: 100 |
| `secrecy_1e8` | 100/100 | 0.963–1.000 | ACCEPT: 100 |
| `secrecy_1e12` | 100/100 | 0.963–1.000 | ACCEPT: 100 |
| `correctness_1e6` | 100/100 | 0.963–1.000 | ACCEPT: 100 |
| `correctness_1e14` | 100/100 | 0.963–1.000 | ACCEPT: 100 |

**Interpretation.** The admission criterion is not equivalent to a QBER-only threshold. In the 3% noise configuration, all 100 sessions ended in an EC leakage-budget abort. At 4% noise, 49 ended at parameter estimation and 51 at the EC leakage gate. With 30% channel loss, all 100 trials aborted before estimation because insufficient sifted detections met the predeclared Z/X targets. At 1% noise, a 20% EC cap failed due to observed disclosure, while a 50% cap left too little candidate key length; the experimentally admitted range is **not** a universal optimal cap.

**Methodological boundaries.** Sequential abort statuses denote the *first* gate that rejected a trial; later checks may never have executed. Scaled-block scenarios adjust both transmitted signals and requested Z/X bit counts; they are not a pure single-variable block-length sweep. Trial seeds are deterministic and reused across configurations but do not guarantee identical channel-error realizations. Confidence intervals quantify Monte Carlo frequency uncertainty, **not** secrecy/correctness guarantees. The fixed finite-key equation, EC transcript accounting, authentication assumptions, and end-to-end hybrid composability still require a separate security-model review.

**Research record.** These results were archived in local Git checkpoint `9095e3a` (2026-10-31). No software license, DOI, GitHub release, or formal security certificate is implied by this documentation.
<!-- ISSUE5-SENSITIVITY:END -->
