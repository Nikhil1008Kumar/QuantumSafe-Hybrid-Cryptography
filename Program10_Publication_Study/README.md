# Program 10 — Reproducible comparative evaluation

**Status:** completed research-simulation and reproducibility package. It is **not** evidence that a composably secure deployed QKD network has been built; see `SECURITY_LIMITATIONS.md`.

## 1. Running on Windows / VS Code (Git Bash)

Extract `Program10_Publication_Study` inside your `Quantum_Project` folder and run:

```bash
cd ~/OneDrive/Desktop/Quantum_Project/Program10_Publication_Study
openssl version
python -m pip install -r requirements.txt
python -m unittest discover -s tests -v
python run_experiments.py
```

Reference environment: **190 tests passed**. The default experiment performs **1,000 independently seeded stochastic BB84 trials** (100 across each of 10 predeclared channel conditions), **8,000 paired controller decisions** (2 policies × 4 controllers per QKD observation), and **20 OpenSSL-backed integration sessions** (2 repetitions × 5 conditions × 2 variants). Your local runtime and timing results will differ.

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
- **Integration spot check:** interactive Program-8 adaptive reconciliation versus Program-9 fixed public syndrome, each using actual OpenSSL-backed ML-DSA/ML-KEM signed handshakes and AES-GCM.

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
- `tests/test_publication_analysis.py`: 17 new tests; all 173 inherited Program-9 tests preserved.
- `SECURITY_LIMITATIONS.md`: open security-proof questions and permitted wording for the manuscript.
- `EXPERIMENTAL_DESIGN.md`: conditions and reporting specifications.
- Inherited Programs 2–9 Python modules: protocols, signatures, KEM, authenticated record encryption, checker, EC alternatives.

## 6. Source references

- Tomamichel, Lim, Gisin and Renner, *Tight finite-key analysis for quantum cryptography*, Nature Communications 3, 634 (2012), https://doi.org/10.1038/ncomms1631
- NIST SP 800-227 (final 2025), https://csrc.nist.gov/pubs/sp/800/227/final
- RFC 5869 HKDF, https://www.rfc-editor.org/rfc/rfc5869
