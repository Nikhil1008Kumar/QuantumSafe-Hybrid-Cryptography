# Finite-Key-Aware Admission and Authenticated Fallback in Hybrid BB84–Post-Quantum Communication

**Research implementation | Quantum key distribution | Post-quantum cryptography | Authenticated protocol fallback**

This repository contains a research-oriented software framework for evaluating finite-key-aware admission, authenticated mode negotiation, and controlled fallback in hybrid BB84 and post-quantum communication systems.

The implementation combines a simulated BB84 quantum channel with OpenSSL-backed post-quantum cryptographic operations. It investigates when candidate QKD-derived key material should be admitted into a hybrid key schedule and how policy enforcement affects protocol outcomes.

**Research status:** Experimental software prototype. Not a production-ready QKD system or a formally proven composably secure hybrid protocol.

## Research objectives

- Evaluate finite-key-aware QKD admission under channel noise, interception, loss, and finite block sizes.
- Compare admission decisions against a simplified QBER-only baseline.
- Enforce authenticated `HYBRID_REQUIRED`, `HYBRID_PREFERRED`, and `PQC_ONLY` policies.
- Evaluate independent endpoint state, signed message exchange, key confirmation, and AES-GCM application records.
- Compare adaptive reconciliation and fixed-syndrome reconciliation using paired experiments.
- Report latency, authenticated relay frames, reconciliation disclosure, and modeled serialized communication volume.

## Repository structure

| Directory | Description |
|---|---|
| `bb84_baseline/` | Baseline BB84 simulation |
| `finite_key_qkd/` | Finite-key estimation and admission |
| `pqc_authentication/` | Post-quantum key establishment and authentication |
| `hybrid_key_establishment/` | Hybrid session construction |
| `fallback_policy_evaluation/` | Admission policies and comparison baselines |
| `authenticated_bb84/` | Authenticated classical communication |
| `independent_endpoint_protocol/` | Independent Alice and Bob protocol states |
| `bounded_security_analysis/` | Bounded adversarial protocol checks |
| `reconciliation_hardening/` | Fixed-syndrome reconciliation implementation |
| `reproducible_evaluation/` | Main research implementation, experiments, tests, and results |

The earlier-stage implementations are retained to document the development and evolution of the research prototype. The primary evaluation is located in `reproducible_evaluation/`.

## Reproducibility

The primary evaluation was tested on Windows using Python 3.11, NumPy, the `cryptography` library, and OpenSSL-backed ML-KEM/ML-DSA operations.

From the repository root:

```bash
cd reproducible_evaluation
python -m pip install -r requirements.txt
openssl version
python -m unittest discover -s tests -q
```

The verified regression suite contains **190 passing tests**.

The experiment runner supports independently seeded BB84 simulation, paired policy decisions, and OpenSSL-backed integration experiments. For additional instructions and model assumptions, see the evaluation directory's `README.md`, `EXPERIMENTAL_DESIGN.md`, and `SECURITY_LIMITATIONS.md`.

**Data preservation warning:** `run_experiments.py` writes to its local `results/` directory and may replace previously generated files. Reproduce experiments in a separate working copy when preserving the published dataset.

## Experimental evidence

The archived working results include:

- 5,000 stochastic BB84 simulation trials across 10 predeclared conditions.
- Controller comparisons based on shared QKD observations.
- 100 OpenSSL-backed protocol executions forming 50 matched P8/P9 pairs.
- Separate PQC-handshake, authenticated-relay, and application-record byte accounting.
- Latency and communication-cost comparisons.
- Protocol regression tests covering successful operation, rejection, replay, tampering, and fallback behavior.

For the instrumented integration study, see:

`reproducible_evaluation/results/integration_accounting_v2/`

The clean-channel condition produced median modeled serialized communication volumes of 252,639 bytes for Adaptive P8 and 198,587 bytes for Fixed P9, based on 10 paired runs. These are implementation measurements, not physical network traffic measurements.

## Security and evaluation limitations

The study uses an idealized quantum-channel simulation and a candidate finite-key admission calculation. It does not establish a full composable finite-key security theorem for the implemented system, a proven robust hybrid key combiner, or an unbounded symbolic security proof.

The recorded execution times are local software measurements and may include Python and cryptographic-backend overhead. Communication-volume estimates exclude physical network headers, retransmissions, and quantum-channel transmission costs.

The statistical confidence intervals represent observed trial variability, not cryptographic secrecy parameters.

## Research outputs

Raw datasets, figures, statistical summaries, and environment manifests are available under `reproducible_evaluation/results/`.

The codebase is intended to support transparent reproduction, methodological evaluation, and future research on hybrid quantum-safe communication.

## Citation and archival status

**Manuscript:** *Finite-Key-Aware Admission and Authenticated Fallback in Hybrid BB84–Post-Quantum Communication*

A versioned research release and archival DOI are planned. No archival DOI is claimed at this stage.

## License

License selection and repository distribution terms are pending final review.

<!-- ISSUE5-SENSITIVITY:START -->
## Verified finite-key sensitivity study (Issue 5)

The reproducible BB84 admission sensitivity evaluation comprises **2,200 simulator trials** across **22 predeclared configurations** (100 per configuration). The archived trial data, scenario-level results, experiment manifest, SHA-256 checksums, and final publication figures are under [`reproducible_evaluation/results/finite_key_sensitivity_full100/`](reproducible_evaluation/results/finite_key_sensitivity_full100/). The verified local research checkpoint is `9095e3a` (2026-10-31).

At the tested settings, model-admission counts include **100/100** for the noise-free baseline, **99/100** at 2% channel noise, **0/100** at 3% noise, and **0/100** with 30% detection loss. At 1% noise, the EC leakage-budget sweep admits **0/100** at a 20% cap, **100/100** at 30%, **100/100** at 40%, **100/100** at 45%, and **0/100** at 50%. Abort causes and 95% Wilson intervals are recorded in the summary CSV.

Reproduction scripts: [`finite_key_sensitivity_v1.py`](reproducible_evaluation/finite_key_sensitivity_v1.py) and [`plot_finite_key_sensitivity_v2.py`](reproducible_evaluation/plot_finite_key_sensitivity_v2.py). Final figures are in [`figures_v3/`](reproducible_evaluation/results/finite_key_sensitivity_full100/figures_v3/). The earlier 5,000-trial QKD comparison and 100 integration executions are separate studies and are **not pooled** with these 2,200 sensitivity trials.

**Scope:** These are admission outcomes under an idealized, seeded BB84 simulation and a candidate finite-key calculation—not deployed-QKD measurements, a composable end-to-end security proof, or cryptographic failure-probability confidence intervals. The 95% Wilson intervals characterize Monte Carlo admission-rate uncertainty only. Reconciliation counts and predeclared leakage caps are model-specific, and stronger security claims require independent theorem-assumption and protocol verification.
<!-- ISSUE5-SENSITIVITY:END -->
