# Program 10 — Predeclared experimental design

## Scientific question

Can model finite-key admission, together with explicit application fallback constraints, avoid **in-model** use of uncertified QKD material while preserving policy-permitted application continuity? What are the trade-offs in signed frames, communication bytes and local implementation latency relative to adaptive reconciliation and PQC-only modes?

## Model and parameters

The Python simulator uses ideal BB84 state/basis measurement with a configurable independent loss filter, independent bit flip noise and random-basis intercept-resend. `p_z = 0.5`. The simulated raw/test bit targets are `round(0.18 * N)` each; fixed tolerance 4%; `epsilon_secrecy = epsilon_correctness = 1e-10` as input parameters to a **candidate** theorem-based bound. EC uses 2 passes in the Monte Carlo stage, with a **predeclared** 40% raw-key EC budget. Final key acceptance target is 256 bits. The early-abort cases are still counted in the denominator.

Scenarios in the source file are: N=500 clean; N=10,000 clean; N=50,000 clean; N=50,000 with 1%, 2%, and 3% noise; N=50,000 with 10%, 20% interception; N=50,000 with 30% independent loss; and N=100,000 clean.

## Controller comparison

Under the same stochastic observation, evaluate four policies for both `HYBRID_PREFERRED` and `HYBRID_REQUIRED`:

1. FINITE_KEY_POLICY (the proposed admission rule, including authorized fallback)
2. QBER_11_PERCENT (a deliberately incomplete negative control, no finite-key checks)
3. FINITE_KEY_NO_FALLBACK (uses the same admission but aborts rather than fallback)
4. PQC_ONLY_BASELINE (respects HYBRID_REQUIRED by aborting)

The labels "model-compliant" and "in-model invalid hybrid" are **defined operationally using the same finite-key simulation**, not an external ground-truth cryptographic break. This makes comparisons transparent but limits claims about real attacks and superiority.

## OpenSSL-backed integration study

Five predeclared conditions compare adaptive Program 8 with Program 9's fixed Hamming(31) syndrome under identical channel seeds. Signed frames, public bytes, elapsed time, verification result and mode are recorded. Inputs are deterministic reproducibility seeds for stochastic BB84; post-quantum cryptographic backend uses OpenSSL 3.5 actual ML-KEM/ML-DSA operations. Report paired medians within the *same machine*.

## Analysis plan

- Report ALL planned configurations including zero-success cases, with N and exact denominators.
- Show observed QBER vs the idealized intercept-resend expression; missing samples are **missing**, not 0%. 
- Wilson two-sided 95% intervals for model-admission probabilities and mode proportions.
- Paired percentile-bootstrap 95% intervals for the difference of controller **model-compliant** outcomes using the same stochastic draw.
- Report raw trial CSVs, seed derivation strategy, key parameter manifest, library versions, and graphs generated solely from the CSVs.
- Avoid inferential claims from 2-pair integration spot checks. For larger integration work, run at least 10+ per condition in a controlled, fixed host and report uncertainty/variability.

## Mathematical definitions

Observed X QBER: \(Q_X = m_X/k_X\) (when \(k_X>0\)). Under the implemented channel: \(\mathbb E[Q_X] = q_0 + (1-2q_0)p_E/4\).

Model-admission rate for a scenario: \(\hat p_A = \sum_i \mathbf 1[A_i]/R\). An *in-model invalid-hybrid* is a session where the comparator selects `HYBRID` but `QKDObservation.finite_key_admitted` is false. It is a definitional model disagreement; no real-key leakage is observed.

For fixed Hamming-31 code, predetermined public syndrome disclosure: \(L_{EC}=5r\lceil n/31\rceil\) bits for \(r\) passes. Not a complete transcript secrecy bound.

## References

Tomamichel et al., Nat. Commun. 3, 634 (2012): https://doi.org/10.1038/ncomms1631

NIST SP 800-227 (2025): https://csrc.nist.gov/pubs/sp/800/227/final

RFC 5869 HKDF: https://www.rfc-editor.org/rfc/rfc5869
