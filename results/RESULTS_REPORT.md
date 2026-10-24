# Program 10 — Reproducible result summary

**Interpretation boundary:** This is an idealized/software BB84 simulation with deterministic random seeds and a candidate finite-key admission calculation. Numerical confidence intervals quantify random trial variation; they are *not* quantum security parameters. This does not discharge the open leakage, source-model, or hybrid combiner proof obligations.

## Model admission by scenario

| Scenario | N | Model-admitted | Wilson 95% CI | X-QBER observed | Theoretical |
|---|---:|---:|---:|---:|---:|
| short_500_clean | 100 | 0.0% | [0.0, 3.7]% | 0.00% | 0.00% |
| small_10000_clean | 100 | 0.0% | [0.0, 3.7]% | 0.00% | 0.00% |
| clean_50000 | 100 | 100.0% | [96.3, 100.0]% | 0.00% | 0.00% |
| noise1_50000 | 100 | 98.0% | [93.0, 99.5]% | 0.99% | 1.00% |
| noise2_50000 | 100 | 84.0% | [75.6, 89.9]% | 2.00% | 2.00% |
| noise3_50000 | 100 | 1.0% | [0.2, 5.4]% | 3.02% | 3.00% |
| eve10_50000 | 100 | 60.0% | [50.2, 69.1]% | 2.51% | 2.50% |
| eve20_50000 | 100 | 0.0% | [0.0, 3.7]% | 4.98% | 5.00% |
| loss30_50000 | 100 | 0.0% | [0.0, 3.7]% | Not estimable | 0.00% |
| clean_100000 | 100 | 100.0% | [96.3, 100.0]% | 0.00% | 0.00% |

## Hybrid-preferred policy comparisons

| Scenario | Strategy | Hybrid | PQC-only | Abort | In-model invalid hybrid |
|---|---|---:|---:|---:|---:|
| short_500_clean | FINITE_KEY_POLICY | 0 | 100 | 0 | 0 |
| short_500_clean | QBER_11_PERCENT | 100 | 0 | 0 | 100 |
| short_500_clean | FINITE_KEY_NO_FALLBACK | 0 | 0 | 100 | 0 |
| short_500_clean | PQC_ONLY_BASELINE | 0 | 100 | 0 | 0 |
| small_10000_clean | FINITE_KEY_POLICY | 0 | 100 | 0 | 0 |
| small_10000_clean | QBER_11_PERCENT | 100 | 0 | 0 | 100 |
| small_10000_clean | FINITE_KEY_NO_FALLBACK | 0 | 0 | 100 | 0 |
| small_10000_clean | PQC_ONLY_BASELINE | 0 | 100 | 0 | 0 |
| clean_50000 | FINITE_KEY_POLICY | 100 | 0 | 0 | 0 |
| clean_50000 | QBER_11_PERCENT | 100 | 0 | 0 | 0 |
| clean_50000 | FINITE_KEY_NO_FALLBACK | 100 | 0 | 0 | 0 |
| clean_50000 | PQC_ONLY_BASELINE | 0 | 100 | 0 | 0 |
| noise1_50000 | FINITE_KEY_POLICY | 98 | 2 | 0 | 0 |
| noise1_50000 | QBER_11_PERCENT | 100 | 0 | 0 | 2 |
| noise1_50000 | FINITE_KEY_NO_FALLBACK | 98 | 0 | 2 | 0 |
| noise1_50000 | PQC_ONLY_BASELINE | 0 | 100 | 0 | 0 |
| noise2_50000 | FINITE_KEY_POLICY | 84 | 16 | 0 | 0 |
| noise2_50000 | QBER_11_PERCENT | 100 | 0 | 0 | 16 |
| noise2_50000 | FINITE_KEY_NO_FALLBACK | 84 | 0 | 16 | 0 |
| noise2_50000 | PQC_ONLY_BASELINE | 0 | 100 | 0 | 0 |
| noise3_50000 | FINITE_KEY_POLICY | 1 | 99 | 0 | 0 |
| noise3_50000 | QBER_11_PERCENT | 100 | 0 | 0 | 99 |
| noise3_50000 | FINITE_KEY_NO_FALLBACK | 1 | 0 | 99 | 0 |
| noise3_50000 | PQC_ONLY_BASELINE | 0 | 100 | 0 | 0 |
| eve10_50000 | FINITE_KEY_POLICY | 60 | 40 | 0 | 0 |
| eve10_50000 | QBER_11_PERCENT | 100 | 0 | 0 | 40 |
| eve10_50000 | FINITE_KEY_NO_FALLBACK | 60 | 0 | 40 | 0 |
| eve10_50000 | PQC_ONLY_BASELINE | 0 | 100 | 0 | 0 |
| eve20_50000 | FINITE_KEY_POLICY | 0 | 100 | 0 | 0 |
| eve20_50000 | QBER_11_PERCENT | 100 | 0 | 0 | 100 |
| eve20_50000 | FINITE_KEY_NO_FALLBACK | 0 | 0 | 100 | 0 |
| eve20_50000 | PQC_ONLY_BASELINE | 0 | 100 | 0 | 0 |
| loss30_50000 | FINITE_KEY_POLICY | 0 | 100 | 0 | 0 |
| loss30_50000 | QBER_11_PERCENT | 0 | 100 | 0 | 0 |
| loss30_50000 | FINITE_KEY_NO_FALLBACK | 0 | 0 | 100 | 0 |
| loss30_50000 | PQC_ONLY_BASELINE | 0 | 100 | 0 | 0 |
| clean_100000 | FINITE_KEY_POLICY | 100 | 0 | 0 | 0 |
| clean_100000 | QBER_11_PERCENT | 100 | 0 | 0 | 0 |
| clean_100000 | FINITE_KEY_NO_FALLBACK | 100 | 0 | 0 | 0 |
| clean_100000 | PQC_ONLY_BASELINE | 0 | 100 | 0 | 0 |

## Paired controller contrasts

The paired bootstrap columns in `paired_controller_contrasts.csv` compare model-compliant outcomes from *the same* QKD observation under two deterministic policies. Because finite-key admission is defined using the same model, a lower in-model invalid-admission rate is partly true by construction; it is not an external adversarial security demonstration.

## OpenSSL-backed integration spot checks

| Scenario | Variant | N | Hybrid | PQC-only | Abort | Median frames | Median bytes | Median time (ms) |
|---|---|---:|---:|---:|---:|---:|---:|---:|
| clean_preferred | adaptive_p8 | 1 | 1 | 0 | 0 | 41 | 234471 | 3923.0 |
| clean_preferred | fixed_p9 | 1 | 1 | 0 | 0 | 31 | 180419 | 2844.3 |
| noise1_preferred | adaptive_p8 | 1 | 0 | 1 | 0 | 62 | 338515 | 5400.8 |
| noise1_preferred | fixed_p9 | 1 | 0 | 1 | 0 | 30 | 174151 | 2846.2 |
| noise3_preferred | adaptive_p8 | 1 | 0 | 1 | 0 | 70 | 385671 | 5795.4 |
| noise3_preferred | fixed_p9 | 1 | 0 | 1 | 0 | 30 | 174149 | 2643.9 |
| eve20_preferred | adaptive_p8 | 1 | 0 | 1 | 0 | 24 | 143381 | 2484.2 |
| eve20_preferred | fixed_p9 | 1 | 0 | 1 | 0 | 24 | 143453 | 2406.1 |
| short_required | adaptive_p8 | 1 | 0 | 0 | 1 | 20 | 96444 | 2037.8 |
| short_required | fixed_p9 | 1 | 0 | 0 | 1 | 18 | 86970 | 1964.9 |

## Conditions for publication

1. Independently verify mapping of the numerical finite-key formula to the theorem, basis assumptions and full protocol transcript.
2. Establish and document reconciliation leakage accounting, beyond a two-parity-bit-per-query proxy.
3. Justify the hybrid key combiner with an applicable composition theorem or narrow security claims.
4. Perform authentic protocol analysis with a dedicated symbolic prover if asserting unbounded security properties.
5. Collect larger OpenSSL protocol runs on the same controlled hardware; do not pool laptop timings with another machine.
6. Compare with the closest recent hybrid QKD/PQC papers before claiming novelty.

## References

- Tomamichel et al. (2012): https://doi.org/10.1038/ncomms1631
- NIST SP 800-227 (2025): https://csrc.nist.gov/pubs/sp/800/227/final
- RFC 5869: https://www.rfc-editor.org/rfc/rfc5869
