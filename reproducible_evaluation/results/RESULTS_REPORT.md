# Program 10 — Reproducible result summary

**Interpretation boundary:** This is an idealized/software BB84 simulation with deterministic random seeds and a candidate finite-key admission calculation. Numerical confidence intervals quantify random trial variation; they are *not* quantum security parameters. This does not discharge the open leakage, source-model, or hybrid combiner proof obligations.

## Model admission by scenario

| Scenario | N | Model-admitted | Wilson 95% CI | X-QBER observed | Theoretical |
|---|---:|---:|---:|---:|---:|
| short_500_clean | 500 | 0.0% | [0.0, 0.8]% | 0.00% | 0.00% |
| small_10000_clean | 500 | 0.0% | [0.0, 0.8]% | 0.00% | 0.00% |
| clean_50000 | 500 | 100.0% | [99.2, 100.0]% | 0.00% | 0.00% |
| noise1_50000 | 500 | 97.6% | [95.9, 98.6]% | 1.00% | 1.00% |
| noise2_50000 | 500 | 85.4% | [82.0, 88.2]% | 1.99% | 2.00% |
| noise3_50000 | 500 | 0.8% | [0.3, 2.0]% | 3.01% | 3.00% |
| eve10_50000 | 500 | 62.4% | [58.1, 66.5]% | 2.51% | 2.50% |
| eve20_50000 | 500 | 0.0% | [0.0, 0.8]% | 5.00% | 5.00% |
| loss30_50000 | 500 | 0.0% | [0.0, 0.8]% | Not estimable | 0.00% |
| clean_100000 | 500 | 100.0% | [99.2, 100.0]% | 0.00% | 0.00% |

## Hybrid-preferred policy comparisons

| Scenario | Strategy | Hybrid | PQC-only | Abort | In-model invalid hybrid |
|---|---|---:|---:|---:|---:|
| short_500_clean | FINITE_KEY_POLICY | 0 | 500 | 0 | 0 |
| short_500_clean | QBER_11_PERCENT | 500 | 0 | 0 | 500 |
| short_500_clean | FINITE_KEY_NO_FALLBACK | 0 | 0 | 500 | 0 |
| short_500_clean | PQC_ONLY_BASELINE | 0 | 500 | 0 | 0 |
| small_10000_clean | FINITE_KEY_POLICY | 0 | 500 | 0 | 0 |
| small_10000_clean | QBER_11_PERCENT | 500 | 0 | 0 | 500 |
| small_10000_clean | FINITE_KEY_NO_FALLBACK | 0 | 0 | 500 | 0 |
| small_10000_clean | PQC_ONLY_BASELINE | 0 | 500 | 0 | 0 |
| clean_50000 | FINITE_KEY_POLICY | 500 | 0 | 0 | 0 |
| clean_50000 | QBER_11_PERCENT | 500 | 0 | 0 | 0 |
| clean_50000 | FINITE_KEY_NO_FALLBACK | 500 | 0 | 0 | 0 |
| clean_50000 | PQC_ONLY_BASELINE | 0 | 500 | 0 | 0 |
| noise1_50000 | FINITE_KEY_POLICY | 488 | 12 | 0 | 0 |
| noise1_50000 | QBER_11_PERCENT | 500 | 0 | 0 | 12 |
| noise1_50000 | FINITE_KEY_NO_FALLBACK | 488 | 0 | 12 | 0 |
| noise1_50000 | PQC_ONLY_BASELINE | 0 | 500 | 0 | 0 |
| noise2_50000 | FINITE_KEY_POLICY | 427 | 73 | 0 | 0 |
| noise2_50000 | QBER_11_PERCENT | 500 | 0 | 0 | 73 |
| noise2_50000 | FINITE_KEY_NO_FALLBACK | 427 | 0 | 73 | 0 |
| noise2_50000 | PQC_ONLY_BASELINE | 0 | 500 | 0 | 0 |
| noise3_50000 | FINITE_KEY_POLICY | 4 | 496 | 0 | 0 |
| noise3_50000 | QBER_11_PERCENT | 500 | 0 | 0 | 496 |
| noise3_50000 | FINITE_KEY_NO_FALLBACK | 4 | 0 | 496 | 0 |
| noise3_50000 | PQC_ONLY_BASELINE | 0 | 500 | 0 | 0 |
| eve10_50000 | FINITE_KEY_POLICY | 312 | 188 | 0 | 0 |
| eve10_50000 | QBER_11_PERCENT | 500 | 0 | 0 | 188 |
| eve10_50000 | FINITE_KEY_NO_FALLBACK | 312 | 0 | 188 | 0 |
| eve10_50000 | PQC_ONLY_BASELINE | 0 | 500 | 0 | 0 |
| eve20_50000 | FINITE_KEY_POLICY | 0 | 500 | 0 | 0 |
| eve20_50000 | QBER_11_PERCENT | 500 | 0 | 0 | 500 |
| eve20_50000 | FINITE_KEY_NO_FALLBACK | 0 | 0 | 500 | 0 |
| eve20_50000 | PQC_ONLY_BASELINE | 0 | 500 | 0 | 0 |
| loss30_50000 | FINITE_KEY_POLICY | 0 | 500 | 0 | 0 |
| loss30_50000 | QBER_11_PERCENT | 0 | 500 | 0 | 0 |
| loss30_50000 | FINITE_KEY_NO_FALLBACK | 0 | 0 | 500 | 0 |
| loss30_50000 | PQC_ONLY_BASELINE | 0 | 500 | 0 | 0 |
| clean_100000 | FINITE_KEY_POLICY | 500 | 0 | 0 | 0 |
| clean_100000 | QBER_11_PERCENT | 500 | 0 | 0 | 0 |
| clean_100000 | FINITE_KEY_NO_FALLBACK | 500 | 0 | 0 | 0 |
| clean_100000 | PQC_ONLY_BASELINE | 0 | 500 | 0 | 0 |

## Paired controller contrasts

The paired bootstrap columns in `paired_controller_contrasts.csv` compare model-compliant outcomes from *the same* QKD observation under two deterministic policies. Because finite-key admission is defined using the same model, a lower in-model invalid-admission rate is partly true by construction; it is not an external adversarial security demonstration.

## OpenSSL-backed integration spot checks

| Scenario | Variant | N | Hybrid | PQC-only | Abort | Median frames | Median bytes | Median time (ms) |
|---|---|---:|---:|---:|---:|---:|---:|---:|
| clean_preferred | adaptive_p8 | 10 | 10 | 0 | 0 | 41.0 | 234475.0 | 3402.7 |
| clean_preferred | fixed_p9 | 10 | 10 | 0 | 0 | 31.0 | 180423.0 | 2670.5 |
| noise1_preferred | adaptive_p8 | 10 | 2 | 8 | 0 | 62.0 | 339276.5 | 4977.4 |
| noise1_preferred | fixed_p9 | 10 | 2 | 8 | 0 | 30.0 | 174151.0 | 2586.0 |
| noise3_preferred | adaptive_p8 | 10 | 0 | 10 | 0 | 72.0 | 396979.0 | 5654.7 |
| noise3_preferred | fixed_p9 | 10 | 0 | 10 | 0 | 30.0 | 174152.0 | 2583.7 |
| eve20_preferred | adaptive_p8 | 10 | 0 | 10 | 0 | 24.0 | 143380.5 | 2091.8 |
| eve20_preferred | fixed_p9 | 10 | 0 | 10 | 0 | 24.0 | 143452.5 | 2101.9 |
| short_required | adaptive_p8 | 10 | 0 | 0 | 10 | 20.0 | 96446.0 | 1827.6 |
| short_required | fixed_p9 | 10 | 0 | 0 | 10 | 18.0 | 86972.0 | 1678.0 |

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
