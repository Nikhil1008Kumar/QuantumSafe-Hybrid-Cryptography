# Program 1 — initial results interpretation

**Experimental design**: ideal BB84 prepare-and-measure Monte Carlo model;
10,000 transmitted signals per calibration trial; 20% public random test
sample of sifted positions; 200 independently seeded trials per intercept
probability; no added noise/loss; p from 0.0 through 0.6. Base seed 20261024.

**Analytical benchmark**: E[QBER] = p/4 under the model assumptions.

| Eve probability | Analytical QBER | Mean simulated test-sample QBER | 95% confidence interval across trials |
|---|---:|---:|---:|
| 0% | 0.000% | 0.000% | [0.000%, 0.000%] |
| 10% | 2.500% | 2.464% | [2.393%, 2.534%] |
| 20% | 5.000% | 4.940% | [4.850%, 5.030%] |
| 30% | 7.500% | 7.525% | [7.407%, 7.642%] |
| 40% | 10.000% | 10.131% | [9.988%, 10.274%] |
| 50% | 12.500% | 12.540% | [12.398%, 12.681%] |
| 60% | 15.000% | 15.056% | [14.898%, 15.214%] |

**Finite-sample illustrative diagnostic**: with 500 transmitted signals, only
10% of sifted bits sampled, 1,000 independent trials per interception rate:

| Eve probability | Zero-error public samples | Samples with QBER <=11% |
|---|---:|---:|
| 10% | 55.2% | 98.5% |
| 40% | 7.2% | 56.5% |
| 60% | 2.3% | 24.6% |

This diagnostic shows false reassurance from a small public sample; the <=11%
rate is **not** an implemented acceptance rule. The 95% CIs here express
uncertainty in a mean estimate from repeated simulation trials, **not** a
security proof or the finite-key bound required for QKD.

**Conclusion**: Program 1 behaves consistently with its idealized analytical
benchmark. This establishes a corrected reproducible baseline but no
composable security claim, end-to-end key agreement, or physical-QKD evidence.
