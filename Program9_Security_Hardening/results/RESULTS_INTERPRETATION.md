# Program 9 pilot — observed results

**Scope:** 2 paired repetitions per configuration, 20 OpenSSL-backed runs overall. These are descriptive pilot results, not strong statistical evidence.

| Configuration | Program 8 adaptive | Program 9 fixed | Median signed frames (P8→P9) |
|---|---|---|---:|
| clean_preferred | HYBRID 2/2 | HYBRID 2/2 | 41 → 31 |
| noise1_preferred | HYBRID 1/2, PQC_ONLY 1/2 | HYBRID 1/2, PQC_ONLY 1/2 | 62 → 30 |
| noise3_preferred | PQC_ONLY 2/2 | PQC_ONLY 2/2 | 71 → 30 |
| eve20_preferred | PQC_ONLY 2/2 | PQC_ONLY 2/2 | 24 → 24 |
| short_required | ABORT 2/2 | ABORT 2/2 | 20 → 18 |

The fixed-code approach uses 2 predeclared syndrome passes with **2910** public EC syndrome bits at n=9000; its finite-key arithmetic adds **98** bookkeeping bits for a second verification tag and a conservative modeling margin. The computed bound at 9000/9000 and Q_tol=4% is **1321 candidate bits**. The corresponding Program 8 result under a 40%-of-n EC cap is **729 candidate bits**; this difference is mostly due to the different, deliberately conservative input leakage caps and **does not establish stronger real-world security**.

In these paired trials, fixed-syndrome reconciliation did not consistently outperform interactive reconciliation in correcting noisy keys. Separate cryptographic composition and unbounded formal proofs have **not** been completed.
