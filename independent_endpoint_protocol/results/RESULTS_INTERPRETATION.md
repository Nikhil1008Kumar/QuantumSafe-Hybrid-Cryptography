# Program 7 first reference run (Python 3.13 / OpenSSL 3.5.5)

- **137 / 137 unit tests passed**, including 116 inherited regressions and 21 new tests.
- **18 paired sessions** across 9 conditions, two trials per condition.
- **19 / 19 injected public-frame alterations rejected** (one test per attacked stage). This is NOT a population-wide attack resistance estimate.
- Mode results for the 18 sessions: **6 hybrid, 8 PQC-only, 4 abort**.
- All application records in sessions permitting data transfer were decrypted successfully in these diagnostic runs.

## Median signed frame count (Program 7 vs Program 6)

| Scenario | Program 7 (interactive) | Program 6 (batched) | Outcome Program 7 |
|---|---:|---:|---|
| Clean preferred | 49 | 30 | 2/2 HYBRID |
| 1% noise preferred | 78 | 38 | 2/2 HYBRID |
| 3% noise preferred | 137 | 54 | 2/2 PQC_ONLY |
| 20% Eve preferred | 24 | 12 | 2/2 PQC_ONLY |
| Short preferred | 28 | 17 | 2/2 PQC_ONLY |
| Clean required | 49 | 30 | 2/2 HYBRID |
| 3% noise required | 138 | 53.5 | 2/2 ABORT |
| Short required | 28 | 17 | 2/2 ABORT |
| PQC-only | 6 | 4 | 2/2 PQC_ONLY |

Program 7 is **more expensive** in signature counts and in measured elapsed time. It supplies online signed error-correction messages missing from Program 6's privileged batching design; the algorithms and message formats also differ, so this is not a fair production performance benchmark or a security-improvement quantification.

The results are engineering validation, not a novelty certificate, a key-security proof, or a deployment performance claim. See full CSV and methodology documentation for individual records and restrictions.
