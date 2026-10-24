# Program 4 — Initial results (NOT final journal evidence)

Executed 80 local sessions (8 independently seeded runs in each of 10 predetermined scenarios). The tests measure local control-flow and cryptographic-library behavior under the explicitly stated simulation assumptions. They do **not** prove security for a physical QKD network.

| Scenario | Hybrid | PQC-only | Abort | Median successful total time (ms) |
|---|---:|---:|---:|---:|
| PQC_only | 0 | 8 | 0 | 121.9 |
| Hybrid_clean | 8 | 0 | 0 | 130.0 |
| Preferred_clean | 8 | 0 | 0 | 130.0 |
| Preferred_noise_1pct | 8 | 0 | 0 | 130.5 |
| Preferred_noise_3pct | 0 | 8 | 0 | 130.7 |
| Required_noise_3pct | 0 | 0 | 8 | — |
| Preferred_Eve_20pct | 0 | 8 | 0 | 128.3 |
| Required_Eve_20pct | 0 | 0 | 8 | — |
| Preferred_short_500 | 0 | 8 | 0 | 130.4 |
| Required_short_500 | 0 | 0 | 8 | — |

**Interpretation:** An authorized fallback makes sessions more available than a QKD-required policy when the simulated QKD estimator or error-reconciliation leakage budget fails. This is expected **policy behavior** and is not by itself a novel performance advantage or a new cryptographic security theorem. Fallback sessions must be labeled PQC-only; they do not achieve accepted QKD admission.

For a clean 50,000-signal scenario the selected Program 2 finite-key bound is 729 bits under the predeclared parameters, and a 256-bit diagnostic key is extracted if reconciliation and verification pass. At 3% simulated background noise the same configured reconciliation-leakage cap was exceeded in these trials, triggering fallback or abort, depending on signed policy.

**Timing caveat:** Timings in this run reflect the execution environment and include OpenSSL CLI subprocesses and temporary-file reads/writes plus the QKD simulator; they cannot be generalized to different laptops, networking stacks or quantum optical devices.

**Statistical caveat:** Eight trials per condition are inadequate for final confidence intervals or security rates. No hypothesis-testing or security-strength inference should be made from the near-0/100% proportions in this pilot.

**Excluded from this stage:** Network transport of authenticated QKD public messages, robust combiner proof, quantum optics/hardware, physical side channels, distributed replay database, standard TLS integration, and journal-grade cross-paper benchmarking.
