# Methods, interpretation and limitations — Program 7

## What is new compared with Program 6?
Program 6 signed batches **after** the parity reconciliation calculation. Program 7 implements parity queries and answers as actual cryptographically checked messages **during** error correction. It also introduces role-specific message-order state and independent local arrays for Alice and Bob, while using one process and synchronous relay for reproducibility.

## Crucial technical qualifications
1. **Single process**: These are independent *objects*, not independently scheduled remote computers. The simulation harness creates both quantum observations and orchestrates deliveries; no TCP transport, delays, partial failure, concurrency, or network packet reordering are tested.
2. **Simulation**: An idealized Bernoulli attack/noise/loss model replaces an optical experiment. No detector blinding, basis dependent efficiency, photon-number-splitting, source imperfections, or hardware side channels are modeled.
3. **Predictable simulation seeds**: NumPy seeded random bits support reproducibility but are NOT suitable for real cryptographic keys. Never use this application for confidential data.
4. **Interactive EC is not Cascade**: The new reconciliation uses block parity/bisection without full Cascade look-back. Its correction efficacy is not identical to Program 6. The comparison is therefore architectural/diagnostic, not a matched security or efficiency comparison between equivalent EC algorithms.
5. **Leakage bound is provisional**: `2 * q` is a conservative *model estimate* for each parity and adaptive branch, but a rigorous upper bound for all publicly revealed EC transcript information under an active attacker has not been proved. The finite-key calculation should not be described as composably validated for this new EC protocol until the exact assumptions are formally justified.
6. **Key admission centrally orchestrated**: Each endpoint holds, reconciles, verifies and hashes its own key bits and both sign status decisions, but the top-level research harness still coordinates global acceptance. A future two-process implementation should have endpoints independently calculate and agree on all parameter-estimation/acceptance invariants.
7. **No robust hybrid combiner proof**: Program 4's labeled HKDF concatenation construction remains an experiment; it is not an independently analyzed combiner with a demonstrated strongest-link guarantee.
8. **PQC protection depends on trusted identities**: ML-DSA and ML-KEM were standardized in NIST FIPS 204 and FIPS 203. Security depends on pinned authentic public keys and computational assumptions.
9. **Cryptographic costs are inflated by tooling**: Every signature and verification invokes OpenSSL 3.5 subprocesses, uses temporary filesystem artifacts, and transfers 3309-byte ML-DSA signatures. Benchmarks cannot be advertised as hardware QKD latency or optimized post-quantum network performance.
10. **Not a formal verification**: 137 tests and observed attack rejections test a finite set of properties only. Formal symbolic analysis may be conducted separately, with appropriate limits on quantum-state modeling.
11. **Statistical sample is small**: The default experiment has 2 repetitions across nine scenarios and one tamper instance per 19 frame types. These are early reproducibility tests, insufficient for population security rates or highly confident performance estimates.

## Interpretation of reference experiments
The Program 7 median number of signed frames exceeded Program 6 in every compared scenario. That is expected from signed, interactive error-correction rounds and chunked basis exchanges. The increased cost is an architectural trade-off; we must not claim that Program 7 is faster or consumes less bandwidth. A realistic publishable efficiency design may require authenticated batching, amortized signatures, or carefully proved channel-level authentication, with honest attack-protection comparisons.

One case of 3% background noise can cause a key-admission rejection while PQC-only fallback remains allowed. This does not imply that all QKD implementations reject 3% noise. The demonstration is tied to the configured finite-sample test and reconciliation parameters.

## References to cite
- NIST FIPS 203 (2024): https://csrc.nist.gov/pubs/fips/203/final
- NIST FIPS 204 (2024): https://csrc.nist.gov/pubs/fips/204/final
- NIST SP 800-38D: https://csrc.nist.gov/pubs/sp/800/38/d/final
- Tomamichel et al. (2012), finite-key BB84 analysis: https://www.nature.com/articles/ncomms1631
- Cascade parity reconciliation overview: https://cascade-python.readthedocs.io/en/latest/protocol.html
- Tamarin model limitations: https://tamarin-prover.com/manual/master/book/014_limitations.html

## Necessary next stage
Before claiming journal-ready novelty: justify reconciliation leakage rigorously, verify an independent-mode agreement state machine, implement a cited robust key combiner with its assumptions, and compare against the closest 2025–2026 hybrid QKD/PQC research on more trials and representative networks. A Tamarin/ProVerif model can assess symbolic authentication properties but cannot substitute for a quantum-composable proof.
