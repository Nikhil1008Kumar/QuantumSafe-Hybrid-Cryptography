# Methods, assumptions, and publication limitations

## What was actually implemented

1. Actual ML-DSA-65 signatures and ML-KEM-768 KEM operations via OpenSSL 3.5 command line (from Program 3). Trust in identity verification keys is provisioned/pinned in the local program, not established using a public-key infrastructure.
2. Seeded finite-key BB84 simulation with Z- and X-basis sifting, X-basis parameter estimation, public leakage accounting, Cascade-like reconciliation, verification and Toeplitz universal hashing (Program 2). Same predeclared `q_tolerance=0.04`, `ec_leakage_cap_fraction=0.40`, and `eps_secrecy=eps_correctness=1e-10`. For the ten-scenario experiment, target key/test bits equal round(18% of transmitted signal count).
3. Signed high-level policy choice, QKD outcome receipts and signed final mode acknowledgment. Signing receipts is **not equivalent** to authenticating actual sifting, EC, PA seed or every QKD classical public message. The latter is a future research requirement.
4. Experimental concatenation/HKDF schedule from domain-separated bootstrap secret and accepted simulated QKD material. All constituent algorithms are existing standards/techniques; no new formal hybrid-security claim.
5. AES-256-GCM using `cryptography` library, 96-bit nonce comprised of four per-direction derived bytes plus eight sequence bytes, authenticated session/role/mode/seq AAD, and record-replay check.
6. 75 passing automated tests (19 Program 2 regression, 28 Program 3 regression, 28 new integration tests) and a *preliminary* set of 80 sessions across ten scenarios (8 repetitions each), not a powered inferential research study.

## Why the simulation is not a security proof

- QKD source and quantum channel are **not actual quantum optics**. Ideal source and basis-independent detection are assumed. Trojan-horse, photon-number-splitting, timing, detector blinding, finite detection-efficiency mismatch, imperfect entropy and physical side channels are not simulated.
- Program 2's mathematical bound is conditional on the theorem's complete assumptions, including authenticated public communication. In Program 4, the BB84 public discussion occurs inside a single process and is NOT instantiated with actual authenticated exchanges. The signed post hoc receipt is therefore a diagnostic demonstration, not a substitution for an authenticated classical QKD channel.
- Program 2 and the Program 4 integration use `numpy.random.default_rng` initialized with reproducible seeds; the simulator's private bits can be reproduced by anyone knowing the seed. Therefore the output is **not** a cryptographically secret real-world quantum key. Those keys are only diagnostic simulation artifacts.
- The authenticated bootstrap is a research handshaking demonstration, not standard TLS, and it writes private key material to temporary files while invoking OpenSSL; it is not production-ready hardened key storage.
- The Program 3 `PQC_ONLY` handshake is deliberately used as the initial authentication bootstrap. The subsequent mode is negotiated by new signed messages, rather than redesigning the original ML-KEM handshake.
- The concatenation-plus-HKDF combination has not been proven robust under arbitrary correlated secrets, post-quantum active adversaries or one-component total compromise. Make no strongest-link, universally composable or information-theoretic-security claims.
- Both endpoints run inside the same interpreter with a privileged simulator. Formal session-state agreement is only tested through selected mutators; malicious authenticated participants, replay across crashes, networking delay/packet reordering and persistence across processes are not covered.
- The chosen fixed QBER bound, leakage cap and 256-bit extraction target are **configuration-specific**. The observed 3% noise rejection in one configuration does NOT represent an intrinsic QKD threshold.
- Lower wall-clock median in one environment is NOT evidence of algorithmic speedup. OpenSSL subprocess startup and filesystem I/O dominate the timing on some systems, and there is no quantum hardware or simulated optical propagation delay.
- Current sample size (8 runs/config) is intended for code verification and illustrative curves only. It is insufficient to substantiate final journal performance or attack-probability claims.

## Before preparing publication claims

- Implement a faithful two-party authenticated BB84 public transcript with independent Alice/Bob state, signatures or session-authenticated MACs on each required message, and make sure the chosen finite-key proof accommodates the authentication mechanism and its budget.
- Research/select a proven robust hybrid combiner, or prove an appropriate theorem for your proposal; account for computational assumptions and authenticated key establishment.
- Formalize policy state-machine and allowed fallback under strong active adversarial control; consider symbolic verification and full replay persistence.
- Use multiple independent seeds, larger trial counts, predeclared hypotheses, confidence intervals, and both negative and positive controls; run fixed-hardware reproducible benchmarking.
- Compare with contemporary QKD-PQC adaptive/fallback schemes rather than only the rejected BB84-RSA-AES study.

## Standards and theorem

- NIST FIPS 203 ML-KEM, https://csrc.nist.gov/pubs/fips/203/final
- NIST FIPS 204 ML-DSA, https://csrc.nist.gov/pubs/fips/204/final
- NIST SP 800-38D GCM, https://csrc.nist.gov/pubs/sp/800/38/d/final
- Tomamichel et al., 'Tight finite-key analysis for quantum cryptography', Nature Communications 3 (2012), https://www.nature.com/articles/ncomms1631
