# Research methods, policy mathematics, and limitations — Program 5

## Paired experimental design

Choose independent seeds indexed by scenario and replicate, with base seed 20261024. There are nine predeclared scenarios and default 20 independent QKD simulations per scenario: short 500 clean, 10,000 clean, 50,000 clean, 50,000 with 1%/3% background errors, 50,000 with 10%/20%/40% intercept-resend, and 50,000 with 30% loss. Each scenario uses exactly the Program 4 configuration rule `target_key_bits = target_test_bits = round(0.18*N)` and `q_tolerance=0.04`.

Run Program 2 `run(cfg, seed)` exactly once per replicate, obtain QKD metrics without exporting keys, and pass the SAME observation into four policy controllers under (1) HYBRID_PREFERRED and (2) HYBRID_REQUIRED. The resulting 180 simulated QKD observations are therefore matched for all controller comparisons. Two policies times four strategies gives 1,440 decision rows.

## Definitions (not new cryptographic results)

Let `A` be the condition that the **Program 2 model** reports `ACCEPT`, returns 256 final bits, has finite-key bound >=256, completes reconciliation verification, and stays within its predeclared EC disclosure budget. The actual finite-key theorem and implementation assumptions matter; this flag is *not* an empirical oracle for adversary knowledge of the final key.

Let `B` be the simpler QBER-only rule `n_X>0` and `observed_X_QBER <= 0.11`. `B` omits finite-key constraints; it is a deliberately simplified comparison, not a recommended complete protocol.

For authenticated session context `V` and application policy `P`, the proposed candidate is:

- If `not V`: ABORT.
- If `P=PQC_ONLY`: PQC_ONLY.
- If `A`: HYBRID.
- If `not A` and `P=HYBRID_PREFERRED`: PQC_ONLY.
- Otherwise: ABORT.

`FINITE_KEY_NO_FALLBACK` aborts on `not A`. `QBER_11_PERCENT` substitutes `B` for `A`. `PQC_ONLY_BASELINE` never reports HYBRID.

A *model-invalid QKD label* is defined as: controller returns HYBRID, but `A` is false. It is **not a cryptographic break**, probability of decryption, key leakage rate, false-negative eavesdropping probability, or evidence of an attacker compromising hardware. The metric evaluates whether a controller respects the selected simulator's admission condition.

The **modeled policy-compliant session count** equals: #PQC_ONLY + #HYBRID with `A=true`. For `HYBRID_REQUIRED` PQC_ONLY is prohibited. This metric measures a policy outcome and cannot be equated to empirically secure end-to-end connectivity. `ABORT` is often the expected correct security outcome.

95% uncertainty intervals for binomial mode-outcome proportions are the **Wilson score intervals**, from independent simulator trials. They do not quantify the confidence of information-theoretic QKD secrecy. Paired differences can be compared directly by seed, but these exploratory experiments do not report inferential tests or pre-registered research hypotheses.

## Authenticated preconditions vs genuine attack tests

The controller uses `VerifiedContext` flags for authenticated identities, verified signed policy and QKD reports, transcript consistency, freshness, and KEM readiness. Boolean-flip tests verify fail-closed policy logic; they do **not** constitute an attack on ML-DSA or proof that an arbitrary network adversary cannot forge messages.

The genuine ML-DSA/ML-KEM operations and AES-GCM are performed by the *unmodified Program 4 module* during five smoke tests. The inherited 75 tests exercise some cryptographic message and record tampering, but **not** actual authenticated per-message QKD network operations. Reproduced cryptographic benchmarks include OpenSSL command-line startup, Python orchestration, file I/O, and no physical optical or network delay.

## Significant limitations to address before journal claims

1. Program 2's QKD source, detectors and channel are **idealized stochastic models** based on a reproducible NumPy generator; real BB84 public messages are not exchanged across distinct processes.
2. The high-level signed receipts in Program 4 DO NOT fully authenticate each actual QKD classical message during public sifting, reconciliation, and privacy amplification.
3. Program 4 concatenation+HKDF has not been proven robust against all one-secret-compromise and composition cases; no strongest-link guarantee is asserted.
4. The model counts leakage using a predeclared budget, with published-theorem assumptions and separate modeled verification. Independent cryptographic review is required before an unconditional/composable security guarantee is claimed.
5. QBER-only decisions can label HYBRID when **no 256-bit key is available**. Such decisions are compared as *hypothetical unsafe labels*, not functioning encrypted sessions.
6. Our proposed policy's 100% modeled availability under preferred policy is **equal to the PQC-only baseline** by construction in this study. It does not establish better availability than a well-designed computational fallback.
7. The experiments are small, exploratory, use limited attack/noise models, and omit physical hardware, trust establishment, relay nodes, side channels, energy/bandwidth lifecycle costs, attack-model completeness, and full network behavior.
8. The new policy is not claimed to be unique. Related work already implements QKD/PQC fallback, finite-key-aware hybrids, and security-constrained controllers; a stronger independently checkable result is needed.

## Next stage for publishable novelty

Program 6 should implement **separate Alice/Bob state machines and authenticated per-message BB84 classical reconciliation/sifting**; it should specify and verify the complete mode negotiation and final key-extraction invariants, and assess a cryptographically justified hybrid combiner with a formally stated security game. It should also add closely competing published baselines and robust confidence/power analysis. This would better isolate any substantive original contribution.
