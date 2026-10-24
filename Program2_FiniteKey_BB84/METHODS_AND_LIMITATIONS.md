# Program 2 — Methods, scope, and remaining research gaps

## Threat / communication model

- Ideal independently prepared BB84 qubits in two mutually unbiased bases; preparation quality q=1.
- Bob's registered detection probability is independent of basis. Optional losses are basis independent; the simulator does not cover basis-dependent detector efficiency, multi-photon pulses, bright-light injection, decoy states, detector blinding, or other implementation attacks.
- Simulation only: interception is an independent random-basis intercept-resend action; background errors are independent post-measurement bit flips.
- Entropic finite-key formula sourced from Tomamichel et al. (2012), Eq. (2), which provides a theorem for its covered device model and authenticated classical channel. The single attacker modeled in these experiments is far less general than the attacker allowed by that proof.
- Authenticated classical communication is an **assumption** here. No authentication library, signature verification, transcript integrity, replay protection, or network transmission exists in Program 2. This is a priority for Program 3.
- Private/source randomness is produced by a seeded noncryptographic generator to permit reproducible experimental calibration. In particular, the trial seeds are intentionally disclosed in the CSV. Do not use output bits as actual secrets: anyone knowing those seeds can reproduce them.

## Security parameter and sampling discipline

1. `n`, `k`, `Q_tol`, epsilons, permitted EC budget, hash output length and measurement probabilities are declared *before* the experiment.
2. Uniform subsets are selected from the sifted basis-specific detected events (the program does not choose posthoc favorable bits).
3. All selected X-basis bits are revealed to estimate QBER; none are reused as key bits.
4. All selected Z-basis candidate bits are subject to the reconciliation, correctness verification and privacy amplification flow. Z-basis mismatch counts are shown only as simulator diagnostics and are **not read by the decision function**.
5. If there are not enough detected events in either basis, abort.
6. If the X test exceeds `Q_tol`, abort.
7. Count both Alice and Bob parity disclosures. Abort if total exceeds predeclared EC ceiling. Charge the **ceiling** (not favorable observed leakage) against the key length theorem.
8. Correctness is checked with an independently seeded Toeplitz hash; the correctness budget is accounted for in the published formula.
9. Compute source-preparation quality q=1 only because the mathematical simulator prepares ideal states; do not carry this assumption into a hardware claim.
10. Extract only the amount permitted by Eq. (2), then publish only statistics, not the simulated key values.

## Research caveats important to reviewers

- A passing code test is **not** a formal quantum security proof. The conditional security argument comes from the cited theorem and its mathematical assumptions.
- The program currently does not implement any real authenticated classical channel. Without authentication, man-in-the-middle attacks compromise practical BB84 security.
- EC uses a small reference Cascade-like implementation, not a validated production reconciliation stack. Its public parity transcript is modeled as two revealed bits per parity query. Hidden deployment metadata, software side channels, timing leakage, and implementation-specific communication patterns are not formally audited.
- Information reconciliation depends on chosen block sizes and random permutations; failure cases correctly abort at verification instead of returning a mismatched key.
- Toeplitz parity computations use floating-point FFT convolution with integer rounding. Verified against exact GF(2) multiplication for multiple short cases, but requires additional high-volume verification and review before production.
- A privacy-amplified bit string is only secure within the idealized source, measurement, authentication, independent randomness, and statistical assumptions of the applied theorem. Reproducible seeds mean the actual generated simulation bits provide no real confidentiality.
- The resource quota is a simplified finite-duration protocol: it aborts when a fixed transmission budget fails to supply both predeclared target counts.
- The 40%-of-n EC leakage budget is chosen for this exploratory experiment, not optimized or novel. Subsequent work must compare realistic efficiency against known reconciliation protocols, vary the budget and extend channel noise/loss models.
- Failure rates of 0/20 and 20/20 imply broad confidence limits; the experiment has not established deployable reliability or publication-grade statistical power.
- Program 3 must introduce authenticated post-quantum cryptography. Later stages must assess formal downgrade protection, hybrid construction/security arguments and meaningful comparative novelty.

## Journal results to collect next

- >= 1,000 trials for critical transition-region configurations, including confidence intervals (or a justified power analysis)
- tests at multiple fixed X-basis error tolerances and multiple predeclared EC ceilings
- failure rates of verification, residual mismatches, leakage efficiency vs Shannon lower bound
- loss- and noise-dependent accepted secret-key yield *per transmitted signal*
- biased-basis BB84 variants with matched protocol security theorem assumptions
- endpoint-authentication enforcement; authenticated transcript and replay/downgrade negative tests
- comparison against a published QKD reference implementation and independent verification of equations

## Sources

- Tomamichel et al., *Nature Communications* **3**, 634 (2012), Eq. (2), https://doi.org/10.1038/ncomms1631
- Bennett and Brassard, BB84 (1984), original quantum key distribution proposal (background)
