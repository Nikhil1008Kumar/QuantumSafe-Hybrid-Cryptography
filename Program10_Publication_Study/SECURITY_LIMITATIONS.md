# Publication security checklist — unresolved obligations

The outcome here is a **research simulator plus comparative data**, not a composably secure QKD/PQC protocol theorem. Use explicit *model-admitted* terminology.

## Open obligation 1 — Finite-key theorem mapping

The numerical function `finite_key_bb84.finite_key_bound` follows an ideal BB84-style bound from Tomamichel et al. (2012), but the full end-to-end simulated implementation must be checked against the theorem's assumptions. In particular: source and measurement preparation quality, independence of basis/detection behavior, fixed n and k, fixed error tolerance, authenticated public channel, disclosure accounting and quantum-vs-computational security definition. Deterministic NumPy seeds invalidate claims of unpredictably private keys in a production threat model.

## Open obligation 2 — Error-correction leakage

The adaptive EC branch publicly reveals query positions/selection and can have a transcript shape depending on raw data and errors. `ec_public_bits_proxy` is a parity bit count, not a complete secrecy-leakage bound. Program 9's nonadaptive Hamming-31 syndrome has a public fixed bit count `5*passes*ceil(n/31)`, but control messages, verification tags, timing and status remain to be addressed. Do not call either branch unconditionally *finite-key secure* until these assumptions and leakage are justified.

## Open obligation 3 — Hybrid key security

The implemented HKDF key schedule combines KEM and QKD material under authenticated session context. Functional and differential tests do not prove that the result remains secure if either secret is adversarially compromised or that all adversarial correlations are harmless. A robust combiner theorem or a narrower declared claim is necessary; see NIST SP 800-227 and RFC 5869.

## Open obligation 4 — Formal protocol proof

Program 8 explored 1,368 bounded abstract states without violations; it is not an unbounded Tamarin or ProVerif proof. The faithful symbolic model and proof log must be supplied before claiming an unbounded authentication/replay/downgrade result.

## Open obligation 5 — Statistical reporting and machine costs

A 95% Wilson/bootstrap interval quantifies Monte Carlo estimation uncertainty **only**. It does not estimate `epsilon_secrecy` or `epsilon_correctness`. A zero-observed-event result still has a nonzero upper confidence limit. Do not combine the local reference environment's OpenSSL timing with Windows timing in a single latency comparison. Small OpenSSL samples (default 2 per condition per variant) are spot checks, not high-powered performance evidence. Profile process startup/temporary files separately if publishing performance comparisons.

## Claims that are supportable

- "Under our explicitly specified idealized channel model, the candidate finite-key admission controller was evaluated in N independently seeded trial simulations per condition."
- "All controllers processed identical QKD outcomes for paired comparison."
- "The naive 11% QBER-only control admitted some sessions the configured finite-key model did not. This is a model inconsistency, not a directly demonstrated cryptographic break."
- "The independent endpoint protocol exercised real ML-DSA/ML-KEM implementation operations, with measured message costs and explicitly limited formal verification."

## Claims NOT supportable

- "We invented quantum-safe QKD–PQC integration."
- "The system is information-theoretically secure end to end."
- "No attacks are possible because automated tests passed."
- "The QKD key has composable epsilon secrecy despite unproved transcript leakage."
- "The hybrid HKDF combiner is proved strongest-link secure."
- "The controller is universally better than PQC-only."
- "The simulator represents actual fiber optics or production device noise."

## Before journal submission

Obtain a genuinely independent, up-to-date novelty survey, fix/justify leakage, analyze key combiner security, create a cryptographic protocol model for a symbolic prover if making broad protocol-security claims, increase protocol integration replication and benchmark consistently. Otherwise describe the paper as a reproducible *simulation-based evaluation and controlled protocol-policy study* rather than a cryptographic proof.
