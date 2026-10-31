# Program 8 — Exact bounded abstract-state specification

## Objective and scope
This program **does not claim Tamarin or ProVerif verification**. It runs an enumerative, **bounded explicit-state model checker** written in Python (`security_model.py`) and executes genuine OpenSSL-backed transport tests against the Program 7 code, modified to enforce local mode policy checks.

The model is intentionally smaller than the implementation. It studies the *control plane* for signed policy, QKD status, mode and key confirmation. It does **not** model actual photon states, full parity exchanges, adaptive leakage, finite-key min-entropy, confidentiality, KEM/ML-DSA mathematical attacks, arbitrary concurrency, and long-lived storage.

## Abstract participants, state and accepted events
Participants are Alice, Bob and an adversarial message relay. Session inputs are:

- policy `P ∈ {HYBRID_REQUIRED, HYBRID_PREFERRED, PQC_ONLY}`;
- externally **assumed** QKD finite-key admission `D_Q ∈ {0,1}`;
- externally **assumed** ML-KEM establishment `D_P ∈ {0,1}`;
- symbolic key agreement `E ∈ {0,1}`.

The abstract signed frame sequence comprises eight expected frames:

```
policy_a -> policy_b -> report_a -> report_b ->
mode_a -> mode_b -> confirm_a -> confirm_b
```

Sender, session, signature, stage and agreement checks must succeed before a receiver advances. `index` is the next expected signed message index. A terminal state is `ACCEPT`, `ABORT`, `REJECT`, or `STALLED`. A `STALLED` state represents an adversary dropping a message: this threatens liveness, not necessarily safety. **All 24 policy/admission/KEM/agreement input configurations are explicitly explored.**

## Enumerated relay actions and bound
For each expected frame, the relay can perform `deliver`, `forge`, `cross_session_replay`, `replay_prior`, `reorder`, `drop`, or `peer_mode_conflict`. `peer_mode_conflict` is meaningful only for Bob's mode message and represents a validly signed, incorrectly configured peer; it is not assumed to be forgeable by a normal network adversary.

The default model enumerates traces containing **at most one non-deliver action** across at most eight signed frames, and its checks can optionally use a two-deviation bound. With intact guards, the first hostile change causes rejection or stall, so raising this bound does not expand the reachable state count. The attacker alphabet is finite and **not** the full Dolev–Yao message algebra.

## Safety invariants encoded in `invariant_violations`

**I1 — Authentication.** No forged payload is accepted as an authentic signed frame.

**I2 — Session freshness.** A previously signed frame from another session is not accepted in the current session.

**I3 — Stage/sequence.** A replay or out-of-order signed frame is not accepted at a wrong protocol stage.

**I4 — QKD admission.** `mode = HYBRID` only when `D_Q = 1` and `D_P = 1`.

**I5 — Required mode.** On successful completion with `HYBRID_REQUIRED`, `mode = HYBRID` (never silent fallback).

**I6 — PQC-only mode.** On successful completion with `PQC_ONLY`, `mode = PQC_ONLY`.

**I7 — Mode agreement.** Successful completion implies Alice and Bob accepted the same mode.

**I8 — Key confirmation.** Successful completion requires agreement of both locally derived keys in the symbolic model.

**I9 — KEM establishment.** Any completed usable session requires `D_P = 1`.

The local mode-selection rule is:

\[
M(P,D_Q,D_P) =
\begin{cases}
\mathrm{ABORT}, &D_P=0,\\
\mathrm{PQC\_ONLY}, &P=\mathrm{PQC\_ONLY},\\
\mathrm{HYBRID}, &D_Q=1,\\
\mathrm{PQC\_ONLY}, &P=\mathrm{HYBRID\_PREFERRED},\ D_Q=0,\\
\mathrm{ABORT}, &\text{otherwise.}
\end{cases}
\]

## Negative-control models
`negative_controls()` switches off these *individual* safeguards in deliberately weakened versions:

1. signature authentication;
2. session-context binding;
3. sequence / expected-stage checks;
4. local policy validation **together with** the independent role agreement check (to make the defective downgrade reachable);
5. independent mode agreement;
6. key confirmation.

Every disabled safeguard produces at least one counterexample, recorded with the exact abstract input and trace in `results/counterexample_traces.json`. These are **model-detected design faults**, not real observed breaches of the functioning cryptographic implementation.

## Relation to Program 7 source
Program 8 changes `Endpoint.allowed()` to reject mode messages if their status, policy or selected mode disagrees with an independently recomputed local decision based on that endpoint's own `final` key state. The source still runs Alice and Bob as distinct Python objects over an in-memory relay. ML-DSA verification is real, via OpenSSL 3.5+, but the quantum channel is only a seeded simulator.

## Boundary of the conclusion
An empty `violations` mapping means **no encoded safety property was violated in the specified bounded finite model**, assuming the model's idealized signature/session semantics and external key admission. It does **not** establish cryptographic security of an implementation, unconditional QKD secrecy, robust hybrid-combiner security, or correctness under arbitrary concurrent sessions. A future Tamarin/ProVerif mechanization and cryptographic composition proof are not part of these results.
