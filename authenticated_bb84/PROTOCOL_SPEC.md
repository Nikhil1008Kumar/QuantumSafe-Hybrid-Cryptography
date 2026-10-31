# Program 6 — Protocol specification and security invariants

## Threat model and intended scope

An attacker can observe, remove, replay, reorder, substitute or modify classical frames after they have been signed. Alice and Bob begin with trusted pinned ML-DSA-65 public identity keys. OpenSSL provides real ML-DSA and ML-KEM primitives. The quantum channel is an *idealized and seeded* single-process BB84 simulator with optional loss, bit-flip noise and intercept–resend attacks. This prototype does not model side channels, photonic devices, source flaws or stateful network service enrollment.

## States and authenticated classical messages

```
INIT:
  Alice -> Bob: signed policy_offer(policy, config hash, KEM bootstrap hash)
  Bob -> Alice: signed policy_ack  (policy, config hash, KEM bootstrap hash)
AUTHENTICATED -> BASIS:
  Bob   -> Alice: signed bob_detected (public detection bitmap)
  Bob   -> Alice: signed bob_basis    (measurement basis bitmap)
  Alice -> Bob:   signed alice_basis  (preparation basis bitmap)
BASIS -> TEST:
  Alice -> Bob: signed sampling_seed (predeclared n,k, sample selector)
  Alice -> Bob: signed alice_test_bits (public X sample)
  Bob   -> Alice: signed bob_test_bits (public X sample)
TEST -> EC, if X-QBER <= predeclared tolerance:
  Alice -> Bob: signed ec_seed (shuffle seed and reconciliation settings)
  Bob   -> Alice: signed ec_batch[0..N] containing public parity events
EC -> VERIFY:
  Alice -> Bob: signed verification_seed (Toeplitz seed)
  Alice -> Bob: signed alice_verification_tag
  Bob   -> Alice: signed bob_verification_tag
VERIFY -> PA, if EC disclosure <= predeclared budget, verification succeeds,
   and finite-key extraction bound allows the requested key:
  Alice -> Bob: signed privacy_amplification_seed (Toeplitz seed)
  Alice/Bob locally hash reconciled raw Z bits into separate final keys
[any exit] -> DECIDED:
  Alice -> Bob: signed qkd_report_alice
  Bob   -> Alice: signed qkd_report_bob (binds Alice report)
DECIDED:
  Alice -> Bob: signed mode_decision (HYBRID/PQC_ONLY/ABORT)
  Bob   -> Alice: signed mode_ack
FINISHED or ABORT:
  If mode succeeds, domain-separated hybrid key derivation, key confirmation,
  and a single AES-256-GCM protected example record.
```

**Implementation caveat:** EC `ec_batch` frames bind actual parity decisions but are emitted after the single-process reconciliation calculation. The simulator therefore does not implement a genuinely asynchronous interactive Cascade protocol with verification before each parity-dependent bit correction. Treat this as a signed-audit-transcript demonstrator, not a complete adversarial QKD message stack.

## Classical frame authenticity

For any classical frame F sent by party S, its canonical signed body is

\[
B_F = (\text{protocol},\text{kind},S,R,\text{session ID},\text{context},\text{seq}_S,\text{prevHash}_S,\text{payload}).
\]

\[
\sigma_F=\mathrm{ML\mbox{-}DSA\mbox{-}65.Sign}_{sk_S}(\mathrm{canonicalJSON}(B_F)).
\]

Receiver verifies the signature with its trusted pinned public key and checks the expected sender, receiver, context, state, per-sender sequence number and previous frame hash. The default replay cache persists only for the lifetime of the local backend instance.

## Finite-key bound

The inherited module uses a stated finite-size form from Tomamichel et al. (2012):

\[
\ell \le n\Big[1-h_2(Q_{tol}+\mu)\Big]-L_{EC}-\log_2\frac{2}{\epsilon_{sec}^2\epsilon_{cor}},
\qquad
\mu=\sqrt{\frac{(n+k)(k+1)}{n k^2}\ln\frac{2}{\epsilon_{sec}}}.
\]

Use only under the theorem's state-preparation, sampling, post-selection, authenticated communication, parameter-setting and finite-key assumptions. The reconciliation leakage bound `L_EC` is **declared before observing errors**, not chosen after the parity transcript. The actual number of public parity bits is counted and the session aborts if it exceeds the predeclared budget. The verification hash and privacy-amplification Toeplitz seeds are public and authenticated. This implementation does **not** independently prove the finite-key theorem.

## Invariants exercised by tests

- `Mode == HYBRID` implies certified simulated BB84 extraction and a 256-bit accepted QKD output at *both* endpoints.
- A QKD-required session with failed BB84 admission ends in `ABORT`.
- `PQC_ONLY` requires an authorized policy and never relabels rejected QKD material as a hybrid key.
- A changed signed frame, wrong role, wrong stage or reused signed frame aborts.
- The application message decrypts only with the derived transcript-bound traffic key.
- Public transcripts and experiment logs do not contain raw Z bits or final QKD key bytes.

These are testable model invariants, not a formal proof of protocol security. `hybrid_protocol._schedule()` retains an experimental unproved HKDF combination, and the local two-endpoint simulator assumes an authenticated KEM bootstrap from Program 3.
