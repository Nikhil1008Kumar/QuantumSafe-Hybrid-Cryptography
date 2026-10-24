# Program 6 — Initial experimental interpretation

Reference execution: **45 integrated protocol sessions** over 9 scenarios × 5 seeded trials; **48 classical-message mutation trials** over 16 authenticated stage types × 3 trials. All 116 automated tests passed in the container runtime.

## Mode outcomes

- `clean_preferred` and `noise1_preferred`: 5/5 HYBRID each.
- `clean_required`: 5/5 HYBRID.
- `noise3_preferred`, `eve20_preferred`, `short_preferred`: 5/5 PQC_ONLY in each configuration, as explicitly authorized by policy.
- `noise3_required` and `short_required`: 5/5 ABORT each.
- `pqc_only`: 5/5 PQC_ONLY with no BB84 attempted.

These are **parameter- and seed-specific findings**, not general security or performance bounds for BB84 or QKD networks. Notably the noisy 3% runs used QKD fallback or abort because of modeled post-processing admission checks, not because 3% is a universal QKD safety boundary.

## Attack injection checks

Each tested mutation changed a signed public payload after signing. The receiving code rejected all **48/48** such injections. The tests also include wrong-role, wrong-state and replay checks. This validates a narrow mutation-injection test suite. It does not establish security against key compromise, quantum-source flaws, sophisticated multi-session attackers or a live network adversary.

## Communication and computational cost

Median authenticated BB84 transcript size (includes signatures but excludes the underlying Program 3 bootstrap messages):

| Scenario | Median signed transcript | Median integrated handshake (local) |
|---|---:|---:|
| Clean preferred | 264,634 bytes | 499.5 ms |
| 1% noise preferred | 358,320 bytes | 582.5 ms |
| 3% noise preferred | 561,708 bytes | 759.5 ms |
| 20% intercept–resend preferred | 86,732 bytes | 205.4 ms |
| 500-signal preferred | 84,192 bytes | 293.7 ms |
| PQC-only | 19,960 bytes | 120.1 ms |

The large increase in reconciliation parity batches is an important **cost of this particular batched transcript encoding**. It is not representative of optimized production message-framing schemes.

## Research conclusion so far

Program 6 extends observable, signed QKD transcript coverage and checks additional protocol invariants. It does not yet prove a new secure key combiner, composable end-to-end security, superiority to all existing authenticated QKD/PQC protocols or physical viability. The next scientifically important step is an independently executed, message-by-message reconciliation with stronger adversarial verification, before drafting substantive final security claims.
