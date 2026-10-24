# Original-code audit: first-pass findings (24 October 2026)

## Scope and provenance

The original manuscript cites https://github.com/Nikhil1008Kumar/Quantum_Project.
We inspected the GitHub web-rendered code for `BB84_code.py`, `BB84_realistic.py`,
and `bb84_timing.py`. We did not execute the original repository and have not
established bit-for-bit reproduction of the original paper's figures.

## Directly observed findings

1. `BB84_code.py` uses the *first 10%* of sifted key entries to estimate QBER,
   rather than a uniformly selected random subset. This can still estimate
   error rates in an IID setting, but random independent sampling is a clearer
   parameter-estimation procedure and avoids depending on temporal ordering.
2. `BB84_code.py` sets `key_matched` to `False` whenever the publicly sampled
   QBER is nonzero, even though equality of retained keys is a logically
   separate question. In contrast, zero sampled QBER does not establish
   equality of all retained bits.
3. The same code labels QBER <= 11% "Safe", which is not justified for
   short finite samples and does not make a complete secure-key protocol.
4. `BB84_realistic.py` randomly reveals some sifted bits but calls remaining
   unreconciled, unamplified bits a "final secret key". Neither error
   correction nor privacy amplification is implemented in that script.
5. `bb84_timing.py` uses five trials for each size and Qiskit Aer circuits.
   Those times cannot be directly compared with our vectorized NumPy
   simulator timings or real quantum transmission latency.

## What the new implementation addresses now

- Random test-position selection without replacement.
- Separate public QBER estimation from privileged retained-bit mismatch
  diagnostics, labeling both appropriately.
- Trial-level CSV data and Student-t 95% CI across independent trial seeds.
- Theory-calibrated intercept–resend test, noise test, loss test, 9 unit tests.
- Clear refusal to call retained bits "final secret keys" or treat 11% as
  a finite-key certificate.

## Deferred to Program 2 and beyond

- Trust/authentication of public classical channel.
- Proper finite-key phase-error estimation and a composable-security proof.
- Information reconciliation, leak accounting, privacy amplification,
  confirmation and authentication of the transcript.
- Device flaws, photon-number distribution, detectors and physical QKD.
- ML-KEM, ML-DSA, secure key combination and AES-GCM integration.

The code in this package is an independent methodological correction, not a
patch committed to the user's original GitHub repository.
