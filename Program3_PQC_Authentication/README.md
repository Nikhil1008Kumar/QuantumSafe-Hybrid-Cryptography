# Program 3 — ML-DSA-65 authentication + ML-KEM-768 key establishment

**Quantum-computing research project, 24 October 2026.** This is a standalone **PQC-only authenticated-handshake baseline**. It is **not yet** coupled to Program 2's BB84 key material, and does **not** include AES encryption or the later hybrid security-policy controller.

## Requirements

- Python 3.10+ (standard library handles all protocol operations).
- **OpenSSL 3.5 or later**, with `ML-DSA-65` and `ML-KEM-768` enabled. OpenSSL must be on `PATH`, so that `openssl version` works in the VS Code terminal. We used OpenSSL 3.5.5.
- Optional `matplotlib` (for plots). Use `python -m pip install -r requirements.txt`.

Check the local OpenSSL version *first*:

```sh
openssl version
openssl list -signature-algorithms
openssl list -kem-algorithms
```

Versions earlier than 3.5 are deliberately rejected rather than silently falling back to a non-PQC signature. If OpenSSL is not available or is too old, install/enable a supported 3.5+ build before attempting to run. No alternative or simulated cryptography is substituted.

## Running in VS Code / terminal

Open the `Program3_PQC_Authentication` folder, then:

```sh
python -m pip install -r requirements.txt
python -m unittest discover -s tests -v
python run_experiments.py
```

The default experiment performs **75 valid independent handshakes** and **15 attempted modifications of each of 10 message types/fields**. You can change workload:

```sh
python run_experiments.py --sessions 200 --attack-repeats 30
```

There is intentionally **no deterministic random seed** for real signature/key-establishment secrets. Measured timings may vary substantially across computers and executions. Do not expect the same exact milliseconds.

## What the handshake does

1. Alice signs `client_hello` with ML-DSA-65, binding protocol version, identities, nonce and the sole supported mode `PQC_ONLY`. Bob verifies Alice's signature with a **pre-pinned** public key and checks a replay cache.
2. Bob creates an ephemeral ML-KEM-768 key pair and signs `server_hello`, including the encapsulation public key and Alice's challenge nonce. Alice verifies Bob's signature against a pre-pinned public key and checks protocol, identity, challenge and transcript binding.
3. Alice runs real ML-KEM-768 encapsulation and signs `client_finish`, including the KEM ciphertext and a transcript hash. Bob verifies, then runs real ML-KEM decapsulation.
4. Alice and Bob derive direction-separated 256-bit application and confirmation keys using HKDF-SHA256 with a transcript-hash salt and labeled context. Both directions exchange independent HMAC-SHA256 Finished messages; only after both verify is the session admitted.
5. No derived secret, private key, or plaintext is recorded in the CSV data. Temporary key files are mode-0600 and removed when the backend context exits.

`PQC_ONLY` is **not a fallback** here. The additional QKD/hybrid modes must be introduced, authenticated and tested separately in a later program.

## Files

- `pqc_protocol.py`: actual ML-DSA-65 and ML-KEM-768 operations through OpenSSL CLI, signed handshake, replay protection, key derivation, confirmation.
- `tests/test_pqc_protocol.py`: 28 unit/integration/negative tests.
- `run_experiments.py`: 75-session experiment, attack trials, CSVs and PNG plots.
- `results/handshake_trials.csv`: per-trial times and serialized wire byte counts.
- `results/timing_summary.csv`: mean, median, p95, minimum, maximum of stage times.
- `results/attack_summary.csv`: negative test rejection outcomes.
- `results/operation_latency.png` and `results/negative_tests.png`: plotting output.
- `results/experiment_manifest.json`: software/platform/time methodology.
- `METHODS_AND_LIMITATIONS.md`: methodological and security caveats.
- `results/RESULTS_INTERPRETATION.md`: reading the initial measurements.

## Standards and reference documentation

- NIST FIPS 203 (ML-KEM): https://csrc.nist.gov/pubs/fips/203/final
- NIST FIPS 204 (ML-DSA): https://csrc.nist.gov/pubs/fips/204/final
- NIST SP 800-227 (KEM guidance): https://csrc.nist.gov/pubs/sp/800/227/final
- OpenSSL 3.5 pkeyutl CLI: https://docs.openssl.org/3.5/man1/openssl-pkeyutl/
- RFC 5869 (HKDF-SHA256): https://www.rfc-editor.org/rfc/rfc5869

**Research integrity:** Standards-based components and this simple handshake structure are not standalone journal novelty. The proposed research novelty—finite-key QKD admission and explicit, downgrade-resistant hybrid policy—must be designed, compared and verified in later experiments.
