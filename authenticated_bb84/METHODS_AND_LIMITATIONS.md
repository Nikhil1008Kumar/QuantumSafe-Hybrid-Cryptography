# Methods, interpretation, and explicit limitations

## What Program 6 adds to Program 5

Program 5 compared abstract security-policy decisions. Program 6 adds a **cryptographically signed classical transcript** for the QKD pipeline, including signed basis/detection announcements, public test samples, reconciliation parity-event batches, verification public data, privacy-amplification seed, end-of-QKD reports and authorized mode decisions. Every frame carries a protocol ID, actor identity, recipient, per-sender sequence number, previous-frame hash and session context. This can catch the tested frame substitutions, replay and bad-order conditions.

## Critical limits before journal submission

1. **Not a physically validated QKD system.** Transmission uses a seeded probabilistic model, not qubits transmitted through optical equipment; loss/noise model does not include basis dependence, decoy-state assumptions, multi-photon leakage, finite detector effects or side channels.
2. **Classical exchanges are partly centralized.** Quantum bits, parity correction and both endpoints exist in one process, meaning the code cannot yet establish independence of two remote participants. Signed basis/test/PA data are actual public payloads, but Cascade-like parity exchanges are reconstructed into authenticated *batches after the calculation*. For stronger claims, implement two separate Alice/Bob state machines where each parity request/response is delivered and authenticated **before** the receiver acts on it.
3. **Randomness is deterministic for experiment reproducibility.** The QKD simulation's NumPy RNG must never be repurposed as a production entropy source, and extracted prototype keys should never protect live user messages.
4. **The finite-key theorem has assumptions.** Numeric calculation is not a proof that those assumptions hold in hardware or that every implementation detail conforms to the cited security reduction. The exact leakage/error/correctness budget is a modeled condition.
5. **PQC authentication is computational, not information-theoretic.** Mutual signing by ML-DSA requires a trusted pinned public key and an unbroken signing primitive. Cryptographic migration and compromise lifetime must be discussed separately from composable QKD parameters.
6. **Hybrid key combiner not proven.** HKDF over the concatenation of ML-KEM and QKD secrets is an experimental schedule; no independent reduction demonstrates robust combiner security under arbitrary active attacks or correlated compromise.
7. **No live networking, persistent replay protection, side-channel hardening, certificate validation or tamper-resistant key storage.** The replay cache only lives inside the OpenSSLBackend object. OpenSSL CLI subprocesses and temporary key files are not production-safe key handling.
8. **Benchmarks measure a local workflow.** Timings include OpenSSL CLI process startup, signing 3,309-byte signatures, temporary-file I/O, NumPy arrays, and the simulation. They do not represent fiber communication latency or production native-library signature speed.
9. **Small study and deterministic test matrix.** The included 45-session/48-attack run is for reproducibility and debugging; 100% rejection in these specific tests does not establish resistance to all attacker strategies. Increase repetitions and use statistical intervals before quantitative journal claims.
10. **No formal symbolic or computational protocol verification yet.** Automated unit tests check explicitly enumerated attacks, but do not replace ProVerif/Tamarin verification or a compositional cryptographic security proof.

## Standards and sources to cite

- ITU-T X.1711 (03/2026), *Framework of quantum key distribution (QKD) protocols in QKD networks*, classical authenticated-channel and post-processing requirements: https://www.itu.int/epublications/publication/itu-t-x-1711-2026-03-framework-of-quantum-key-distribution-qkd-protocols-in-qkd-networks
- NIST FIPS 203, Module-Lattice-Based Key-Encapsulation Mechanism: https://csrc.nist.gov/pubs/fips/203/final
- NIST FIPS 204, Module-Lattice-Based Digital Signature Standard: https://csrc.nist.gov/pubs/fips/204/final
- NIST SP 800-38D, GCM: https://csrc.nist.gov/pubs/sp/800/38/d/final
- Tomamichel et al., *Tight finite-key analysis for quantum cryptography*, Nature Communications (2012): https://www.nature.com/articles/ncomms1631

## Required work before claiming journal-ready novelty

Implement independently controlled Alice and Bob on an untrusted message transport, authenticate and verify EC parity requests/responses interactively, formalize the policy/downgrade and key-schedule proof obligations, verify the independent actor state machine with a model checker, use a standard/analyzed hybrid combiner, broaden noise/attack trials, and compare against the strongest directly relevant 2025–2026 authenticated QKD–PQC systems.
