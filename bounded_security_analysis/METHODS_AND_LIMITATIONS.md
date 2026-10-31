# Program 8 — Experimental methodology and scientific limitations

## Verification methods

1. **Source regression:** the 137 tests inherited from Program 7 are rerun against the copied source with additional local mode validation.
2. **Bounded abstract-state checking:** 24 parameter assignments, up to eight signed frames, seven attacker actions and a configurable bound on modified actions. Counts are **visited states or terminal traces of an abstract machine**, not numbers of quantum or OpenSSL security trials.
3. **Fault injection/negative controls:** intentionally disabled guards are required to yield concrete safety-invariant counterexamples. This checks that the abstract properties can reveal at least certain relevant mistakes.
4. **Real signed transport probes:** OpenSSL-backed ML-DSA signatures reject modified policy frames, stale-session signed frames and duplicate frames in specific tests.
5. **Integrated smoke trials:** Program 7's actual ML-DSA / ML-KEM, local policy checks, simulated BB84, experimental HKDF key schedule and AES-GCM are exercised for seven model scenarios. These tests demonstrate correct outputs for the tested conditions, not quantitative superiority.

## Critical outstanding gaps for journal submission

**A. Quantum finite-key theorem preconditions.** The original Program 2 finite-key bound follows an ideal-source published theorem. Program 7's adaptive reconciliation allows public query counts and label sequences to depend on secret-related errors. Its present `2 * parity_queries` counter is an experimental **budget proxy**, not a proved conditional information-leakage bound. A rigorous analysis must bound leakage from the entire adaptive transcript, including termination patterns and all public messages, or replace the method with one satisfying a documented theorem.

**B. Hybrid key-combiner security.** `_schedule()` concatenates ML-KEM and accepted BB84 key inputs into HKDF. The code tests key equality and mode separation, but does **not** prove that the output remains secure if either branch is compromised under malicious input manipulation. A peer-reviewed robust combiner or formal reduction is needed before making strongest-link security claims.

**C. Symbolic model != full cryptographic proof.** The explicit-state checker assumes unforgeable authenticated frames and externally sound quantum key acceptance. Tamarin or ProVerif is NOT installed/executed here. Its enumerated attack traces are not an unbounded active-network adversary model. Proof of secrecy, computational assumptions and chosen-ciphertext attacks is absent.

**D. Channel model and key-generation assumptions.** QKD is simulated and NumPy seeds are predictable research inputs. There is no measured optical loss, multiphoton emission, detector mismatch, authentication trust provisioning, key storage, power-loss replay recovery, or network deployment.

**E. Experimental power and reproducibility.** Seven default integration scenarios provide *smoke tests only*. The program's source tests are deterministic as far as feasible; production-rate performance and statistical confidence would require a pre-registered larger experiment over many independent trials and hardware environments. Wall-clock observations include OpenSSL process spawn and file I/O. Store raw data and platform metadata.

**F. Specific Program 7 limitation fixed here.** Previous code accepted locally precomputed `mode_a`/`mode_b` values in the signed relay without each receiver recomputing its own policy decision at that stage. Program 8 adds independent local mode validation. This is a targeted protocol hardening, not a new cryptographic primitive.

## Recommended follow-up after Program 8
1. Carefully select and implement a finite-key/security theorem with **fully justified interactive EC leakage**.
2. Formalize message-level authentication, correspondence and key secrecy in Tamarin or ProVerif, execute the prover and report its exact verdict, assumptions and trace.
3. Replace or justify the hybrid key combiner using published robust-combiner security notions.
4. Run matched, statistically powered baseline comparisons and revise novelty claims against close prior work.

## Reference resources
- Tomamichel, Lim, Gisin, Renner (2012), *Tight finite-key analysis for quantum cryptography*, Nature Communications 3, 634; DOI 10.1038/ncomms1631.
- NIST FIPS 203 (ML-KEM), FIPS 204 (ML-DSA); NIST SP 800-227 (KEM recommendations).
- Official Tamarin manual: https://tamarin-prover.com/manual/index.html; symbolic multiset rewriting, trace properties and Dolev–Yao attacker model.
