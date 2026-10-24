# Program 3 — Methods, equations, threat model and limitations

## Scope and assumptions

This is a **single-process simulated network handshake** employing **real post-quantum cryptographic primitives**. Alice and Bob know one another's authentic ML-DSA-65 public keys from **pre-established trusted pinning**. Provisioning or rotating those keys, certificate/PKI validation, HSM support, cryptographic side channels, distributed replay-state synchronization, key deletion after crash, actual network sockets and physical quantum channels are **not implemented**.

Unlike Programs 1–2, protocol secrets use OpenSSL/OS CSPRNG rather than disclosed NumPy random seeds. However, **this does not supply quantum randomness or a quantum-proof hardware implementation**. It is software based on the computational assumptions of ML-DSA and ML-KEM.

## Main mathematical operations

**ML-DSA mutual authentication** (FIPS 204):

- Alice signs her full canonical ClientHello body, Bob verifies with a pre-pinned ML-DSA-65 public key.
- Bob signs his full ServerHello body containing Alice's nonce and the ephemeral ML-KEM public key, Alice verifies with Bob's pinned ML-DSA-65 public key.
- Alice signs ClientFinish containing the transcript prefix hash and ML-KEM ciphertext, Bob verifies.
- Messages also encode `protocol`, `mode`, `from`, `to`, nonces and a fixed schema; unauthorized changes are rejected.

**ML-KEM-768 agreement** (FIPS 203):

\[
(c,K_A)\leftarrow \operatorname{ML\text{-}KEM.Encaps}(ek_B),\quad
K_B\leftarrow \operatorname{ML\text{-}KEM.Decaps}(dk_B,c).
\]

The honest transcript must yield \(K_A=K_B\). NIST's ML-KEM-768 parameters have 1088-byte ciphertext and 32-byte shared secret, and ML-DSA-65 signatures are 3309 raw bytes. The JSON/Base64 serialization used here is larger than these **raw** sizes.

**Authenticated transcript digest**:

\[
H_T = \operatorname{SHA256}(\operatorname{canonicalJSON}([\mathrm{ClientHello},\mathrm{ServerHello},\mathrm{ClientFinish}])).
\]

The transcript arrays include the respective signed envelopes, not just unsigned bodies.

**PQC-only domain-separated key schedule**:

\[
S=\operatorname{SHA256}(\texttt{"Program3-pqc-only-extract-v1"}\Vert H_T),
\]

\[
K_r=\operatorname{HKDF\text{-}SHA256}(K_{PQC},\,\mathrm{salt}=S,\,
\mathrm{info}=\texttt{"Program3/"}\Vert r\Vert\texttt{"/"}\Vert H_T,\,L=32),
\]

where \(r\) is one of `app_key`, `server_confirmation`, `client_confirmation`. Confirmations use HMAC-SHA256 on role-specific strings concatenated with \(H_T\), and each party verifies the other side before accepting. The HKDF algorithm is tested against a known RFC 5869 vector.

## Experimental design

- All honest runs use ephemeral ML-KEM key pairs, nonces and fresh encapsulations. Persistent ML-DSA identities remain stable across trials to model key provisioning, while the nonce replay cache persists for the life of the backend.
- Test 10 defined message modifications, 15 repeats each, and 75 successful handshakes by default.
- Time with `time.perf_counter_ns` and report mean, median and interpolated p95. The **timings include subprocess startup, temporary-file writes and reads, Python orchestration and actual crypto**, and must not be published as isolated native ML-KEM/ML-DSA latencies.
- Report `json_wire_bytes` as the serialized length of all five messages. It is **not** an estimate of optimized TLS, QUIC or raw cryptographic payload size.
- The reported baseline timing does not include generation of the long-lived Alice/Bob signing identity keys. Identity key provisioning is pre-established and amortized across sessions.

## Security properties tested

- Honest signatures verify and KEM secrets match.
- Mutating any of the signed body fields or the corresponding signatures results in abort.
- Sender, intended recipient, session protocol, nonce and mode are bound to signed messages.
- Replaying an already accepted ClientHello is detected when the replay cache survives; the in-memory cache does not persist across process restarts and has no expiry/memory bound.
- Distinct server/client Finished MAC checks reject mismatched key derivations or active changes to confirmation messages.

These are protocol functional and negative-test properties; **not** a cryptographic proof under universal active adversaries. Since only one mode exists, the downgrade tests merely demonstrate rejection of unauthorized mode modifications, **not** completed hybrid-to-PQC fallback security.

## Implementation risks and research boundaries

1. The OpenSSL executable is invoked as a separate process for each crypto action. Sensitive PEM private keys and KEM shared secrets are created in an OS temporary directory with restricted permissions (mode 0600/0700), then removed. **No secure erasure is guaranteed**. Do not use this backend in production or with real confidential secrets.
2. Real deployments must use audited library APIs, secure key storage, lifecycle management and defense-in-depth rather than plaintext private keys in temporary files.
3. A real replay cache must be persistent/cluster-aware, bounded, and correctly expired; current replay checks are only in-process.
4. We assume authenticated trusted public keys. ML-DSA alone cannot prevent substitution of the pinned public keys at provisioning.
5. A true network protocol needs framing, authenticated errors, timeout/retry logic, denial-of-service protection, robust parsing, separate connection identities, and formal or more comprehensive protocol validation.
6. The protocol does **not** provide AES-GCM record encryption, QKD integration, finite-key QKD certificates, or a hybrid combiner yet. It does **not** demonstrate the new paper's proposed novelty by itself.
7. This toy protocol composition has not received independent cryptographic review. OpenSSL 3.5 provider support is not by itself an accreditation or formal compliance assessment of this project.
8. Independent randomness means exact timing and wire data may vary slightly. Report environment, hardware and sample count when citing results.
9. For publication, compare with a fair RSA/TLS or ML-KEM baseline under the same interface, instrument genuine crypto-only latency using an in-process provider, run substantially more trials and test on representative devices.

## References

- NIST FIPS 203 (2024), https://csrc.nist.gov/pubs/fips/203/final
- NIST FIPS 204 (2024), https://csrc.nist.gov/pubs/fips/204/final
- NIST SP 800-227 (2025), https://csrc.nist.gov/pubs/sp/800/227/final
- OpenSSL 3.5 `pkeyutl` documentation, https://docs.openssl.org/3.5/man1/openssl-pkeyutl/
- RFC 5869 (2010), https://www.rfc-editor.org/rfc/rfc5869
