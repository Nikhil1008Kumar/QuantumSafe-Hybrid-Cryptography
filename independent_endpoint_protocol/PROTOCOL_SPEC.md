# Program 7 mathematical and state-machine specification

## Formalized participants
Alice: `(x_A, theta_A, s_A, K_A, state_A)`; Bob: `(x_B, theta_B, d_B, s_B, K_B, state_B)`.  Their local raw Z-strings are never placed on the classical relay. A central **simulation harness** samples the idealized quantum observations and injects *separate arrays* into each actor. Each endpoint holds its own signing secret and is provisioned with the peer's ML-DSA-65 public key.

## Authenticated public frame
Every frame has `version, session, context, kind, from, to, seq, previous, payload` plus ML-DSA signature. The context commits to the negotiated policy, settings and ML-KEM-authenticated bootstrap transcript. Receivers check the ML-DSA signature against the pinned key, actor role, expected protocol stage, context, sequence, and global hash-chain predecessor. Both endpoints commit a frame only after receiver validation. Replays, out-of-sequence frames, and unauthenticated message changes are rejected in the specified model.

State transitions (normal path):

```
policy_a -> policy_b -> detect_b* -> basis_b* -> basis_a*
 -> sample_a -> test_a -> test_b -> ec_seed_a
 -> (parity_query -> parity_answer)*
 -> verification_seed_a -> verification_tag_a -> verification_tag_b
 -> [pa_seed_a if admitted] -> report_a -> report_b -> mode_a -> mode_b
```

`*` for `detect_b` and both bases means bounded, explicitly indexed bitmap chunks; for parity exchange it means interactive, data-dependent signed query–answer rounds. Rejection branches can skip directly to the reporting phase at specified decision points. PQC-only policy skips QKD and goes from policy messages to reports.

## Interactive reconciliation
Pass `p` uses public pseudorandom permutation `pi_p` derived from an authenticated seed and a block size `B_p=min(n, 24 * 2^p)`. For a public query label `(p, block, binary_path)`, its corresponding subset of raw-Z positions is `S`. Alice responds with:

`u_A(S) = XOR_{i in S} A_i`.

Bob locally calculates:

`u_B(S) = XOR_{i in S} B_i`.

When `u_A(S) != u_B(S)` Bob narrows the erroneous block via signed binary-search parity queries and flips one bit. The simulator performs multiple passes but omits Cascade's full look-back optimization. Residual errors can remain; an independent Toeplitz verification hash is required before final-key extraction.

`q = total parity queries` and `r = number of signed query/answer rounds`. The experimental disclosure meter is:

`L_EC,model = 2 * q bits`,

which counts one publicly revealed Alice parity and one conservative bit allowance per adaptive binary-branch disclosure. It is **not** yet a fully justified information-theoretic upper bound for every active adversary or every variable-length transcript. A precommitted cap `L_max = ceil(f_cap * n_Z)` is used for the finite-key model. If observed disclosures exceed the cap the session refuses QKD use. A complete conditional min-entropy security proof for this adaptive EC transcript remains future work.

## X-basis parameter estimation
`Q_X = mismatched_X / tested_X`. Threshold is specified before data observation; `Q_X > Q_tol` causes QKD admission rejection. Parameter-estimation confidence comes from the finite-key theorem specified in Program 2, NOT from using 11% as a universal cutoff.

## Finite-key calculation
We reuse the Program 2 finite-key function using the following schematic form for allowed extraction bits:

`ell <= floor(n_Z*(1-h2(Q_tol+mu(n_Z,n_X,eps_sec))) - L_max - log2(2/(eps_sec^2*eps_cor)))`

The finite-size correction `mu` is defined in `finite_key_bb84.py`, following its cited bound and assumption set. This number is only meaningful under that theorem's source, sampling, authentication and leakage prerequisites. It is not a measured secrecy guarantee for actual optical channels. When the modeled bound is at least the configured minimum and 256 bits, both agents independently apply Toeplitz-hash privacy amplification with a signed public seed.

## Hybrid mode and ciphertext
With a successful ML-DSA-authenticated ML-KEM bootstrap, QKD success yields an experimental HKDF-based hybrid key schedule; otherwise only a policy-permitted **PQC_ONLY** mode can proceed. `HYBRID_REQUIRED` forbids silent downgrade and returns `ABORT` on failure. Each role computes traffic keys and confirms them before AES-256-GCM authenticated encryption. The concatenation-based schedule reused from Program 4 is NOT formally proved as a robust hybrid combiner.

## Properties tested (not formally proved)
1. Authenticity of the enumerated signed public frames assuming secure ML-DSA and correctly trusted keys.
2. Both endpoints maintain matching signed-transcript state in completed sessions.
3. A second replay of an existing signed frame fails its expected sequence/stage.
4. A mode requiring QKD aborts if modeled finite-key admission fails.
5. Signed parity answers are delivered before Bob's next adaptive EC query.
6. Reconciliation mismatch prevents release of QKD-derived key material if detected by verification.
7. AES-GCM authenticated records use matching confirmed keys in successful paths.
