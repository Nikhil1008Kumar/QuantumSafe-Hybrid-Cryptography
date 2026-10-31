# Program 4 message and key schedule specification (prototype)

## Preconditions

Trusted/pinned ML-DSA-65 verification keys for Alice and Bob. OpenSSL 3.5 or newer with ML-KEM-768 and ML-DSA-65. Local simulator holds both endpoints' secrets; model is not an independently implemented distributed protocol.

## Message and computation order

1. Run the already tested Program 3 `negotiate()` with its strictly PQC-only signed bootstrap messages. It returns **separately computed Alice and Bob bootstrap secrets** based on ML-KEM-768 and ML-DSA verified transcript.
2. Alice signs `policy_offer` binding expected identities, bootstrapped transcript hash, policy, and canonical finite-key configuration hash. Bob verifies with the pinned Alice public key.
3. Bob signs `policy_ack` binding exact policy offer and bootstrap. Alice verifies with pinned Bob public key.
4. If policy is not PQC_ONLY, simulate BB84, fixed-basis sampling, Cascade-like reconciliation, verification and privacy amplification from Program 2. Only the simulator can access the generated 256-bit QKD key bytes; **no raw/key bytes are written to output files**.
5. Each party signs an end-of-run QKD receipt `qkd_report` / `qkd_report_ack`, bound to the bootstrap and QKD parameter hash. In a real protocol, **ALL** BB84 public classical messages would have to be authenticated as they occur, not merely the final report; this prototype has not implemented that requirement.
6. Decide mode: HYBRID when QKD admitted, PQC_ONLY only if the policy authorizes it, otherwise ABORT. Sign and verify `mode_decision` and `mode_agreement` to prevent silent changes in the modeled transport.
7. Hash the signed transcripts into a session context. Using the Program 3 independently derived bootstrap secrets and the Program 2 separately computed QKD keys, each endpoint derives domain-separated directional traffic keys, nonce prefixes and Finished-MAC keys.
8. Exchange and verify BobFinished and AliceFinished MACs. If either fails, no application message is released.
9. Alice sends the test plaintext through AES-256-GCM with AAD covering protocol, session, mode, direction and sequence. Bob checks the tag, authenticating the AAD. Replayed sequences are rejected.

## Mathematical description

For the toy intercept-resend model with no background noise:

\[ \mathbb{E}[Q] = p_{\\mathrm{Eve}}/4. \]

The Program 2 code uses a predeclared error tolerance `Q_tol` and predeclared EC leakage cap in the finite-key formula as presented in Tomamichel *et al.* (2012), Equation 2, with model-specific assumptions. Program 4 accepts QKD material **only** if that model returns `ACCEPT` and 256-bit keys.

For a 32-byte post-quantum bootstrap secret `K_P` and a 32-byte QKD secret `K_Q`, the *prototype* builds an input string:

- HYBRID: `IKM = 'P4-HYBRID\\0' || K_P || K_Q`
- PQC_ONLY: `IKM = 'P4-PQC-ONLY\\0' || K_P`

With `T` the authenticated high-level transcript hash:

\[\mathrm{salt}=H(\texttt{Program4/v1/transcript-salt} \parallel T).\]

For label `role`, output keys are:

\[ K_{role}=\mathrm{HKDF}_{SHA256}(IKM,\mathrm{salt},\texttt{Program4/v1/role/mode} \parallel T). \]

This construction has not been independently proved to be a robust combiner under one-secret compromise. It is an implementation candidate to analyze, *not* a new cryptographic security theorem.

GCM nonce per role and session is:

\[ N=\mathrm{IVprefix}_{32} \parallel \mathrm{seq}_{64}. \]

Directional keys and prefixes are separate. Receiver records seen sequence values; new sessions use fresh authenticated ML-KEM handshake material. Do not reuse a session key with a reset sequence counter in any adapted implementation.

## Main protocol invariants we test

- A HYBRID key is never used unless the finite-key module exports *accepted* 256-bit material.
- Required-hybrid policy aborts on QKD rejection.
- PQC-only fallback is selected only with the explicitly signed HYBRID_PREFERRED policy.
- Both parties' derived keys agree before encrypted payload transfer.
- Modifying the modeled signed receipts or mode agreement is rejected.
- GCM ciphertext/tag/context modification and duplicated record sequence values are rejected.

Model-based testing of these conditions is not a machine-checked proof of a full network protocol. Independent policy choice, on-wire QKD public messages, timing side channels, real devices and robust combiner analysis remain outside scope.
