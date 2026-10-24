# Program 3 — Initial measurement interpretation

Run on this container (see `experiment_manifest.json` for OpenSSL, Python, platform and UTC timestamp). This is an exploratory reproducibility check, **not** the final journal experiment.

## Verified behavior

- 28/28 automated tests passed.
- 75/75 honest authenticated handshakes completed and derived matching 256-bit (32-byte) application keys.
- Median end-to-end local simulated handshake time was **58.440 ms**; interpolated 95th percentile was **67.794 ms**. Median includes multiple OpenSSL CLI launches and temporary-file operations. It does **not** measure network round-trip delay and is not a native cryptographic primitive benchmark.
- All messages serialized as canonical JSON and Base64 totalled **17,839 bytes** per observed handshake. This includes three 3,309-byte raw ML-DSA signatures (Base64 inflated), an ephemeral PEM-encoded KEM encapsulation public key, a 1,088-byte raw KEM ciphertext (Base64 inflated), and signed/unsigned framing. Different encoding approaches will change this number.
- Across 10 deliberately altered message cases with 15 repeats each, **150/150 attempts were rejected**. These are deliberately constructed attacks, **not** a statistical estimate of real-world attack-defense efficacy or a proof of immunity.

## What can be claimed

This validates a reproducible **software-only, post-quantum-authenticated key-establishment baseline** for the next hybrid integration experiment. It demonstrates functional session-key agreement, message verification, explicit mode-field binding, and rejection of the ten alterations tested.

## What cannot be claimed

- That the design is a new cryptographic protocol or that the use of ML-DSA with ML-KEM is novel.
- That BB84 keys have been integrated. The QKD branch is still a separate module.
- That the system is provably quantum-safe in the full, composable, operational sense.
- That ~58 ms is portable to a different processor, implementation, hardware or network.
- That 100% rejection in these test categories establishes a universal 100% detection rate.

## Next experiment

**Program 4**: use Program 2's accepted QKD material as a conditional input, build a reviewed transcript-bound key-combination and mode-policy design, then derive AES-256-GCM traffic keys. Add adversarial downgrade/fallback experiments and direct PQC-only vs authorized hybrid comparisons.
