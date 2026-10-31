# Unbounded symbolic verification work — not executed in Program 9

The Program 8 Python checker explored a bounded control-plane abstraction and found no property violations under specified guards. **This is not equivalent to a Tamarin/ProVerif theorem.** Program 9 does not mislabel any Python check as an unbounded formal proof.

## Candidate protocol events and properties

- `Start(A,B,sid,policy,mode)` / `Accept(A,B,sid,policy,mode,transcript_hash)` / `PeerAccept(...)`.
- **Injective agreement:** every `Accept(A,B,sid,mode,h)` has a unique matching peer run (unless a signing key is declared compromised).
- **Explicit entity authentication:** valid signed messages alone are insufficient; roles, session identities, message sequence, context and peer key pins must match.
- **Downgrade resistance:** `policy = HYBRID_REQUIRED` implies `mode != PQC_ONLY` at every accepted trace.
- **Mode agreement:** both peers accept the same `mode` and same prior transcript hash.
- **Session key secrecy (symbolic):** for uncompromised endpoint keys and idealized secure KEM/QKD sources, a private session key is not derivable by the attacker.
- **Replay resistance:** reuse of old signed messages, old sid and old nonces does not result in an accepted fresh session.
- **Key confirmation:** a peer accepts traffic keys only after receipt/verification of the appropriate key-confirmation data.

## Symbolic abstraction that must be declared

- Attacker controls and replays all network messages (Dolev-Yao).
- ML-DSA signatures are modeled as an ideal signature constructor/verification equation, not a quantum reduction.
- ML-KEM shared-secret establishment is modeled as an ideal symbolic KEM, not a proof of IND-CCA security.
- BB84 key material is represented as either a fresh private input after *accepted finite-key processing* or as unavailable. The Tamarin model **cannot prove quantum finite-key secrecy**.
- Authentication public-key pinning, signing-key compromise and initial trust are explicit.
- The hybrid key schedule is abstracted by a symbolic constructor; theorem-level quantum/PQC composability is outside the model.

## Required experiment for a defensible paper

1. Write a faithful `.spthy` protocol, including all accepted frames, fallback branches, signing key compromise and peer agreement events.
2. Install Tamarin with the official instructions (on Windows use WSL2), run `tamarin-prover --prove <file>.spthy`.
3. Capture exact prover version, full proof output, lemmas and counterexample traces. Mark timeouts or inconclusive lemmas as inconclusive, not proved.
4. Model malicious peers and manipulated mode offers, not only unforgeable external messages.
5. Connect symbolic claims to code with a documented message mapping and negative integration tests.

**Status (24 October 2026): NOT DONE. No Tamarin/ProVerif theorem or proof transcript is included.**
