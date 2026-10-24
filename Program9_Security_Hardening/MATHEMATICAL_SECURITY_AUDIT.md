# Mathematical security audit — Program 9

## 1. Source and theorem scope

Baseline finite-key reference: M. Tomamichel, C. C. W. Lim, N. Gisin, R. Renner, *Tight finite-key analysis for quantum cryptography*, Nature Communications **3**, 634 (2012), DOI: 10.1038/ncomms1631.

Program 2's `finite_key_bound` is **intended to evaluate** a published expression for a particular asymmetric, ideal-device BB84 family:

\[
\ell \le \left\lfloor n [1-h_2(Q_{\mathrm{tol}}+\mu)]
-\mathrm{leak}_{EC}
-\log_2\left(\frac{2}{\epsilon_{sec}^2\epsilon_{cor}}\right) \right\rfloor,
\]

\[
\mu=\sqrt{\frac{(n+k)(k+1)}{nk^2}\ln\left(\frac{2}{\epsilon_{sec}}\right)}
\]

for ideal preparation quality q=1, predeclared Q_tol and finite-key theorem conditions. Here `n` and `k` are the fixed raw-key and testing lengths (selected on sifting acceptance); h2 is binary entropy. A **numerical value is conditional on ALL theorem assumptions** and is not itself a quantum proof. The manuscript must inspect the exact hypotheses and version of the published theorem before adopting this numerical expression as a formal security claim.

## 2. A concrete issue in Programs 7 and 8

Interactive error reconciliation (`InteractiveEC`) returns `2 * number_of_parity_queries` as a *proxy* for public leakage. Although both public parities are counted, the **number, timing, and requested positions of adaptive queries can depend on raw data and error locations**. This proxy does NOT by itself bound the entire observable transcript and cannot be inserted in a composable finite-key theorem without further proof.

Program 8 conservatively used a predeclared EC cap for `finite_key_bound`, but its adaptive pattern still needs an information-leakage argument. Treat P7/P8 `MODEL_ACCEPT` labels as **simulation admission decisions**, not independently certified physical QKD keys.

## 3. Program 9 nonadaptive syndrome alternative

Partition each publicly permuted length-n raw vector into B=ceil(n/31) blocks of size at most 31. In each block, define a public linear syndrome over GF(2):

\[
S(x)= \bigoplus_{j=1}^{|x|} x_j \cdot j,
\quad S\in\{0,1\}^{5},
\]

where the five-bit integer label j is XORed for each 1-bit. Alice publishes exactly 5 syndrome bits per block in each of p **predeclared** passes. Bob computes delta = S(A) XOR S(B) and flips the position indexed by delta if it is inside the block. A multi-error block may be miscorrected; the independent verification hash is mandatory. The new schedule transmits exactly:

\[
L_{EC}=5p\left\lceil\frac{n}{31}\right\rceil \text{bits}.
\]

The permutations and number of passes do not depend on raw-key values. Therefore, conditional on a public, independently selected schedule, the entire EC syndrome string ranges over at most \(2^{L_{EC}}\) values. For this **syndrome-only** public view, the usual min-entropy chain rule incurs at most L_EC bits of public disclosure. This is a narrowly scoped counting argument; it does not prove the implemented QKD system secure.

**Example:** n=k=9000, p=2 yields L_EC=2910 bits. With verification bit length v=ceil(log2(1/epsilon_cor))=34, Program 9 additionally reserves **v+64 = 98** bits in the finite-key bound for a *second published verification tag plus a heuristic control-message margin*. Consequently, the finite-key calculation uses a predeclared **3008-bit** deduction for these disclosures. The 64-bit margin is an engineering choice **not backed by a composability theorem**; until all status and transcript side information is formally accounted for, report the computed 1321-bit result as **conditional / candidate**, not as a proven 1321-bit certified secret key.

The reconciliation acceptance policy compares the full modeled budget to a predeclared cap. A fixed-length code can fail despite a favorable QBER; we count such runs honestly as abort or authorized fallback.

## 4. Published theorem requirements that remain open

- *Quantum model:* ideal single-photon encoding / trusted BB84 measurements and no basis-dependent losses; the simulator does not establish these experimentally.
- *Randomness:* independent random bit, basis, sample and hash seeds. NumPy seeded generators are deterministic development aids, not QKD randomness. Merely adding constants to a master seed does not demonstrate physical independence or unpredictability.
- *Authentication:* authenticated public classical messages with initial trusted long-term public keys; the signature scheme is computationally secure (ML-DSA), hence the combined system must be described with computational assumptions.
- *Public leakage:* test disclosures, EC syndrome, verification tags from both parties, decisions, retransmissions, failure modes and any key-dependent metadata must be carefully covered. A fixed EC bit count is a useful subproblem, not the entire analysis.
- *Finite-key proof mapping:* review the exact theorem's basis-choice, sample-size, correctness and secrecy definitions; document the complete security budget before claiming composable security.

## 5. Hybrid key-combiner audit

Current Program 8 `_schedule` builds an unambiguous mode-prefixed concatenation of 32-byte ML-KEM-derived and, in hybrid mode, 32-byte BB84 material; HKDF-SHA256 uses a transcript-dependent salt and mode-/purpose-specific `info`. The new tests confirm different output labels, modes, contexts and changed secrets yield different tested derived keys. **These are functional tests, not a proof** of indistinguishability or 'secure if either branch remains secure' under adversarially correlated keys.

The RFC 5869 HKDF analysis depends on input distributions, entropy, salt independence and authenticated context. NIST SP 800-227 provides guidance for KEM use and hybrid combiners, but **no automatic security theorem** for this specific QKD + ML-KEM protocol is established by citing the document. A theorem-based combiner analysis is required before a strongest-link claim.

## 6. Actual Program 9 result scope

The pilot compares independently signed Program 8's adaptive reconciliation and Program 9's fixed syndrome on identical stochastic channel seeds. Both run with two configured EC passes, 40% maximum EC cap, 9000 raw and 9000 test bits in 50,000 transmitted-signal configurations. These are small pilot trials, and the two algorithms have different correction abilities. In the default 2 repetitions per scenario, there was no clear improvement in admission probability, although signed-frame overhead was lower for the fixed alternative. This suggests a research direction: a fixed-schedule *more efficient* code (e.g. a properly analyzed LDPC reconciliation scheme) if security and noise tolerance are to be demonstrated together.

## 7. References

- Tomamichel et al. (2012), DOI: https://doi.org/10.1038/ncomms1631 ; https://pmc.ncbi.nlm.nih.gov/articles/PMC3274703/
- NIST SP 800-227 (final, 2025): https://csrc.nist.gov/pubs/sp/800/227/final
- RFC 5869 HKDF: https://www.rfc-editor.org/rfc/rfc5869
- Tamarin official manual: https://tamarin-prover.com/manual/
