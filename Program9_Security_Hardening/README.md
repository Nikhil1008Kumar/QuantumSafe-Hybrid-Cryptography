# Program 9 — Finite-key leakage hardening and protocol audit

**Status:** Reproducible research prototype. This does **not** establish unconditional QKD security, a strongest-link hybrid-combiner theorem, or an unbounded formal protocol proof.

Program 9 preserves the Program 8 source and all 160 inherited tests, and adds an alternative, *fixed-length* syndrome reconciliation design to reduce uncertainty caused by adaptive parity-query transcript lengths. It also exercises the existing ML-DSA / ML-KEM / AES-GCM handshake, tests key-schedule domain separation, and produces a paired pilot comparison against Program 8.

## Windows / Git Bash

Extract the `Program9_Security_Hardening` directory inside `Quantum_Project` and run:

```bash
cd ~/OneDrive/Desktop/Quantum_Project/Program9_Security_Hardening
openssl version
python -m pip install -r requirements.txt
python -m unittest discover -s tests -v
python run_experiments.py
```

In the reference environment the full suite reports **173 tests, OK**. The default pilot performs **10 paired scenario trials = 20 OpenSSL-backed sessions**, plus 9 static leakage checks. It produces CSVs, PNG graphs and a manifest under `results/`.

Only run the fast mathematical audit (no OpenSSL sessions):

```bash
python run_experiments.py --audit-only
```

More paired trials (costs time because OpenSSL CLI starts repeatedly):

```bash
python run_experiments.py --repetitions 10
```

## Important files

- `fixed_syndrome.py` — Hamming(31) linear syndrome reconciliation. Exactly 5 bits are disclosed for each block of up to 31 positions in each *predeclared* pass. No adaptive query pattern.
- `hardened_independent_protocol.py` — Program 8's independent signing endpoints with a fixed-syndrome message stage and explicit leakage accounting.
- `tests/test_hardening.py` — 13 additional tests for algebra, leakage length, key schedule, signed-message tampering and integrated behavior.
- `run_experiments.py` — paired Program 8 / Program 9 scenario runner, exact leakage reports and charts.
- `MATHEMATICAL_SECURITY_AUDIT.md` — published bound, assumptions, leakage argument, combiner audit and limitations.
- `FORMAL_VERIFICATION_PLAN.md` — detailed unbounded symbolic proof obligations, no fabricated Tamarin/ProVerif result.
- `results/` — `paired_reconciliation.csv`, `fixed_leakage_audit.csv`, three plots, manifest and interpretation.

## Guardrails

1. **Model acceptance is not proof of secure physical key extraction.** The quantum channel is stochastic simulation and its bit-generation seed is predictable.
2. **The syndrome disclosure length has a simple public bit-count bound; the complete protocol's composability does not follow automatically.** Additional public tags/control metadata and errors require theorem-level assessment.
3. **The reconciliation algorithm is deliberately simple, not an advanced LDPC code.** It can fail when blocks contain multiple errors. Independent key verification detects failure and aborts/falls back.
4. **The combiner still needs a published security reduction for the QKD + ML-KEM setting.** Tests confirm functionality and domain separation only.
5. **Neither Tamarin nor ProVerif was executed.** Program 8's bounded model and its negative controls are retained but should not be called a full formal proof.

See `MATHEMATICAL_SECURITY_AUDIT.md` for precise equations and distinctions.
