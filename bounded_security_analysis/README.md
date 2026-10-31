# Program 8 — Bounded protocol-security verification + hardened role checks

**Research-only code. Not a production QKD system or unbounded formal security proof.**

Program 8 extends Program 7 with independently enforced Alice/Bob local mode checks and a fully reproducible explicit-state checker for the control-plane handshake. It also preserves the Program 7 implementation and inherited tests.

## Requirements

- Python 3.11+; NumPy, SciPy, Matplotlib and Cryptography per `requirements.txt`.
- OpenSSL 3.5+ with ML-DSA-65 and ML-KEM-768 for real signed-frame and integration tests.
- No Tamarin/ProVerif installation is needed: `security_model.py` is a **bounded Python state explorer**, not a stand-in for an unbounded formal prover.

## Windows / Git Bash

Extract `bounded_security_analysis` under `Quantum_Project`, then:

```bash
cd ~/OneDrive/Desktop/Quantum_Project/bounded_security_analysis
openssl version
python -m pip install -r requirements.txt
python -m unittest discover -s tests -v
python run_experiments.py
```

Expected test result in our validation environment: **160 tests, OK**. The default runner performs the abstract checking, tests six weakened variants and runs seven integrated OpenSSL-backed smoke sessions. Computer timings vary.

To explore only the abstract state machine (doesn't invoke OpenSSL):

```bash
python run_experiments.py --model-only
```

To repeat each of the seven integration scenarios three times:

```bash
python run_experiments.py --repetitions 3
```

To enumerate traces permitting up to two attacker deviations (see bounded-model limitations):

```bash
python run_experiments.py --max-attacks 2 --model-only
```

## Main files

- `security_model.py`: role/policy state machine, enumerated attacker transitions, invariant checker, disabled-guard negative controls.
- `independent_protocol.py`: copied Program 7 implementation with **new receiver-side local mode-policy checks**.
- `tests/`: 137 inherited regressions plus 23 new tests (9 bounded-model, 8 local-mode, 6 real-signed-frame checks).
- `run_experiments.py`: runs bounded verification and OpenSSL-backed smoke tests, writing the result CSV/JSON/PNG files.
- `FORMAL_MODEL_SPEC.md`: exact abstraction, state bounds, adversary assumptions and safety invariants.
- `METHODS_AND_LIMITATIONS.md`: explicit security gaps before publication.
- `results/bounded_state_report.json`: precise checker scope and violation outcomes.
- `results/counterexample_traces.json`: exact examples of violations induced by weakened controls.
- `results/model_check_summary.csv`: compact model-control comparison.
- `results/integration_trials.csv`: OpenSSL-backed smoke-session outcomes.
- `results/*.png`: charts. `experiment_manifest.json` records tool versions / conditions.

**Caution:** These checks do not constitute a proof of secret-key indistinguishability, QKD implementation security, or strong security of the concatenation/HKDF hybrid combiner.
