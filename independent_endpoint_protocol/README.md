# Program 7 — Independent BB84 endpoints and interactive authenticated reconciliation

**Status:** experimental simulation. Do not use any output as a production cryptographic key.

Program 7 builds on Programs 2–6. Alice and Bob now hold **separate** quantum-observation and raw-key arrays in separately instantiated protocol roles. Their classical messages traverse a deliberately mutable **in-memory relay**, and the recipient checks ML-DSA-65 signatures, pinned peer identity, session ID, context, ordering, and protocol stage **before** accepting each frame. The quantum transmission remains a seeded probabilistic simulation in one process: there is **no real fiber channel or separate network process**.

Most importantly, error-correction query/answer interactions are *live*: Bob issues a signed parity-query batch; Alice computes the requested parities from only her local raw key and returns a signed reply; Bob uses the verified replies and his own bits to choose the next queries or corrections. This is a multiround block-parity bisection study, **not a verified Cascade implementation with look-back**, and not a composable security proof.

## System requirements
- Python 3.11+ (tested in Python 3.13)
- OpenSSL >= 3.5 with ML-DSA-65 and ML-KEM-768 enabled
- Packages in `requirements.txt` (`numpy`, `scipy`, `matplotlib`, `cryptography`)

## Run on Windows / Git Bash

Extract this project as `Quantum_Project/independent_endpoint_protocol`, then:

```bash
cd ~/OneDrive/Desktop/Quantum_Project/independent_endpoint_protocol
openssl version
python -m pip install -r requirements.txt
python -m unittest discover -s tests -v
python run_experiments.py
```

Expected local reference test result: **137 tests, OK**. The script performs **18 paired Program 6/7 sessions** (2 trials each across 9 scenarios), then **19 modified-message rejection trials**. It creates 3 CSV files, 4 PNG graphs and a reproducibility manifest in `results/`.

For a broader preliminary study:

```bash
python run_experiments.py --repetitions 10 --attack-repetitions 3
```

Longer studies can be expensive because OpenSSL is invoked as a subprocess for each signature and verification. Do not compare the wall-clock timings with production native-library benchmarks.

## File map
- `independent_protocol.py`: new role-bound signed-message state machine, interactive parity reconciliation and integrated hybrid AEAD
- `quantum_channel_model.py`: the idealized quantum state and bit/basis utility model adapted from Program 6
- `finite_key_bb84.py`: predeclared finite-key parameter and privacy-amplification model from Program 2
- `pqc_protocol.py`: real ML-DSA-65 / ML-KEM-768 OpenSSL subprocess backend from Program 3
- `hybrid_protocol.py`: authenticated-encryption and experimental hybrid key schedule from Program 4
- `authenticated_bb84.py`, `policy_comparison.py`: baselines and regression compatibility from Programs 5–6
- `tests/`: 116 inherited regression tests plus 21 new Program 7 tests
- `run_experiments.py`: paired comparisons and targeted message tampering
- `PROTOCOL_SPEC.md`: state machine and equations
- `METHODS_AND_LIMITATIONS.md`: interpretation and scientifically necessary limitations
- `results/RESULTS_INTERPRETATION.md`: exact reference run summary

## Research claims allowed
The recorded tests show the implemented **software state machine** can perform authenticated interactive parity requests and reject the enumerated modifications in this environment. `MODEL_ACCEPT` is **not** evidence of deployment-grade secrecy; all quantum inputs are simulated and seeded NumPy randomness is not cryptographically secure.
