# Program 1 — Reproducible BB84 intercept–resend calibration

This is an **independent corrected educational BB84 simulator**, based on the
model and intended experiment in the paper *Mitigating Quantum Threats to
Classical Cryptography: A Hybrid BB84-RSA-AES Approach* (Samal et al.). It is
not a reproduction of the original GitHub code or its performance numbers.

## How to run (Python 3.10+)

```bash
python -m pip install -r requirements.txt
python -m unittest discover -s tests -v
python run_experiments.py
```

Optional custom simulation:

```bash
python run_experiments.py --n 20000 --trials 500 --test-fraction 0.2 --noise 0.01 --loss 0.1
```

Output files in `results/`:

- `qber_trials.csv`: per-trial public test QBER, counts, diagnostic agreement, measured simulation time.
- `qber_summary.csv`: independent-trial mean QBER, Student-t 95% CI, theoretical expectation.
- `qber_vs_interception.png` / `.pdf`: publication-draft QBER calibration graph.
- `small_sample_diagnostics.csv`: probability of zero observed errors and of being below 11% at N=500 with 10% public test sample.
- `timing_summary.csv` / `timing_vs_signals.png`: runtime of *this NumPy simulator only*, not channel latency or Qiskit quantum-circuit execution.
- `experiment_manifest.json`: parameters, versions and seeded replay information.

## Model and analytical benchmarks

Alice chooses independent uniform bits and independent random Z/X preparation
bases. Bob chooses independent Z/X measurement bases. Eve independently
intercepts a signal with probability `p`, measures in an independent random
basis and resends her measurement state. A measurement in the wrong basis has
a random outcome. Loss (`loss_probability`) is independent of bit/basis and
interception; noisy channel flips Bob's bit after his quantum measurement,
independently with probability `q0`.

For a sifted bit, in this model:

    expected_QBER(p, q0) = q0 + (1 - 2*q0) * p/4

In the noiseless case this becomes `Q = p/4`; about half of received signals
are sifted. The public test sample is uniformly drawn without replacement
from matched-basis indices and discarded before the remaining raw key is
counted. A 95% confidence interval is computed **across independently seeded
trials** (not a composable QKD security confidence bound).

## Research integrity and limitations

1. The retained raw bits are **NOT final secret key bits**. There is no
   authenticated classical channel, reconciliation, privacy amplification,
   or composable finite-key security theorem in Program 1.
2. The privileged simulator can compare unrevealed raw bits for diagnostics;
   Alice and Bob cannot do this without disclosure.
3. A low QBER **does not prove absence of Eve**, and a fixed 11% QBER cutoff
   is **not** a finite-key security certification rule.
4. Baseline noise is an ideal independent bit-flip model, not physical
   polarization, dark-count, detector, multi-photon or side-channel physics.
5. `runtime_ms` measures Python/NumPy simulation only. Compare hardware,
   algorithm, and simulator timings only when properly isolated and labeled.
6. Test seeds are deterministic for reproducibility; they are **not
   cryptographic key-generation randomness** for deployment.
7. The small-sample diagnostic flags the rate of samples with QBER <=11%
   purely to **criticize** the old cutoff. It is not an authorization/acceptance
   rule in this simulator.

**Next module:** formal finite-key phase-error estimation, reconciliation,
privacy amplification, and authenticated protocol behavior. Never connect
Program 1's raw bits directly to AES as if they were secure keys.
