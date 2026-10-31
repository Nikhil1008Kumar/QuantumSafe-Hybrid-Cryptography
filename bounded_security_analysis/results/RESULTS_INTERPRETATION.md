# Program 8 — Reference results and how to interpret them

## Bounded protocol checker
- Enumerated **24** assignments of application policy, QKD key admission, ML-KEM establishment and symbolic key agreement.
- Maximum **8** signed message stages.
- Enumerated **7** relay action types, with at most **1** non-clean action on a trace in the default run.
- Explored **1,368 bounded states** under intact guard conditions, with **zero encoded invariant violations**.
- Six intentionally weakened variants each produced one or more invariant counterexamples; `no_policy_check` produced three distinct violations under its combined disabled guards.

These quantities are *bounded model states and violations*, not 1,368 independent experimental quantum security attacks, and zero violations does not establish real-world safety.

## Real OpenSSL-backed integration smoke tests
Seven single-run configurations yielded these policy-consistent outcomes:

| Scenario | Observed mode |
|---|---|
| Clean channel, hybrid required | HYBRID |
| Clean channel, hybrid preferred | HYBRID |
| 3% background noise, hybrid preferred | PQC_ONLY |
| 3% background noise, hybrid required | ABORT |
| Short (500-signal) key, hybrid preferred | PQC_ONLY |
| Short (500-signal) key, hybrid required | ABORT |
| PQC-only policy | PQC_ONLY |

These seven trials confirm only the tested integration behavior. Timings should not be used as an optimization result without a more extensive paired experiment.

## Test-suite result
The complete inherited-plus-new Python suite finished **160/160 passed** in the local validation environment (16.3 seconds). The tests cover individual components as well as selected adversarial transport and state-control cases. Consult `test_log.txt` for detailed case names.

## Scientific conclusion
The program demonstrates that independent mode-policy checks, authenticated transcript constraints and key confirmation are necessary conditions for the secure control flow of the modeled hybrid system. It does **not** prove confidentiality against quantum or classical attackers. Important open tasks are composable finite-key analysis with validated adaptive-EC leakage and a formally justified hybrid combiner.
