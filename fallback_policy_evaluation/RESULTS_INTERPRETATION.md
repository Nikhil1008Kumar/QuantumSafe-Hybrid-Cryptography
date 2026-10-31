# Program 5 preliminary results (2026-10-24 local execution)

All counts below are from 180 *independent QKD simulation results*, with each result reused for 8 decisions (4 strategies and 2 application policies). The 1,440 decisions **are not 1,440 independent QKD experiments**.

The code passed 95 inherited-and-new tests; five Program 4 cryptographic integration smoke checks also passed. Local OpenSSL was 3.5.5. All values will differ when simulation parameters change.

## Hybrid-preferred policy: 180 QKD observations

| Strategy | Hybrid labelled | PQC-only | Abort | Labels failing Program 2 finite-key admission | Model-compliant sessions |
|---|---:|---:|---:|---:|---:|
| Finite-key policy candidate | 41 | 139 | 0 | 0 | 180 |
| QBER-only 11% fallback | 160 | 20 | 0 | 119 | 61 |
| Finite-key without fallback | 41 | 0 | 139 | 0 | 41 |
| PQC-only baseline | 0 | 180 | 0 | 0 | 180 |

The QBER-only algorithm's 119 invalid HYBRID labels are a deliberately weak baseline: treating it as an implementation of a secure full QKD protocol would be incorrect. The proposed policy **ties** PQC-only for modeled availability; that is a meaningful negative result against claims of universal superiority.

## Hybrid-required policy: 180 QKD observations

| Strategy | Hybrid labelled | PQC-only | Abort | Invalid QKD labels | Model-compliant sessions |
|---|---:|---:|---:|---:|---:|
| Finite-key policy candidate | 41 | 0 | 139 | 0 | 41 |
| QBER-only 11% | 160 | 0 | 20 | 119 | 41 |
| Finite-key without fallback | 41 | 0 | 139 | 0 | 41 |
| PQC-only baseline | 0 | 0 | 180 | 0 | 0 |

Required mode correctly sacrifices availability when the model does not certify QKD material. PQC-only is not permitted to bypass a required QKD policy.

## Scenario-level standout examples

- **N=500, ideal:** 20/20 runs lacked a suitable 256-bit finite-key admission certificate; all 20 would nevertheless be labelled HYBRID by a naive <=11% QBER rule. The proposed controller selected PQC-only only because the preferred policy permitted it.
- **N=50,000, 1% simulated background noise:** 20/20 were admitted by the Program 2 model; no model-invalid QBER labels.
- **N=50,000, 3% simulated noise:** 0/20 were admitted; all 20 were HYBRID-labelled by the naive QBER-only baseline despite violating the finite-key model's admissibility constraints.
- **N=50,000, Eve intercepts 10%:** 1/20 met the conditional finite-key model's requirements; 19/20 were ineligible despite <=11% QBER. This does not prove any other 19 real keys were insecure.
- **N=50,000, 30% loss:** 0/20 had sufficient selected raw/test detections under the chosen targets. The naive QBER-only rule also could not admit these cases due to missing sample data.

## Interpretation for a journal paper

This is useful **internal evidence that a finite-key admission guard has a different decision behavior than a fixed QBER threshold** under the chosen simulator. It does not, by itself, make the admission guard a novel invention, since applying valid finite-key criteria is already established practice. We should not write an abstract claiming higher security, universal availability, or quantified encryption-break resistance from these counts.

For publication, we need (a) formal authentication of individual QKD public messages; (b) an analyzed combiner; (c) strong current baselines, including realistic adaptive finite-key systems; (d) deeper adversarial and channel models; (e) larger independent trials and calibrated confidence intervals; and ideally (f) model-checking or a security argument for the complete end-to-end state machine.
