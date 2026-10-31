# Reproducibility Environment

## Hardware
- CPU: AMD Ryzen 5 3450U with Radeon Vega Mobile Graphics
- Logical processors: 8
- Reported RAM: 5.89 GB

## Software
- Operating system: Windows, build 26200
- Python: 3.11.9
- NumPy: 2.4.6
- SciPy: 1.17.1
- Matplotlib: 3.11.1
- cryptography: 49.0.0
- External OpenSSL CLI: 3.5.7
- Python SSL OpenSSL: 3.0.13

## Experiment Provenance
- Python: MATCH
  - Original: 3.11.9
  - Updated: 3.11.9
- Platform: MATCH
  - Original: Windows-10-10.0.26200-SP0
  - Updated: Windows-10-10.0.26200-SP0
- OpenSSL backend: MATCH
  - Original: OpenSSL 3.5.7 9 Jun 2026 (Library: OpenSSL 3.5.7 9 Jun 2026)
  - Updated: OpenSSL 3.5.7 9 Jun 2026 (Library: OpenSSL 3.5.7 9 Jun 2026)

## Measurement Limitations
- Local software execution, not real quantum-network latency.
- Serialized byte counts are modeled, not physical packet traffic.
- Adaptive P8 was executed before Fixed P9.
- Each integration scenario contains 10 matched pairs.
- Historical and updated timing runs must be reported separately.
- No formal composable security proof is claimed.

## Dataset Integrity
Checksums: results/SHA256SUMS.txt

## Reproduction
Install requirements.txt and run the unittest discovery suite.
Use a separate working copy when regenerating experimental results.
