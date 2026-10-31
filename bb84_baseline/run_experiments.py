"""Reproducible QBER calibration, small-sample study, and timing study."""
from __future__ import annotations

import argparse
from dataclasses import asdict
from pathlib import Path
import csv
import json
import platform
import sys
from collections import defaultdict

import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
import numpy as np
from scipy.stats import t

from bb84 import BB84Config, simulate, expected_qber


RATES = (0, 0.1, 0.2, 0.3, 0.4, 0.5, 0.6)
BASE_SEED = 20261024


def save_csv(path, rows):
    if not rows:
        raise ValueError('No rows to save')
    with open(path, 'w', newline='', encoding='utf-8') as handle:
        writer = csv.DictWriter(handle, fieldnames=list(rows[0].keys()))
        writer.writeheader()
        writer.writerows(rows)


def ci95(values):
    x = np.asarray(values, dtype=float)
    x = x[np.isfinite(x)]
    if len(x) < 2:
        return float('nan'), float('nan')
    mean = float(np.mean(x))
    error = float(t.ppf(0.975, len(x) - 1) * np.std(x, ddof=1) / np.sqrt(len(x)))
    return mean - error, mean + error


def main():
    parser = argparse.ArgumentParser(description='BB84 Program 1 reproducible experiment')
    parser.add_argument('--n', type=int, default=10_000, help='transmitted signals per trial')
    parser.add_argument('--trials', type=int, default=200, help='independent trials per interception rate')
    parser.add_argument('--test-fraction', type=float, default=0.20)
    parser.add_argument('--noise', type=float, default=0.0)
    parser.add_argument('--loss', type=float, default=0.0)
    parser.add_argument('--out', type=Path, default=Path(__file__).parent / 'results')
    args = parser.parse_args()
    if args.trials < 2:
        parser.error('--trials must be >= 2 for confidence intervals')
    args.out.mkdir(exist_ok=True, parents=True)
    raw, summary = [], []

    for rate_idx, p in enumerate(RATES):
        group = []
        for rep in range(args.trials):
            seed = int(np.random.SeedSequence([BASE_SEED, 1, rate_idx, rep]).generate_state(1)[0])
            result = simulate(BB84Config(args.n, p, args.noise, args.loss, args.test_fraction), seed)
            raw.append({'interception_probability': p, 'replicate': rep, 'seed': seed, **asdict(result)})
            if np.isfinite(result.estimated_qber):
                group.append(result)
        qbers = [g.estimated_qber for g in group]
        lci, uci = ci95(qbers)
        summary.append({
            'interception_probability': p,
            'expected_qber': expected_qber(p, args.noise),
            'mean_estimated_qber': float(np.mean(qbers)),
            'ci95_lower': lci,
            'ci95_upper': uci,
            'mean_sifted_bits': float(np.mean([g.sifted_bits for g in group])),
            'mean_test_bits': float(np.mean([g.publicly_revealed_bits for g in group])),
            'mean_retained_raw_bits': float(np.mean([g.retained_raw_bits for g in group])),
            'mean_retained_raw_mismatches_diagnostic': float(np.mean([g.retained_raw_mismatches_diagnostic for g in group])),
            'valid_trials': len(group),
        })

    save_csv(args.out / 'qber_trials.csv', raw)
    save_csv(args.out / 'qber_summary.csv', summary)

    x = np.asarray([s['interception_probability'] for s in summary]) * 100
    measured = np.asarray([s['mean_estimated_qber'] for s in summary]) * 100
    expected = np.asarray([s['expected_qber'] for s in summary]) * 100
    lo = np.asarray([s['ci95_lower'] for s in summary]) * 100
    hi = np.asarray([s['ci95_upper'] for s in summary]) * 100

    fig, ax = plt.subplots(figsize=(8, 5.2))
    ax.plot(x, expected, linestyle='--', label='Analytical expectation')
    ax.errorbar(x, measured, yerr=[measured-lo, hi-measured], fmt='o-',
                capsize=4, label='Simulation mean ± 95% CI')
    ax.set(xlabel='Probability that Eve intercepts a transmitted signal (%)',
           ylabel='Estimated QBER from disclosed sifted-bit sample (%)',
           title='BB84 intercept–resend calibration')
    ax.set_ylim(bottom=-0.5)
    ax.grid(alpha=0.3)
    ax.legend()
    fig.tight_layout()
    fig.savefig(args.out / 'qber_vs_interception.png', dpi=180)
    fig.savefig(args.out / 'qber_vs_interception.pdf')
    plt.close(fig)

    # Reproduce a key concern in the old manuscript: 500 signals and only 10%
    # of the sifted positions publicly tested. A zero-error sample is common
    # despite a nonzero interception probability.
    small_rows = []
    for p_idx, p in enumerate((0.1, 0.4, 0.6)):
        results = []
        for rep in range(1000):
            seed = int(np.random.SeedSequence([BASE_SEED, 2, p_idx, rep]).generate_state(1)[0])
            results.append(simulate(BB84Config(500, p, 0, 0, 0.10), seed))
        small_rows.append({
            'transmitted_signals': 500,
            'interception_probability': p,
            'trials': len(results),
            'expected_qber': expected_qber(p),
            'mean_test_bits': float(np.mean([r.publicly_revealed_bits for r in results])),
            'fraction_zero_observed_qber': float(np.mean([r.publicly_revealed_errors == 0 for r in results])),
            'fraction_qber_at_or_below_11pct': float(np.mean([r.estimated_qber <= 0.11 for r in results])),
            'mean_retained_raw_mismatches_diagnostic': float(np.mean([
                r.retained_raw_mismatches_diagnostic for r in results])),
        })
    save_csv(args.out / 'small_sample_diagnostics.csv', small_rows)

    # Timing study measures this NumPy probability simulator only, not optical
    # transmission, hardware QKD, or Qiskit. Run warmups for each size.
    timing_rows = []
    for size in (500, 1000, 5000, 10000, 50000):
        config = BB84Config(size, 0.3, 0, 0, 0.2)
        for i in range(5):
            simulate(config, seed=BASE_SEED + i)
        vals = [simulate(config, seed=BASE_SEED + i + 50).runtime_ms
                for i in range(30)]
        timing_rows.append({
            'transmitted_signals': size,
            'trials': len(vals),
            'median_ms': float(np.median(vals)),
            'q1_ms': float(np.percentile(vals, 25)),
            'q3_ms': float(np.percentile(vals, 75)),
            'mean_ms': float(np.mean(vals)),
        })
    save_csv(args.out / 'timing_summary.csv', timing_rows)
    fig, ax = plt.subplots(figsize=(8, 5.2))
    tx = np.array([r['transmitted_signals'] for r in timing_rows])
    ty = np.array([r['median_ms'] for r in timing_rows])
    tq1 = np.array([r['q1_ms'] for r in timing_rows])
    tq3 = np.array([r['q3_ms'] for r in timing_rows])
    ax.plot(tx, ty, marker='o', label='Median runtime')
    ax.fill_between(tx, tq1, tq3, alpha=0.15, label='IQR (25th–75th percentile)')
    ax.set(xlabel='Signals simulated', ylabel='Runtime (milliseconds)',
           title='Program 1 NumPy simulator timing (not hardware-QKD latency)')
    ax.grid(alpha=0.3)
    ax.legend()
    fig.tight_layout()
    fig.savefig(args.out / 'timing_vs_signals.png', dpi=180)
    plt.close(fig)

    manifest = {
        'script': 'run_experiments.py', 'base_seed': BASE_SEED,
        'n_per_calibration_trial': args.n, 'trials_per_interception_rate': args.trials,
        'test_fraction': args.test_fraction, 'noise_probability': args.noise,
        'loss_probability': args.loss,
        'interception_rates': RATES,
        'python': sys.version, 'platform': platform.platform(),
        'numpy': np.__version__, 'matplotlib': matplotlib.__version__,
        'model_scope': 'Monte Carlo ideal BB84; NOT finite-key secure QKD',
    }
    with open(args.out / 'experiment_manifest.json', 'w', encoding='utf-8') as f:
        json.dump(manifest, f, indent=2)

    print('QBER CALIBRATION:')
    print('Eve % | Theory % | Measured % | 95% CI %')
    for row in summary:
        print(f"{row['interception_probability']*100:5.0f} | {row['expected_qber']*100:8.3f} | "
              f"{row['mean_estimated_qber']*100:10.3f} | "
              f"[{row['ci95_lower']*100:.3f}, {row['ci95_upper']*100:.3f}]")
    print('\nSMALL-SAMPLE DIAGNOSTICS (500 signals, 10% of sifted bits tested):')
    for row in small_rows:
        print(f"Eve {row['interception_probability']:.0%} : "
              f"zero-error sample {row['fraction_zero_observed_qber']:.1%}; "
              f"QBER <=11% {row['fraction_qber_at_or_below_11pct']:.1%}")
    print(f'\nSaved to: {args.out.resolve()}')


if __name__ == '__main__':
    main()
