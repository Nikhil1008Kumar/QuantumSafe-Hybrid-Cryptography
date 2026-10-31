"""Issue 5: model-level finite-key sensitivity; not a security proof."""
import argparse
import csv
import hashlib
import json
import math
import re
import statistics
import subprocess
from collections import Counter
from dataclasses import asdict, replace
from pathlib import Path

from finite_key_bb84 import FiniteKeyConfig, run

BASE = FiniteKeyConfig(
    transmitted_signals=50000,
    target_key_bits=9000,
    target_test_bits=9000,
)

# One-factor-at-a-time, except the labeled noise-1% EC-cap sweep.
CASES = [
    ("baseline_clean", {}),
    ("block_20000", dict(transmitted_signals=20000, target_key_bits=3600, target_test_bits=3600)),
    ("block_35000", dict(transmitted_signals=35000, target_key_bits=6300, target_test_bits=6300)),
    ("block_70000", dict(transmitted_signals=70000, target_key_bits=12600, target_test_bits=12600)),
    ("test_3000", dict(target_test_bits=3000)),
    ("test_6000", dict(target_test_bits=6000)),
    ("test_11000", dict(target_test_bits=11000)),
    ("noise_1pct", dict(noise_probability=.01)),
    ("noise_2pct", dict(noise_probability=.02)),
    ("noise_3pct", dict(noise_probability=.03)),
    ("noise_4pct", dict(noise_probability=.04)),
    ("loss_10pct", dict(loss_probability=.10)),
    ("loss_20pct", dict(loss_probability=.20)),
    ("loss_30pct", dict(loss_probability=.30)),
    ("noise1_cap20", dict(noise_probability=.01, ec_leakage_cap_fraction=.20)),
    ("noise1_cap30", dict(noise_probability=.01, ec_leakage_cap_fraction=.30)),
    ("noise1_cap45", dict(noise_probability=.01, ec_leakage_cap_fraction=.45)),
    ("noise1_cap50", dict(noise_probability=.01, ec_leakage_cap_fraction=.50)),
    ("secrecy_1e8", dict(eps_secrecy=1e-8)),
    ("secrecy_1e12", dict(eps_secrecy=1e-12)),
    ("correctness_1e6", dict(eps_correctness=1e-6)),
    ("correctness_1e14", dict(eps_correctness=1e-14)),
]

MASTER_SEED = 20261031

def seed_for(rep):
    raw = f"issue5/v1|{MASTER_SEED}|{rep}".encode("ascii")
    return int.from_bytes(hashlib.sha256(raw).digest()[:8], "big")

def wilson(successes, trials):
    z = 1.959963984540054
    p = successes / trials
    den = 1 + z*z/trials
    center = (p + z*z/(2*trials)) / den
    half = z * math.sqrt(p*(1-p)/trials + z*z/(4*trials*trials)) / den
    return max(0.0, center-half), min(1.0, center+half)

def write_csv(path, records):
    with path.open("w", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=list(records[0]))
        writer.writeheader()
        writer.writerows(records)

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--repetitions", type=int, default=100)
    parser.add_argument("--run-label", default="v1")
    args = parser.parse_args()

    if args.repetitions < 1:
        parser.error("repetitions must be positive")
    if not re.fullmatch(r"[a-zA-Z0-9_-]{1,40}", args.run_label):
        parser.error("invalid run-label")

    root = Path(__file__).resolve().parent
    out = root / "results" / ("finite_key_sensitivity_" + args.run_label)
    if out.exists():
        raise SystemExit(f"STOP: Output directory already exists: {out}")

    trials, summaries = [], []
    print(f"Configurations: {len(CASES)}; repetitions each: {args.repetitions}", flush=True)

    for name, changes in CASES:
        cfg = replace(BASE, **changes)
        observations = []

        for rep in range(args.repetitions):
            seed = seed_for(rep)
            result = run(cfg, seed)
            observations.append(result)
            trials.append({
                "scenario": name,
                "repetition": rep,
                "seed": seed,
                **asdict(cfg),
                **asdict(result),
            })

        counts = Counter(r.status for r in observations)
        accepted = counts["ACCEPT"]
        low, high = wilson(accepted, args.repetitions)
        evaluated = [r for r in observations if r.ec_leakage_budget_bits > 0]

        summaries.append({
            "scenario": name,
            "repetitions": args.repetitions,
            "accepted": accepted,
            "admission_rate": accepted / args.repetitions,
            "wilson95_low": low,
            "wilson95_high": high,
            "mean_ec_bits_when_evaluated": (
                statistics.mean(r.ec_public_bits for r in evaluated) if evaluated else ""
            ),
            "mean_bound_bits_when_evaluated": (
                statistics.mean(r.finite_bound_bits for r in evaluated) if evaluated else ""
            ),
            "status_counts_json": json.dumps(dict(sorted(counts.items())), sort_keys=True),
        })
        print(f"{name:<23} ACCEPT={accepted:>3}/{args.repetitions}", flush=True)

    out.mkdir(parents=True)
    write_csv(out / "trial_data.csv", trials)
    write_csv(out / "summary.csv", summaries)

    git_head = subprocess.check_output(
        ["git", "rev-parse", "HEAD"], cwd=root, text=True
    ).strip()
    manifest = {
        "study": "Issue 5 finite-key full-protocol sensitivity v1",
        "design": "Predeclared one-factor-at-a-time sweeps; EC-cap sweep at 1% noise",
        "repetitions": args.repetitions,
        "master_seed": MASTER_SEED,
        "seed_rule": "SHA256(issue5/v1|master_seed|rep), first eight bytes big-endian",
        "seed_note": "Same seed schedule across scenarios; not identical physical noise realizations",
        "git_head_at_run": git_head,
        "script_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
        "baseline": asdict(BASE),
        "cases": [{"scenario": name, "overrides": changes} for name, changes in CASES],
        "limitations": [
            "Model admission is not a composable QKD security proof",
            "Wilson intervals describe Monte Carlo uncertainty only",
            "Some aborts occur before QBER, leakage or finite-bound evaluation",
            "Privileged Z-error diagnostics are never admission-policy inputs",
            "Measured runtime is machine-dependent",
        ],
    }
    (out / "manifest.json").write_text(
        json.dumps(manifest, indent=2) + "\n", encoding="utf-8"
    )

    with (out / "SHA256SUMS.txt").open("w", encoding="utf-8", newline="\n") as f:
        for name in ("trial_data.csv", "summary.csv", "manifest.json"):
            digest = hashlib.sha256((out / name).read_bytes()).hexdigest()
            f.write(f"{digest}  {name}\n")

    print(f"PASS: Saved {len(trials)} trials to {out}", flush=True)

if __name__ == "__main__":
    main()
