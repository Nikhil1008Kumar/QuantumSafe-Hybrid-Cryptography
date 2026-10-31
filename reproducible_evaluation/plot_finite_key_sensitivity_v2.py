"""Reproducible plots for Issue 5 finite-key sensitivity."""
import csv
import hashlib
from collections import Counter, defaultdict
from pathlib import Path

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt

ROOT = Path(__file__).resolve().parent
DATA = ROOT / "results" / "finite_key_sensitivity_full100"
OUT = DATA / "figures_v3"

if OUT.exists():
    raise SystemExit(f"STOP: Figure directory already exists: {OUT}")

def read_csv(name):
    with (DATA / name).open(encoding="utf-8", newline="") as f:
        return list(csv.DictReader(f))

summary = {row["scenario"]: row for row in read_csv("summary.csv")}
trials = read_csv("trial_data.csv")
assert len(summary) == 22 and len(trials) == 2200

counts = defaultdict(Counter)
for row in trials:
    counts[row["scenario"]][row["status"]] += 1

def rate_and_ci(scenario):
    r = summary[scenario]
    return (
        100 * float(r["admission_rate"]),
        100 * float(r["wilson95_low"]),
        100 * float(r["wilson95_high"]),
    )

OUT.mkdir(parents=True)

def save(fig, name):
    fig.savefig(OUT / f"{name}.png", dpi=300, bbox_inches="tight")
    fig.savefig(OUT / f"{name}.pdf", bbox_inches="tight")
    plt.close(fig)
    print(f"PASS: {name} (PNG + PDF)")

# Figure 1: Noise sensitivity.
noise_cases = [
    ("baseline_clean", 0),
    ("noise_1pct", 1),
    ("noise_2pct", 2),
    ("noise_3pct", 3),
    ("noise_4pct", 4),
]
x = [noise for _, noise in noise_cases]
v = [rate_and_ci(name) for name, _ in noise_cases]
rates = [r[0] for r in v]
lower = [max(0.0, r[0] - r[1]) for r in v]
upper = [max(0.0, r[2] - r[0]) for r in v]

fig, ax = plt.subplots(figsize=(7.5, 4.8))
ax.errorbar(x, rates, yerr=[lower, upper], fmt="o-", capsize=5)
ax.set_xticks(x)
ax.set_xlabel("Simulated channel noise (%)")
ax.set_ylabel("Model admission rate (%)")
ax.set_ylim(-5, 105)
ax.set_title("Noise sensitivity of finite-key admission")
ax.grid(alpha=0.25)
fig.tight_layout()
save(fig, "figure1_noise_admission")

# Figure 2: Abort mechanisms.
cases = [
    ("block_20000", "20k signals"),
    ("block_35000", "35k signals"),
    ("test_3000", "3k test bits"),
    ("noise_2pct", "2% noise"),
    ("noise_3pct", "3% noise"),
    ("noise_4pct", "4% noise"),
    ("loss_30pct", "30% loss"),
    ("noise1_cap20", "1% noise, 20% cap"),
    ("noise1_cap50", "1% noise, 50% cap"),
]
statuses = [
    ("ACCEPT", "Accepted"),
    ("ABORT_INSUFFICIENT_FINITE_KEY", "Finite-key shortfall"),
    ("ABORT_EC_LEAKAGE_BUDGET", "EC leakage exceeded"),
    ("ABORT_PARAMETER_ESTIMATION", "Parameter estimation"),
    ("ABORT_INSUFFICIENT_DETECTIONS", "Insufficient detections"),
]

fig, ax = plt.subplots(figsize=(9.5, 6.0))
left = [0] * len(cases)

for code, label in statuses:
    values = [counts[name][code] for name, _ in cases]
    ax.barh(range(len(cases)), values, left=left, label=label)
    left = [a + b for a, b in zip(left, values)]

# Exact counts for mixed outcomes.
label_y = {name: i for i, (name, _) in enumerate(cases)}

ax.text(
    49.5, label_y["noise_2pct"],
    "99 accepted / 1 EC abort",
    ha="center", va="center",
    color="white", fontsize=9, fontweight="bold"
)

ax.text(
    25.5, label_y["noise_4pct"],
    "51 EC",
    ha="center", va="center",
    color="white", fontsize=10, fontweight="bold"
)

ax.text(
    75.5, label_y["noise_4pct"],
    "49 PE",
    ha="center", va="center",
    color="white", fontsize=10, fontweight="bold"
)

ax.set_yticks(range(len(cases)), [label for _, label in cases])
ax.invert_yaxis()
ax.set_xlim(0, 100)
ax.set_xlabel("Simulated sessions out of 100")
ax.set_title("Admission outcomes and abort mechanisms")
ax.legend(loc="upper center", bbox_to_anchor=(0.5, -0.13), ncol=2)
fig.tight_layout()
save(fig, "figure2_abort_reasons")

# Figure 3: EC budget trade-off at 1% noise.
cap_cases = [
    (20, "noise1_cap20"),
    (30, "noise1_cap30"),
    (40, "noise_1pct"),
    (45, "noise1_cap45"),
    (50, "noise1_cap50"),
]
caps = [cap for cap, _ in cap_cases]
v = [rate_and_ci(name) for _, name in cap_cases]
rates = [r[0] for r in v]
lower = [max(0.0, r[0] - r[1]) for r in v]
upper = [max(0.0, r[2] - r[0]) for r in v]
bounds = [
    float(summary[name]["mean_bound_bits_when_evaluated"])
    for _, name in cap_cases
]

fig, axes = plt.subplots(1, 2, figsize=(11, 4.5))
axes[0].errorbar(caps, rates, yerr=[lower, upper], fmt="o-", capsize=5)
axes[0].set_ylim(-5, 105)
axes[0].set_ylabel("Model admission rate (%)")
axes[0].set_title("Observed admissions")
axes[0].grid(alpha=0.25)

axes[1].plot(caps, bounds, "o-")
axes[1].axhline(256, linestyle="--", label="256-bit requirement")
axes[1].set_ylabel("Mean candidate key bound (bits)")
axes[1].set_title("Finite-key bound")
axes[1].legend()
axes[1].grid(alpha=0.25)

for ax in axes:
    ax.set_xticks(caps)
    ax.set_xlabel("Predeclared EC leakage budget (% of n)")

fig.suptitle("Reconciliation leakage-budget trade-off at 1% noise")
fig.tight_layout()
save(fig, "figure3_ec_budget_tradeoff")

with (OUT / "SHA256SUMS.txt").open(
    "w", encoding="utf-8", newline="\n"
) as f:
    for file in sorted(OUT.glob("figure*")):
        digest = hashlib.sha256(file.read_bytes()).hexdigest()
        f.write(f"{digest}  {file.name}\n")

print("PASS: All 3 figures generated in PNG and PDF")
print("PASS: Figure checksums recorded")
print(f"OUTPUT: {OUT}")
