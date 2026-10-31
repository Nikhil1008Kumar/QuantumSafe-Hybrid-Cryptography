"""Reproduce finite-key BB84 preliminary experiments (simulated, not hardware)."""
from __future__ import annotations
import csv
from dataclasses import asdict
from pathlib import Path
import json
import math
import platform
import sys
from collections import Counter
import numpy as np
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
from finite_key_bb84 import FiniteKeyConfig, run

ROOT=Path(__file__).resolve().parent
OUT=ROOT/'results'
OUT.mkdir(exist_ok=True)
BASE_SEED=20261024
SIZES=(500,10_000,50_000,100_000,200_000)
NOISE=(0.0,0.01,0.03)
ATTACK=(0.0,0.1,0.2,0.4,0.6)
REPS=20   # preliminary study; NOT final journal statistical power
TOLERANCE=0.04

def config(n,noise=0.0,attack=0.0):
    target=max(1,round(.18*n))
    return FiniteKeyConfig(transmitted_signals=n,target_key_bits=target,
        target_test_bits=target,intercept_probability=attack,
        noise_probability=noise,q_tolerance=TOLERANCE)

def run_grid():
    rows=[]
    for si,N in enumerate(SIZES):
        for ni,noise in enumerate(NOISE):
            for repeat in range(REPS):
                seed=BASE_SEED+1_000_000*si+10_000*ni+repeat
                r=run(config(N,noise),seed)
                rows.append({'experiment':'length_noise','noise':noise,
                    'intercept_probability':0.0,'seed':seed,**asdict(r)})
    # Attack study at a fixed length, with no background noise.
    N=100_000
    for pi,p in enumerate(ATTACK):
        for repeat in range(REPS):
            seed=BASE_SEED+20_000_000+10_000*pi+repeat
            r=run(config(N,0.0,p),seed)
            rows.append({'experiment':'attack','noise':0.0,
                'intercept_probability':p,'seed':seed,**asdict(r)})
    cols=list(rows[0])
    with (OUT/'session_trials.csv').open('w',newline='') as fd:
        writer=csv.DictWriter(fd,fieldnames=cols)
        writer.writeheader()
        writer.writerows(rows)
    return rows

def aggregate(rows):
    summary=[]
    groups={}
    for row in rows:
        key=(row['experiment'],row['transmitted'],row['noise'],row['intercept_probability'])
        groups.setdefault(key,[]).append(row)
    for (exp,N,noise,attack),sub in sorted(groups.items()):
        successes=[r for r in sub if r['status']=='ACCEPT']
        valid=[r for r in sub if r['raw_z_used']]
        count=len(sub)
        summary.append(dict(experiment=exp,transmitted=N,noise=noise,
            intercept_probability=attack,trials=count,accepted=len(successes),
            accepted_percent=100*len(successes)/count,
            mean_bound_bits=float(np.mean([r['finite_bound_bits'] for r in valid])) if valid else None,
            mean_ec_leakage=float(np.mean([r['ec_public_bits'] for r in valid])) if valid else None,
            mean_x_qber=float(np.mean([r['x_qber'] for r in valid])) if valid else None,
            mean_runtime_ms=float(np.mean([r['runtime_ms'] for r in sub])),
            abort_counts='; '.join(f'{k}: {v}' for k,v in sorted(Counter(r['status'] for r in sub).items()))))
    with (OUT/'summary.csv').open('w',newline='') as fd:
        writer=csv.DictWriter(fd,fieldnames=list(summary[0]))
        writer.writeheader();writer.writerows(summary)
    return summary

def plots(summary):
    length=[r for r in summary if r['experiment']=='length_noise']
    plt.figure(figsize=(8.6,5.4))
    subset=sorted([r for r in length if r['noise']==0.0],key=lambda r:r['transmitted'])
    plt.plot([r['transmitted'] for r in subset],
             [r['mean_bound_bits'] for r in subset],marker='o',
             label='Fixed predeclared QBER and leakage bounds')
    plt.axhline(256,ls='--',linewidth=1,label='256-bit target')
    plt.xscale('log');plt.xlabel('Transmitted quantum signals (simulation)')
    plt.ylabel('Mean eligible extraction bound (bits)')
    plt.title('Finite-key bound using predeclared parameters')
    plt.grid(alpha=.2);plt.legend();plt.tight_layout()
    plt.savefig(OUT/'finite_key_vs_signals.png',dpi=180)
    plt.close()

    plt.figure(figsize=(8.6,5.4))
    for noise in NOISE:
        subset=sorted([r for r in length if r['noise']==noise],key=lambda r:r['transmitted'])
        plt.plot([r['transmitted'] for r in subset],
            [r['accepted_percent'] for r in subset],marker='o',label=f'Noise {noise:.0%}')
    plt.xscale('log');plt.ylim(-5,105)
    plt.xlabel('Transmitted quantum signals (simulation)')
    plt.ylabel('Accepted sessions (%)')
    plt.title(f'Finite-key-aware key admission ({REPS} independent trials/configuration)')
    plt.grid(alpha=.2);plt.legend();plt.tight_layout()
    plt.savefig(OUT/'admission_vs_signals.png',dpi=180)
    plt.close()

    plt.figure(figsize=(8.6,5.4))
    for noise in NOISE:
        subset=sorted([r for r in length if r['noise']==noise],key=lambda r:r['transmitted'])
        plt.plot([r['transmitted'] for r in subset],
                 [r['mean_ec_leakage'] for r in subset],marker='o',label=f'Noise {noise:.0%}')
    xs=[r['transmitted'] for r in sorted([r for r in length if r['noise']==0.0],key=lambda r:r['transmitted'])]
    plt.plot(xs,[math.ceil(round(.18*n)*.4) for n in xs],
             ls='--',label='Predeclared public-leakage budget')
    plt.xscale('log')
    plt.xlabel('Transmitted quantum signals (simulation)')
    plt.ylabel('Measured public EC bits')
    plt.title('Leakage accounting changes acceptance with channel noise')
    plt.grid(alpha=.2);plt.legend();plt.tight_layout()
    plt.savefig(OUT/'ec_leakage_vs_signals.png',dpi=180)
    plt.close()

    attack=[r for r in summary if r['experiment']=='attack']
    plt.figure(figsize=(8.6,5.4))
    plt.plot([100*r['intercept_probability'] for r in attack],
             [100*r['mean_x_qber'] for r in attack],marker='o',label='Observed X-basis QBER')
    plt.plot([100*r['intercept_probability'] for r in attack],
             [25*r['intercept_probability'] for r in attack],ls='--',label='Theory p / 4')
    plt.axhline(100*TOLERANCE,ls=':',label='Predeclared 4% test tolerance')
    plt.xlabel('Eve interception probability (%)');plt.ylabel('QBER (%)')
    plt.title('Independent X-basis parameter estimation')
    plt.grid(alpha=.2);plt.legend();plt.tight_layout()
    plt.savefig(OUT/'test_basis_qber.png',dpi=180)
    plt.close()

    plt.figure(figsize=(8.6,5.4))
    plt.plot([100*r['intercept_probability'] for r in attack],
             [r['accepted_percent'] for r in attack],marker='o')
    plt.xlabel('Eve interception probability (%)')
    plt.ylabel('Accepted sessions (%)')
    plt.ylim(-5,105);plt.grid(alpha=.2)
    plt.title('Finite-key admission under intercept-resend (preliminary)')
    plt.tight_layout();plt.savefig(OUT/'attack_admission.png',dpi=180)
    plt.close()


def main():
    rows=run_grid()
    summary=aggregate(rows)
    plots(summary)
    manifest=dict(study='Program 2 finite-key BB84 simulated baseline',
        base_seed=BASE_SEED, repetitions=REPS,
        reference='Tomamichel et al, Nature Communications 3:634 (2012), Eq. (2)',
        q_tolerance=TOLERANCE, ec_leakage_cap_fraction=0.40,
        public_reconciliation_messages_per_parity_query=2,
        eps_secrecy=1e-10,
        eps_correctness=1e-10, finite_key_ideal_source_quality=1,
        simulator_not_hardware=True, classical_channel_assumed_authenticated=True,
        random_generator='numpy.default_rng seeded (not cryptographically secure)',
        numpy=np.__version__,python=sys.version.split()[0],platform=platform.platform())
    (OUT/'experiment_manifest.json').write_text(json.dumps(manifest,indent=2))
    print(f'Completed {len(rows)} simulated sessions')
    print('STUDY 1: LENGTH AND BACKGROUND NOISE')
    for r in summary:
        if r['experiment']=='length_noise':
            print(f"  N={r['transmitted']:>6,}, noise={r['noise']:.0%}, "
                  f"accepted={r['accepted_percent']:>5.1f}%, bound={r['mean_bound_bits']:>8.1f} bits, "
                  f"EC leakage={r['mean_ec_leakage']:>7.1f} bits")
    print('STUDY 2: INTERCEPT-RESEND')
    for r in summary:
        if r['experiment']=='attack':
            print(f"  Eve={r['intercept_probability']:.0%}, "
                  f"X-QBER={100*r['mean_x_qber']:.2f}%, "
                  f"accepted={r['accepted_percent']:.1f}%")
    print('Saved: results/session_trials.csv, summary.csv, five PNG charts, manifest.json')

if __name__=='__main__':
    main()
