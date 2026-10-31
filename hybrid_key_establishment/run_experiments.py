"""Preliminary independent Program 4 integration trials (NOT publication power)."""
from __future__ import annotations
import argparse
import csv
import json
import math
import platform
import statistics
import sys
from collections import Counter
from dataclasses import asdict
from pathlib import Path

import numpy as np
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt

from finite_key_bb84 import FiniteKeyConfig
from hybrid_protocol import HybridAbort, Policy, run_hybrid
from pqc_protocol import OpenSSLBackend, ProtocolAbort, generate_identity

OUT=Path(__file__).resolve().parent/'results'
OUT.mkdir(exist_ok=True)
BASE_SEED=20261024

SCENARIOS=[
    ('PQC_only',Policy.PQC_ONLY,500,0.0,0.0),
    ('Hybrid_clean',Policy.HYBRID_REQUIRED,50_000,0.0,0.0),
    ('Preferred_clean',Policy.HYBRID_PREFERRED,50_000,0.0,0.0),
    ('Preferred_noise_1pct',Policy.HYBRID_PREFERRED,50_000,.01,0.0),
    ('Preferred_noise_3pct',Policy.HYBRID_PREFERRED,50_000,.03,0.0),
    ('Required_noise_3pct',Policy.HYBRID_REQUIRED,50_000,.03,0.0),
    ('Preferred_Eve_20pct',Policy.HYBRID_PREFERRED,100_000,0.0,.20),
    ('Required_Eve_20pct',Policy.HYBRID_REQUIRED,100_000,0.0,.20),
    ('Preferred_short_500',Policy.HYBRID_PREFERRED,500,0.0,0.0),
    ('Required_short_500',Policy.HYBRID_REQUIRED,500,0.0,0.0),
]

def config(n,noise,eve):
    target=max(1,round(.18*n))
    return FiniteKeyConfig(transmitted_signals=n,target_key_bits=target,
        target_test_bits=target,noise_probability=noise,
        intercept_probability=eve,q_tolerance=.04)


def record_rows(reps:int):
    rows=[]
    with OpenSSLBackend() as backend:
        a=generate_identity(backend,'Alice')
        b=generate_identity(backend,'Bob')
        for si, (name,pol,n,noise,eve) in enumerate(SCENARIOS):
            for rep in range(reps):
                seed=BASE_SEED+10_000*si+rep
                base=dict(scenario=name,policy=pol.value,transmitted_signals=n,
                          noise_probability=noise,intercept_probability=eve,
                          repetition=rep,seed=seed)
                try:
                    r=run_hybrid(backend,a,b,config(n,noise,eve),seed,pol,
                                 plaintext=b'Test message for Program 4 study')
                    row=dict(base,status='SUCCESS',mode=r.mode,qkd_status=r.qkd_status,
                        bound_bits=r.qkd_bound_bits,x_qber=r.qkd_observed_x_qber,
                        ec_leakage_bits=r.qkd_ec_leakage_bits,
                        qkd_ms=r.qkd_runtime_ms,handshake_ms=r.handshake_runtime_ms,
                        total_ms=r.complete_runtime_ms,record_ciphertext_bytes=r.ciphertext_bytes,
                        on_wire_bytes=r.on_wire_bytes,key_confirmation_ok=r.application_keys_match,
                        abort_stage='')
                except HybridAbort as exc:
                    row=dict(base,status='ABORT',mode='ABORT',qkd_status=exc.qkd_status,
                        bound_bits='',x_qber='',ec_leakage_bits='',qkd_ms='',handshake_ms='',
                        total_ms='',record_ciphertext_bytes='',on_wire_bytes='',
                        key_confirmation_ok=False,abort_stage=exc.stage)
                except ProtocolAbort as exc:
                    row=dict(base,status='ABORT',mode='ABORT',qkd_status='UNDETERMINED',
                        bound_bits='',x_qber='',ec_leakage_bits='',qkd_ms='',handshake_ms='',
                        total_ms='',record_ciphertext_bytes='',on_wire_bytes='',
                        key_confirmation_ok=False,abort_stage='PROTOCOL')
                rows.append(row)
            print(f'{name:<25}: '+str(dict(Counter(r['mode'] for r in rows if r['scenario']==name))),flush=True)
        version=backend.version
    return rows, version


def save_csv(path, rows):
    with path.open('w',newline='',encoding='utf-8') as handle:
        writer=csv.DictWriter(handle,fieldnames=list(rows[0]))
        writer.writeheader();writer.writerows(rows)


def summarize(rows):
    summary=[]
    for name,*_ in SCENARIOS:
        group=[r for r in rows if r['scenario']==name]
        successes=[r for r in group if r['status']=='SUCCESS']
        times=[r['total_ms'] for r in successes]
        summary.append(dict(scenario=name,trials=len(group),
            hybrid=sum(r['mode']=='HYBRID' for r in group),
            pqc_only=sum(r['mode']=='PQC_ONLY' for r in group),
            aborts=sum(r['mode']=='ABORT' for r in group),
            success_rate_percent=100*len(successes)/len(group),
            median_total_ms=statistics.median(times) if times else '',
            p95_total_ms=float(np.percentile(times,95)) if times else '',
            median_wire_bytes=statistics.median(r['on_wire_bytes'] for r in successes) if successes else '',
            mean_qkd_bound_bits=statistics.mean(r['bound_bits'] for r in successes) if successes else ''))
    return summary


def render(summary):
    names=[r['scenario'].replace('_','\n') for r in summary]
    ind=np.arange(len(summary))
    widths=.7
    plt.figure(figsize=(12.5,5.8))
    for label in ('hybrid','pqc_only','aborts'):
        bottom=sum(np.array([s[k] for s in summary]) for k in ('hybrid','pqc_only','aborts')[:('hybrid','pqc_only','aborts').index(label)])
        plt.bar(ind, [s[label] for s in summary],bottom=bottom,width=widths,label=label.replace('_',' ').title())
    plt.xticks(ind,names,rotation=25,ha='right',fontsize=8)
    plt.ylabel('Simulated sessions');plt.title('Preliminary policy outcomes (fixed predeclared BB84 settings)')
    plt.legend();plt.tight_layout();plt.savefig(OUT/'mode_outcomes.png',dpi=175);plt.close()

    valid=[s for s in summary if s['median_total_ms'] != '']
    plt.figure(figsize=(11.5,5.5))
    xs=np.arange(len(valid))
    plt.bar(xs,[r['median_total_ms'] for r in valid])
    plt.xticks(xs,[r['scenario'].replace('_','\n') for r in valid],rotation=25,ha='right',fontsize=8)
    plt.ylabel('Local wall-clock handshake + record time (ms)')
    plt.title('Median successful-session latency (OpenSSL CLI and filesystem included)')
    plt.tight_layout();plt.savefig(OUT/'successful_latency.png',dpi=175);plt.close()

    plt.figure(figsize=(10,5))
    xs=np.arange(len(summary))
    plt.bar(xs,[r['success_rate_percent'] for r in summary])
    plt.xticks(xs,names,rotation=25,ha='right',fontsize=8)
    plt.ylabel('Authorized session success (%)');plt.ylim(0,105)
    plt.title('Session success is policy dependent: fallback ≠ successful QKD')
    plt.tight_layout();plt.savefig(OUT/'authorized_session_availability.png',dpi=175);plt.close()


def main():
    parser=argparse.ArgumentParser()
    parser.add_argument('--repetitions',type=int,default=8,
                        help='Preliminary trials per scenario (default 8; increase for full study)')
    args=parser.parse_args()
    if not 1 <= args.repetitions <= 10000:
        parser.error('repetitions must be from 1 to 10000')
    print('Program 4 integration study / research simulation only',flush=True)
    rows,version=record_rows(args.repetitions)
    save_csv(OUT/'session_trials.csv',rows)
    summary=summarize(rows)
    save_csv(OUT/'summary.csv',summary)
    render(summary)
    manifest=dict(protocol='research-bb84-pqc-aead-v1',studies=len(SCENARIOS),
        total_sessions=len(rows),repetitions_per_scenario=args.repetitions,
        base_seed=BASE_SEED, python=sys.version.split()[0],
        numpy=np.__version__,matplotlib=matplotlib.__version__,
        platform=platform.platform(),openssl=version,
        random_seed_note='QKD uses deterministic NumPy PRNG. NOT real quantum randomness.',
        security_note='No authenticated QKD message exchange or general combiner proof in prototype.',
        timing_note='Includes OpenSSL CLI startup, filesystem, and QKD simulation. No networking.')
    (OUT/'experiment_manifest.json').write_text(json.dumps(manifest,indent=2),encoding='utf-8')
    print('\nSummary:')
    for s in summary:
        t=f"{s['median_total_ms']:.1f} ms" if s['median_total_ms'] != '' else 'n/a'
        print(f" {s['scenario']:<25} hybrid={s['hybrid']}, PQC={s['pqc_only']},"
              f" abort={s['aborts']}, median={t}")
    print('Saved: results/session_trials.csv, summary.csv, experiment_manifest.json, 3 PNG charts')

if __name__=='__main__':
    main()
