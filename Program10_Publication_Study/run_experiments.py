"""Program 10: reproducible research simulation and separate OpenSSL spot checks.

Usage:
  python run_experiments.py
  python run_experiments.py --repetitions 500 --integration-repetitions 10
  python run_experiments.py --repetitions 1000 --no-integration

The research model has not been proved compositionally secure. This runner does
NOT call conditional model admissions 'certified physical QKD secrets'.
"""
from __future__ import annotations
import argparse
import csv
import datetime as dt
import json
import math
import os
import platform
from pathlib import Path
from collections import Counter
from statistics import median
import numpy as np
from publication_analysis import (
    SCENARIOS, STRATEGIES, POLICIES, MASTER_SEED, simulate,
    summarize_qkd, summarize_decisions, paired_strategy_contrasts, wilson,
)
from hybrid_protocol import Policy

ROOT=Path(__file__).resolve().parent
OUT=ROOT/'results'
OUT.mkdir(exist_ok=True)


def csvwrite(name, records):
    records=list(records)
    if not records:
        raise ValueError(f'empty results for {name}')
    with (OUT/name).open('w',newline='',encoding='utf-8') as f:
        w=csv.DictWriter(f,fieldnames=list(records[0].keys()),extrasaction='raise')
        w.writeheader(); w.writerows(records)


def integration_study(repetitions:int, master_seed:int)->tuple[list[dict],str]:
    if repetitions == 0:return [],'not run'
    from pqc_protocol import OpenSSLBackend, generate_identity
    from independent_protocol import run_session as run_adaptive
    from hardened_independent_protocol import run_session as run_fixed
    from finite_key_bb84 import FiniteKeyConfig
    from publication_analysis import trial_seed
    specs=(
        ('clean_preferred',50_000,0.,0.,Policy.HYBRID_PREFERRED),
        ('noise1_preferred',50_000,.01,0.,Policy.HYBRID_PREFERRED),
        ('noise3_preferred',50_000,.03,0.,Policy.HYBRID_PREFERRED),
        ('eve20_preferred',50_000,0.,.20,Policy.HYBRID_PREFERRED),
        ('short_required',500,0.,0.,Policy.HYBRID_REQUIRED),
    )
    rows=[]
    with OpenSSLBackend() as bk:
        alice=generate_identity(bk,'alice')
        bob=generate_identity(bk,'bob')
        for name,signals,noise,eve,policy in specs:
            for trial in range(repetitions):
                seed=trial_seed(master_seed,'integration_'+name,trial)
                cfg=FiniteKeyConfig(transmitted_signals=signals,
                     target_key_bits=max(1,round(signals*.18)),
                     target_test_bits=max(1,round(signals*.18)),
                     noise_probability=noise,intercept_probability=eve,
                     reconciliation_passes=2,ec_leakage_cap_fraction=.4)
                for variant,func in (('adaptive_p8',run_adaptive),('fixed_p9',run_fixed)):
                    result=func(bk,alice,bob,cfg,seed,policy)
                    if result.mode not in ('ABORT','HYBRID','PQC_ONLY'):
                        raise AssertionError('Unexpected handshake mode')
                    if result.mode == 'HYBRID' and not result.agreement:
                        raise AssertionError('Alice and Bob disagree after HYBRID')
                    if result.mode != 'ABORT' and not result.encrypted_record_ok:
                        raise AssertionError('Authenticated application record failed')
                    if result.mode != 'ABORT' and policy is Policy.HYBRID_REQUIRED and result.mode != 'HYBRID':
                        raise AssertionError('QKD-required policy was downgraded')
                    rows.append({'scenario':name,'trial':trial,'seed':seed,'variant':variant,
                       'policy':policy.value,'mode':result.mode,
                       'qkd_status':result.qkd_status,'x_qber':result.x_qber,
                       'candidate_qkd_bound_bits':result.qkd_bound_bits,
                       'public_ec_bits':result.public_ec_bits,
                       'parity_queries':result.ec_queries,'ec_rounds':result.ec_rounds,
                       'ec_bit_flips':result.ec_flips,
                       'signed_frames':result.messages,'on_wire_bytes':result.public_bytes,
                       'elapsed_ms':round(result.elapsed_ms,4),
                       'record_ok':bool(result.encrypted_record_ok),
                       'key_agreement':bool(result.agreement)})
            print(f'  OpenSSL integration {name}: {repetitions} PAIRED runs')
        return rows,bk.version


def integration_summary(rows:list[dict])->list[dict]:
    if not rows:return []
    output=[]
    for scenario in dict.fromkeys(r['scenario'] for r in rows):
        for variant in ('adaptive_p8','fixed_p9'):
            items=[r for r in rows if r['scenario']==scenario and r['variant']==variant]
            n=len(items)
            accepted=sum(r['mode']=='HYBRID' for r in items)
            lo,hi=wilson(accepted,n)
            output.append({'scenario':scenario,'variant':variant,'n_trials':n,
                'hybrid_count':accepted,'pqc_only_count':sum(r['mode']=='PQC_ONLY' for r in items),
                'abort_count':sum(r['mode']=='ABORT' for r in items),
                'hybrid_pct':round(100*accepted/n,3),
                'hybrid_wilson_95_low_pct':round(100*lo,3),
                'hybrid_wilson_95_high_pct':round(100*hi,3),
                'median_signed_frames':median(r['signed_frames'] for r in items),
                'median_on_wire_bytes':median(r['on_wire_bytes'] for r in items),
                'median_elapsed_ms':round(median(r['elapsed_ms'] for r in items),3),
                'dominant_qkd_status':Counter(r['qkd_status'] for r in items).most_common(1)[0][0]})
    return output


def make_plots(qsum,dsum,icompare):
    import matplotlib
    matplotlib.use('Agg')
    import matplotlib.pyplot as plt
    scenarios=[r['scenario'] for r in qsum]
    x=list(range(len(scenarios)))
    fig,ax=plt.subplots(figsize=(13,5))
    means=[r['mean_observed_qber_pct'] if r['mean_observed_qber_pct']!='' else np.nan for r in qsum]
    theory=[r['expected_qber_pct'] for r in qsum]
    ax.plot(x,theory,marker='o',label='Theoretical (ideal model)')
    ax.plot(x,means,marker='s',linestyle='--',label='Measured mean (where sample exists)')
    ax.set_xticks(x,[s.replace('_','\n') for s in scenarios]);ax.set_ylabel('X-basis QBER (%)')
    ax.set_title('Channel calibration by predeclared condition');ax.legend();fig.tight_layout()
    fig.savefig(OUT/'01_qber_calibration.png',dpi=160);plt.close(fig)

    fig,ax=plt.subplots(figsize=(13,5))
    mids=[r['model_admission_pct'] for r in qsum]
    lower=[mid-r['admission_ci_low_pct'] for mid,r in zip(mids,qsum)]
    upper=[r['admission_ci_high_pct']-mid for mid,r in zip(mids,qsum)]
    ax.errorbar(x,mids,yerr=[lower,upper],fmt='o',capsize=3)
    ax.set_xticks(x,[s.replace('_','\n') for s in scenarios]);ax.set_ylim(-5,105)
    ax.set_ylabel('Model-admitted QKD sessions (%)')
    ax.set_title('Finite-key model admission with Wilson 95% simulation confidence intervals')
    fig.tight_layout();fig.savefig(OUT/'02_model_admission_ci.png',dpi=160);plt.close(fig)

    rows=[r for r in dsum if r['policy']=='HYBRID_PREFERRED' and
          r['strategy'] in ('QBER_11_PERCENT','FINITE_KEY_POLICY')]
    fig,ax=plt.subplots(figsize=(13,5))
    a=[next(r for r in rows if r['scenario']==case and r['strategy']=='QBER_11_PERCENT')['invalid_hybrid_pct'] for case in scenarios]
    b=[next(r for r in rows if r['scenario']==case and r['strategy']=='FINITE_KEY_POLICY')['invalid_hybrid_pct'] for case in scenarios]
    ax.bar([v-.2 for v in x],a,width=.4,label='Fixed 11% QBER-only')
    ax.bar([v+.2 for v in x],b,width=.4,label='Finite-key admission')
    ax.set_xticks(x,[s.replace('_','\n') for s in scenarios]);ax.set_ylim(0,105)
    ax.set_ylabel('HYBRID decisions without model admission (%)')
    ax.set_title('In-model invalid admission, not evidence of leaked real keys')
    ax.legend();fig.tight_layout();fig.savefig(OUT/'03_uncertified_qkd_decisions.png',dpi=160);plt.close(fig)

    fig,ax=plt.subplots(figsize=(13,5))
    rows=[next(r for r in dsum if r['scenario']==s and r['policy']=='HYBRID_PREFERRED' and r['strategy']=='FINITE_KEY_POLICY') for s in scenarios]
    h=[100*r['hybrid_count']/r['n_trials'] for r in rows]
    p=[100*r['pqc_only_count']/r['n_trials'] for r in rows]
    ab=[100*r['abort_count']/r['n_trials'] for r in rows]
    ax.bar(x,h,label='HYBRID')
    ax.bar(x,p,bottom=h,label='PQC_ONLY')
    ax.bar(x,ab,bottom=[u+v for u,v in zip(h,p)],label='ABORT')
    ax.set_xticks(x,[s.replace('_','\n') for s in scenarios]);ax.set_ylabel('Mode outcomes (%)')
    ax.set_title('Configured HYBRID_PREFERRED controller (not a cryptographic proof)')
    ax.legend();fig.tight_layout();fig.savefig(OUT/'04_preferred_mode_mix.png',dpi=160);plt.close(fig)

    if icompare:
        cases=list(dict.fromkeys(r['scenario'] for r in icompare))
        fig,ax=plt.subplots(figsize=(11,5))
        for shift,variant in [(-.19,'adaptive_p8'),(.19,'fixed_p9')]:
            vals=[next(r for r in icompare if r['scenario']==s and r['variant']==variant)['median_signed_frames'] for s in cases]
            ax.bar([j+shift for j in range(len(cases))],vals,width=.38,label=variant)
        ax.set_xticks(list(range(len(cases))),[s.replace('_','\n') for s in cases])
        ax.set_ylabel('Median signed frames')
        ax.set_title('OpenSSL-backed integration: messaging cost, small validation sample')
        ax.legend();fig.tight_layout();fig.savefig(OUT/'05_signed_frame_overhead.png',dpi=160);plt.close(fig)


def write_report(qsum,dsum,contrasts,iraws,isum,manifest):
    lines=['# Program 10 — Reproducible result summary','',
       '**Interpretation boundary:** This is an idealized/software BB84 simulation with deterministic random seeds and a candidate finite-key admission calculation. Numerical confidence intervals quantify random trial variation; they are *not* quantum security parameters. This does not discharge the open leakage, source-model, or hybrid combiner proof obligations.','',
       '## Model admission by scenario','',
       '| Scenario | N | Model-admitted | Wilson 95% CI | X-QBER observed | Theoretical |','|---|---:|---:|---:|---:|---:|']
    for r in qsum:
        measured=f"{r['mean_observed_qber_pct']:.2f}%" if r['mean_observed_qber_pct']!='' else 'Not estimable'
        lines.append(f"| {r['scenario']} | {r['n_trials']} | {r['model_admission_pct']:.1f}% | [{r['admission_ci_low_pct']:.1f}, {r['admission_ci_high_pct']:.1f}]% | {measured} | {r['expected_qber_pct']:.2f}% |")
    lines+=['','## Hybrid-preferred policy comparisons','',
       '| Scenario | Strategy | Hybrid | PQC-only | Abort | In-model invalid hybrid |','|---|---|---:|---:|---:|---:|']
    for s in [r['scenario'] for r in qsum]:
        for r in dsum:
            if r['scenario']!=s or r['policy']!='HYBRID_PREFERRED':continue
            lines.append(f"| {s} | {r['strategy']} | {r['hybrid_count']} | {r['pqc_only_count']} | {r['abort_count']} | {r['invalid_hybrid_count']} |")
    lines+=['','## Paired controller contrasts','',
       'The paired bootstrap columns in `paired_controller_contrasts.csv` compare model-compliant outcomes from *the same* QKD observation under two deterministic policies. Because finite-key admission is defined using the same model, a lower in-model invalid-admission rate is partly true by construction; it is not an external adversarial security demonstration.','']
    if isum:
        lines+=['## OpenSSL-backed integration spot checks','',
             '| Scenario | Variant | N | Hybrid | PQC-only | Abort | Median frames | Median bytes | Median time (ms) |','|---|---|---:|---:|---:|---:|---:|---:|---:|']
        for r in isum:
            lines.append(f"| {r['scenario']} | {r['variant']} | {r['n_trials']} | {r['hybrid_count']} | {r['pqc_only_count']} | {r['abort_count']} | {r['median_signed_frames']} | {r['median_on_wire_bytes']} | {r['median_elapsed_ms']:.1f} |")
    lines+=['','## Conditions for publication','',
       '1. Independently verify mapping of the numerical finite-key formula to the theorem, basis assumptions and full protocol transcript.','2. Establish and document reconciliation leakage accounting, beyond a two-parity-bit-per-query proxy.','3. Justify the hybrid key combiner with an applicable composition theorem or narrow security claims.','4. Perform authentic protocol analysis with a dedicated symbolic prover if asserting unbounded security properties.','5. Collect larger OpenSSL protocol runs on the same controlled hardware; do not pool laptop timings with another machine.','6. Compare with the closest recent hybrid QKD/PQC papers before claiming novelty.','',
       '## References','',
       '- Tomamichel et al. (2012): https://doi.org/10.1038/ncomms1631',
       '- NIST SP 800-227 (2025): https://csrc.nist.gov/pubs/sp/800/227/final',
       '- RFC 5869: https://www.rfc-editor.org/rfc/rfc5869','']
    (OUT/'RESULTS_REPORT.md').write_text('\n'.join(lines),encoding='utf-8')


def main(repetitions:int=100,integration_repetitions:int=1,master_seed:int=MASTER_SEED,bootstrap_draws:int=1000):
    raw=[];decisions=[]
    for case in SCENARIOS:
        for rep in range(repetitions):
            a,b=simulate(case,rep,master_seed)
            raw.append(a);decisions.extend(b)
        k=sum(r['qkd_model_admitted'] for r in raw if r['scenario']==case.name)
        print(f'  {case.name:<22} {repetitions} QKD trials; {k} model admitted')
    qsum=summarize_qkd(raw)
    dsum=summarize_decisions(decisions)
    contrasts=paired_strategy_contrasts(decisions,draws=bootstrap_draws)
    csvwrite('qkd_trial_data.csv',raw)
    csvwrite('decision_trial_data.csv',decisions)
    csvwrite('qkd_summary.csv',qsum)
    csvwrite('controller_summary.csv',dsum)
    csvwrite('paired_controller_contrasts.csv',contrasts)
    integr,version=integration_study(integration_repetitions,master_seed)
    isum=integration_summary(integr)
    if integr:
        csvwrite('integration_trial_data.csv',integr)
        csvwrite('integration_summary.csv',isum)
    else:
        for name in ('integration_trial_data.csv','integration_summary.csv','05_signed_frame_overhead.png'):
            (OUT/name).unlink(missing_ok=True)
    make_plots(qsum,dsum,isum)
    manifest={'program':'10','created_utc':dt.datetime.now(dt.timezone.utc).isoformat(),
              'python':platform.python_version(),'numpy':np.__version__,
              'platform':platform.platform(),'openssl':version,
              'master_seed':master_seed,'n_per_scenario':repetitions,
              'n_integration_pairs_per_scenario':integration_repetitions,
              'bootstrap_draws':bootstrap_draws,
              'design':'Predeclared 10 QKD conditions; 2 enforced policies; 4 paired strategy decisions',
              'scenario_specs':[vars(x) for x in SCENARIOS],
              'model_limitations':['Deterministic simulation only, not physically secure QKD',
                      'Finite-key candidate admission depends on unproved implementation assumptions and leakage budget',
                      'No proof of strongest-link security for QKD/ML-KEM/HKDF combiner',
                      'OpenSSL timings include Python/process/file overhead; compare only within same host',
                      'Neither unbounded ProVerif nor Tamarin proof executed',
                      'The simple fixed Hamming syndrome may reject noisy sessions',
                      'Monte Carlo 95% CI is not eps_secrecy; no unreported hypothesis testing']}
    (OUT/'experiment_manifest.json').write_text(json.dumps(manifest,indent=2),encoding='utf-8')
    write_report(qsum,dsum,contrasts,integr,isum,manifest)
    print(f'Program 10 completed: {len(raw)} independent simulated QKD trials; {len(decisions)} paired controller decisions; {len(integr)} OpenSSL-backed integration sessions')
    print('Saved results/*.csv, PNG figures, RESULTS_REPORT.md and experiment_manifest.json')

if __name__=='__main__':
    ap=argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--repetitions',type=int,default=100,help='Independent QKD runs per condition (default 100)')
    ap.add_argument('--integration-repetitions',type=int,default=1,help='OpenSSL-backed paired runs per scenario (default 1)')
    ap.add_argument('--no-integration',action='store_true',help='Skip slow OpenSSL-backed sessions')
    ap.add_argument('--master-seed',type=int,default=MASTER_SEED)
    ap.add_argument('--bootstrap-draws',type=int,default=1000)
    x=ap.parse_args()
    if x.repetitions < 1 or x.repetitions > 10000 or x.integration_repetitions < 0 or x.integration_repetitions > 200 or x.master_seed < 0 or x.bootstrap_draws < 50:
        ap.error('invalid repetitions/seed/draws')
    main(x.repetitions,0 if x.no_integration else x.integration_repetitions,x.master_seed,x.bootstrap_draws)
