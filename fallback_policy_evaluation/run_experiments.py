"""Program 5: reproducible paired decision-policy comparison.

Default runs simulator-only paired policies plus four actual Program 4
cryptographic integration smoke trials (OpenSSL 3.5+ required). Does not claim
hybrid-combiner security, independent networked QKD or novel security proof.
"""
from __future__ import annotations
import argparse
import csv
import json
import math
import platform
import statistics
import sys
from collections import Counter, defaultdict
from dataclasses import dataclass
from pathlib import Path

import numpy as np
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt

from finite_key_bb84 import FiniteKeyConfig, run
from hybrid_protocol import Policy, run_hybrid, HybridAbort
from pqc_protocol import OpenSSLBackend, generate_identity, ProtocolAbort
from policy_comparison import Mode, Strategy, QKDObservation, decide

OUT=Path(__file__).resolve().parent/'results'
OUT.mkdir(exist_ok=True)
BASE_SEED=20261024

@dataclass(frozen=True)
class Scenario:
    name: str
    signals: int
    noise: float = 0.
    eve: float = 0.
    loss: float = 0.

SCENARIOS = [
    Scenario('short_500_clean',500),
    Scenario('short_10000_clean',10000),
    Scenario('clean_50000',50000),
    Scenario('noise_1pct',50000,.01),
    Scenario('noise_3pct',50000,.03),
    Scenario('eve_10pct',50000,0,.10),
    Scenario('eve_20pct',50000,0,.20),
    Scenario('eve_40pct',50000,0,.40),
    Scenario('loss_30pct',50000,0,0,.30),
]


def config(s: Scenario)->FiniteKeyConfig:
    target=max(1,round(.18*s.signals))
    return FiniteKeyConfig(transmitted_signals=s.signals,
        target_key_bits=target,target_test_bits=target,
        intercept_probability=s.eve,noise_probability=s.noise,
        loss_probability=s.loss,q_tolerance=.04)


def wilson(successes:int, samples:int, z:float=1.95996398454)->tuple[float,float]:
    if samples<=0: return (float('nan'),float('nan'))
    p=successes/samples
    den=1+z*z/samples
    center=(p+z*z/(2*samples))/den
    half=z*math.sqrt(p*(1-p)/samples+z*z/(4*samples*samples))/den
    return max(0,center-half),min(1,center+half)


def save_csv(file: Path, rows: list[dict]):
    if not rows: raise ValueError('Refusing empty CSV')
    with file.open('w',encoding='utf-8',newline='') as f:
        writer=csv.DictWriter(f,fieldnames=list(rows[0]))
        writer.writeheader()
        writer.writerows(rows)


def run_paired(repetitions:int):
    observations=[]
    decisions=[]
    strategies=list(Strategy)
    policies=[Policy.HYBRID_PREFERRED,Policy.HYBRID_REQUIRED]
    for i,s in enumerate(SCENARIOS):
        cfg=config(s)
        for rep in range(repetitions):
            seed=BASE_SEED+10000*i+rep
            r=run(cfg,seed)
            q=QKDObservation.from_result(r)
            observations.append(dict(scenario=s.name,trial=rep,seed=seed,
                signals=s.signals,noise=s.noise,eve=s.eve,loss=s.loss,
                qkd_status=q.status,model_qualified_qkd=q.finite_key_admitted,
                qber_11pct_would_admit=q.qber11_admitted,
                x_qber=q.x_qber if q.x_qber is not None else '',
                x_test_bits=q.x_bits,finite_bound_bits=q.bound_bits,
                final_bits=q.output_bits,ec_bits=q.ec_leakage_bits,
                ec_cap_bits=q.ec_budget_bits,simulator_ms=r.runtime_ms))
            for policy in policies:
                for strategy in strategies:
                    d=decide(strategy,policy,q)
                    decisions.append(dict(scenario=s.name,trial=rep,seed=seed,
                        policy=policy.value,strategy=strategy.value,mode=d.mode.value,
                        invalid_qkd_label=d.model_invalid_hybrid,
                        qualified_qkd=d.qkd_qualified,decision_reason=d.reason))
        print(f' {s.name:<20} {repetitions} paired QKD observations',flush=True)
    return observations,decisions


def summarize(decisions:list[dict]):
    grouped=defaultdict(list)
    for row in decisions:
        grouped[(row['scenario'],row['policy'],row['strategy'])].append(row)
    data=[]
    for s in SCENARIOS:
        for pol in (Policy.HYBRID_PREFERRED,Policy.HYBRID_REQUIRED):
            for strategy in Strategy:
                group=grouped[(s.name,pol.value,strategy.value)]
                total=len(group)
                hybrid=sum(x['mode']=='HYBRID' for x in group)
                pqc=sum(x['mode']=='PQC_ONLY' for x in group)
                abort=sum(x['mode']=='ABORT' for x in group)
                invalid=sum(x['invalid_qkd_label'] for x in group)
                authorized=hybrid-invalid+pqc
                lo,hi=wilson(authorized,total)
                data.append(dict(scenario=s.name,policy=pol.value,
                    strategy=strategy.value,trials=total,
                    hybrid=hybrid,pqc_only=pqc,abort=abort,
                    invalid_qkd_label=invalid,
                    model_qualified_hybrid=hybrid-invalid,
                    modeled_authorized_success=authorized,
                    modeled_authorized_success_pct=100*authorized/total,
                    modeled_authorized_ci_lower_pct=100*lo,
                    modeled_authorized_ci_upper_pct=100*hi))
    return data


def consistency_checks(observations,decisions):
    # Verify pairs use identical seed/outcome and all proposed decisions obey
    # security policy. These are computer-checked *model properties*.
    assert len(decisions)==len(observations)*2*len(Strategy)
    obsbykey={(o['scenario'],o['trial']):o for o in observations}
    for d in decisions:
        o=obsbykey[(d['scenario'],d['trial'])]
        if d['strategy']==Strategy.PROPOSED.value:
            assert not d['invalid_qkd_label']
            if d['mode']=='HYBRID':
                assert o['model_qualified_qkd']
            if d['policy']==Policy.HYBRID_REQUIRED.value:
                assert d['mode']!='PQC_ONLY'
        if d['invalid_qkd_label']:
            assert d['mode']=='HYBRID' and not o['model_qualified_qkd']
    return True


def plot_summary(summary):
    names=[s.name for s in SCENARIOS]
    idx=np.arange(len(names))
    strategies=list(Strategy)
    width=.18
    for metric,file,title in [
       ('modeled_authorized_success_pct','authorized_availability.png',
        'Model-policy compliant session outcomes (not a security proof)'),
       ('invalid_qkd_label','invalid_qkd_admissions.png',
        'HYBRID choices that lack the model finite-key admission certificate')]:
        fig,ax=plt.subplots(figsize=(12.5,5.8))
        for j,strategy in enumerate(strategies):
            group=[next(r for r in summary if r['scenario']==name and
                r['policy']==Policy.HYBRID_PREFERRED.value and
                r['strategy']==strategy.value) for name in names]
            data=[r[metric] if metric!='invalid_qkd_label' else
                  100*r[metric]/r['trials'] for r in group]
            ax.bar(idx+(j-1.5)*width,data,width,label=strategy.value)
        ax.set_xticks(idx,names,rotation=30,ha='right',fontsize=8)
        ax.set_ylim(0,105)
        ax.set_ylabel('Percentage of sessions')
        ax.set_title(title+'\nHYBRID_PREFERRED, paired simulations')
        ax.legend(fontsize=8,loc='upper left',ncol=2)
        fig.tight_layout();fig.savefig(OUT/file,dpi=170);plt.close(fig)
    group=[r for r in summary if r['strategy']==Strategy.PROPOSED.value]
    fig,ax=plt.subplots(figsize=(11.5,5.8))
    for j,policy in enumerate((Policy.HYBRID_PREFERRED,Policy.HYBRID_REQUIRED)):
        vals=[next(r['modeled_authorized_success_pct'] for r in group
                if r['scenario']==n and r['policy']==policy.value) for n in names]
        ax.bar(idx+(j-.5)*.36,vals,.36,label=policy.value)
    ax.set_xticks(idx,names,rotation=30,ha='right',fontsize=8)
    ax.set_ylim(0,105);ax.set_ylabel('Modeled authorized success (%)')
    ax.set_title('The same finite-key controller under two application policies')
    ax.legend();fig.tight_layout()
    fig.savefig(OUT/'policy_required_vs_preferred.png',dpi=170);plt.close(fig)


def integration_spot_checks():
    """Execute real ML-DSA/ML-KEM crypto + GCM via unmodified Program 4.

    These demonstrate consistency of the deterministic policy adapter; don't
    conflate one trial per case with statistically powered research.
    """
    cases=[('clean_preferred',Policy.HYBRID_PREFERRED,Scenario('x',50000)),
           ('noise3_preferred',Policy.HYBRID_PREFERRED,Scenario('x',50000,.03)),
           ('noise3_required',Policy.HYBRID_REQUIRED,Scenario('x',50000,.03)),
           ('short_required',Policy.HYBRID_REQUIRED,Scenario('x',500)),
           ('pqc_only',Policy.PQC_ONLY,Scenario('x',500))]
    rows=[]
    with OpenSSLBackend() as backend:
        alice=generate_identity(backend,'Alice')
        bob=generate_identity(backend,'Bob')
        for ix,(name,policy,s) in enumerate(cases):
            seed=BASE_SEED+500000+ix
            expected=('PQC_ONLY' if policy is Policy.PQC_ONLY else
                  decide(Strategy.PROPOSED,policy,
                      QKDObservation.from_result(run(config(s),seed))).mode.value)
            try:
                result=run_hybrid(backend,alice,bob,config(s),seed,policy,
                      plaintext=b'Program5 authenticated AEAD test')
                actual=result.mode
                passed=bool(result.application_keys_match and result.recovered_plaintext==
                            b'Program5 authenticated AEAD test')
                ms=result.complete_runtime_ms
                wire=result.on_wire_bytes
            except HybridAbort as exc:
                actual='ABORT';passed=exc.stage=='qkd_admission'
                ms='';wire=''
            except ProtocolAbort:
                actual='ERROR';passed=False;ms='';wire=''
            equal=actual==expected and passed
            if not equal:
                raise AssertionError(f'Integration spot check {name}: expected={expected}, actual={actual}, tests={passed}')
            rows.append(dict(case=name,policy=policy.value,expected=expected,
                             actual=actual,passed=equal,total_wall_ms=ms,on_wire_bytes=wire))
            print(f'  integration {name}: {actual} OK',flush=True)
        openssl_ver=backend.version
    return rows,openssl_ver


def main():
    parser=argparse.ArgumentParser()
    parser.add_argument('--repetitions',type=int,default=20,
          help='Paired QKD simulations per scenario (default 20)')
    parser.add_argument('--skip-integration',action='store_true',
          help='Skip OpenSSL-backed Program 4 smoke checks (policy-only study)')
    args=parser.parse_args()
    if not 1<=args.repetitions<=10000: parser.error('repetitions out of range')
    print('PROGRAM 5 / PAIRED SECURITY-POLICY COMPARISON - RESEARCH SIMULATION',flush=True)
    observations,decisions=run_paired(args.repetitions)
    consistency_checks(observations,decisions)
    summary=summarize(decisions)
    save_csv(OUT/'qkd_observations.csv',observations)
    save_csv(OUT/'paired_policy_decisions.csv',decisions)
    save_csv(OUT/'policy_summary.csv',summary)
    plot_summary(summary)
    smoke=[];ossl='skipped'
    if not args.skip_integration:
        smoke,ossl=integration_spot_checks()
        save_csv(OUT/'integration_smoke.csv',smoke)
    manifest=dict(program='program5-policy-comparison-v1',
        model='Program2 finite-key QKD + Program4 signed PQC hybrid adapter',
        total_qkd_simulations=len(observations),total_paired_decisions=len(decisions),
        repetitions=args.repetitions,base_seed=BASE_SEED,
        scenario_count=len(SCENARIOS),OpenSSL=ossl,python=sys.version.split()[0],
        numpy=np.__version__,matplotlib=matplotlib.__version__,platform=platform.platform(),
        qkd_randomness='Reproducible seeded NumPy PRNG (not cryptographically secure).',
        caveats=['Baseline QBER choice is a hypothetical decision, not successful crypto.',
          'Finite-key status is a conditional model certificate, not an independent secrecy oracle.',
          'Signed QKD public messages are not individually exchanged in Program4.',
          'The Program4 key combiner has no independent composition proof.',
          'Outcomes are policy metrics, not physical-network performance.',
          'QKD and PQC-only are not equivalent security guarantees.'])
    (OUT/'experiment_manifest.json').write_text(json.dumps(manifest,indent=2),encoding='utf-8')
    print('\nSummary: HYBRID_PREFERRED; paired trials',flush=True)
    for s in SCENARIOS:
        subset=[r for r in summary if r['scenario']==s.name and
                r['policy']==Policy.HYBRID_PREFERRED.value]
        prop=next(r for r in subset if r['strategy']==Strategy.PROPOSED.value)
        qber=next(r for r in subset if r['strategy']==Strategy.QBER_ONLY.value)
        strict=next(r for r in subset if r['strategy']==Strategy.FINITE_NO_FALLBACK.value)
        print(f' {s.name:<20} proposed hybrid={prop["hybrid"]:2}, PQC={prop["pqc_only"]:2}; '
              f'QBER-only invalid-HYBRID={qber["invalid_qkd_label"]:2}; '
              f'finite-no-fallback abort={strict["abort"]:2}',flush=True)
    print(f'Completed {len(observations)} independent QKD simulations / {len(decisions)} paired decisions.')
    print(f'Integration spot checks: {len(smoke)} passed, OpenSSL={ossl}')
    print('Saved: results/*.csv, 3 PNG plots, experiment_manifest.json')

if __name__=='__main__': main()
