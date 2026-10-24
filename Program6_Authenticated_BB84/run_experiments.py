"""Program 6: generate reproducible authenticated BB84 research-only experiments.

All reported sessions use seeded idealized quantum simulation; ML-DSA/ML-KEM
are real OpenSSL 3.5 operations. This is NOT a production end-to-end protocol.
"""
import argparse
import csv
import json
import platform
import statistics
import sys
from collections import Counter,defaultdict
from dataclasses import asdict,dataclass
from datetime import datetime,timezone
from pathlib import Path
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
from authenticated_bb84 import run_session
from finite_key_bb84 import FiniteKeyConfig
from hybrid_protocol import Policy
from pqc_protocol import OpenSSLBackend,generate_identity,ProtocolAbort

ROOT=Path(__file__).resolve().parent
OUT=ROOT/'results'
OUT.mkdir(exist_ok=True)
BASE_SEED=20261024

@dataclass(frozen=True)
class Scenario:
    name:str
    n:int
    noise:float=0.0
    eve:float=0.0
    policy:Policy=Policy.HYBRID_PREFERRED

SCENARIOS=[
    Scenario('clean_preferred',50000),
    Scenario('noise1_preferred',50000,.01),
    Scenario('noise3_preferred',50000,.03),
    Scenario('eve20_preferred',50000,0.0,.20),
    Scenario('short_preferred',500),
    Scenario('clean_required',50000,0,0,Policy.HYBRID_REQUIRED),
    Scenario('noise3_required',50000,.03,0,Policy.HYBRID_REQUIRED),
    Scenario('short_required',500,0,0,Policy.HYBRID_REQUIRED),
    Scenario('pqc_only',50000,0,0,Policy.PQC_ONLY),
]

def cfg_for(s:Scenario):
    target=max(1,round(.18*s.n))
    return FiniteKeyConfig(transmitted_signals=s.n,target_key_bits=target,
      target_test_bits=target,q_tolerance=.04,
      intercept_probability=s.eve,noise_probability=s.noise)


def write_rows(name,rows):
    if not rows: raise ValueError('No results to write')
    with (OUT/name).open('w',newline='',encoding='utf-8') as f:
        writer=csv.DictWriter(f,fieldnames=list(rows[0]));writer.writeheader();writer.writerows(rows)


def experiment(reps,attacks):
    trials=[];negative=[]
    with OpenSSLBackend() as backend:
        alice=generate_identity(backend,'Alice')
        bob=generate_identity(backend,'Bob')
        for i,s in enumerate(SCENARIOS):
            for rep in range(reps):
                seed=BASE_SEED+i*10_000+rep
                result=run_session(backend,alice,bob,cfg_for(s),seed,s.policy)
                trials.append({'scenario':s.name,'trial':rep,'seed':seed,'signals':s.n,
                   'noise_probability':s.noise,'eve_probability':s.eve,
                   'policy':s.policy.value,'mode':result.mode,'qkd_status':result.qkd_status,
                   'qkd_bound_bits':result.qkd_bound_bits,
                   'x_qber':result.qkd_test_qber if result.qkd_test_qber is not None else '',
                   'signed_frames':result.classical_frames,
                   'signed_classical_bytes':result.classical_bytes,
                   'handshake_ms':round(result.handshake_ms,3),
                   'total_ms':round(result.total_ms,3),
                   'key_confirmation_ok':result.key_confirmation_ok,
                   'application_record_ok':result.recovered_ok,
                   'qkd_transcript_hash':result.qkd_transcript_hash})
            counts=Counter(x['mode'] for x in trials if x['scenario']==s.name)
            print(f'{s.name:<21} {dict(counts)}')
        attack_stages=['policy_offer','bob_detected','bob_basis','alice_basis',
            'sampling_seed','alice_test_bits','bob_test_bits','ec_seed','ec_batch',
            'verification_seed','alice_verification_tag','bob_verification_tag',
            'privacy_amplification_seed','qkd_report_alice','mode_decision','mode_ack']
        cfg=cfg_for(SCENARIOS[0])
        for i,stage in enumerate(attack_stages):
            for j in range(attacks):
                encountered=[False]
                def tamper(kind,envelope):
                    if kind==stage:
                        encountered[0]=True
                        envelope['body']['payload']['malicious_extra_field']='ATTACK'
                    return envelope
                was_rejected=False
                try:
                    run_session(backend,alice,bob,cfg,BASE_SEED+900_000+i*100+j,
                                Policy.HYBRID_PREFERRED,mutator=tamper)
                except ProtocolAbort:
                    was_rejected=True
                negative.append({'attack_stage':stage,'trial':j,
                    'attack_exercised':encountered[0],
                    'session_rejected':was_rejected})
                if not (encountered[0] and was_rejected):
                    raise RuntimeError(f'Attack did not cause expected rejection: {stage}')
            print(f'attack {stage:<28} blocked {attacks}/{attacks}')
        openssl_version=backend.version
    write_rows('session_trials.csv',trials)
    write_rows('attack_trials.csv',negative)
    summary=[]
    for s in SCENARIOS:
        obs=[x for x in trials if x['scenario']==s.name]
        modes=Counter(x['mode'] for x in obs)
        summary.append({'scenario':s.name,'trials':len(obs),
                        'hybrid':modes['HYBRID'],'pqc_only':modes['PQC_ONLY'],
                        'abort':modes['ABORT'],
                        'median_signed_frames':statistics.median(x['signed_frames'] for x in obs),
                        'median_signed_classical_bytes':statistics.median(x['signed_classical_bytes'] for x in obs),
                        'median_handshake_ms':round(statistics.median(x['handshake_ms'] for x in obs),3),
                        'recovered_records':sum(bool(x['application_record_ok']) for x in obs)})
    write_rows('summary.csv',summary)
    attack_summary=[]
    for stage in attack_stages:
        subset=[x for x in negative if x['attack_stage']==stage]
        attack_summary.append({'attack_stage':stage,'attempts':len(subset),
             'exercised':sum(x['attack_exercised'] for x in subset),
             'rejected':sum(x['session_rejected'] for x in subset)})
    write_rows('attack_summary.csv',attack_summary)

    names=[x['scenario'] for x in summary]
    fig,ax=plt.subplots(figsize=(11,5))
    bottom=[0]*len(summary)
    for mode,col in [('HYBRID','hybrid'),('PQC_ONLY','pqc_only'),('ABORT','abort')]:
        vals=[x[col] for x in summary]
        ax.bar(names,vals,bottom=bottom,label=mode)
        bottom=[a+b for a,b in zip(bottom,vals)]
    ax.set_ylabel('Number of sessions');ax.set_title('Program 6: outcomes under authenticated policies')
    ax.tick_params(axis='x',labelrotation=45)
    ax.legend();fig.tight_layout();fig.savefig(OUT/'mode_outcomes.png',dpi=180);plt.close(fig)

    fig,ax=plt.subplots(figsize=(11,5))
    ax.bar(names,[x['median_signed_classical_bytes']/1024 for x in summary])
    ax.set_ylabel('Authenticated BB84 classical transcript (KiB)')
    ax.set_title('Program 6: transmitted authenticated classical-message size')
    ax.tick_params(axis='x',labelrotation=45)
    fig.tight_layout();fig.savefig(OUT/'signed_transcript_bytes.png',dpi=180);plt.close(fig)

    fig,ax=plt.subplots(figsize=(11,5))
    ax.bar([x['attack_stage'] for x in attack_summary],[x['rejected'] for x in attack_summary])
    ax.set_ylabel('Rejected tampering attempts')
    ax.set_title('Program 6: rejection of invalid signed frames (specific test cases)')
    ax.tick_params(axis='x',labelrotation=70)
    fig.tight_layout();fig.savefig(OUT/'attack_rejections.png',dpi=180);plt.close(fig)

    manifest={'program':'Program6_Authenticated_BB84',
      'utc_created':datetime.now(timezone.utc).isoformat(),
      'python':sys.version.split()[0],'platform':platform.platform(),
      'openssl':openssl_version,'seed_base':BASE_SEED,
      'repetitions_per_scenario':reps,'tamper_repetitions_per_stage':attacks,
      'scenarios':[asdict(s)|{'policy':s.policy.value} for s in SCENARIOS],
      'limitations':['ideal simulated quantum channel','NumPy seeded simulated bits',
       'locally executed ML-DSA via subprocess','EC parity batches authenticated only after simulation',
       'no live independent Alice and Bob network endpoints',
       'not a complete cryptographic proof or physically validated QKD link']}
    (OUT/'experiment_manifest.json').write_text(json.dumps(manifest,indent=2),encoding='utf-8')
    print(f'Completed {len(trials)} sessions; {len(negative)} tampering trials; OpenSSL={openssl_version}')
    print('Saved: results/session_trials.csv, summary.csv, attack_trials.csv, attack_summary.csv,')
    print('       3 PNG charts, experiment_manifest.json')
    return summary,attack_summary

if __name__=='__main__':
    parser=argparse.ArgumentParser()
    parser.add_argument('--repetitions',type=int,default=5)
    parser.add_argument('--attack-repetitions',type=int,default=3)
    args=parser.parse_args()
    if not 1<=args.repetitions<=10_000 or not 1<=args.attack_repetitions<=10_000:
        parser.error('Repetitions must be positive and <=10,000')
    experiment(args.repetitions,args.attack_repetitions)
