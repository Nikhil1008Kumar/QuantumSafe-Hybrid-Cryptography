"""Program 7: reproducible paired endpoint/batched-message comparisons and attack trials."""
import argparse
import csv
import json
import platform
import statistics
from collections import Counter,defaultdict
from dataclasses import asdict,dataclass
from datetime import datetime,timezone
from pathlib import Path
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
from finite_key_bb84 import FiniteKeyConfig
from hybrid_protocol import Policy
from pqc_protocol import OpenSSLBackend,generate_identity,ProtocolAbort
from independent_protocol import run_session
from authenticated_bb84 import run_session as run_program6

OUT=Path(__file__).resolve().parent/'results'
OUT.mkdir(exist_ok=True)
BASE_SEED=20261024

@dataclass(frozen=True)
class Scenario:
    name:str
    signals:int
    noise:float=0
    eve:float=0
    policy:Policy=Policy.HYBRID_PREFERRED

SCENARIOS=[
    Scenario('clean_preferred',50_000),
    Scenario('noise1_preferred',50_000,0.01),
    Scenario('noise3_preferred',50_000,0.03),
    Scenario('eve20_preferred',50_000,0,0.20),
    Scenario('short_preferred',500),
    Scenario('clean_required',50_000,0,0,Policy.HYBRID_REQUIRED),
    Scenario('noise3_required',50_000,0.03,0,Policy.HYBRID_REQUIRED),
    Scenario('short_required',500,0,0,Policy.HYBRID_REQUIRED),
    Scenario('pqc_only',50_000,0,0,Policy.PQC_ONLY),
]

def config(s):
    target=max(1,round(s.signals*.18))
    return FiniteKeyConfig(transmitted_signals=s.signals,target_key_bits=target,
               target_test_bits=target,noise_probability=s.noise,
               intercept_probability=s.eve)

def save_csv(fname,rows):
    with (OUT/fname).open('w',newline='',encoding='utf-8') as f:
        w=csv.DictWriter(f,fieldnames=list(rows[0]))
        w.writeheader();w.writerows(rows)

def do_experiment(repetitions:int,attacks:int):
    trials=[]; negatives=[]
    with OpenSSLBackend() as bk:
        a=generate_identity(bk,'alice')
        b=generate_identity(bk,'bob')
        for i,s in enumerate(SCENARIOS):
            for r in range(repetitions):
                seed=BASE_SEED+1000*i+r
                ours=run_session(bk,a,b,config(s),seed,s.policy)
                # The previous prototype is evaluated on the same model and seed,
                # but EC protocol differs; a controlled comparison, NOT an apples-
                # to-apples optimization proof.
                old=run_program6(bk,a,b,config(s),seed,s.policy)
                trials.append({'scenario':s.name,'trial':r,'seed':seed,
                    'signals':s.signals,'noise':s.noise,'eve':s.eve,
                    'policy':s.policy.value,'mode':ours.mode,'qkd_status':ours.qkd_status,
                    'key_bound_bits':ours.qkd_bound_bits,
                    'x_qber':ours.x_qber if ours.x_qber is not None else '',
                    'interactive_queries':ours.ec_queries,'interactive_rounds':ours.ec_rounds,
                    'corrected_bits':ours.ec_flips,'ec_disclosed_budget_bits':ours.public_ec_bits,
                    'signed_frames':ours.messages,'public_wire_bytes':ours.public_bytes,
                    'runtime_ms':ours.elapsed_ms,'record_ok':ours.encrypted_record_ok,
                    'shared_key_match':ours.agreement,
                    'old_mode':old.mode,'old_signed_frames':old.classical_frames,
                    'old_public_wire_bytes':old.classical_bytes,
                    'old_handshake_ms':round(old.handshake_ms,3),
                    'old_qkd_status':old.qkd_status})
            counts=Counter(x['mode'] for x in trials if x['scenario']==s.name)
            print(f'{s.name:<20} {dict(counts)}')

        attack_kinds=['policy_a','policy_b','detect_b','basis_b','basis_a',
                      'sample_a','test_a','test_b','ec_seed_a','parity_query',
                      'parity_answer','verification_seed_a','verification_tag_a',
                      'verification_tag_b','pa_seed_a','report_a','report_b',
                      'mode_a','mode_b']
        clean_cfg=config(SCENARIOS[0]); count=0
        for i,attack in enumerate(attack_kinds):
            for rep in range(attacks):
                hit=[0]
                def mutator(kind,env):
                    if kind==attack and not hit[0]:
                        hit[0]+=1
                        env['body']['payload']['injected_field']='untrusted modification'
                    return env
                rejected=False
                try:
                    run_session(bk,a,b,clean_cfg,BASE_SEED+700_000+i*100+rep,
                                Policy.HYBRID_PREFERRED,mutator=mutator)
                except ProtocolAbort:
                    rejected=True
                negatives.append({'attack':attack,'rep':rep,'reached':bool(hit[0]),
                                  'rejected':rejected})
                if not (hit[0] and rejected):
                    raise RuntimeError(f'Attack missing or not rejected: {attack}')
            count+=attacks
            print(f'attack {attack:<27} blocked {attacks}/{attacks}')
        openssl=bk.version
    save_csv('session_trials.csv',trials)
    save_csv('attack_trials.csv',negatives)
    summary=[]
    for s in SCENARIOS:
        matches=[t for t in trials if t['scenario']==s.name]
        summary.append({'scenario':s.name,'sessions':len(matches),
                        'hybrid':sum(x['mode']=='HYBRID' for x in matches),
                        'pqc_only':sum(x['mode']=='PQC_ONLY' for x in matches),
                        'abort':sum(x['mode']=='ABORT' for x in matches),
                        'median_interactive_ms':round(statistics.median(x['runtime_ms'] for x in matches),2),
                        'median_old_ms':round(statistics.median(x['old_handshake_ms'] for x in matches),2),
                        'median_ec_queries':statistics.median(x['interactive_queries'] for x in matches),
                        'median_ec_rounds':statistics.median(x['interactive_rounds'] for x in matches),
                        'median_frames':statistics.median(x['signed_frames'] for x in matches),
                        'median_old_frames':statistics.median(x['old_signed_frames'] for x in matches),
                        'median_public_bytes':statistics.median(x['public_wire_bytes'] for x in matches),
                        'median_old_public_bytes':statistics.median(x['old_public_wire_bytes'] for x in matches)})
    save_csv('summary.csv',summary)
    xs=list(range(len(summary)))
    labels=[s['scenario'].replace('_','\n') for s in summary]
    fig,ax=plt.subplots(figsize=(12,5))
    ax.bar([v-.2 for v in xs],[s['median_frames'] for s in summary],width=.4,label='Program 7: interactive')
    ax.bar([v+.2 for v in xs],[s['median_old_frames'] for s in summary],width=.4,label='Program 6: batched')
    ax.set_xticks(xs,labels,fontsize=8);ax.set_ylabel('Median signed classical frames')
    ax.set_title('Authenticated transcript frame overhead (different EC protocols)')
    ax.legend();fig.tight_layout();fig.savefig(OUT/'signed_frame_overhead.png',dpi=180);plt.close(fig)
    fig,ax=plt.subplots(figsize=(12,5))
    ax.bar([v-.2 for v in xs],[s['median_interactive_ms'] for s in summary],width=.4,label='Program 7: interactive')
    ax.bar([v+.2 for v in xs],[s['median_old_ms'] for s in summary],width=.4,label='Program 6: batched')
    ax.set_xticks(xs,labels,fontsize=8);ax.set_ylabel('Median simulated handshake duration (ms)')
    ax.set_title('Elapsed time includes OpenSSL startup and filesystem I/O')
    ax.legend();fig.tight_layout();fig.savefig(OUT/'endpoint_latency_comparison.png',dpi=180);plt.close(fig)
    fig,ax=plt.subplots(figsize=(11,4))
    ax.bar([s['scenario'] for s in summary],[s['median_ec_queries'] for s in summary])
    ax.tick_params(axis='x',labelrotation=35);ax.set_ylabel('Median interactive parity queries')
    ax.set_title('Public parity-query workload');fig.tight_layout();fig.savefig(OUT/'interactive_parity_queries.png',dpi=180);plt.close(fig)
    fig,ax=plt.subplots(figsize=(10,4))
    ax.bar([z['attack'] for z in negatives[::attacks]],[100 for _ in negatives[::attacks]])
    ax.tick_params(axis='x',labelrotation=65);ax.set_ylim(0,105)
    ax.set_ylabel('Rejection (%)');ax.set_title('Tested unauthenticated modifications: observed rejection')
    fig.tight_layout();fig.savefig(OUT/'attack_rejections.png',dpi=180);plt.close(fig)
    manifest={'created_at_utc':datetime.now(timezone.utc).isoformat(),
              'program':'7','openssl':openssl,'python':platform.python_version(),
              'platform':platform.platform(),'seed':BASE_SEED,'repetitions':repetitions,
              'attack_repetitions':attacks,'scenarios':[asdict(s)|{'policy':s.policy.value} for s in SCENARIOS],
              'notes':'Pure software QKD. Deterministic NumPy randomness not a CSPRNG; no hardware or formal composable proof.'}
    (OUT/'experiment_manifest.json').write_text(json.dumps(manifest,indent=2))
    print(f'Completed {len(trials)} paired sessions, {len(negatives)} tampering trials. OpenSSL={openssl}')
    print('Saved: results/session_trials.csv, summary.csv, attack_trials.csv, 4 PNG charts, experiment_manifest.json')
    for s in summary:
        print(f"  {s['scenario']:<20} H={s['hybrid']}, PQC={s['pqc_only']}, abort={s['abort']}; "
              f"interactive_queries={s['median_ec_queries']:.0f}, signed_frames={s['median_frames']:.0f}")

if __name__=='__main__':
    parser=argparse.ArgumentParser()
    parser.add_argument('--repetitions',type=int,default=2)
    parser.add_argument('--attack-repetitions',type=int,default=1)
    args=parser.parse_args()
    if not 1<=args.repetitions<=500 or not 1<=args.attack_repetitions<=100:
        parser.error('Requested repetition count out of range')
    do_experiment(args.repetitions,args.attack_repetitions)
