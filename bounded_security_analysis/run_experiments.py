"""Program 8 bounded protocol model + actual OpenSSL-backed integration smoke trials.

Outputs are reproducible (except timing, nonce and signed-message randomness).
Run with --model-only to skip OpenSSL and the real-signature sessions.
"""
from __future__ import annotations
import argparse,csv,json,platform,statistics,datetime
from pathlib import Path
from dataclasses import asdict
from collections import Counter
from security_model import explore,negative_controls
OUT=Path(__file__).resolve().parent/'results'
OUT.mkdir(exist_ok=True)

def csv_file(name,rows):
    if not rows:return
    with (OUT/name).open('w',newline='',encoding='utf-8') as handle:
        writer=csv.DictWriter(handle,fieldnames=list(rows[0]))
        writer.writeheader();writer.writerows(rows)

def main(model_only=False,repetitions=1,max_attacks=1):
    base=explore(max_attacks=max_attacks)
    bad=negative_controls()
    assert not base['violations'], base['violations']
    assert all(x['violations'] for x in bad.values())
    (OUT/'bounded_state_report.json').write_text(json.dumps(base,indent=2))
    (OUT/'counterexample_traces.json').write_text(json.dumps(bad,indent=2))
    rows=[]
    for label,obj in [('intact_model',base),*bad.items()]:
        rows.append({'configuration':label,'states_explored':obj['states_explored'],
          'distinct_violations':len(obj['violations']),
          'accepted_traces':obj['completed_trace_counts'].get('ACCEPT',0),
          'rejected_traces':obj['completed_trace_counts'].get('REJECT',0),
          'stalled_traces':obj['completed_trace_counts'].get('STALLED',0)})
    csv_file('model_check_summary.csv',rows)
    print(f"MODEL: {base['scenarios']} input scenarios; {base['states_explored']} bounded states explored; "
          f"{len(base['violations'])} violations under intact guards.")
    for name,res in bad.items():
        print(f"NEGATIVE CONTROL {name}: {len(res['violations'])} property violations; "
              f"example={next(iter(res['violations']))}")

    traces=[];version='not run'
    if not model_only:
        from pqc_protocol import OpenSSLBackend,generate_identity
        from independent_protocol import run_session
        from hybrid_protocol import Policy
        from finite_key_bb84 import FiniteKeyConfig
        configs=[
          ('clean_required',50_000,0.0,0.0,Policy.HYBRID_REQUIRED,'HYBRID'),
          ('clean_preferred',50_000,0.0,0.0,Policy.HYBRID_PREFERRED,'HYBRID'),
          ('noise3_preferred',50_000,0.03,0.0,Policy.HYBRID_PREFERRED,'PQC_ONLY'),
          ('noise3_required',50_000,0.03,0.0,Policy.HYBRID_REQUIRED,'ABORT'),
          ('short_preferred',500,0.0,0.0,Policy.HYBRID_PREFERRED,'PQC_ONLY'),
          ('short_required',500,0.0,0.0,Policy.HYBRID_REQUIRED,'ABORT'),
          ('pqc_only',500,0.0,0.0,Policy.PQC_ONLY,'PQC_ONLY'),
        ]
        with OpenSSLBackend() as bk:
            alice=generate_identity(bk,'alice')
            bob=generate_identity(bk,'bob')
            version=bk.version
            for i,(name,signals,noise,eve,policy,expected) in enumerate(configs):
                for rep in range(repetitions):
                    n=max(1,round(signals*.18))
                    cfg=FiniteKeyConfig(transmitted_signals=signals,
                      target_key_bits=n,target_test_bits=n,
                      noise_probability=noise,intercept_probability=eve)
                    res=run_session(bk,alice,bob,cfg,20261024+i*10000+rep,policy)
                    if res.mode!=expected:
                        raise AssertionError(f'{name}: expected {expected}, got {res.mode}')
                    if res.mode!='ABORT' and not res.encrypted_record_ok:
                        raise AssertionError(f'{name}: AEAD record failed')
                    traces.append({'scenario':name,'rep':rep,'mode':res.mode,
                        'qkd_status':res.qkd_status,'signed_frames':res.messages,
                        'wire_bytes':res.public_bytes,'elapsed_ms':res.elapsed_ms,
                        'key_bound_bits':res.qkd_bound_bits,
                        'ec_queries':res.ec_queries,'record_ok':res.encrypted_record_ok})
                print(f'INTEGRATION {name}: {expected} ({repetitions}/{repetitions})')
        csv_file('integration_trials.csv',traces)
    elif (OUT/'integration_trials.csv').exists():
        (OUT/'integration_trials.csv').unlink()  # prevent stale evidence

    import matplotlib
    matplotlib.use('Agg')
    import matplotlib.pyplot as plt
    fig,ax=plt.subplots(figsize=(11,5))
    labels=[x['configuration'].replace('no_','without\n').replace('_',' ') for x in rows]
    values=[x['distinct_violations'] for x in rows]
    bars=ax.bar(labels,values)
    for bar,n in zip(bars,values):
        ax.annotate(str(n),(bar.get_x()+bar.get_width()/2,bar.get_height()),
                    ha='center',va='bottom',fontsize=10)
    ax.set_ylim(0,max(values)+1.3)
    ax.set_ylabel('Distinct violated safety properties (bounded model)')
    ax.set_title('Intact controller versus intentionally weakened negative controls')
    ax.tick_params(axis='x',labelrotation=25)
    fig.tight_layout();fig.savefig(OUT/'model_violations.png',dpi=170);plt.close(fig)
    fig,ax=plt.subplots(figsize=(9,5))
    ax.bar([x['configuration'] for x in rows],[x['states_explored'] for x in rows])
    ax.set_ylabel('Visited bounded model states')
    ax.set_title('Exploration scope is NOT an unbounded proof')
    ax.tick_params(axis='x',labelrotation=38)
    fig.tight_layout();fig.savefig(OUT/'model_states.png',dpi=170);plt.close(fig)
    if traces:
        groups={k:[t for t in traces if t['scenario']==k] for k in sorted(set(t['scenario'] for t in traces))}
        fig,ax=plt.subplots(figsize=(10,5))
        ax.bar(list(groups),[statistics.median(t['signed_frames'] for t in records) for records in groups.values()])
        ax.set_ylabel('Median signed frames')
        ax.set_title('OpenSSL-backed integration smoke tests (not a full performance study)')
        ax.tick_params(axis='x',labelrotation=30)
        fig.tight_layout();fig.savefig(OUT/'integrated_signed_frames.png',dpi=170);plt.close(fig)
    elif (OUT/'integrated_signed_frames.png').exists():
        (OUT/'integrated_signed_frames.png').unlink()
    manifest={'created_utc':datetime.datetime.now(datetime.timezone.utc).isoformat(),
       'program':'8','python':platform.python_version(),'platform':platform.platform(),
       'openssl':version,'max_attacks_per_trace':max_attacks,
       'model_action_alphabet':'enumerated, non-adaptive','repetitions':repetitions,
       'model_only':model_only,'source_ref':'Program 7 augmented with local mode checks',
       'warnings':['No Tamarin/ProVerif proof was executed',
         'The model is a bounded role/policy abstraction, not the full 7-stage source protocol',
         'No security proof of quantum finite-key theorem assumptions or hybrid HKDF combiner',
         'Some independence and EC information-leakage questions remain open']}
    (OUT/'experiment_manifest.json').write_text(json.dumps(manifest,indent=2))
    print(f"Completed {len(traces)} OpenSSL integration sessions; "
          'saved bounded-state report, counterexamples, CSVs, plots and manifest.')

if __name__=='__main__':
    ap=argparse.ArgumentParser()
    ap.add_argument('--model-only',action='store_true')
    ap.add_argument('--repetitions',type=int,default=1)
    ap.add_argument('--max-attacks',type=int,choices=[0,1,2],default=1)
    args=ap.parse_args()
    if not 1<=args.repetitions<=20:ap.error('repetitions must be 1..20')
    main(args.model_only,args.repetitions,args.max_attacks)
