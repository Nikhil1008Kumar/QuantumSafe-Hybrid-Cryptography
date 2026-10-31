"""Program 9: paired legacy interactive vs fixed-disclosure reconciliation.

Runs REAL ML-KEM/ML-DSA OpenSSL-backed handshakes with simulated quantum data.
No claims of unbounded cryptographic security or independent physical sources.
"""
from __future__ import annotations
import argparse,csv,datetime,json,math,platform,statistics
from collections import Counter
from pathlib import Path
from finite_key_bb84 import FiniteKeyConfig,finite_key_bound
from fixed_syndrome import leakage_bits
from hybrid_protocol import Policy

OUT=Path(__file__).resolve().parent/'results'
OUT.mkdir(exist_ok=True)

def save_csv(filename, records):
    if not records:return
    with (OUT/filename).open('w',newline='',encoding='utf-8') as f:
        w=csv.DictWriter(f,fieldnames=list(records[0]))
        w.writeheader();w.writerows(records)

def main(repetitions:int=2,audit_only:bool=False):
    # A pair of static, paper-level accounting checks, not a QKD secrecy proof.
    audit=[]
    for n in (500,9000,18000):
        for passes in (1,2,3):
            v=math.ceil(math.log2(1/1e-10))
            ec_bits=leakage_bits(n,passes)
            auxiliary=v+64  # modeled second tag and conservative control margin
            bound,mu=finite_key_bound(n,n,.04,ec_bits+auxiliary,1e-10,1e-10)
            audit.append({'n_raw_bits':n,'n_test_bits':n,'passes':passes,
                'syndrome_disclosure_bits':ec_bits,'additional_budget_bits':auxiliary,
                'total_budget_in_bound_bits':ec_bits+auxiliary,'finite_mu':round(mu,8),
                'finite_bound_bits':bound,'source_assumptions_required':True})
    save_csv('fixed_leakage_audit.csv',audit)
    rows=[];openssl_version='not run'
    if not audit_only:
        from pqc_protocol import OpenSSLBackend,generate_identity
        from independent_protocol import run_session as run_adaptive
        from hardened_independent_protocol import run_session as run_fixed
        scenarios=[
           ('clean_preferred',50000,0,0,Policy.HYBRID_PREFERRED),
           ('noise1_preferred',50000,.01,0,Policy.HYBRID_PREFERRED),
           ('noise3_preferred',50000,.03,0,Policy.HYBRID_PREFERRED),
           ('eve20_preferred',50000,0,.20,Policy.HYBRID_PREFERRED),
           ('short_required',500,0,0,Policy.HYBRID_REQUIRED),
        ]
        with OpenSSLBackend() as bk:
            a=generate_identity(bk,'alice');b=generate_identity(bk,'bob')
            openssl_version=bk.version
            for j,(name,num,noise,eve,policy) in enumerate(scenarios):
                outcomes=[]
                for rep in range(repetitions):
                    n=max(1,round(num*.18))
                    cfg=FiniteKeyConfig(transmitted_signals=num,target_key_bits=n,
                            target_test_bits=n,noise_probability=noise,
                            intercept_probability=eve,reconciliation_passes=2,
                            ec_leakage_cap_fraction=.4)
                    seed=20261024+10000*j+rep
                    for label,fn in [('adaptive_p8',run_adaptive),('fixed_p9',run_fixed)]:
                        result=fn(bk,a,b,cfg,seed,policy)
                        if result.mode!='ABORT' and not result.encrypted_record_ok:
                            raise AssertionError(f'Authenticated application record failed: {name} {label}')
                        if result.mode=='HYBRID' and not result.agreement:
                            raise AssertionError(f'Hybrid final keys disagree: {name} {label}')
                        if label=='fixed_p9' and result.public_ec_bits and result.public_ec_bits!=leakage_bits(n,2):
                            raise AssertionError('Fixed reconciliation disclosure deviated from declared budget')
                        rows.append({'scenario':name,'repetition':rep,'seed':seed,
                           'variant':label,'mode':result.mode,'qkd_status':result.qkd_status,
                           'qkd_bound_bits':result.qkd_bound_bits,'x_qber':result.x_qber,
                           'ec_disclosed_bits':result.public_ec_bits,'parity_queries':result.ec_queries,
                           'ec_rounds':result.ec_rounds,'corrected_bits':result.ec_flips,
                           'signed_frames':result.messages,'on_wire_bytes':result.public_bytes,
                           'elapsed_ms':result.elapsed_ms,'record_ok':result.encrypted_record_ok})
                        outcomes.append(f'{label}:{result.mode}({result.qkd_status})')
                print(f'{name}: {repetitions} paired trials; '+', '.join(outcomes[:4]))
        save_csv('paired_reconciliation.csv',rows)
    elif (OUT/'paired_reconciliation.csv').exists():
        (OUT/'paired_reconciliation.csv').unlink()

    import matplotlib
    matplotlib.use('Agg')
    import matplotlib.pyplot as plt
    if rows:
        cases=list(dict.fromkeys(r['scenario'] for r in rows))
        series=('adaptive_p8','fixed_p9')
        fig,ax=plt.subplots(figsize=(11,5))
        positions=range(len(cases))
        for shift,variant in [(-.19,'adaptive_p8'),(.19,'fixed_p9')]:
            values=[100*sum(r['mode']=='HYBRID' for r in rows if r['scenario']==s and r['variant']==variant)/repetitions for s in cases]
            ax.bar([i+shift for i in positions],values,width=.38,label=variant)
        ax.set_xticks(list(positions),[x.replace('_','\n') for x in cases]);ax.set_ylim(0,105)
        ax.set_ylabel('Observed HYBRID admission (%)');ax.set_title(f'Program 9 pilot, {repetitions} paired trials/scenario; NOT a secrecy proof')
        ax.legend();fig.tight_layout();fig.savefig(OUT/'hybrid_admission_comparison.png',dpi=160);plt.close(fig)
        fig,ax=plt.subplots(figsize=(11,5))
        for shift,variant in [(-.19,'adaptive_p8'),(.19,'fixed_p9')]:
            values=[statistics.median(r['signed_frames'] for r in rows if r['scenario']==s and r['variant']==variant) for s in cases]
            ax.bar([i+shift for i in positions],values,width=.38,label=variant)
        ax.set_xticks(list(positions),[x.replace('_','\n') for x in cases]);ax.set_ylabel('Median signed frames');ax.legend()
        ax.set_title('Signed-message cost of each reconciliation design')
        fig.tight_layout();fig.savefig(OUT/'signed_frame_comparison.png',dpi=160);plt.close(fig)
    fig,ax=plt.subplots(figsize=(8,5))
    samples=[x for x in audit if x['n_raw_bits']==9000]
    ax.bar([str(x['passes']) for x in samples],[x['syndrome_disclosure_bits'] for x in samples])
    ax.set_xlabel('Fixed syndrome passes');ax.set_ylabel('Predeclared public syndrome bits')
    ax.set_title('Leakage accounting: 9000-bit raw key, Hamming-31 blocks')
    fig.tight_layout();fig.savefig(OUT/'fixed_disclosure_budget.png',dpi=160);plt.close(fig)
    manifest={'created_utc':datetime.datetime.now(datetime.timezone.utc).isoformat(),
       'program':'9','python':platform.python_version(),'platform':platform.platform(),
       'openssl':openssl_version,'repetitions':repetitions,'audit_only':audit_only,
       'basis':'Program 8 independent endpoints with experimental nonadaptive syndrome variant',
       'warnings':['Fixed syndrome leakage is bounded by a predetermined bit length but not a full QKD security proof.',
                   'Modeled extra verification tag and status disclosures need theorem-level review.',
                   'NumPy seeded bits are not cryptographically unpredictable.',
                   'No unbounded Tamarin or ProVerif proof has been run.',
                   'Concatenation-HKDF security in QKD plus ML-KEM composition is not proved.',
                   'At low noise the simple fixed code may have worse recovery than interactive reconciliation.']}
    (OUT/'experiment_manifest.json').write_text(json.dumps(manifest,indent=2),encoding='utf-8')
    print(f'PROGRAM 9: {len(audit)} static leakage checks; {len(rows)} OpenSSL-backed paired runs. Saved CSVs, graphs, manifest.')

if __name__=='__main__':
    ap=argparse.ArgumentParser()
    ap.add_argument('--repetitions',type=int,default=2)
    ap.add_argument('--audit-only',action='store_true')
    args=ap.parse_args()
    if not 1<=args.repetitions<=50:ap.error('repetitions must be 1..50')
    main(args.repetitions,args.audit_only)
