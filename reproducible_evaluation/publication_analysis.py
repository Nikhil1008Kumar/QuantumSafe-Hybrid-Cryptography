"""Predeclared, reproducible numerical analysis for Program 10.

The word 'accepted' means model-admitted by the Program-2 calculation,
not physically certified secrecy. Confidence intervals quantify Monte Carlo
uncertainty only; they do NOT quantify cryptographic failure probability.
"""
from __future__ import annotations
from dataclasses import dataclass
from collections import Counter
from math import sqrt, isfinite
from statistics import mean, median
import hashlib
import math
import numpy as np
from finite_key_bb84 import FiniteKeyConfig, run
from policy_comparison import Strategy, Mode, QKDObservation, decide
from hybrid_protocol import Policy

MASTER_SEED=20261024

@dataclass(frozen=True)
class Scenario:
    name: str
    signals: int
    noise: float=0.
    interception: float=0.
    loss: float=0.

# Predeclare these scenario names and parameters before inspecting results.
SCENARIOS = (
    Scenario('short_500_clean',500),
    Scenario('small_10000_clean',10_000),
    Scenario('clean_50000',50_000),
    Scenario('noise1_50000',50_000,noise=.01),
    Scenario('noise2_50000',50_000,noise=.02),
    Scenario('noise3_50000',50_000,noise=.03),
    Scenario('eve10_50000',50_000,interception=.10),
    Scenario('eve20_50000',50_000,interception=.20),
    Scenario('loss30_50000',50_000,loss=.30),
    Scenario('clean_100000',100_000),
)
STRATEGIES=tuple(Strategy)
POLICIES=(Policy.HYBRID_PREFERRED,Policy.HYBRID_REQUIRED)


def trial_seed(master_seed: int, scenario: str, repetition: int) -> int:
    """Stable scenario-separated seed (for simulation only, not secrecy)."""
    if not isinstance(master_seed,int) or master_seed < 0 or repetition < 0 or not scenario:
        raise ValueError('invalid seed input')
    h=hashlib.sha256(f'program10/v1|{master_seed}|{scenario}|{repetition}'.encode('ascii')).digest()
    return int.from_bytes(h[:8],'big')


def expected_qber(intercept: float, noise: float) -> float:
    if not 0 <= intercept <= 1 or not 0 <= noise <= 1:
        raise ValueError('invalid channel probabilities')
    return noise+(1-2*noise)*intercept/4


def wilson(successes: int, trials: int, z: float=1.959963984540054)->tuple[float,float]:
    """95% Wilson score interval for a Bernoulli rate; no SciPy dependency."""
    if type(successes) is not int or type(trials) is not int or not 0 <= successes <= trials or trials < 1:
        raise ValueError('invalid Wilson input')
    phat=successes/trials
    denom=1+z*z/trials
    mid=(phat+z*z/(2*trials))/denom
    half=z*sqrt(phat*(1-phat)/trials+z*z/(4*trials*trials))/denom
    return (0.0 if successes == 0 else max(0.,mid-half)),(1.0 if successes == trials else min(1.,mid+half))


def paired_bootstrap_difference(x: list[float], y: list[float], seed: int=117, draws: int=2000)->tuple[float,float,float]:
    """Difference x - y with paired percentile bootstrap, not a security bound."""
    if len(x) != len(y) or not x or draws < 50:
        raise ValueError('matched nonempty arrays and draws>=50 required')
    d=np.asarray(x,dtype=float)-np.asarray(y,dtype=float)
    if np.any(~np.isfinite(d)):
        raise ValueError('non-finite observations')
    rng=np.random.default_rng(seed)
    estimates=[]
    for _ in range(draws):
        indices=rng.integers(0,len(d),size=len(d))
        estimates.append(float(d[indices].mean()))
    return float(d.mean()),float(np.quantile(estimates,.025)),float(np.quantile(estimates,.975))


def model_config(case: Scenario) -> FiniteKeyConfig:
    bits=max(1,round(case.signals*.18))
    return FiniteKeyConfig(transmitted_signals=case.signals,
           target_key_bits=bits,target_test_bits=bits,
           noise_probability=case.noise,
           intercept_probability=case.interception,
           loss_probability=case.loss,
           reconciliation_passes=2,
           ec_leakage_cap_fraction=.40)


def simulate(case: Scenario, repetition: int, master_seed: int=MASTER_SEED):
    seed=trial_seed(master_seed,case.name,repetition)
    res=run(model_config(case),seed)
    obs=QKDObservation.from_result(res)
    row={
       'scenario':case.name,'repetition':repetition,'seed':seed,
       'transmitted':case.signals,'noise_probability':case.noise,
       'interception_probability':case.interception,'loss_probability':case.loss,
       'theoretical_qber':expected_qber(case.interception,case.noise),
       'qkd_status':res.status,'qkd_model_admitted':int(obs.finite_key_admitted),
       'qber_only_admitted':int(obs.qber11_admitted),
       'x_qber':res.x_qber if math.isfinite(res.x_qber) else '',
       'x_test_bits':res.test_x_used,'raw_z_bits':res.raw_z_used,
       'ec_public_bits_proxy':res.ec_public_bits,
       'ec_predeclared_cap_bits':res.ec_leakage_budget_bits,
       'finite_key_candidate_bound_bits':res.finite_bound_bits,
       'verification_passed':int(res.verification_passed),
       'final_length_bits':res.final_bits,
       'model_runtime_ms':round(res.runtime_ms,6),
    }
    decisions=[]
    for policy in POLICIES:
        for strategy in STRATEGIES:
            d=decide(strategy,policy,obs)
            decisions.append({
               'scenario':case.name,'repetition':repetition,'seed':seed,
               'policy':policy.value,'strategy':strategy.value,
               'mode':d.mode.value,'in_model_invalid_hybrid':int(d.model_invalid_hybrid),
               'model_compliant_session':int(d.mode is not Mode.ABORT and not d.model_invalid_hybrid),
               'qualified_hybrid':int(d.qkd_qualified),
               'reason':d.reason,
            })
    return row,decisions


def summarize_qkd(rows: list[dict]) -> list[dict]:
    output=[]
    for case in SCENARIOS:
        items=[r for r in rows if r['scenario']==case.name]
        if not items: continue
        n=len(items); k=sum(r['qkd_model_admitted'] for r in items)
        lo,hi=wilson(k,n)
        measured=[float(r['x_qber']) for r in items if r['x_qber']!='']
        output.append({
           'scenario':case.name,'n_trials':n,'n_model_admitted':k,
           'model_admission_pct':round(100*k/n,3),
           'admission_ci_low_pct':round(100*lo,3),'admission_ci_high_pct':round(100*hi,3),
           'expected_qber_pct':round(100*expected_qber(case.interception,case.noise),4),
           'mean_observed_qber_pct':round(100*mean(measured),4) if measured else '',
           'qber_samples':len(measured),
           'median_candidate_bound_bits':median(r['finite_key_candidate_bound_bits'] for r in items),
           'median_ec_public_proxy_bits':median(r['ec_public_bits_proxy'] for r in items),
           'median_runtime_ms':round(median(r['model_runtime_ms'] for r in items),5),
           'dominant_abort_status':Counter(r['qkd_status'] for r in items if r['qkd_status']!='ACCEPT').most_common(1)[0][0]
              if any(r['qkd_status']!='ACCEPT' for r in items) else '',
        })
    return output


def summarize_decisions(rows: list[dict]) -> list[dict]:
    result=[]
    for case in SCENARIOS:
        for policy in POLICIES:
            for strategy in STRATEGIES:
                items=[r for r in rows if r['scenario']==case.name and
                    r['policy']==policy.value and r['strategy']==strategy.value]
                if not items: continue
                n=len(items)
                successes=sum(r['model_compliant_session'] for r in items)
                invalid=sum(r['in_model_invalid_hybrid'] for r in items)
                lo,hi=wilson(successes,n)
                ilo,ihi=wilson(invalid,n)
                result.append({'scenario':case.name,'policy':policy.value,'strategy':strategy.value,
                   'n_trials':n,'hybrid_count':sum(r['mode']=='HYBRID' for r in items),
                   'pqc_only_count':sum(r['mode']=='PQC_ONLY' for r in items),
                   'abort_count':sum(r['mode']=='ABORT' for r in items),
                   'model_compliant_count':successes,
                   'model_compliant_pct':round(100*successes/n,3),
                   'model_compliant_ci_low_pct':round(100*lo,3),
                   'model_compliant_ci_high_pct':round(100*hi,3),
                   'invalid_hybrid_count':invalid,
                   'invalid_hybrid_pct':round(100*invalid/n,3),
                   'invalid_ci_low_pct':round(100*ilo,3),
                   'invalid_ci_high_pct':round(100*ihi,3)})
    return result


def paired_strategy_contrasts(rows:list[dict], seed:int=118, draws:int=2000)->list[dict]:
    """Compare paired decisions generated from EXACTLY the same QKD observation."""
    out=[]
    for case in SCENARIOS:
        for policy in POLICIES:
            rr=[r for r in rows if r['scenario']==case.name and r['policy']==policy.value]
            if not rr: continue
            by_rep={}
            for r in rr:
                by_rep.setdefault(r['repetition'],{})[r['strategy']]=r
            for comparator in (Strategy.QBER_ONLY,Strategy.FINITE_NO_FALLBACK,Strategy.PQC_ONLY):
                left=[];right=[]
                for rep,decisions in sorted(by_rep.items()):
                    if Strategy.PROPOSED.value not in decisions or comparator.value not in decisions:
                        raise ValueError('missing matched baseline')
                    left.append(decisions[Strategy.PROPOSED.value]['model_compliant_session'])
                    right.append(decisions[comparator.value]['model_compliant_session'])
                diff,low,high=paired_bootstrap_difference(left,right,seed+sum(map(ord,case.name))+len(left),draws)
                out.append({'scenario':case.name,'policy':policy.value,
                    'contrast':f'{Strategy.PROPOSED.value} minus {comparator.value}',
                    'paired_n':len(left),'model_compliant_diff_pp':round(100*diff,3),
                    'bootstrap_95_low_pp':round(100*low,3),
                    'bootstrap_95_high_pp':round(100*high,3),
                    'uncertainty_type':'Monte Carlo paired bootstrap; NOT a cryptographic security interval'})
    return out
