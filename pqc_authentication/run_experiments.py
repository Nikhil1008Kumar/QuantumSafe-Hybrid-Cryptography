"""Reproducible Program-3 study (real OpenSSL PQC operations, no QKD link yet)."""
from __future__ import annotations

import argparse
import copy
import csv
import json
import platform
import statistics
import sys
from datetime import datetime, timezone
from pathlib import Path

from pqc_protocol import OpenSSLBackend, ProtocolAbort, generate_identity, negotiate, b64

BASE = Path(__file__).resolve().parent
RESULTS = BASE / "results"


def percentile(values, p):
    s = sorted(values)
    if not s:
        return 0.0
    location = (len(s) - 1) * p
    lo = int(location)
    hi = min(lo + 1, len(s) - 1)
    return s[lo] + (s[hi] - s[lo]) * (location - lo)


def write_csv(path, rows):
    if not rows:
        raise ValueError("Empty output")
    with path.open("w", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=list(rows[0]))
        writer.writeheader()
        writer.writerows(rows)


def make_mutator(stage, kind):
    def mutate(current, msg):
        result = copy.deepcopy(msg)
        if current != stage:
            return result
        if kind == "signature":
            result["signature"] = b64(bytes(3309))
        elif kind == "mode":
            result["body"]["mode"] = "UNAUTHORIZED_DOWNGRADE"
        elif kind == "nonce":
            field = "server_nonce" if stage == "server_hello" else "nonce"
            result["body"][field] = b64(b"X" * 32)
        elif kind == "kem_public":
            result["body"]["kem_public_key"] = b64(b"tampered")
        elif kind == "ciphertext":
            result["body"]["kem_ciphertext"] = b64(b"t" * 1088)
        elif kind == "mac":
            result["mac"] = b64(bytes(32))
        else:
            raise ValueError(kind)
        return result
    return mutate


def generate_plots(timing_rows, attack_rows):
    try:
        import matplotlib
        matplotlib.use("Agg")
        import matplotlib.pyplot as plt
    except ImportError:
        print("matplotlib unavailable; CSV results saved, plots skipped")
        return
    labels = [r["stage"].replace("_", " ") for r in timing_rows if r["stage"] != "full_session"]
    med = [r["median_ms"] for r in timing_rows if r["stage"] != "full_session"]
    p95 = [r["p95_ms"] for r in timing_rows if r["stage"] != "full_session"]
    fig, ax = plt.subplots(figsize=(11, 6))
    y = list(range(len(labels)))
    ax.barh(y, med, label="Median")
    ax.scatter(p95, y, marker="|", s=150, label="95th percentile")
    ax.set_yticks(y, labels)
    ax.invert_yaxis()
    ax.set_xlabel("Milliseconds per operation (OpenSSL CLI + file I/O)")
    ax.set_title("ML-DSA-65 / ML-KEM-768 protocol-stage timings")
    ax.legend()
    fig.tight_layout()
    fig.savefig(RESULTS / "operation_latency.png", dpi=180)
    plt.close(fig)

    fig, ax = plt.subplots(figsize=(10, 5))
    names = [r["attack"] for r in attack_rows]
    blocked = [r["blocked_pct"] for r in attack_rows]
    ax.barh(list(range(len(names))), blocked)
    ax.set_yticks(list(range(len(names))), names)
    ax.invert_yaxis()
    ax.set_xlabel("Simulated attempts rejected (%)")
    ax.set_xlim(0, 105)
    ax.set_title("Negative tests: rejection under specified attacker modifications")
    fig.tight_layout()
    fig.savefig(RESULTS / "negative_tests.png", dpi=180)
    plt.close(fig)


def main():
    parser = argparse.ArgumentParser(description="Program 3 PQC-only research benchmark")
    parser.add_argument("--sessions", type=int, default=75)
    parser.add_argument("--attack-repeats", type=int, default=15)
    args = parser.parse_args()
    if args.sessions < 2 or args.attack_repeats < 1:
        parser.error("sessions >=2 and attack-repeats >=1 required")
    RESULTS.mkdir(parents=True, exist_ok=True)

    with OpenSSLBackend() as backend:
        alice = generate_identity(backend, "Alice")
        bob = generate_identity(backend, "Bob")
        for _ in range(5):  # exclude warmups; do not report as trials
            warmup = negotiate(backend, alice, bob)
            if warmup.session_key_alice != warmup.session_key_bob:
                raise AssertionError("KEM agreement failed during warmup")

        trials = []
        samples = {}
        for i in range(args.sessions):
            result = negotiate(backend, alice, bob)
            if result.session_key_alice != result.session_key_bob:
                raise AssertionError("Accepted session generated unequal keys")
            row = {"trial": i + 1,
                   "session_total_ms": round(result.timings_ms["full_session"], 4),
                   "json_wire_bytes": result.on_wire_bytes,
                   "accepted": 1}
            for name, value in result.timings_ms.items():
                samples.setdefault(name, []).append(value)
                row[name + "_ms"] = round(value, 4)
            trials.append(row)
        write_csv(RESULTS / "handshake_trials.csv", trials)
        timing_rows = [
            {"stage": name,
             "mean_ms": round(statistics.mean(values), 4),
             "median_ms": round(statistics.median(values), 4),
             "p95_ms": round(percentile(values, 0.95), 4),
             "min_ms": round(min(values), 4),
             "max_ms": round(max(values), 4),
             "trials": len(values)}
            for name, values in samples.items()
        ]
        write_csv(RESULTS / "timing_summary.csv", timing_rows)

        attacks = [
            ("bad_client_signature", "client_hello", "signature"),
            ("client_mode_downgrade", "client_hello", "mode"),
            ("client_nonce_change", "client_hello", "nonce"),
            ("bad_server_signature", "server_hello", "signature"),
            ("server_nonce_change", "server_hello", "nonce"),
            ("server_kem_public_change", "server_hello", "kem_public"),
            ("bad_client_finish_signature", "client_finish", "signature"),
            ("kem_ciphertext_change", "client_finish", "ciphertext"),
            ("server_mac_change", "server_finished", "mac"),
            ("client_mac_change", "client_finished", "mac"),
        ]
        attack_rows = []
        for name, stage, kind in attacks:
            blocked = 0
            for _ in range(args.attack_repeats):
                try:
                    negotiate(backend, alice, bob, mutator=make_mutator(stage, kind))
                except ProtocolAbort:
                    blocked += 1
            attack_rows.append({"attack": name, "blocked": blocked,
                                "attempts": args.attack_repeats,
                                "blocked_pct": round(100 * blocked / args.attack_repeats, 2)})
        write_csv(RESULTS / "attack_summary.csv", attack_rows)
        generate_plots(timing_rows, attack_rows)

        manifest = {
            "experiment": "Program3-ML-DSA65-ML-KEM768-authenticated-handshake",
            "date_utc": datetime.now(timezone.utc).isoformat(),
            "openssl": backend.version,
            "python": sys.version,
            "platform": platform.platform(),
            "session_trials": args.sessions,
            "attack_trials_per_type": args.attack_repeats,
            "algorithm_parameters": {"mldsa": "ML-DSA-65", "mlkem": "ML-KEM-768",
                                     "kem_ciphertext_raw_bytes": 1088,
                                     "kem_shared_secret_bytes": 32,
                                     "mldsa_signature_raw_bytes": 3309},
            "timing_scope": "Python orchestration + OpenSSL CLI process startup + temp file I/O + crypto",
            "wire_scope": "UTF-8 canonical JSON with Base64 encodings, 5 messages",
            "randomness": "OS CSPRNG/OpenSSL, not deterministic; reruns yield different times and bytes",
            "not_included": "BB84, hybrid combiner, AES-GCM, live network, formal protocol proof",
            "security_limitations": "pinned public keys in-process; disk temporary secret keys; research-only"
        }
        (RESULTS / "experiment_manifest.json").write_text(
            json.dumps(manifest, indent=2), encoding="utf-8")

    total = next(x for x in timing_rows if x["stage"] == "full_session")
    print(f"OPENSSL: {manifest['openssl']}")
    print(f"Completed {args.sessions} valid ML-DSA/ML-KEM authenticated sessions")
    print("Handshakes: key confirmation and Alice/Bob key agreement succeeded 100% in these trials")
    print(f"Handshake total: median {total['median_ms']:.3f} ms; p95 {total['p95_ms']:.3f} ms")
    print(f"On-wire JSON bytes: median {statistics.median(r['json_wire_bytes'] for r in trials):.0f}")
    print("ATTACK TESTS:")
    for row in attack_rows:
        print(f"  {row['attack']:<34} blocked {row['blocked']}/{row['attempts']}")
    print("Saved: results/*.csv, timing and attack PNG graphs, experiment_manifest.json")


if __name__ == "__main__":
    main()
