"""Program 3: Research-only ML-DSA-65 authenticated ML-KEM-768 handshake.

Requires OpenSSL >= 3.5 with ML-DSA-65 and ML-KEM-768 enabled.
Private keys/shared secrets are temporarily written to mode-0600 files and
removed on exit. This is NOT a production networking/TLS implementation.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import re
import subprocess
import tempfile
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Any

PROTOCOL = "research-pqc-only-v1"
IDENTITY_ALGORITHM = "ML-DSA-65"
KEM_ALGORITHM = "ML-KEM-768"
CIPHERTEXT_BYTES = 1088
SIGNATURE_BYTES = 3309
SHARED_SECRET_BYTES = 32
MAX_MESSAGE_BYTES = 20_000


class ProtocolAbort(Exception):
    """Intentional rejection of an unauthenticated/invalid session."""


def encode(obj: Any) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii")


def b64(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def unb64(data: str, limit: int = 10000) -> bytes:
    if not isinstance(data, str) or len(data) > limit * 2:
        raise ProtocolAbort("Invalid binary encoding")
    try:
        result = base64.b64decode(data, validate=True)
    except Exception as exc:
        raise ProtocolAbort("Invalid base64 payload") from exc
    if len(result) > limit or b64(result) != data:
        raise ProtocolAbort("Invalid or noncanonical binary payload")
    return result


def sha(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


def hkdf(ikm: bytes, salt: bytes, info: bytes, length: int = 32) -> bytes:
    """RFC 5869 HKDF-SHA256, for the isolated PQC-only key schedule."""
    if not 0 < length <= 255 * hashlib.sha256().digest_size:
        raise ValueError("invalid HKDF output length")
    prk = hmac.new(salt, ikm, hashlib.sha256).digest()
    t = b""
    out = b""
    for i in range(1, (length + 31) // 32 + 1):
        t = hmac.new(prk, t + info + bytes([i]), hashlib.sha256).digest()
        out += t
    return out[:length]


class OpenSSLBackend:
    """Real OpenSSL 3.5 cryptographic operations via subprocess (disk-based CLI).

    Benchmarks include process startup and temporary-file I/O. The backend is
    appropriate for independently reproducible research, not private-key storage.
    """
    def __init__(self, executable: str = "openssl"):
        self.executable = executable
        self._tmp = None
        self._root = None
        self._sequence = 0
        self.replay_cache: set[str] = set()  # in-memory cache for this backend lifetime

    def __enter__(self):
        self._tmp = tempfile.TemporaryDirectory(prefix="pqc-research-")
        self._root = Path(self._tmp.name)
        os.chmod(self._root, 0o700)
        try:
            output = self._run(["version"]).decode(errors="replace")
            match = re.search(r"OpenSSL\s+(\d+)\.(\d+)\.(\d+)", output)
            if not match or (int(match[1]), int(match[2])) < (3, 5):
                raise RuntimeError("OpenSSL >=3.5 is required. Found: " + output.strip())
            supported = self._run(["list", "-signature-algorithms"]).decode(errors="replace")
            if "ML-DSA-65" not in supported:
                raise RuntimeError("OpenSSL lacks ML-DSA-65 provider support")
            supported = self._run(["list", "-kem-algorithms"]).decode(errors="replace")
            if "ML-KEM-768" not in supported:
                raise RuntimeError("OpenSSL lacks ML-KEM-768 provider support")
            self.version = output.strip()
            return self
        except Exception:
            self.__exit__(None, None, None)
            raise

    def __exit__(self, *args):
        if self._tmp is not None:
            self._tmp.cleanup()
        self._tmp, self._root = None, None

    def _run(self, args: list[str]) -> bytes:
        try:
            result = subprocess.run([self.executable, *args], capture_output=True, check=False)
        except OSError as exc:
            raise RuntimeError("OpenSSL executable not found") from exc
        if result.returncode:
            raise ProtocolAbort("Cryptographic operation rejected by OpenSSL")
        return result.stdout

    def _file(self, content: bytes | None = None) -> Path:
        if self._root is None:
            raise RuntimeError("Use OpenSSLBackend inside a with statement")
        self._sequence += 1
        path = self._root / f"item-{self._sequence:08d}.bin"
        descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(descriptor, "wb") as handle:
            if content is not None:
                handle.write(content)
        return path

    def keypair(self, algorithm: str) -> tuple[bytes, bytes]:
        if algorithm not in (IDENTITY_ALGORITHM, KEM_ALGORITHM):
            raise ValueError("Unsupported algorithm")
        secret = self._file()
        public = self._file()
        self._run(["genpkey", "-algorithm", algorithm, "-out", str(secret)])
        self._run(["pkey", "-in", str(secret), "-pubout", "-out", str(public)])
        return secret.read_bytes(), public.read_bytes()

    def sign(self, secret_key: bytes, message: bytes) -> bytes:
        if len(message) > MAX_MESSAGE_BYTES:
            raise ProtocolAbort("Message too large")
        secret = self._file(secret_key)
        msg = self._file(message)
        signature = self._file()
        self._run(["pkeyutl", "-sign", "-rawin", "-inkey", str(secret),
                   "-in", str(msg), "-out", str(signature)])
        result = signature.read_bytes()
        if len(result) != SIGNATURE_BYTES:
            raise ProtocolAbort("Unexpected ML-DSA signature size")
        return result

    def verify(self, public_key: bytes, message: bytes, signature: bytes) -> None:
        if len(message) > MAX_MESSAGE_BYTES or len(signature) != SIGNATURE_BYTES:
            raise ProtocolAbort("Invalid signed message or signature")
        key = self._file(public_key)
        msg = self._file(message)
        sig = self._file(signature)
        self._run(["pkeyutl", "-verify", "-rawin", "-pubin", "-inkey", str(key),
                   "-in", str(msg), "-sigfile", str(sig)])

    def encapsulate(self, public_key: bytes) -> tuple[bytes, bytes]:
        key = self._file(public_key)
        ciphertext = self._file()
        shared = self._file()
        self._run(["pkeyutl", "-encap", "-pubin", "-inkey", str(key),
                   "-out", str(ciphertext), "-secret", str(shared)])
        ct, ss = ciphertext.read_bytes(), shared.read_bytes()
        if len(ct) != CIPHERTEXT_BYTES or len(ss) != SHARED_SECRET_BYTES:
            raise ProtocolAbort("Unexpected ML-KEM output length")
        return ct, ss

    def decapsulate(self, secret_key: bytes, ciphertext: bytes) -> bytes:
        if len(ciphertext) != CIPHERTEXT_BYTES:
            raise ProtocolAbort("Invalid ML-KEM ciphertext length")
        key = self._file(secret_key)
        ct = self._file(ciphertext)
        shared = self._file()
        self._run(["pkeyutl", "-decap", "-inkey", str(key),
                   "-in", str(ct), "-secret", str(shared)])
        result = shared.read_bytes()
        if len(result) != SHARED_SECRET_BYTES:
            raise ProtocolAbort("Unexpected ML-KEM shared-secret length")
        return result


@dataclass(frozen=True)
class Identity:
    name: str
    signing_private: bytes
    signing_public: bytes


def generate_identity(backend: OpenSSLBackend, name: str) -> Identity:
    if not name or len(name) > 64 or not name.isascii():
        raise ValueError("Invalid identity")
    sk, pk = backend.keypair(IDENTITY_ALGORITHM)
    return Identity(name, sk, pk)


def sign_envelope(backend: OpenSSLBackend, key: bytes, body: dict) -> dict:
    return {"body": body, "signature": b64(backend.sign(key, encode(body)))}


def verify_envelope(backend: OpenSSLBackend, pinned_key: bytes, envelope: dict) -> dict:
    if not isinstance(envelope, dict) or set(envelope) != {"body", "signature"}:
        raise ProtocolAbort("Malformed signed envelope")
    body = envelope["body"]
    if not isinstance(body, dict):
        raise ProtocolAbort("Malformed signed body")
    backend.verify(pinned_key, encode(body), unb64(envelope["signature"], 4000))
    return body


def assert_fields(body: dict, required: set[str], type_name: str) -> None:
    if set(body) != required or body.get("type") != type_name:
        raise ProtocolAbort("Wrong signed message schema")
    if body.get("protocol") != PROTOCOL:
        raise ProtocolAbort("Unknown protocol or unauthorized mode")


@dataclass
class SessionResult:
    # Keys exist in memory for checking test agreement; never put in CSV/logs.
    session_key_alice: bytes
    session_key_bob: bytes
    timings_ms: dict[str, float]
    on_wire_bytes: int
    envelope_hello: dict
    transcript_hash: str


Mutator = Callable[[str, dict], dict]


def negotiate(backend: OpenSSLBackend,
              alice: Identity,
              bob: Identity,
              replay_cache: set[str] | None = None,
              mutator: Mutator | None = None,
              replay_hello: dict | None = None) -> SessionResult:
    """One local simulated exchange. Requires trusted (pinned) public keys.

    A mutator models an untrusted transport and is applied at message boundaries.
    The independent server/client confirmations are required before acceptance.
    """
    timings: dict[str, float] = {}
    wire_bytes = 0
    start = time.perf_counter_ns()

    def time_op(label, fn):
        t = time.perf_counter_ns()
        result = fn()
        timings[label] = (time.perf_counter_ns() - t) / 1e6
        return result

    def transport(stage: str, envelope: dict) -> dict:
        nonlocal wire_bytes
        sent = mutator(stage, envelope) if mutator else envelope
        if not isinstance(sent, dict):
            raise ProtocolAbort("Malformed transport message")
        packed = encode(sent)
        if len(packed) > MAX_MESSAGE_BYTES:
            raise ProtocolAbort("Transport message too large")
        wire_bytes += len(packed)
        return sent

    # Step 1. Alice signs a hello including expected identity and requested mode.
    client_nonce = os.urandom(32)
    hello_body = {"type": "client_hello", "protocol": PROTOCOL,
                  "from": alice.name, "to": bob.name, "nonce": b64(client_nonce),
                  "mode": "PQC_ONLY"}
    original_hello = replay_hello if replay_hello is not None else time_op(
        "alice_sign_hello", lambda: sign_envelope(backend, alice.signing_private, hello_body))
    received_hello = transport("client_hello", original_hello)
    accepted_hello = time_op("bob_verify_hello", lambda:
                             verify_envelope(backend, alice.signing_public, received_hello))
    assert_fields(accepted_hello,
                  {"type", "protocol", "from", "to", "nonce", "mode"}, "client_hello")
    if (accepted_hello["from"] != alice.name or accepted_hello["to"] != bob.name
            or accepted_hello["mode"] != "PQC_ONLY"
            or len(unb64(accepted_hello["nonce"], 64)) != 32):
        raise ProtocolAbort("Identity, mode, or nonce invalid")

    # Replay state lives on this backend instance unless a shared store is injected.
    # A real multi-process server needs an authenticated persistent cache with expiry.
    cache = backend.replay_cache if replay_cache is None else replay_cache
    nonce_tag = bob.name + ":" + accepted_hello["nonce"]
    if nonce_tag in cache:
        raise ProtocolAbort("Replay detected at Bob")
    cache.add(nonce_tag)

    # Step 2. Bob signs a fresh ephemeral KEM public key AND Alice's nonce.
    server_nonce = os.urandom(32)
    kem_sk, kem_pk = time_op("bob_kem_keygen", lambda: backend.keypair(KEM_ALGORITHM))
    server_body = {"type": "server_hello", "protocol": PROTOCOL,
                   "from": bob.name, "to": alice.name,
                   "client_nonce": accepted_hello["nonce"],
                   "server_nonce": b64(server_nonce),
                   "mode": "PQC_ONLY", "kem_algorithm": KEM_ALGORITHM,
                   "kem_public_key": b64(kem_pk),
                   "hello_hash": b64(sha(encode(received_hello)))}
    signed_server = time_op("bob_sign_server", lambda:
                            sign_envelope(backend, bob.signing_private, server_body))
    received_server = transport("server_hello", signed_server)
    approved_server = time_op("alice_verify_server", lambda:
                              verify_envelope(backend, bob.signing_public, received_server))
    assert_fields(approved_server,
                  {"type", "protocol", "from", "to", "client_nonce", "server_nonce",
                   "mode", "kem_algorithm", "kem_public_key", "hello_hash"}, "server_hello")
    if (approved_server["from"] != bob.name or approved_server["to"] != alice.name
            or approved_server["mode"] != "PQC_ONLY"
            or approved_server["kem_algorithm"] != KEM_ALGORITHM
            or approved_server["client_nonce"] != b64(client_nonce)
            or approved_server["hello_hash"] != b64(sha(encode(received_hello)))
            or len(unb64(approved_server["server_nonce"], 64)) != 32):
        raise ProtocolAbort("Server failed challenge, identity, mode or transcript binding")
    bob_kem_public = unb64(approved_server["kem_public_key"], 4000)

    # Step 3. Alice encapsulates and signs the transcript plus ciphertext.
    ct, ss_alice = time_op("alice_kem_encaps", lambda:
                           backend.encapsulate(bob_kem_public))
    prefix_hash = b64(sha(encode([received_hello, received_server])))
    finish_body = {"type": "client_finish", "protocol": PROTOCOL,
                   "from": alice.name, "to": bob.name,
                   "mode": "PQC_ONLY", "prefix_hash": prefix_hash,
                   "kem_ciphertext": b64(ct)}
    signed_finish = time_op("alice_sign_finish", lambda:
                            sign_envelope(backend, alice.signing_private, finish_body))
    received_finish = transport("client_finish", signed_finish)
    accepted_finish = time_op("bob_verify_finish", lambda:
                              verify_envelope(backend, alice.signing_public, received_finish))
    assert_fields(accepted_finish,
                  {"type", "protocol", "from", "to", "mode", "prefix_hash", "kem_ciphertext"},
                  "client_finish")
    if (accepted_finish["from"] != alice.name or accepted_finish["to"] != bob.name
            or accepted_finish["mode"] != "PQC_ONLY"
            or accepted_finish["prefix_hash"] != prefix_hash):
        raise ProtocolAbort("Client finish does not bind the negotiated transcript")
    ss_bob = time_op("bob_kem_decaps", lambda:
                     backend.decapsulate(kem_sk, unb64(accepted_finish["kem_ciphertext"], 1200)))

    # Step 4. Independent transcript-bound KDF + BOTH confirmation directions.
    transcript_hash = sha(encode([received_hello, received_server, received_finish]))

    def derive(secret: bytes):
        salt = sha(b"Program3-pqc-only-extract-v1" + transcript_hash)
        return {role: hkdf(secret, salt, b"Program3/" + role.encode() + b"/" + transcript_hash)
                for role in ("app_key", "server_confirmation", "client_confirmation")}

    alice_keys, bob_keys = derive(ss_alice), derive(ss_bob)
    server_confirmation = hmac.new(bob_keys["server_confirmation"],
                                   b"ServerFinished" + transcript_hash, hashlib.sha256).digest()
    server_received = transport("server_finished", {"type": "server_finished", "mac": b64(server_confirmation)})
    if server_received.get("type") != "server_finished" or not hmac.compare_digest(
        unb64(server_received.get("mac"), 64),
        hmac.new(alice_keys["server_confirmation"], b"ServerFinished" + transcript_hash,
                 hashlib.sha256).digest()):
        raise ProtocolAbort("Server confirmation failed")

    client_confirmation = hmac.new(alice_keys["client_confirmation"],
                                   b"ClientFinished" + transcript_hash, hashlib.sha256).digest()
    client_received = transport("client_finished", {"type": "client_finished", "mac": b64(client_confirmation)})
    if client_received.get("type") != "client_finished" or not hmac.compare_digest(
        unb64(client_received.get("mac"), 64),
        hmac.new(bob_keys["client_confirmation"], b"ClientFinished" + transcript_hash,
                 hashlib.sha256).digest()):
        raise ProtocolAbort("Client confirmation failed")

    timings["full_session"] = (time.perf_counter_ns() - start) / 1e6
    return SessionResult(alice_keys["app_key"], bob_keys["app_key"], timings,
                         wire_bytes, received_hello, transcript_hash.hex())
