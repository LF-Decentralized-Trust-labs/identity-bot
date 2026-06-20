"""ML-DSA-65 sign/verify via pqc-poc-rust (deterministic C2 golden vectors)."""

from __future__ import annotations

import json
import subprocess
from pathlib import Path

from .cesr import C2_MLDSA_SEED, MLDSA65_SIG_BYTES, MLDSA65_VERKEY_BYTES

ROOT = Path(__file__).resolve().parents[3]
PQC_RUST = ROOT / "pqc-poc-rust"


def _run_rust(op: str, payload: dict) -> dict:
    proc = subprocess.run(
        ["cargo", "run", "--quiet", "--bin", "pqc_mldsa_cli", "--", op, json.dumps(payload)],
        cwd=PQC_RUST,
        capture_output=True,
        text=True,
        check=False,
    )
    if proc.returncode != 0:
        raise RuntimeError(proc.stderr.strip() or proc.stdout.strip() or "mldsa cli failed")
    return json.loads(proc.stdout)


def mldsa_sign(msg: bytes, seed: bytes = C2_MLDSA_SEED) -> bytes:
    if len(seed) != 32:
        raise ValueError("ML-DSA seed must be 32 bytes")
    out = _run_rust("sign", {"seed_b64": seed.hex(), "msg_b64": msg.hex()})
    raw = bytes.fromhex(out["sig_hex"])
    if len(raw) != MLDSA65_SIG_BYTES:
        raise ValueError(f"unexpected sig len {len(raw)}")
    return raw


def mldsa_verkey(seed: bytes = C2_MLDSA_SEED) -> bytes:
    if len(seed) != 32:
        raise ValueError("ML-DSA seed must be 32 bytes")
    out = _run_rust("verkey", {"seed_b64": seed.hex()})
    raw = bytes.fromhex(out["vk_hex"])
    if len(raw) != MLDSA65_VERKEY_BYTES:
        raise ValueError(f"unexpected vk len {len(raw)}")
    return raw


def mldsa_verify(vk: bytes, msg: bytes, sig: bytes) -> bool:
    out = _run_rust(
        "verify",
        {"vk_hex": vk.hex(), "msg_hex": msg.hex(), "sig_hex": sig.hex()},
    )
    return bool(out.get("ok"))