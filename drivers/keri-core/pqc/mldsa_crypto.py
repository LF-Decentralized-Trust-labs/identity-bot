"""ML-DSA-65 sign/verify via the Go core (deterministic C2 golden vectors).

This shells out to `identity-agent-core/cmd/mldsa-cli` rather than implementing
ML-DSA here. There is one KERI engine on every platform and it is the Go core;
a second implementation living in the Python driver is exactly the kind of
quiet divergence the single-engine rule exists to prevent.

What this cross-checks is therefore the CESR wire framing of a hybrid signature
— keripy's encoding against the Go core's — not the ML-DSA primitive itself,
which both sides now take from the same place.
"""

from __future__ import annotations

import json
import subprocess
from pathlib import Path

from .cesr import C2_MLDSA_SEED, MLDSA65_SIG_BYTES, MLDSA65_VERKEY_BYTES

ROOT = Path(__file__).resolve().parents[3]
GO_CORE = ROOT / "identity-agent-core"


def _run_go(op: str, payload: dict) -> dict:
    proc = subprocess.run(
        ["go", "run", "./cmd/mldsa-cli", op, json.dumps(payload)],
        cwd=GO_CORE,
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
    out = _run_go("sign", {"seed_hex": seed.hex(), "msg_hex": msg.hex()})
    raw = bytes.fromhex(out["sig_hex"])
    if len(raw) != MLDSA65_SIG_BYTES:
        raise ValueError(f"unexpected sig len {len(raw)}")
    return raw


def mldsa_verkey(seed: bytes = C2_MLDSA_SEED) -> bytes:
    if len(seed) != 32:
        raise ValueError("ML-DSA seed must be 32 bytes")
    out = _run_go("verkey", {"seed_hex": seed.hex()})
    raw = bytes.fromhex(out["vk_hex"])
    if len(raw) != MLDSA65_VERKEY_BYTES:
        raise ValueError(f"unexpected vk len {len(raw)}")
    return raw


def mldsa_verify(vk: bytes, msg: bytes, sig: bytes) -> bool:
    out = _run_go(
        "verify",
        {"vk_hex": vk.hex(), "msg_hex": msg.hex(), "sig_hex": sig.hex()},
    )
    return bool(out.get("ok"))