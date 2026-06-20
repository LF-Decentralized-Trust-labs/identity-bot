#!/usr/bin/env python3
"""Pin M63 C2 hybrid-signature golden vectors from keripy reference."""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
KERI_CORE = ROOT / "drivers" / "keri-core"
GOLDEN = ROOT / "identity-agent-core" / "m63" / "golden_vectors.json"
VENV_PY = KERI_CORE / ".venv-keri1117" / "bin" / "python"


def main() -> int:
    sys.path.insert(0, str(KERI_CORE))
    from m63.hybrid_inception import build_hybrid_inception, synthetic_hybrid_key_material
    from m63.hybrid_signature import (
        c2_signing_verkeys,
        sign_hybrid_message,
        verify_hybrid_signature,
    )

    sig = sign_hybrid_message()
    ed_vk, mldsa_vk = c2_signing_verkeys()
    msg = bytes.fromhex(sig["message_b64"])
    inc = build_hybrid_inception(synthetic_hybrid_key_material(seed=0))

    assert verify_hybrid_signature(
        msg,
        sig["composite_wire"],
        ed_vk,
        mldsa_vk,
        inception_event=inc["inception_event"],
    )

    corrupt_classical = bytearray(sig["composite_wire"], "utf-8")
    corrupt_classical[10] ^= 0x01
    corrupt_pqc = bytearray(sig["composite_wire"], "utf-8")
    corrupt_pqc[-10] ^= 0x01

    assert not verify_hybrid_signature(
        msg,
        corrupt_classical.decode("utf-8"),
        ed_vk,
        mldsa_vk,
        inception_event=inc["inception_event"],
    )
    assert not verify_hybrid_signature(
        msg,
        corrupt_pqc.decode("utf-8"),
        ed_vk,
        mldsa_vk,
        inception_event=inc["inception_event"],
    )

    single_k = dict(inc["inception_event"])
    single_k["k"] = [single_k["k"][0]]
    assert not verify_hybrid_signature(
        msg, sig["composite_wire"], ed_vk, mldsa_vk, inception_event=single_k
    )

    data = json.loads(GOLDEN.read_text()) if GOLDEN.exists() else {}
    data["hybrid_signature"] = {
        "description": "M63 C2 composite signature — deterministic C2 seeds (pinned)",
        "message": "m63-c2-hybrid-signature-golden-vector",
        "composite_wire": sig["composite_wire"],
        "composite_wire_len": sig["composite_wire_len"],
        "ed25519_siger": sig["ed25519_siger"],
        "mldsa65_sig": sig["mldsa65_sig"],
        "cesr_selectors": {
            "ed25519_indexed_sig": "B",
            "mldsa65_indexed_sig": "1PDS",
            "controller_idx_sigs_counter": "-A",
        },
        "negative_vectors": {
            "hybrid_sig_classical_corrupt": corrupt_classical.decode("utf-8"),
            "hybrid_sig_pqc_corrupt": corrupt_pqc.decode("utf-8"),
            "hybrid_single_half_inception_k_len": 1,
        },
    }
    GOLDEN.write_text(json.dumps(data, indent=2) + "\n")
    print(f"PASS: pinned hybrid_signature composite_wire_len={sig['composite_wire_len']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())