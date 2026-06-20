#!/usr/bin/env python3
"""Hybrid PQC C2 — cross-engine hybrid-signature + both-must-verify harness."""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
KERI_CORE = ROOT / "drivers" / "keri-core"
GO_CORE = ROOT / "identity-agent-core"
RUST_CRATE = ROOT / "identity_agent_ui" / "rust"
GOLDEN = GO_CORE / "iacrypto" / "golden_vectors.json"


def main() -> int:
    sys.path.insert(0, str(KERI_CORE))

    from pqc.hybrid_inception import build_hybrid_inception, synthetic_hybrid_key_material
    from pqc.hybrid_signature import (
        c2_signing_verkeys,
        sign_hybrid_message,
        verify_hybrid_signature,
    )

    golden = json.loads(GOLDEN.read_text())
    if "hybrid_signature" not in golden:
        print("FAIL: hybrid_signature missing from golden_vectors.json — run pin_iacrypto_c2_golden.py", file=sys.stderr)
        return 1

    vec = golden["hybrid_signature"]
    inc = build_hybrid_inception(synthetic_hybrid_key_material(seed=0))
    ed_vk, mldsa_vk = c2_signing_verkeys()
    msg = vec["message"].encode()

    py = sign_hybrid_message()
    assert py["composite_wire"] == vec["composite_wire"], "keripy composite wire drift"
    assert verify_hybrid_signature(
        msg, vec["composite_wire"], ed_vk, mldsa_vk, inception_event=inc["inception_event"]
    )
    print("PASS: keripy reference + positive verify")

    neg = vec["negative_vectors"]
    for name in ("hybrid_sig_classical_corrupt", "hybrid_sig_pqc_corrupt"):
        assert not verify_hybrid_signature(
            msg, neg[name], ed_vk, mldsa_vk, inception_event=inc["inception_event"]
        ), f"negative vector {name} should reject"
    single_k = dict(inc["inception_event"])
    single_k["k"] = [single_k["k"][0]]
    assert not verify_hybrid_signature(
        msg, vec["composite_wire"], ed_vk, mldsa_vk, inception_event=single_k
    )
    print("PASS: negative vectors reject (keripy)")

    go = subprocess.run(
        ["go", "test", "./iacrypto/", "-run", "TestC2HybridSignatureGolden", "-count=1"],
        cwd=GO_CORE,
        capture_output=True,
        text=True,
    )
    if go.returncode != 0:
        print(go.stdout, go.stderr, file=sys.stderr)
        print("FAIL: Go core C2", file=sys.stderr)
        return 1
    print("PASS: Go core")

    rust = subprocess.run(
        [
            "cargo",
            "test",
            "--features",
            "dev_skip_frb",
            "c2_hybrid_signature_golden",
            "--",
            "--nocapture",
        ],
        cwd=RUST_CRATE,
        capture_output=True,
        text=True,
    )
    if rust.returncode != 0:
        print(rust.stdout, rust.stderr, file=sys.stderr)
        print("FAIL: Rust bridge C2", file=sys.stderr)
        return 1
    print("PASS: Rust bridge")

    print(
        f"PASS: C2 hybrid-signature byte-identical composite_wire_len={vec['composite_wire_len']}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())