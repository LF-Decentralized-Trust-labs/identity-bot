#!/usr/bin/env python3
"""Regenerate M63 C3 golden_vectors.json from keripy 1.1.17 reference."""

from __future__ import annotations

import base64
import ctypes
import ctypes.util
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
KERI_CORE = ROOT / "drivers" / "keri-core"
GOLDEN = ROOT / "identity-agent-core" / "m63" / "golden_vectors.json"
VENV_PY = KERI_CORE / ".venv-keri1117" / "bin" / "python"


def _preload_libsodium() -> None:
    if ctypes.util.find_library("sodium"):
        return
    for path in ("/opt/homebrew/lib/libsodium.dylib", "/usr/local/lib/libsodium.dylib"):
        try:
            ctypes.CDLL(path)
            _orig = ctypes.util.find_library
            ctypes.util.find_library = lambda name, p=path, o=_orig: (  # type: ignore
                p if name == "sodium" else o(name)
            )
            return
        except OSError:
            continue


def main() -> int:
    if VENV_PY.exists():
        print(f"hint: run tests with {VENV_PY}", file=sys.stderr)
    _preload_libsodium()
    sys.path.insert(0, str(KERI_CORE))

    import importlib.metadata

    from m63.conformance import verify_hybrid_icp_conformance
    from m63.hybrid_inception import build_hybrid_inception, synthetic_hybrid_key_material

    version = importlib.metadata.version("keri")
    if version != "1.1.17":
        print(f"FAIL: need keri==1.1.17, got {version}", file=sys.stderr)
        return 1

    seed = 0
    result = build_hybrid_inception(synthetic_hybrid_key_material(seed=seed))
    verify_hybrid_icp_conformance(result["inception_event"], result["raw_bytes_b64"])

    cesr = result["cesr"]
    golden = {
        "hybrid_inception": {
            "description": "M63 keri 1.1.17 conformant hybrid icp — synthetic seed=0 (C3 pinned)",
            "keri_version": "1.1.17",
            "seed": seed,
            "aid": result["aid"],
            "said": result["said"],
            "raw_bytes_b64": result["raw_bytes_b64"],
            "raw_bytes_b64_len": len(result["raw_bytes_b64"]),
            "cipher_suite": "IA-HYBRID-1",
            "anchor_field": "a",
            "signing_keys_in_k": 2,
            "key_agreement_in_anchor": 2,
            "pre_rotation_digests_in_n": 2,
            "field_order": "v,t,d,i,s,kt,k,nt,n,bt,b,c,a",
            "cesr_selectors": {
                "ed25519_verkey": "D",
                "mldsa65_verkey": "1PDA",
                "x25519_pubkey": "1PXB",
                "mlkem768_encap": "1PKM",
            },
            "cesr_wire": cesr,
            "cesr_wire_lengths": {k: len(v) for k, v in cesr.items()},
            "said_algorithm": "keri 1.1.17 SerderKERI makify (dummy d/i Blake3-256)",
        }
    }
    GOLDEN.write_text(json.dumps(golden, indent=2) + "\n")
    print(
        f"pinned {GOLDEN} aid={result['aid'][:16]}... "
        f"len={len(result['raw_bytes_b64'])} keri={version}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())