#!/usr/bin/env python3
"""Hybrid PQC C3 — cross-engine golden-vector + keripy conformance harness."""

from __future__ import annotations

import ctypes
import ctypes.util
import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
KERI_CORE = ROOT / "drivers" / "keri-core"
GO_CORE = ROOT / "identity-agent-core"
GOLDEN = GO_CORE / "iacrypto" / "golden_vectors.json"
VENV_PY = KERI_CORE / ".venv-keri1117" / "bin" / "python"
REQUIRED_KERI = "1.1.17"


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
    _preload_libsodium()
    sys.path.insert(0, str(KERI_CORE))

    import importlib.metadata

    from pqc.conformance import REQUIRED_KERI_VERSION, verify_hybrid_icp_conformance
    from pqc.hybrid_inception import build_hybrid_inception, synthetic_hybrid_key_material

    installed = importlib.metadata.version("keri")
    if installed != REQUIRED_KERI_VERSION:
        print(
            f"FAIL: harness requires keri=={REQUIRED_KERI_VERSION}, got {installed}. "
            f"Use {VENV_PY} (scripts/setup_keripy_1117.sh).",
            file=sys.stderr,
        )
        return 1

    golden = json.loads(GOLDEN.read_text())["hybrid_inception"]
    seed = golden["seed"]

    # keripy reference
    py = build_hybrid_inception(synthetic_hybrid_key_material(seed=seed))
    verify_hybrid_icp_conformance(py["inception_event"], py["raw_bytes_b64"])
    print("PASS: keripy + conformance")

    # Go core
    go = subprocess.run(
        ["go", "test", "./iacrypto/", "-run", "TestCrossEngineByteIdentitySeed0", "-count=1"],
        cwd=GO_CORE,
        capture_output=True,
        text=True,
    )
    if go.returncode != 0:
        print(go.stdout, go.stderr, file=sys.stderr)
        print("FAIL: Go core", file=sys.stderr)
        return 1
    print("PASS: Go core")

    # Byte-identity summary (keripy reference vs pinned golden)
    assert golden.get("keri_version") == REQUIRED_KERI
    assert py["aid"] == golden["aid"]
    assert py["said"] == golden["said"]
    assert py["aid"] == py["said"], "keri 1.1.17 Blake3 inceptive icp: i == d"
    assert len(py["raw_bytes_b64"]) == golden["raw_bytes_b64_len"]
    pinned_b64 = golden.get("raw_bytes_b64")
    if pinned_b64:
        assert py["raw_bytes_b64"] == pinned_b64, "keripy raw_bytes_b64 drifted from pinned golden"
    cesr = golden.get("cesr_wire") or {}
    if cesr:
        for key, wire in cesr.items():
            assert py["cesr"][key] == wire, f"CESR wire drift: {key}"

    selectors = golden.get("cesr_selectors") or {}
    for name, code in selectors.items():
        assert len(code) in (1, 4), f"selector {name}: {code!r}"

    print(
        f"PASS: golden vector hybrid-inception seed={seed} "
        f"aid={py['aid'][:16]}... said={py['said'][:16]}... len={len(py['raw_bytes_b64'])}"
    )
    print(
        f"PASS: CESR selectors pinned "
        f"D / {selectors.get('mldsa65_verkey')} / {selectors.get('x25519_pubkey')} / "
        f"{selectors.get('mlkem768_encap')}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())