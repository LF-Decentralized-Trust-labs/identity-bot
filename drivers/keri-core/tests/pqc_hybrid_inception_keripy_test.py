"""hybrid PQC C1/C3 keripy hybrid inception + KERI-conformance tests."""

from __future__ import annotations

import ctypes
import ctypes.util
import json
import unittest
from pathlib import Path


def _preload_libsodium() -> None:
    if ctypes.util.find_library("sodium"):
        return
    for path in (
        "/opt/homebrew/lib/libsodium.dylib",
        "/usr/local/lib/libsodium.dylib",
    ):
        try:
            ctypes.CDLL(path)
            _orig = ctypes.util.find_library
            ctypes.util.find_library = lambda name, p=path, o=_orig: (  # type: ignore[assignment]
                p if name == "sodium" else o(name)
            )
            return
        except OSError:
            continue


_preload_libsodium()

import importlib.metadata

from pqc.conformance import REQUIRED_KERI_VERSION, verify_hybrid_icp_conformance  # noqa: E402
from pqc.hybrid_inception import build_hybrid_inception, synthetic_hybrid_key_material  # noqa: E402

GOLDEN_PATH = (
    Path(__file__).resolve().parents[3]
    / "identity-agent-core"
    / "pqc"
    / "golden_vectors.json"
)


class TestHybridInceptionKeripy(unittest.TestCase):
    def test_keri_version_pinned(self) -> None:
        self.assertEqual(importlib.metadata.version("keri"), REQUIRED_KERI_VERSION)

    def test_cross_engine_byte_identity_seed0(self) -> None:
        result = build_hybrid_inception(synthetic_hybrid_key_material(seed=0))
        golden = json.loads(GOLDEN_PATH.read_text())["hybrid_inception"]

        self.assertEqual(result["aid"], golden["aid"])
        self.assertEqual(result["said"], golden["said"])
        self.assertEqual(result["aid"], result["said"])
        self.assertEqual(len(result["raw_bytes_b64"]), golden["raw_bytes_b64_len"])
        pinned = golden.get("raw_bytes_b64")
        if pinned:
            self.assertEqual(result["raw_bytes_b64"], pinned)
        self.assertEqual(result["cipher_suite"], golden["cipher_suite"])

        ked = result["inception_event"]
        self.assertEqual(len(ked["k"]), golden["signing_keys_in_k"])
        self.assertEqual(len(ked["n"]), golden["pre_rotation_digests_in_n"])
        self.assertNotIn("na", ked)
        self.assertNotIn("ka", ked)
        self.assertNotIn("cs", ked)

        anchor = ked["a"][0]
        self.assertEqual(anchor["ia"], "IA-HYBRID-1")
        self.assertEqual(len(anchor["ka"]), golden["key_agreement_in_anchor"])

    def test_keripy_conformance_seed0(self) -> None:
        result = build_hybrid_inception(synthetic_hybrid_key_material(seed=0))
        verify_hybrid_icp_conformance(
            result["inception_event"], result["raw_bytes_b64"]
        )


if __name__ == "__main__":
    unittest.main()