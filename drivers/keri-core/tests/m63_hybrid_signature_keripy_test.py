"""M63 C2 keripy tests — composite signature + both-must-verify."""

from __future__ import annotations

import json
import unittest
from pathlib import Path

from m63.hybrid_inception import build_hybrid_inception, synthetic_hybrid_key_material
from m63.hybrid_signature import (
    c2_signing_verkeys,
    is_hybrid_identity,
    sign_hybrid_message,
    verify_hybrid_signature,
)

GOLDEN = (
    Path(__file__).resolve().parents[3]
    / "identity-agent-core"
    / "m63"
    / "golden_vectors.json"
)


class TestHybridSignatureKeripy(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        data = json.loads(GOLDEN.read_text())
        cls.vec = data.get("hybrid_signature")
        if cls.vec is None:
            raise unittest.SkipTest("hybrid_signature not pinned — run pin_m63_c2_golden.py")

    def test_is_hybrid_identity_gate(self) -> None:
        inc = build_hybrid_inception(synthetic_hybrid_key_material(seed=0))
        self.assertTrue(is_hybrid_identity(inc["inception_event"]))

    def test_positive_composite_verifies(self) -> None:
        inc = build_hybrid_inception(synthetic_hybrid_key_material(seed=0))
        ed_vk, mldsa_vk = c2_signing_verkeys()
        msg = self.vec["message"].encode()
        self.assertTrue(
            verify_hybrid_signature(
                msg,
                self.vec["composite_wire"],
                ed_vk,
                mldsa_vk,
                inception_event=inc["inception_event"],
            )
        )

    def test_negative_vectors_reject(self) -> None:
        inc = build_hybrid_inception(synthetic_hybrid_key_material(seed=0))
        ed_vk, mldsa_vk = c2_signing_verkeys()
        msg = self.vec["message"].encode()
        neg = self.vec["negative_vectors"]
        for key in ("hybrid_sig_classical_corrupt", "hybrid_sig_pqc_corrupt"):
            self.assertFalse(
                verify_hybrid_signature(
                    msg,
                    neg[key],
                    ed_vk,
                    mldsa_vk,
                    inception_event=inc["inception_event"],
                ),
                key,
            )

    def test_single_half_rejects(self) -> None:
        inc = build_hybrid_inception(synthetic_hybrid_key_material(seed=0))
        single = dict(inc["inception_event"])
        single["k"] = [single["k"][0]]
        ed_vk, mldsa_vk = c2_signing_verkeys()
        msg = self.vec["message"].encode()
        self.assertFalse(
            verify_hybrid_signature(
                msg,
                self.vec["composite_wire"],
                ed_vk,
                mldsa_vk,
                inception_event=single,
            )
        )

    def test_keripy_wire_matches_pinned_golden(self) -> None:
        py = sign_hybrid_message()
        self.assertEqual(py["composite_wire"], self.vec["composite_wire"])


if __name__ == "__main__":
    unittest.main()