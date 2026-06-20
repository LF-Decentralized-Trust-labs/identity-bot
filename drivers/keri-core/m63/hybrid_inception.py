"""Build M63 KERI-conformant hybrid icp — keripy reference (keri==1.1.17)."""

from __future__ import annotations

import base64
from dataclasses import dataclass
from typing import Any

from keri.core import coring, serdering
from keri.core.coring import Diger, Ilks, MtrDex, Serials, Verfer, versify
from keri.kering import Version

from .cesr import (
    CESR_MLDSA65_VERKEY,
    CESR_MLKEM768_ENCAP,
    CESR_X25519_PUBKEY,
    CIPHER_SUITE_IA_HYBRID_1,
    MLDSA65_VERKEY_BYTES,
    MLKEM768_ENCAP_BYTES,
    X25519_PUBKEY_BYTES,
    encode_large_fixed,
)


@dataclass(frozen=True)
class HybridKeyMaterial:
    """Raw key bytes for a hybrid inception (synthetic or caller-supplied)."""

    ed25519_signing_raw: bytes
    mldsa65_signing_raw: bytes
    x25519_agreement_raw: bytes
    mlkem768_encap_raw: bytes
    next_ed25519_signing_raw: bytes
    next_mldsa65_signing_raw: bytes


def synthetic_hybrid_key_material(seed: int = 0) -> HybridKeyMaterial:
    """Deterministic synthetic key material for harness vectors (not production keys)."""

    def fill(n: int, tag: int) -> bytes:
        return bytes([(seed + tag + i) % 256 for i in range(n)])

    return HybridKeyMaterial(
        ed25519_signing_raw=fill(32, 0x01),
        mldsa65_signing_raw=fill(MLDSA65_VERKEY_BYTES, 0x02),
        x25519_agreement_raw=fill(X25519_PUBKEY_BYTES, 0x03),
        mlkem768_encap_raw=fill(MLKEM768_ENCAP_BYTES, 0x04),
        next_ed25519_signing_raw=fill(32, 0x11),
        next_mldsa65_signing_raw=fill(MLDSA65_VERKEY_BYTES, 0x12),
    )


def _ed25519_verfer_qb64(raw32: bytes) -> str:
    if len(raw32) != 32:
        raise ValueError("Ed25519 public key must be 32 bytes")
    return Verfer(raw=raw32, code=MtrDex.Ed25519).qb64


def _blake3_digest_qb64(data: bytes) -> str:
    return Diger(ser=data, code=MtrDex.Blake3_256).qb64


def material_to_cesr(material: HybridKeyMaterial) -> dict[str, str]:
    ed_q = _ed25519_verfer_qb64(material.ed25519_signing_raw)
    mldsa_q = encode_large_fixed(
        CESR_MLDSA65_VERKEY, material.mldsa65_signing_raw, MLDSA65_VERKEY_BYTES
    )
    x25519_q = encode_large_fixed(
        CESR_X25519_PUBKEY, material.x25519_agreement_raw, X25519_PUBKEY_BYTES
    )
    mlkem_q = encode_large_fixed(
        CESR_MLKEM768_ENCAP, material.mlkem768_encap_raw, MLKEM768_ENCAP_BYTES
    )
    n_ed = _blake3_digest_qb64(material.next_ed25519_signing_raw)
    n_mldsa = _blake3_digest_qb64(material.next_mldsa65_signing_raw)
    return {
        "ed25519_signing": ed_q,
        "mldsa65_signing": mldsa_q,
        "x25519_agreement": x25519_q,
        "mlkem768_encap": mlkem_q,
        "next_ed25519_digest": n_ed,
        "next_mldsa65_digest": n_mldsa,
    }


def _hybrid_anchor(cesr: dict[str, str]) -> list[dict[str, Any]]:
    """IA-HYBRID-1 cipher-suite tag + KA keys in standard a anchor (OQ-2 D1)."""
    return [
        {
            "ia": CIPHER_SUITE_IA_HYBRID_1,
            "ka": [cesr["x25519_agreement"], cesr["mlkem768_encap"]],
        }
    ]


def build_hybrid_inception(material: HybridKeyMaterial) -> dict[str, Any]:
    """Return keri 1.1.x conformant hybrid icp via SerderKERI makify."""
    cesr = material_to_cesr(material)
    anchor = _hybrid_anchor(cesr)

    vs = versify(version=Version, kind=Serials.json, size=0)
    ked: dict[str, Any] = {
        "v": vs,
        "t": Ilks.icp,
        "d": "",
        "i": "",
        "s": "0",
        "kt": "1",
        "k": [cesr["ed25519_signing"], cesr["mldsa65_signing"]],
        "nt": "1",
        "n": [cesr["next_ed25519_digest"], cesr["next_mldsa65_digest"]],
        "bt": "0",
        "b": [],
        "c": [],
        "a": anchor,
    }

    serder = serdering.SerderKERI(sad=ked, makify=True)
    serder._verify()

    inception_event = dict(serder.sad)
    said = serder.said
    aid = serder.pre

    return {
        "aid": aid,
        "said": said,
        "inception_event": inception_event,
        "raw_bytes_b64": base64.b64encode(serder.raw).decode("ascii"),
        "cipher_suite": CIPHER_SUITE_IA_HYBRID_1,
        "cesr": cesr,
        "public_key": cesr["ed25519_signing"],
        "next_key_digest": cesr["next_ed25519_digest"],
    }


def generate_hybrid_key_material() -> HybridKeyMaterial:
    """Generate fresh classical + placeholder PQC material (PQC bytes filled for structure)."""
    import pysodium  # lazy: synthetic harness path does not need libsodium

    ed_seed = pysodium.randombytes(32)
    ed_pk, _ = pysodium.crypto_sign_seed_keypair(ed_seed)
    next_ed_seed = pysodium.randombytes(32)
    next_ed_pk, _ = pysodium.crypto_sign_seed_keypair(next_ed_seed)
    return HybridKeyMaterial(
        ed25519_signing_raw=ed_pk,
        mldsa65_signing_raw=pysodium.randombytes(MLDSA65_VERKEY_BYTES),
        x25519_agreement_raw=pysodium.randombytes(X25519_PUBKEY_BYTES),
        mlkem768_encap_raw=pysodium.randombytes(MLKEM768_ENCAP_BYTES),
        next_ed25519_signing_raw=next_ed_pk,
        next_mldsa65_signing_raw=pysodium.randombytes(MLDSA65_VERKEY_BYTES),
    )