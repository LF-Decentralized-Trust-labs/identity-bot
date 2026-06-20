"""hybrid PQC C2 — hybrid composite signature wire format + both-must-verify."""

from __future__ import annotations

import base64
from typing import Any

from keri.core.coring import Counter, CtrDex, MtrDex, Signer, Verfer, intToB64

from .cesr import (
    C2_ED25519_SEED,
    C2_MESSAGE,
    C2_MLDSA_SEED,
    CESR_MLDSA65_SIG,
    CIPHER_SUITE_IA_HYBRID_1,
    CTR_CONTROLLER_IDX_SIGS,
    MLDSA65_SIG_BYTES,
)
from .mldsa_crypto import mldsa_sign, mldsa_verkey, mldsa_verify


def is_hybrid_identity(inception_event: dict[str, Any]) -> bool:
    """True when anchor seal carries IA-HYBRID-1 (KERI-conformant gate)."""
    anchors = inception_event.get("a") or []
    if not anchors:
        return False
    seal = anchors[0]
    return isinstance(seal, dict) and seal.get("ia") == CIPHER_SUITE_IA_HYBRID_1


def signing_key_count(inception_event: dict[str, Any]) -> int:
    keys = inception_event.get("k") or []
    return len(keys) if isinstance(keys, list) else 0


def encode_indexed_mldsa_sig(index: int, raw_sig: bytes) -> str:
    if len(raw_sig) != MLDSA65_SIG_BYTES:
        raise ValueError(f"ML-DSA-65 sig must be {MLDSA65_SIG_BYTES} bytes, got {len(raw_sig)}")
    if index < 0 or index > 63:
        raise ValueError(f"index out of range: {index}")
    idx = intToB64(index, l=1)
    body = base64.urlsafe_b64encode(raw_sig).decode("ascii").rstrip("=")
    return CESR_MLDSA65_SIG + idx + body


def decode_indexed_mldsa_sig(wire: str) -> tuple[int, bytes]:
    if len(wire) < 5 or not wire.startswith(CESR_MLDSA65_SIG):
        raise ValueError(f"expected {CESR_MLDSA65_SIG} indexed sig, got {wire[:8]!r}")
    index = _b64_to_int(wire[4:5])
    pad = "=" * ((4 - (len(wire[5:]) % 4)) % 4)
    raw = base64.urlsafe_b64decode(wire[5:] + pad)
    if len(raw) != MLDSA65_SIG_BYTES:
        raise ValueError(f"decoded sig len {len(raw)} != {MLDSA65_SIG_BYTES}")
    return index, raw


def compose_hybrid_signature(ed25519_siger_qb64: str, mldsa_sig_qb64: str) -> str:
    ctr = Counter(code=CtrDex.ControllerIdxSigs, count=2)
    return ctr.qb64 + ed25519_siger_qb64 + mldsa_sig_qb64


def parse_composite_signature(wire: str) -> tuple[str, str]:
    if not wire.startswith(CTR_CONTROLLER_IDX_SIGS):
        raise ValueError("composite signature must start with -A counter")
    count = _b64_to_int(wire[2:4])
    if count != 2:
        raise ValueError(f"expected 2 indexed sigs, counter={count}")
    rest = wire[4:]
    if len(rest) < 88:
        raise ValueError("truncated composite signature")
    ed = rest[:88]
    mldsa = rest[88:]
    if not mldsa.startswith(CESR_MLDSA65_SIG):
        raise ValueError(f"ML-DSA half missing {CESR_MLDSA65_SIG} prefix")
    return ed, mldsa


def sign_hybrid_message(
    msg: bytes = C2_MESSAGE,
    ed25519_seed: bytes = C2_ED25519_SEED,
    mldsa_seed: bytes = C2_MLDSA_SEED,
) -> dict[str, Any]:
    signer = Signer(code=MtrDex.Ed25519_Seed, raw=ed25519_seed)
    ed_siger = signer.sign(ser=msg, index=0, only=True)
    mldsa_raw = mldsa_sign(msg, seed=mldsa_seed)
    mldsa_wire = encode_indexed_mldsa_sig(1, mldsa_raw)
    composite = compose_hybrid_signature(ed_siger.qb64, mldsa_wire)
    return {
        "message_b64": msg.hex(),
        "ed25519_siger": ed_siger.qb64,
        "mldsa65_sig": mldsa_wire,
        "composite_wire": composite,
        "composite_wire_len": len(composite),
    }


def verify_hybrid_signature(
    msg: bytes,
    composite_wire: str,
    ed25519_verkey_raw: bytes,
    mldsa_verkey_raw: bytes,
    *,
    require_hybrid: bool = True,
    inception_event: dict[str, Any] | None = None,
) -> bool:
    if require_hybrid and inception_event is not None:
        if not is_hybrid_identity(inception_event):
            return False
        if signing_key_count(inception_event) != 2:
            return False

    try:
        ed_wire, mldsa_wire = parse_composite_signature(composite_wire)
        ed_siger = _verify_ed25519_siger(ed_wire, ed25519_verkey_raw, msg)
        if not ed_siger:
            return False
        _, mldsa_raw = decode_indexed_mldsa_sig(mldsa_wire)
        return mldsa_verify(mldsa_verkey_raw, msg, mldsa_raw)
    except (ValueError, Exception):
        return False


def c2_signing_verkeys(
    ed25519_seed: bytes = C2_ED25519_SEED,
    mldsa_seed: bytes = C2_MLDSA_SEED,
) -> tuple[bytes, bytes]:
    signer = Signer(code=MtrDex.Ed25519_Seed, raw=ed25519_seed)
    return signer.verfer.raw, mldsa_verkey(mldsa_seed)


def _verify_ed25519_siger(siger_qb64: str, verkey_raw: bytes, msg: bytes) -> bool:
    from keri.core.coring import Siger

    try:
        siger = Siger(qb64=siger_qb64)
        verfer = Verfer(raw=verkey_raw, code=MtrDex.Ed25519)
        return verfer.verify(siger.raw, msg)
    except Exception:
        return False


def _b64_to_int(s: str) -> int:
    from keri.core.coring import B64IdxByChr

    val = 0
    for c in s:
        val = val * 64 + B64IdxByChr[c]
    return val


