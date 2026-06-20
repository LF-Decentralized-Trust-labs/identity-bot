"""Provisional IA-HYBRID-1 CESR codes (C3-pinned wire bytes in golden_vectors.json)."""

from __future__ import annotations

import base64

# Cipher-suite tag (plain JSON field, not CESR-coded).
CIPHER_SUITE_IA_HYBRID_1 = "IA-HYBRID-1"

# FIPS 204 / 203 parameter sizes for level-3 set (ML-DSA-65 + ML-KEM-768).
MLDSA65_VERKEY_BYTES = 1952
MLKEM768_ENCAP_BYTES = 1184
X25519_PUBKEY_BYTES = 32

# Provisional large-fixed CESR selectors (C3-pinned: 1PDA / 1PKM / 1PXB).
CESR_MLDSA65_VERKEY = "1PDA"
CESR_MLDSA65_SIG = "1PDS"
CESR_MLKEM768_ENCAP = "1PKM"
CESR_X25519_PUBKEY = "1PXB"

MLDSA65_SIG_BYTES = 3309

# C2 golden-vector deterministic inputs (synthetic — not production keys).
C2_MESSAGE = b"m63-c2-hybrid-signature-golden-vector"
C2_ED25519_SEED = bytes([(i + 0x21) % 256 for i in range(32)])
C2_MLDSA_SEED = b"m63-c2-hybrid-signature-golden!!"

CTR_CONTROLLER_IDX_SIGS = "-A"


def encode_large_fixed(code: str, raw: bytes, expected_len: int | None = None) -> str:
    """Encode raw bytes as IA-HYBRID-1 provisional large-fixed CESR material."""
    if len(code) != 4:
        raise ValueError(f"provisional CESR code must be 4 chars, got {code!r}")
    if expected_len is not None and len(raw) != expected_len:
        raise ValueError(f"expected {expected_len} raw bytes for {code}, got {len(raw)}")
    b64 = base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")
    return code + b64


def decode_large_fixed(cesr: str, code: str, expected_len: int | None = None) -> bytes:
    if not cesr.startswith(code):
        raise ValueError(f"expected CESR prefix {code}, got {cesr[:4]!r}")
    pad = "=" * ((4 - (len(cesr[4:]) % 4)) % 4)
    raw = base64.urlsafe_b64decode(cesr[4:] + pad)
    if expected_len is not None and len(raw) != expected_len:
        raise ValueError(f"decoded length {len(raw)} != expected {expected_len}")
    return raw