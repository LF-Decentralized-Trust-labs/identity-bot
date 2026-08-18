"""Provisional IA-HYBRID-1 CESR codes (C3-pinned wire bytes in golden_vectors.json)."""

from __future__ import annotations

import base64

# Cipher-suite tag (plain JSON field, not CESR-coded).
CIPHER_SUITE_IA_HYBRID_1 = "IA-HYBRID-1"

# FIPS 204 / 203 parameter sizes for level-3 set (ML-DSA-65 + ML-KEM-768).
MLDSA65_VERKEY_BYTES = 1952
MLKEM768_ENCAP_BYTES = 1184
X25519_PUBKEY_BYTES = 32

# CESR codes for the keys an identity publishes.
#
# Which table a primitive belongs in is not a choice — it follows from the raw
# size modulo 3, because the encoding has to land on a 24-bit boundary. 0 mod 3
# takes the `1` table with no lead byte, 2 mod 3 takes `2` with one, 1 mod 3
# takes `3` with two.
#
# These were 1PDA / 1PKM / 1PXB: four-character codes in the `1` table with no
# lead byte, which left every one of them a character short of a whole number of
# base64 quadruples. The specification is explicit that a malformed primitive can
# confuse a parser into a cold-start resync, so the cost was not confined to the
# bad value.
#
# C is the ASSIGNED code for an X25519 public key and always was — a provisional
# one was invented for a key that already had one. 2AAE and 1AAT are what the
# specification's open pull request PROPOSES for ML-DSA-65; unassigned until it
# merges. 2PKM remains ours, because no code for ML-KEM-768 exists or is
# proposed, and a key counterparties encrypt to has to be published somehow.
CESR_X25519_PUBKEY = "C"
CESR_MLDSA65_VERKEY = "2AAE"
CESR_MLDSA65_SIG = "1AAT"
CESR_MLKEM768_ENCAP = "2PKM"

MLDSA65_SIG_BYTES = 3309

# C2 golden-vector deterministic inputs (synthetic — not production keys).
C2_MESSAGE = b"m63-c2-hybrid-signature-golden-vector"
C2_ED25519_SEED = bytes([(i + 0x21) % 256 for i in range(32)])
C2_MLDSA_SEED = b"m63-c2-hybrid-signature-golden!!"

CTR_CONTROLLER_IDX_SIGS = "-A"


def encode_large_fixed(code: str, raw: bytes, expected_len: int | None = None) -> str:
    """Encode raw bytes as CESR, with the lead bytes the size requires.

    Mirrors keripy's Matter._infil. The previous version concatenated the code
    with raw base64 and emitted no lead bytes, which is correct only when the
    raw size divides by three.
    """
    if not code:
        raise ValueError("a CESR code is required")
    if expected_len is not None and len(raw) != expected_len:
        raise ValueError(f"expected {expected_len} raw bytes for {code}, got {len(raw)}")
    ps = (3 - (len(raw) % 3)) % 3
    b64 = base64.urlsafe_b64encode(bytes(ps) + raw).decode("ascii").rstrip("=")
    return code + b64[len(code) % 4:]


def decode_large_fixed(cesr: str, code: str, expected_len: int | None = None) -> bytes:
    if not cesr.startswith(code):
        raise ValueError(f"expected CESR prefix {code}, got {cesr[:4]!r}")
    body = "A" * (len(code) % 4) + cesr[len(code):]
    pad = "=" * ((4 - (len(body) % 4)) % 4)
    raw = base64.urlsafe_b64decode(body + pad)
    if expected_len is not None and len(raw) > expected_len:
        raw = raw[len(raw) - expected_len:]
    if expected_len is not None and len(raw) != expected_len:
        raise ValueError(f"decoded length {len(raw)} != expected {expected_len}")
    return raw