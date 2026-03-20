"""
Phase 1 — CESR Signing interoperability tests.

Verifies:
  - keripy native signing produces CESR-encoded Ed25519 signatures
  - pysodium raw signatures wrapped in coring.Siger are identical
  - keripy verifier accepts both signing paths
  - Dart seed derivation path (sha256 of seed) produces valid keripy keys
  - A signed inception event verifies correctly
"""

import hashlib
import pytest
import pysodium
from keri.core import coring, eventing
from keri.core.coring import MtrDex

from conftest import SEED_ISSUER, derive_key


# ---------------------------------------------------------------------------
# Fixtures local to phase 1
# ---------------------------------------------------------------------------

@pytest.fixture(scope="module")
def keripy_signer():
    return coring.Signer(raw=SEED_ISSUER, code=MtrDex.Ed25519_Seed)


@pytest.fixture(scope="module")
def test_data():
    return b"test message for keri interop verification"


# ---------------------------------------------------------------------------
# Step 1: keripy native signing
# ---------------------------------------------------------------------------

def test_keripy_signer_produces_signature(keripy_signer, test_data):
    sig = keripy_signer.sign(ser=test_data)
    assert sig is not None


def test_keripy_sig_cesr_prefix(keripy_signer, test_data):
    """Ed25519 CESR signature code is '0B' per KERI spec Matter code table."""
    sig = keripy_signer.sign(ser=test_data)
    assert sig.qb64.startswith("0B"), f"Expected '0B' prefix, got: {sig.qb64[:10]}"


def test_keripy_sig_cesr_length(keripy_signer, test_data):
    """Ed25519 CESR signature is 88 characters (2-char code + 86 base64 chars)."""
    sig = keripy_signer.sign(ser=test_data)
    assert len(sig.qb64) == 88, f"Expected 88 chars, got: {len(sig.qb64)}"


def test_keripy_verfer_accepts_own_signature(keripy_signer, test_data):
    sig = keripy_signer.sign(ser=test_data)
    assert keripy_signer.verfer.verify(sig=sig.raw, ser=test_data)


# ---------------------------------------------------------------------------
# Step 2: pysodium raw sig wrapped in coring.Siger == keripy native
# ---------------------------------------------------------------------------

def test_pysodium_raw_sig_is_64_bytes(test_data):
    pk, sk = pysodium.crypto_sign_seed_keypair(SEED_ISSUER)
    raw_sig = pysodium.crypto_sign_detached(test_data, sk)
    assert len(raw_sig) == 64, f"Expected 64 bytes, got: {len(raw_sig)}"


def test_pysodium_wrapped_sig_equals_keripy_native(keripy_signer, test_data):
    """pysodium + coring.Cigar wrapper produces the identical CESR output as keripy native.

    Note: use Cigar (non-indexed, code='0B') not Siger (indexed, code='AA').
    keripy's signer.sign() returns a non-indexed Cigar-style signature.
    """
    keripy_cesr = keripy_signer.sign(ser=test_data).qb64

    pk, sk = pysodium.crypto_sign_seed_keypair(SEED_ISSUER)
    raw_sig = pysodium.crypto_sign_detached(test_data, sk)
    wrapped_cesr = coring.Cigar(raw=raw_sig, code=MtrDex.Ed25519_Sig).qb64

    assert wrapped_cesr == keripy_cesr, (
        f"keripy: {keripy_cesr}\nwrapped: {wrapped_cesr}"
    )


def test_keripy_verfer_accepts_pysodium_sig(keripy_signer, test_data):
    pk, sk = pysodium.crypto_sign_seed_keypair(SEED_ISSUER)
    raw_sig = pysodium.crypto_sign_detached(test_data, sk)
    assert keripy_signer.verfer.verify(sig=raw_sig, ser=test_data)


def test_pysodium_pubkey_matches_keripy_verfer(keripy_signer):
    pk, _ = pysodium.crypto_sign_seed_keypair(SEED_ISSUER)
    assert pk == keripy_signer.verfer.raw


# ---------------------------------------------------------------------------
# Step 3: CESR public key encoding
# ---------------------------------------------------------------------------

def test_verfer_from_raw_matches_signer_verfer(keripy_signer):
    pk, _ = pysodium.crypto_sign_seed_keypair(SEED_ISSUER)
    verfer = coring.Verfer(raw=pk, code=MtrDex.Ed25519)
    assert verfer.qb64 == keripy_signer.verfer.qb64


def test_ed25519_pubkey_cesr_prefix():
    """Ed25519 public key CESR starts with 'D' in keri==1.1.17.

    Note: keripy main branch uses 'B'. Update when upgrading keri.
    """
    pk, _ = pysodium.crypto_sign_seed_keypair(SEED_ISSUER)
    verfer = coring.Verfer(raw=pk, code=MtrDex.Ed25519)
    assert verfer.qb64.startswith(MtrDex.Ed25519), f"Got prefix: {verfer.qb64[:5]}"


def test_ed25519_pubkey_cesr_length():
    """Ed25519 public key CESR is 44 characters (1-char code + 43 base64 chars)."""
    pk, _ = pysodium.crypto_sign_seed_keypair(SEED_ISSUER)
    verfer = coring.Verfer(raw=pk, code=MtrDex.Ed25519)
    assert len(verfer.qb64) == 44, f"Expected 44 chars, got: {len(verfer.qb64)}"


# ---------------------------------------------------------------------------
# Step 4: Dart seed derivation path
# ---------------------------------------------------------------------------

def test_dart_derived_key_produces_valid_sig(test_data):
    pk, sk = derive_key(SEED_ISSUER, 0)
    verfer = coring.Verfer(raw=pk, code=MtrDex.Ed25519)
    raw_sig = pysodium.crypto_sign_detached(test_data, sk)
    assert verfer.verify(sig=raw_sig, ser=test_data)


def test_dart_derived_sig_has_correct_cesr_prefix(test_data):
    pk, sk = derive_key(SEED_ISSUER, 0)
    raw_sig = pysodium.crypto_sign_detached(test_data, sk)
    cigar = coring.Cigar(raw=raw_sig, code=MtrDex.Ed25519_Sig)
    assert cigar.qb64.startswith("0B")


def test_keripy_rejects_wrong_key_signature(test_data):
    """Signature from one key must not verify against a different key."""
    pk0, sk0 = derive_key(SEED_ISSUER, 0)
    pk1, sk1 = derive_key(SEED_ISSUER, 1)
    vf0 = coring.Verfer(raw=pk0, code=MtrDex.Ed25519)

    dart_sig = pysodium.crypto_sign_detached(test_data, sk1)
    assert not vf0.verify(sig=dart_sig, ser=test_data)


# ---------------------------------------------------------------------------
# Step 5: Full signed inception event
# ---------------------------------------------------------------------------

def test_signed_inception_event_verifies(issuer):
    """A full inception event signed with the Dart derivation path verifies."""
    icp = issuer["icp"]
    pk, sk = derive_key(SEED_ISSUER, 0)
    verfer = issuer["verfer"]

    sig_raw = pysodium.crypto_sign_detached(icp.raw, sk)
    assert verfer.verify(sig=sig_raw, ser=icp.raw)


def test_inception_aid_is_non_empty(issuer):
    assert len(issuer["aid"]) > 0


def test_inception_sig_has_correct_cesr_prefix(issuer):
    pk, sk = derive_key(SEED_ISSUER, 0)
    sig_raw = pysodium.crypto_sign_detached(issuer["icp"].raw, sk)
    cigar = coring.Cigar(raw=sig_raw, code=MtrDex.Ed25519_Sig)
    assert cigar.qb64.startswith("0B")
