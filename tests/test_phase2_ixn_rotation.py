"""
Phase 2 — IXN Events + Key Rotation interoperability tests.

Verifies:
  - keripy creates valid IXN (interaction) events
  - Dart-path signing of IXN events verifies with keripy
  - keripy creates valid rotation events committing a pre-rotated key
  - Rotation events are signed with the pre-rotated key (not the current key)
  - Pre-rotation commitment (Blake3_256 digest) is verifiable
  - Post-rotation events require the new key; old key is rejected
"""

import pytest
import pysodium
from keri.core import coring, eventing
from keri.core.coring import MtrDex

from conftest import SEED_ISSUER, derive_key


# ---------------------------------------------------------------------------
# Module-scoped fixtures: key material and events built once for all tests
# ---------------------------------------------------------------------------

@pytest.fixture(scope="module")
def keys():
    pk0, sk0 = derive_key(SEED_ISSUER, 0)
    pk1, sk1 = derive_key(SEED_ISSUER, 1)
    pk2, sk2 = derive_key(SEED_ISSUER, 2)
    return {
        0: (pk0, sk0, coring.Verfer(raw=pk0, code=MtrDex.Ed25519)),
        1: (pk1, sk1, coring.Verfer(raw=pk1, code=MtrDex.Ed25519)),
        2: (pk2, sk2, coring.Verfer(raw=pk2, code=MtrDex.Ed25519)),
    }


@pytest.fixture(scope="module")
def icp(keys):
    pk0, sk0, vf0 = keys[0]
    pk1, _, _     = keys[1]
    d1 = coring.Diger(raw=pk1, code=MtrDex.Blake3_256)
    return eventing.incept(keys=[vf0.qb64], ndigs=[d1.qb64], code=MtrDex.Blake3_256)


@pytest.fixture(scope="module")
def ixn(icp):
    return eventing.interact(
        pre=icp.pre,
        dig=icp.said,
        sn=1,
        data=[{"d": "EsomethingFromCredentialSAID00000000000000000"}],
    )


@pytest.fixture(scope="module")
def rot(icp, keys):
    pk1, _, vf1 = keys[1]
    pk2, _, vf2 = keys[2]
    d2 = coring.Diger(raw=pk2, code=MtrDex.Blake3_256)
    return eventing.rotate(
        pre=icp.pre,
        keys=[vf1.qb64],
        dig=icp.said,
        ndigs=[d2.qb64],
        sn=1,
    )


# ---------------------------------------------------------------------------
# Step 1: IXN event structure
# ---------------------------------------------------------------------------

def test_ixn_type(ixn):
    assert ixn.ked.get("t") == "ixn"


def test_ixn_sequence_number(ixn):
    assert ixn.ked.get("s") == "1"


def test_ixn_prior_matches_icp_said(ixn, icp):
    assert ixn.ked.get("p") == icp.said, (
        f"ICP SAID: {icp.said}\nIXN prior: {ixn.ked.get('p')}"
    )


def test_ixn_raw_is_non_empty(ixn):
    assert len(ixn.raw) > 0


# ---------------------------------------------------------------------------
# Step 2: IXN event signing
# ---------------------------------------------------------------------------

def test_ixn_sig_is_64_bytes(ixn, keys):
    _, sk0, _ = keys[0]
    raw_sig = pysodium.crypto_sign_detached(ixn.raw, sk0)
    assert len(raw_sig) == 64


def test_ixn_sig_cesr_prefix(ixn, keys):
    _, sk0, _ = keys[0]
    raw_sig = pysodium.crypto_sign_detached(ixn.raw, sk0)
    cigar = coring.Cigar(raw=raw_sig, code=MtrDex.Ed25519_Sig)
    assert cigar.qb64.startswith("0B")


def test_ixn_sig_cesr_length(ixn, keys):
    _, sk0, _ = keys[0]
    raw_sig = pysodium.crypto_sign_detached(ixn.raw, sk0)
    cigar = coring.Cigar(raw=raw_sig, code=MtrDex.Ed25519_Sig)
    assert len(cigar.qb64) == 88


def test_keripy_verfer0_accepts_ixn_sig(ixn, keys):
    _, sk0, vf0 = keys[0]
    raw_sig = pysodium.crypto_sign_detached(ixn.raw, sk0)
    assert vf0.verify(sig=raw_sig, ser=ixn.raw)


def test_keripy_rejects_ixn_sig_from_wrong_key(ixn, keys):
    _, sk0, _  = keys[0]
    _, _,  vf1 = keys[1]
    raw_sig = pysodium.crypto_sign_detached(ixn.raw, sk0)
    assert not vf1.verify(sig=raw_sig, ser=ixn.raw)


# ---------------------------------------------------------------------------
# Step 3: Rotation event structure
# ---------------------------------------------------------------------------

def test_rot_type(rot):
    assert rot.ked.get("t") == "rot"


def test_rot_sequence_number(rot):
    assert rot.ked.get("s") == "1"


def test_rot_keys_contains_new_verfer(rot, keys):
    _, _, vf1 = keys[1]
    assert vf1.qb64 in rot.ked.get("k", [])


def test_rot_ndigs_contains_next_digest(rot, keys):
    pk2, _, _ = keys[2]
    d2 = coring.Diger(raw=pk2, code=MtrDex.Blake3_256)
    assert d2.qb64 in rot.ked.get("n", [])


# ---------------------------------------------------------------------------
# Step 4: Rotation event signed with pre-rotated key (key1)
# ---------------------------------------------------------------------------

def test_rot_sig_verifies_with_prerotated_key(rot, keys):
    _, sk1, vf1 = keys[1]
    raw_sig = pysodium.crypto_sign_detached(rot.raw, sk1)
    assert vf1.verify(sig=raw_sig, ser=rot.raw)


# ---------------------------------------------------------------------------
# Step 5: Pre-rotation commitment check
# ---------------------------------------------------------------------------

def test_prerotation_digest_matches_inception_commitment(icp, keys):
    pk1, _, _ = keys[1]
    d1_recomputed = coring.Diger(raw=pk1, code=MtrDex.Blake3_256)
    assert d1_recomputed.qb64 in icp.ked.get("n", []), (
        f"ICP ndigs: {icp.ked.get('n')}\nRecomputed: {d1_recomputed.qb64}"
    )


# ---------------------------------------------------------------------------
# Step 6: Post-rotation signing uses new key (key1)
# ---------------------------------------------------------------------------

def test_post_rotation_ixn_verifies_with_new_key(rot, icp, keys):
    _, sk1, vf1 = keys[1]
    ixn2 = eventing.interact(pre=icp.pre, dig=rot.said, sn=2, data=[])
    sig = pysodium.crypto_sign_detached(ixn2.raw, sk1)
    assert vf1.verify(sig=sig, ser=ixn2.raw)


def test_post_rotation_ixn_rejected_by_old_key(rot, icp, keys):
    _, sk1, _  = keys[1]
    _, _, vf0  = keys[0]
    ixn2 = eventing.interact(pre=icp.pre, dig=rot.said, sn=2, data=[])
    sig_with_key1 = pysodium.crypto_sign_detached(ixn2.raw, sk1)
    assert not vf0.verify(sig=sig_with_key1, ser=ixn2.raw)


# ---------------------------------------------------------------------------
# Step 7: Wrong-key rotation rejection
# ---------------------------------------------------------------------------

def test_rotation_signed_with_old_key_rejected_by_new_verfer(rot, keys):
    _, sk0, _  = keys[0]
    _, _, vf1  = keys[1]
    wrong_sig = pysodium.crypto_sign_detached(rot.raw, sk0)
    assert not vf1.verify(sig=wrong_sig, ser=rot.raw)
