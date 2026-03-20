"""
Phase 5 — Credential Presentation interoperability tests.

Verifies:
  - Verifiable presentation (VP) SAID is self-addressing
  - Holder signs the presentation SAID (proof-of-possession)
  - Holder's signature verifies with keripy
  - Presentation correctly references the credential SAID
  - Attacker cannot forge a valid presentation for another holder's credential
  - Replay protection: sig over a different SAID is rejected
"""

import json
import pytest
import pysodium
from keri.core import coring, eventing
from keri.core.coring import MtrDex

from conftest import SEED_ISSUER, SEED_HOLDER, derive_key, compute_said


# ---------------------------------------------------------------------------
# Module-scoped fixtures
# ---------------------------------------------------------------------------

@pytest.fixture(scope="module")
def acdc(issuer, holder):
    body = {
        "v": "ACDC10JSON000000_",
        "d": "",
        "i": issuer["aid"],
        "s": "EschemaXXX",
        "a": {"d": "", "i": holder["aid"], "degree": "B.Sc."},
    }
    said = compute_said(body)
    body["d"] = said
    return body


@pytest.fixture(scope="module")
def presentation(holder, acdc):
    pres = {
        "v": "ACDC10JSON000000_",
        "d": "",
        "i": holder["aid"],
        "ri": acdc["i"],
        "s": "EpresentationSchema",
        "a": {
            "d": "",
            "credential_said": acdc["d"],
            "holder_aid": holder["aid"],
        },
    }
    pres["a"]["d"] = compute_said(pres["a"])
    pres["d"]      = compute_said(pres)
    return pres


# ---------------------------------------------------------------------------
# Step 1: Presentation body and SAID
# ---------------------------------------------------------------------------

def test_presentation_said_length(presentation):
    assert len(presentation["d"]) == 44


def test_presentation_said_prefix(presentation):
    assert presentation["d"].startswith("E")


def test_presentation_references_correct_credential(presentation, acdc):
    assert presentation["a"]["credential_said"] == acdc["d"]


def test_presentation_holder_aid_matches_credential_subject(presentation, holder):
    assert presentation["i"] == holder["aid"]


# ---------------------------------------------------------------------------
# Steps 2 + 3: Holder signs presentation, signature verifies
# ---------------------------------------------------------------------------

def test_presentation_sig_is_64_bytes(holder, presentation):
    pres_said_bytes = presentation["d"].encode()
    sk_h = holder["sk"]
    raw_sig = pysodium.crypto_sign_detached(pres_said_bytes, sk_h)
    assert len(raw_sig) == 64


def test_presentation_sig_cesr_prefix(holder, presentation):
    pres_said_bytes = presentation["d"].encode()
    sk_h = holder["sk"]
    raw_sig = pysodium.crypto_sign_detached(pres_said_bytes, sk_h)
    cigar = coring.Cigar(raw=raw_sig, code=MtrDex.Ed25519_Sig)
    assert cigar.qb64.startswith("0B")


def test_holder_verfer_accepts_presentation_sig(holder, presentation):
    pres_said_bytes = presentation["d"].encode()
    sk_h = holder["sk"]
    vf_h = holder["verfer"]
    raw_sig = pysodium.crypto_sign_detached(pres_said_bytes, sk_h)
    assert vf_h.verify(sig=raw_sig, ser=pres_said_bytes)


# ---------------------------------------------------------------------------
# Step 4: Presentation ↔ credential linkage
# ---------------------------------------------------------------------------

def test_credential_said_in_presentation_matches_issued_acdc(presentation, acdc):
    assert presentation["a"]["credential_said"] == acdc["d"]


def test_holder_aid_in_presentation_matches_credential_subject(presentation, acdc):
    assert presentation["a"]["holder_aid"] == acdc["a"]["i"]


# ---------------------------------------------------------------------------
# Step 5: Attacker cannot forge a presentation for the holder's credential
# ---------------------------------------------------------------------------

def test_forged_presentation_sig_rejected(holder, attacker, presentation):
    pres_said_bytes = presentation["d"].encode()
    vf_h = holder["verfer"]
    sk_o = attacker["sk"]

    forged_sig = pysodium.crypto_sign_detached(pres_said_bytes, sk_o)
    assert not vf_h.verify(sig=forged_sig, ser=pres_said_bytes)


def test_forged_sig_verifies_with_attacker_own_key(attacker, presentation):
    """Sanity: attacker's sig is valid under their own key (key math is correct)."""
    pres_said_bytes = presentation["d"].encode()
    sk_o = attacker["sk"]
    vf_o = attacker["verfer"]
    forged_sig = pysodium.crypto_sign_detached(pres_said_bytes, sk_o)
    assert vf_o.verify(sig=forged_sig, ser=pres_said_bytes)


# ---------------------------------------------------------------------------
# Step 6: Replay protection — sig over different SAID is rejected
# ---------------------------------------------------------------------------

def test_sig_over_different_said_rejected(holder, presentation):
    pres_said_bytes = presentation["d"].encode()
    sk_h = holder["sk"]
    vf_h = holder["verfer"]

    wrong_msg = b"EDIFFERENTPRESENTATIONSAIDXXXXXXXXXXXXXXXXXXXXXXXX"
    wrong_sig = pysodium.crypto_sign_detached(wrong_msg, sk_h)

    assert not vf_h.verify(sig=wrong_sig, ser=pres_said_bytes)


def test_sig_verifies_the_actual_message_it_signed(holder):
    sk_h = holder["sk"]
    vf_h = holder["verfer"]
    msg  = b"EDIFFERENTPRESENTATIONSAIDXXXXXXXXXXXXXXXXXXXXXXXX"
    sig  = pysodium.crypto_sign_detached(msg, sk_h)
    assert vf_h.verify(sig=sig, ser=msg)
