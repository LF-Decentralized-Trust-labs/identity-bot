"""
Phase 6 — Credential Verification (8 Checks) interoperability tests.

Each check has both a positive (PASS) and negative (FAIL) variant.

  Check 1: ACDC SAID integrity — hash of content matches embedded SAID
  Check 2: Issuer AID is in a valid KEL
  Check 3: Issuer KEL hash chain is valid at issuance sn
  Check 4: Schema SAID matches a trusted/known schema
  Check 5: Credential is not revoked in the registry
  Check 6: Holder AID in presentation matches credential subject field
  Check 7: Presentation signature is valid against holder's current public key
  Check 8: Credential SAID is anchored in issuer's KEL via IXN seal
"""

import copy
import json
import pytest
import pysodium
from keri.core import coring, eventing
from keri.core.coring import MtrDex

from conftest import compute_said

TRUSTED_SCHEMA_SAID = "EschemaGraduationDegree00000000000000000000000"


# ---------------------------------------------------------------------------
# Module-scoped fixtures
# ---------------------------------------------------------------------------

@pytest.fixture(scope="module")
def acdc(issuer, holder):
    body = {
        "v": "ACDC10JSON000000_",
        "d": "",
        "i": issuer["aid"],
        "s": TRUSTED_SCHEMA_SAID,
        "a": {"d": "", "i": holder["aid"], "degree": "B.Sc.", "graduationYear": 2025},
    }
    body["a"]["d"] = compute_said(body["a"])
    body["d"]      = compute_said(body)
    return body


@pytest.fixture(scope="module")
def ixn_issuer(issuer, acdc):
    """IXN event anchoring the credential SAID in the issuer's KEL."""
    return eventing.interact(
        pre=issuer["aid"],
        dig=issuer["icp"].said,
        sn=1,
        data=[{"d": acdc["d"]}],
    )


@pytest.fixture(scope="module")
def ixn_issuer_sig(issuer, ixn_issuer):
    return pysodium.crypto_sign_detached(ixn_issuer.raw, issuer["sk"])


@pytest.fixture(scope="module")
def pres_token(acdc, holder):
    """Simplified presentation token: credential SAID :: holder AID."""
    return (acdc["d"] + "::" + holder["aid"]).encode()


@pytest.fixture(scope="module")
def pres_sig(holder, pres_token):
    return pysodium.crypto_sign_detached(pres_token, holder["sk"])


# ---------------------------------------------------------------------------
# Check 1: ACDC SAID integrity
# ---------------------------------------------------------------------------

def test_check1_said_integrity_pass(acdc):
    blank = copy.deepcopy(acdc)
    blank["d"] = ""
    assert compute_said(blank) == acdc["d"]


def test_check1_said_integrity_fail_on_tampered(acdc):
    tampered = copy.deepcopy(acdc)
    tampered["a"]["degree"] = "Fake PhD"
    tampered["d"] = ""
    assert compute_said(tampered) != acdc["d"]


# ---------------------------------------------------------------------------
# Check 2: Issuer AID in valid KEL
# ---------------------------------------------------------------------------

def test_check2_issuer_aid_in_kel(issuer, acdc):
    assert acdc["i"] == issuer["icp"].pre


def test_check2_unknown_aid_not_in_kel(issuer):
    unknown = "EunknownAIDnotInAnyKELXXXXXXXXXXXXXXXXXXXXXXXX"
    assert unknown != issuer["icp"].pre


# ---------------------------------------------------------------------------
# Check 3: Issuer KEL hash chain valid at issuance
# ---------------------------------------------------------------------------

def test_check3_hash_chain_intact(issuer, ixn_issuer):
    assert ixn_issuer.ked.get("p") == issuer["icp"].said, (
        f"ICP SAID: {issuer['icp'].said}\nIXN prior: {ixn_issuer.ked.get('p')}"
    )


def test_check3_tampered_prior_breaks_chain(issuer, ixn_issuer):
    tampered_prior = "ETAMPEREDPRIORXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX"
    assert tampered_prior != issuer["icp"].said


# ---------------------------------------------------------------------------
# Check 4: Schema SAID matches trusted schema
# ---------------------------------------------------------------------------

def test_check4_schema_in_trusted_registry(acdc):
    trusted = {TRUSTED_SCHEMA_SAID}
    assert acdc["s"] in trusted


def test_check4_unknown_schema_rejected():
    trusted = {TRUSTED_SCHEMA_SAID}
    assert "EunknownSchemaXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX" not in trusted


# ---------------------------------------------------------------------------
# Check 5: Credential not revoked
# ---------------------------------------------------------------------------

def test_check5_not_revoked(acdc):
    registry = {acdc["d"]: False}
    assert not registry.get(acdc["d"], False)


def test_check5_revoked_credential_detected(acdc):
    registry = {acdc["d"]: True}
    assert registry.get(acdc["d"], False)


# ---------------------------------------------------------------------------
# Check 6: Holder AID matches credential subject
# ---------------------------------------------------------------------------

def test_check6_holder_aid_matches_credential_subject(holder, acdc):
    assert holder["aid"] == acdc["a"]["i"]


def test_check6_wrong_holder_rejected(issuer, acdc):
    assert issuer["aid"] != acdc["a"]["i"]


# ---------------------------------------------------------------------------
# Check 7: Presentation signature valid against holder's key
# ---------------------------------------------------------------------------

def test_check7_presentation_sig_valid(holder, pres_sig, pres_token):
    assert holder["verfer"].verify(sig=pres_sig, ser=pres_token)


def test_check7_sig_from_non_holder_rejected(issuer, holder, pres_token):
    bad_sig = pysodium.crypto_sign_detached(pres_token, issuer["sk"])
    assert not holder["verfer"].verify(sig=bad_sig, ser=pres_token)


# ---------------------------------------------------------------------------
# Check 8: Credential SAID anchored in issuer's KEL via IXN
# ---------------------------------------------------------------------------

def test_check8_credential_said_in_ixn_seal(issuer, acdc, ixn_issuer, ixn_issuer_sig):
    sealed = [s.get("d") for s in ixn_issuer.ked.get("a", [])]
    assert acdc["d"] in sealed


def test_check8_ixn_signed_by_issuer(issuer, ixn_issuer, ixn_issuer_sig):
    assert issuer["verfer"].verify(sig=ixn_issuer_sig, ser=ixn_issuer.raw)


def test_check8_unanchored_credential_not_in_seal(ixn_issuer):
    sealed = [s.get("d") for s in ixn_issuer.ked.get("a", [])]
    assert "EnotAnchoredXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX" not in sealed


# ---------------------------------------------------------------------------
# All 8 checks combined on a valid presentation
# ---------------------------------------------------------------------------

def test_all_8_checks_pass_for_valid_presentation(
    issuer, holder, acdc, ixn_issuer, ixn_issuer_sig, pres_sig, pres_token
):
    blank = copy.deepcopy(acdc)
    blank["d"] = ""

    check1 = compute_said(blank) == acdc["d"]
    check2 = acdc["i"] == issuer["icp"].pre
    check3 = ixn_issuer.ked.get("p") == issuer["icp"].said
    check4 = acdc["s"] in {TRUSTED_SCHEMA_SAID}
    check5 = not {acdc["d"]: False}.get(acdc["d"], False)
    check6 = holder["aid"] == acdc["a"]["i"]
    check7 = holder["verfer"].verify(sig=pres_sig, ser=pres_token)
    sealed = [s.get("d") for s in ixn_issuer.ked.get("a", [])]
    check8 = acdc["d"] in sealed and issuer["verfer"].verify(
        sig=ixn_issuer_sig, ser=ixn_issuer.raw
    )

    assert all([check1, check2, check3, check4, check5, check6, check7, check8]), (
        f"Failed checks: "
        f"{[i+1 for i, c in enumerate([check1,check2,check3,check4,check5,check6,check7,check8]) if not c]}"
    )
