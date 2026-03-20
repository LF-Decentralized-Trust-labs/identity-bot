"""
Phase 4 — ACDC Credential Issuance interoperability tests.

Verifies:
  - ACDC credential body SAID is computed correctly with keripy Diger (Blake3_256)
  - SAID is self-addressing: blank → compute → embed → recompute → same value
  - Attribute block SAID is computed and embedded separately
  - IXN seal anchors the credential SAID in the issuer's KEL
  - IXN event signed with Dart-path key verifies correctly
  - Full chain: ACDC → SAID → IXN seal → signature is valid
  - Tampering the credential body changes the SAID (integrity protected)
"""

import copy
import json
import pytest
import pysodium
from keri.core import coring, eventing
from keri.core.coring import MtrDex

from conftest import SEED_ISSUER, derive_key, compute_said

SCHEMA_SAID = "EFgnk_c08WmZGgv9_mpldibingSchemaXXXXXXXXXXXXXX"


# ---------------------------------------------------------------------------
# Module-scoped fixtures
# ---------------------------------------------------------------------------

@pytest.fixture(scope="module")
def acdc(issuer, holder):
    body = {
        "v": "ACDC10JSON000000_",
        "d": "",
        "i": issuer["aid"],
        "s": SCHEMA_SAID,
        "a": {
            "d": "",
            "i": holder["aid"],
            "name": "Alice Smith",
            "studentId": "S-12345",
            "degree": "Bachelor of Science",
            "graduationYear": 2025,
        },
    }
    # Compute attribute block SAID
    body["a"]["d"] = compute_said(body["a"])
    # Compute top-level SAID
    said = compute_said(body)
    body["d"] = said
    return body


@pytest.fixture(scope="module")
def ixn_for_credential(issuer, acdc):
    seal = {"d": acdc["d"]}
    return eventing.interact(
        pre=issuer["aid"],
        dig=issuer["icp"].said,
        sn=1,
        data=[seal],
    )


# ---------------------------------------------------------------------------
# Step 1: ACDC SAID computation
# ---------------------------------------------------------------------------

def test_acdc_said_is_non_empty(acdc):
    assert bool(acdc["d"])


def test_acdc_said_starts_with_e(acdc):
    """Blake3_256 SAID code is 'E' per KERI spec Matter code table."""
    assert acdc["d"].startswith("E"), f"Got prefix: {acdc['d'][:5]}"


def test_acdc_said_is_44_chars(acdc):
    assert len(acdc["d"]) == 44, f"Got: {len(acdc['d'])}"


def test_attribute_block_said_is_embedded(acdc):
    assert acdc["a"]["d"].startswith("E")
    assert len(acdc["a"]["d"]) == 44


# ---------------------------------------------------------------------------
# Step 2: SAID self-addressing integrity
# ---------------------------------------------------------------------------

def test_said_is_self_addressing(acdc):
    """Blanking 'd' and recomputing must reproduce the same SAID."""
    blank = copy.deepcopy(acdc)
    blank["d"] = ""
    recomputed = compute_said(blank)
    assert recomputed == acdc["d"], (
        f"Embedded: {acdc['d']}\nRecomputed: {recomputed}"
    )


# ---------------------------------------------------------------------------
# Step 3: IXN seal creation
# ---------------------------------------------------------------------------

def test_ixn_type(ixn_for_credential):
    assert ixn_for_credential.ked.get("t") == "ixn"


def test_credential_said_in_ixn_seal(ixn_for_credential, acdc):
    sealed = [s.get("d") for s in ixn_for_credential.ked.get("a", [])]
    assert acdc["d"] in sealed, f"Sealed SAIDs: {sealed}"


# ---------------------------------------------------------------------------
# Step 4: IXN event signing
# ---------------------------------------------------------------------------

def test_ixn_sig_cesr_prefix(issuer, ixn_for_credential):
    _, sk0, _, _, _ = issuer["pk"], issuer["sk"], issuer["verfer"], issuer["icp"], None
    sk0 = issuer["sk"]
    raw_sig = pysodium.crypto_sign_detached(ixn_for_credential.raw, sk0)
    cigar = coring.Cigar(raw=raw_sig, code=MtrDex.Ed25519_Sig)
    assert cigar.qb64.startswith("0B")


def test_keripy_verfer_accepts_ixn_sig_for_credential(issuer, ixn_for_credential):
    sk0 = issuer["sk"]
    vf0 = issuer["verfer"]
    raw_sig = pysodium.crypto_sign_detached(ixn_for_credential.raw, sk0)
    assert vf0.verify(sig=raw_sig, ser=ixn_for_credential.raw)


# ---------------------------------------------------------------------------
# Step 5: Full issuance chain integrity
# ---------------------------------------------------------------------------

def test_full_issuance_chain_is_valid(issuer, acdc, ixn_for_credential):
    sk0 = issuer["sk"]
    vf0 = issuer["verfer"]
    icp = issuer["icp"]
    raw_sig = pysodium.crypto_sign_detached(ixn_for_credential.raw, sk0)

    found_in_seal = any(
        s.get("d") == acdc["d"] for s in ixn_for_credential.ked.get("a", [])
    )
    chain_valid = ixn_for_credential.ked.get("p") == icp.said
    sig_valid   = vf0.verify(sig=raw_sig, ser=ixn_for_credential.raw)

    assert found_in_seal, "Credential SAID not found in IXN seal"
    assert chain_valid, "IXN prior does not match ICP SAID"
    assert sig_valid, "IXN signature invalid"


# ---------------------------------------------------------------------------
# Step 6: Tampered credential changes SAID
# ---------------------------------------------------------------------------

def test_tampered_credential_produces_different_said(acdc):
    tampered = copy.deepcopy(acdc)
    tampered["a"]["degree"] = "Doctor of Philosophy"
    tampered_said = compute_said({**tampered, "d": ""})
    assert tampered_said != acdc["d"]


def test_tampered_said_not_in_ixn_seal(acdc, ixn_for_credential):
    tampered = copy.deepcopy(acdc)
    tampered["a"]["degree"] = "Doctor of Philosophy"
    tampered_said = compute_said({**tampered, "d": ""})
    sealed = [s.get("d") for s in ixn_for_credential.ked.get("a", [])]
    assert tampered_said not in sealed
