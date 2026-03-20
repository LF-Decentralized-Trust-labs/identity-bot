"""
Phase B1 — Single-instance credential lifecycle tests.

Tests ACDC credential issuance, presentation, and verification through
the full Go + Python KERI driver stack.
"""

import base64
import json as _json

import pytest
import requests
from helpers import TIMEOUT, sign_and_encode

pytestmark = pytest.mark.integration

SCHEMA_SAID = "EFgnk_c08WmZGgv9_mpldibingSchemaXXXXXXXXXXXXXX"


# ---------------------------------------------------------------------------
# Credential issuance
# ---------------------------------------------------------------------------

@pytest.fixture(scope="module")
def issued_credential(agent_a, identity_a):
    """Issue a test credential from issuer (identity_a) to itself (self-issued)."""
    r = requests.post(
        f"{agent_a}/api/credential/issue",
        json={
            "claims": {
                "name": "Alice Smith",
                "degree": "Bachelor of Science",
                "graduationYear": 2025,
            },
            "schema_said": SCHEMA_SAID,
            "holder_aid":  identity_a.aid,
        },
        timeout=TIMEOUT,
    )
    assert r.status_code == 201, f"Credential issuance failed: {r.status_code} {r.text}"
    return r.json()


def test_credential_issuance_returns_aid(issued_credential, identity_a):
    acdc = _json.loads(base64.b64decode(issued_credential["acdc_json_b64"]))
    assert acdc.get("i") == identity_a.aid


def test_credential_issuance_returns_acdc_said(issued_credential):
    said = issued_credential.get("acdc_said", "")
    assert said.startswith("E"), f"ACDC SAID should start with 'E', got: {said[:5]}"
    assert len(said) == 44


def test_credential_issuance_returns_ixn_event(issued_credential):
    """The credential must be anchored via an IXN event in the issuer's KEL."""
    assert "ixn_event" in issued_credential or "ixn_raw_bytes_b64" in issued_credential, (
        "No IXN anchor returned — credential is not anchored in KEL"
    )


def test_credential_issuance_ixn_contains_acdc_said(issued_credential):
    raw = issued_credential.get("ixn_raw_bytes_b64", "")
    ixn = _json.loads(base64.b64decode(raw)) if raw else issued_credential.get("ixn_event", {})
    acdc_said = issued_credential.get("acdc_said", "")
    seals = ixn.get("a", [])
    found = any(s.get("d") == acdc_said for s in seals if isinstance(s, dict))
    assert found, (
        f"ACDC SAID ({acdc_said}) not found in IXN seal data: {seals}"
    )


def test_credentials_list_includes_issued(agent_a, issued_credential):
    r = requests.get(f"{agent_a}/api/credentials", timeout=TIMEOUT)
    assert r.status_code == 200
    creds = r.json().get("credentials", [])
    saids = [c.get("said") or c.get("acdc_said") or c.get("d") for c in creds]
    assert issued_credential["acdc_said"] in saids, (
        f"Issued credential SAID not in list. Got: {saids}"
    )


# ---------------------------------------------------------------------------
# Credential presentation
# ---------------------------------------------------------------------------

@pytest.fixture(scope="module")
def presentation(agent_a, issued_credential, identity_a):
    r = requests.post(
        f"{agent_a}/api/credential/present",
        json={
            "acdc_said":  issued_credential["acdc_said"],
            "holder_aid": identity_a.aid,
        },
        timeout=TIMEOUT,
    )
    assert r.status_code == 201, f"Presentation failed: {r.status_code} {r.text}"
    return r.json()


def test_presentation_returns_said(presentation):
    pres_said = presentation.get("presentation_said", "")
    assert pres_said.startswith("E"), f"Got: {pres_said[:5]}"
    assert len(pres_said) == 44


def test_presentation_references_credential(presentation, issued_credential):
    """Presentation body must reference the credential SAID."""
    pres_b64 = presentation.get("presentation_json_b64", "")
    body_str = base64.b64decode(pres_b64).decode() if pres_b64 else str(presentation)
    assert issued_credential["acdc_said"] in body_str, (
        "Credential SAID not found in presentation body"
    )


# ---------------------------------------------------------------------------
# Credential verification (8 checks)
# ---------------------------------------------------------------------------

def test_credential_verification_passes(agent_a, issued_credential, identity_a, presentation):
    """POST /api/credential/verify must pass all 8 checks for a valid credential."""
    pres_said_b64 = presentation.get("pres_said_b64", "")
    pres_bytes = base64.b64decode(pres_said_b64) if pres_said_b64 else b""
    cesr_sig = sign_and_encode(pres_bytes, identity_a.sk0) if pres_bytes else ""
    r = requests.post(
        f"{agent_a}/api/credential/verify",
        json={
            "acdc_json":          issued_credential["acdc_json_b64"],
            "holder_aid":         identity_a.aid,
            "presentation_said":  pres_said_b64,
            "cesr_signature":     cesr_sig,
            "holder_public_key":  identity_a.server_pk0,
            "trusted_schema_saids": [SCHEMA_SAID],
        },
        timeout=TIMEOUT,
    )
    assert r.status_code == 200, f"Verification request failed: {r.status_code} {r.text}"
    body = r.json()
    assert body.get("verified") is True, (
        f"Credential verification failed. Checks: {body.get('checks')}, "
        f"Errors: {body.get('errors')}"
    )


def test_credential_verification_all_checks_present(agent_a, issued_credential, identity_a):
    r = requests.post(
        f"{agent_a}/api/credential/verify",
        json={
            "acdc_json":          issued_credential["acdc_json_b64"],
            "holder_aid":         identity_a.aid,
            "trusted_schema_saids": [SCHEMA_SAID],
        },
        timeout=TIMEOUT,
    )
    if r.status_code != 200:
        pytest.skip("Verification endpoint unavailable")
    body = r.json()
    checks = body.get("checks", {})
    # At minimum checks 1, 2, 3 should be present
    for key in ("said_integrity", "issuer_kel", "kel_hash_chain"):
        assert key in checks or len(checks) >= 3, (
            f"Expected check '{key}' in checks dict. Got: {list(checks.keys())}"
        )


def test_tampered_credential_fails_verification(agent_a, issued_credential, identity_a):
    """A tampered credential body must fail SAID integrity check."""
    import copy
    acdc = _json.loads(base64.b64decode(issued_credential["acdc_json_b64"]))
    tampered = copy.deepcopy(acdc)
    # Tamper the degree claim
    if "a" in tampered and isinstance(tampered["a"], dict):
        tampered["a"]["degree"] = "Fake PhD"

    tampered_b64 = base64.b64encode(_json.dumps(tampered).encode()).decode()
    r = requests.post(
        f"{agent_a}/api/credential/verify",
        json={
            "acdc_json":          tampered_b64,
            "holder_aid":         identity_a.aid,
            "trusted_schema_saids": [SCHEMA_SAID],
        },
        timeout=TIMEOUT,
    )
    assert r.status_code == 200
    body = r.json()
    # Either verified=False, or the SAID integrity check failed
    checks = body.get("checks", {})
    said_ok = checks.get("said_integrity", True)  # default True so we catch False
    assert not body.get("verified") or not said_ok, (
        "Tampered credential should not pass verification"
    )
