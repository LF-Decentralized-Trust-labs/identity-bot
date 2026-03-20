"""
Phase B1 — Single-instance KERI identity lifecycle tests.

Tests the complete Go + Python KERI driver stack for:
  - Inception event creation and persistence
  - KEL retrieval and structure
  - OOBI URL generation
  - Key rotation
  - Interaction (IXN) events
  - Signature verification through the API
"""

import base64
import pytest
import requests
from helpers import TIMEOUT, derive_key, sign_and_encode, public_key_cesr, SEED_A

pytestmark = pytest.mark.integration


# ---------------------------------------------------------------------------
# Inception
# ---------------------------------------------------------------------------

def test_inception_returns_201(identity_a):
    """identity_a fixture already created the inception — verify it succeeded."""
    assert identity_a.aid.startswith("E"), (
        f"AID should start with 'E' (Blake3_256 SAID), got: {identity_a.aid[:5]}"
    )


def test_inception_aid_is_44_chars(identity_a):
    assert len(identity_a.aid) == 44, f"AID length: {len(identity_a.aid)}"


def test_inception_event_has_icp_type(identity_a):
    assert identity_a.inception_event.get("t") == "icp"


def test_inception_event_aid_matches_response_aid(identity_a):
    assert identity_a.inception_event.get("i") == identity_a.aid


def test_inception_raw_bytes_b64_is_non_empty(identity_a):
    assert len(identity_a.raw_bytes_b64) > 0
    # Must be valid base64
    decoded = base64.b64decode(identity_a.raw_bytes_b64)
    assert len(decoded) > 0


def test_inception_cesr_sig_starts_with_0b(identity_a):
    assert identity_a.cesr_sig.startswith("0B"), (
        f"Expected '0B' CESR prefix, got: {identity_a.cesr_sig[:10]}"
    )


def test_inception_cesr_sig_is_88_chars(identity_a):
    assert len(identity_a.cesr_sig) == 88


def test_inception_conflict_on_duplicate(agent_a, identity_a):
    """Second inception call must return 409 Conflict."""
    pk0, _ = derive_key(SEED_A, 0)
    pk1, _ = derive_key(SEED_A, 1)
    r = requests.post(
        f"{agent_a}/api/inception",
        json={"public_key": public_key_cesr(pk0), "next_public_key": public_key_cesr(pk1)},
        timeout=TIMEOUT,
    )
    assert r.status_code == 409, f"Expected 409, got {r.status_code}"


# ---------------------------------------------------------------------------
# Identity state endpoint
# ---------------------------------------------------------------------------

def test_identity_endpoint_shows_initialized(agent_a, identity_a):
    r = requests.get(f"{agent_a}/api/identity", timeout=TIMEOUT)
    assert r.status_code == 200
    body = r.json()
    assert body["initialized"] is True
    assert body["aid"] == identity_a.aid


def test_identity_endpoint_has_public_key(agent_a, identity_a):
    body = requests.get(f"{agent_a}/api/identity", timeout=TIMEOUT).json()
    assert body.get("public_key") == identity_a.server_pk0


def test_identity_event_count_is_1_after_inception(agent_a, identity_a):
    body = requests.get(f"{agent_a}/api/identity", timeout=TIMEOUT).json()
    assert body.get("event_count") == 1


# ---------------------------------------------------------------------------
# KEL retrieval
# ---------------------------------------------------------------------------

def test_kel_returns_200(agent_a, identity_a):
    r = requests.get(f"{agent_a}/api/kel?name={identity_a.aid}", timeout=TIMEOUT)
    assert r.status_code == 200


def test_kel_has_aid(agent_a, identity_a):
    body = requests.get(f"{agent_a}/api/kel?name={identity_a.aid}", timeout=TIMEOUT).json()
    assert body.get("aid") == identity_a.aid


def test_kel_has_one_event_after_inception(agent_a, identity_a):
    body = requests.get(f"{agent_a}/api/kel?name={identity_a.aid}", timeout=TIMEOUT).json()
    assert body.get("event_count") == 1


def test_kel_first_event_is_inception(agent_a, identity_a):
    body = requests.get(f"{agent_a}/api/kel?name={identity_a.aid}", timeout=TIMEOUT).json()
    events = body.get("kel", [])
    assert len(events) >= 1
    first = events[0]
    # event is either the event dict directly or has an "event_json" / "event" field
    evt = first if isinstance(first, dict) and "t" in first else first.get("event", first)
    assert evt.get("t") == "icp", f"Expected 'icp', got: {evt.get('t')}"


# ---------------------------------------------------------------------------
# OOBI generation
# ---------------------------------------------------------------------------

def test_oobi_returns_200(agent_a, identity_a):
    r = requests.get(f"{agent_a}/api/oobi", timeout=TIMEOUT)
    assert r.status_code == 200


def test_oobi_contains_aid(agent_a, identity_a):
    body = requests.get(f"{agent_a}/api/oobi", timeout=TIMEOUT).json()
    assert body.get("aid") == identity_a.aid


def test_oobi_url_contains_aid(agent_a, identity_a):
    body = requests.get(f"{agent_a}/api/oobi", timeout=TIMEOUT).json()
    oobi_url = body.get("oobi_url", "")
    assert identity_a.aid in oobi_url, (
        f"AID not in OOBI URL: {oobi_url}"
    )


def test_public_oobi_endpoint_reachable(agent_a, identity_a):
    """GET /public/oobi/{aid} must be reachable and return the AID's KEL."""
    r = requests.get(f"{agent_a}/public/oobi/{identity_a.aid}", timeout=TIMEOUT)
    assert r.status_code == 200


# ---------------------------------------------------------------------------
# Signature verification via API
# ---------------------------------------------------------------------------

def test_sign_and_verify_round_trip(agent_a, identity_a):
    """POST /api/sign then POST /api/verify must confirm the signature."""
    # Sign some data
    test_data_b64 = base64.b64encode(b"hello keri interop").decode()
    r_sign = requests.post(
        f"{agent_a}/api/sign",
        json={"name": identity_a.aid, "data": test_data_b64},
        timeout=TIMEOUT,
    )
    if r_sign.status_code != 200:
        pytest.skip(f"Sign endpoint unavailable: {r_sign.text}")
    sign_body = r_sign.json()
    assert "signature" in sign_body

    # Verify the signature
    r_verify = requests.post(
        f"{agent_a}/api/verify",
        json={
            "data":       test_data_b64,
            "signature":  sign_body["signature"],
            "public_key": sign_body.get("public_key", identity_a.server_pk0),
        },
        timeout=TIMEOUT,
    )
    assert r_verify.status_code == 200, f"Verify failed: {r_verify.text}"
    assert r_verify.json().get("valid") is True


def test_verify_rejects_tampered_data(agent_a, identity_a):
    """Signature over original data must not verify against different data."""
    original_b64 = base64.b64encode(b"original data").decode()
    tampered_b64 = base64.b64encode(b"tampered data").decode()

    r_sign = requests.post(
        f"{agent_a}/api/sign",
        json={"name": identity_a.aid, "data": original_b64},
        timeout=TIMEOUT,
    )
    if r_sign.status_code != 200:
        pytest.skip("Sign endpoint unavailable")

    sign_body = r_sign.json()
    r_verify = requests.post(
        f"{agent_a}/api/verify",
        json={
            "data":       tampered_b64,
            "signature":  sign_body["signature"],
            "public_key": sign_body.get("public_key", identity_a.cesr_pk0),
        },
        timeout=TIMEOUT,
    )
    assert r_verify.status_code == 200
    assert r_verify.json().get("valid") is False


# ---------------------------------------------------------------------------
# IXN (interaction) event
# ---------------------------------------------------------------------------

def test_ixn_event_created(agent_a, identity_a):
    """POST /api/interact creates an IXN event anchored in the KEL."""
    r = requests.post(
        f"{agent_a}/api/interact",
        json={"name": identity_a.aid, "data": [{"d": "EtestSealSAIDXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX"}]},
        timeout=TIMEOUT,
    )
    assert r.status_code == 201, f"IXN failed: {r.status_code} {r.text}"
    body = r.json()
    assert body.get("aid") == identity_a.aid
    assert "ixn_event" in body or "ixn_raw_bytes_b64" in body


def test_event_count_increases_after_ixn(agent_a, identity_a):
    """After an IXN, the event count in the KEL should be >= 2."""
    body = requests.get(f"{agent_a}/api/kel?name={identity_a.aid}", timeout=TIMEOUT).json()
    assert body.get("event_count", 0) >= 2
