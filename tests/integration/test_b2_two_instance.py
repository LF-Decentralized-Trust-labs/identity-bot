"""
Phase B2 — Two-instance KERI interoperability tests.

Requires two running Identity Agent instances:
  Instance A: AGENT_A_URL (default http://127.0.0.1:5000)
  Instance B: AGENT_B_URL (e.g. http://127.0.0.1:5001)

These tests prove the core interoperability property:
  1. A and B each create independent AIDs
  2. A generates an OOBI URL containing its KEL
  3. B resolves A's OOBI and validates A's KEL — this is the KERI handshake
  4. A resolves B's OOBI — mutual discovery
  5. A issues a credential to B's AID
  6. B presents the credential
  7. B (or A) verifies the credential against A's KEL

This is the minimum viable KERI interop proof. If this passes, the implementation
is interoperable with any KERI implementation that follows the same protocol.

Run with:
  AGENT_B_URL=http://127.0.0.1:5001 python -m pytest tests/integration/ -m two_instance -v
"""

import pytest
import requests
from helpers import TIMEOUT

pytestmark = [pytest.mark.integration, pytest.mark.two_instance]

SCHEMA_SAID = "EFgnk_c08WmZGgv9_mpldibingSchemaXXXXXXXXXXXXXX"


# ---------------------------------------------------------------------------
# Step 1: Both instances have independent AIDs
# ---------------------------------------------------------------------------

def test_instance_a_has_aid(identity_a):
    assert len(identity_a.aid) == 44
    assert identity_a.aid.startswith("E")


def test_instance_b_has_aid(identity_b):
    assert len(identity_b.aid) == 44
    assert identity_b.aid.startswith("E")


def test_a_and_b_have_different_aids(identity_a, identity_b):
    """Two independent Identity Agent instances must have different AIDs."""
    assert identity_a.aid != identity_b.aid, (
        "Instances A and B have the same AID — they may be sharing state. "
        "Ensure each instance has its own AGENT_DATA_DIR."
    )


# ---------------------------------------------------------------------------
# Step 2: OOBI URL generation
# ---------------------------------------------------------------------------

@pytest.fixture(scope="module")
def oobi_a(agent_a, identity_a):
    """OOBI URL for instance A (points to A's /public/oobi/{aid})."""
    r = requests.get(f"{agent_a}/api/oobi", timeout=TIMEOUT)
    assert r.status_code == 200, f"OOBI endpoint failed: {r.text}"
    body = r.json()
    url = body.get("oobi_url", "")
    assert url, "OOBI URL is empty"
    return url


@pytest.fixture(scope="module")
def oobi_b(agent_b, identity_b):
    """OOBI URL for instance B."""
    r = requests.get(f"{agent_b}/api/oobi", timeout=TIMEOUT)
    assert r.status_code == 200
    return r.json()["oobi_url"]


def test_oobi_a_contains_aid_a(oobi_a, identity_a):
    assert identity_a.aid in oobi_a


def test_oobi_b_contains_aid_b(oobi_b, identity_b):
    assert identity_b.aid in oobi_b


# ---------------------------------------------------------------------------
# Step 3: B resolves A's OOBI — the KERI handshake
# ---------------------------------------------------------------------------

@pytest.fixture(scope="module")
def b_resolves_a(agent_b, oobi_a, identity_a):
    """Instance B resolves instance A's OOBI. This is the KERI discovery handshake."""
    r = requests.post(
        f"{agent_b}/api/resolve-oobi",
        json={"url": oobi_a},
        timeout=TIMEOUT,
    )
    assert r.status_code == 200, (
        f"B could not resolve A's OOBI.\n"
        f"OOBI URL: {oobi_a}\n"
        f"Response: {r.status_code} {r.text}\n\n"
        "Possible causes:\n"
        "  - Instance A's URL is not reachable from instance B\n"
        "  - If running on different machines, use AGENT_A_URL with a publicly reachable URL\n"
        "  - If using ngrok/Cloudflare tunnel, ensure the tunnel is active"
    )
    return r.json()


def test_b_resolves_a_oobi_succeeds(b_resolves_a):
    """Core interop test: B validates A's KEL via OOBI resolution."""
    assert b_resolves_a is not None


def test_b_resolved_a_kel_is_verified(b_resolves_a):
    """After resolution, the KEL must be marked as verified."""
    kel_verified = b_resolves_a.get("kel_verified", None)
    assert kel_verified is True, (
        f"KEL not verified after OOBI resolution. Response: {b_resolves_a}"
    )


def test_b_resolved_a_aid_matches(b_resolves_a, identity_a):
    """The resolved AID must match instance A's AID."""
    cid = b_resolves_a.get("cid", "")
    assert cid == identity_a.aid, (
        f"Resolved AID mismatch.\nExpected: {identity_a.aid}\nGot: {cid}"
    )


def test_b_resolved_a_events_validated(b_resolves_a):
    """At least one KEL event must have been validated."""
    events_validated = b_resolves_a.get("events_validated", 0)
    assert events_validated >= 1, (
        f"No events validated. events_validated={events_validated}"
    )


def test_b_has_a_as_contact(agent_b, identity_a, b_resolves_a):
    """After resolving A's OOBI, B should have A in its contacts list."""
    r = requests.get(f"{agent_b}/api/contacts", timeout=TIMEOUT)
    assert r.status_code == 200
    contacts = r.json()
    aids = [c.get("aid") for c in contacts]
    assert identity_a.aid in aids, (
        f"A's AID not in B's contacts after OOBI resolution. Contacts: {aids}"
    )


# ---------------------------------------------------------------------------
# Step 4: A resolves B's OOBI (mutual discovery)
# ---------------------------------------------------------------------------

@pytest.fixture(scope="module")
def a_resolves_b(agent_a, oobi_b, identity_b):
    r = requests.post(
        f"{agent_a}/api/resolve-oobi",
        json={"url": oobi_b},
        timeout=TIMEOUT,
    )
    assert r.status_code == 200, (
        f"A could not resolve B's OOBI. {r.status_code} {r.text}"
    )
    return r.json()


def test_a_resolves_b_oobi_succeeds(a_resolves_b):
    assert a_resolves_b is not None


def test_a_resolved_b_kel_is_verified(a_resolves_b):
    assert a_resolves_b.get("kel_verified") is True


def test_a_has_b_as_contact(agent_a, identity_b, a_resolves_b):
    r = requests.get(f"{agent_a}/api/contacts", timeout=TIMEOUT)
    contacts = r.json()
    aids = [c.get("aid") for c in contacts]
    assert identity_b.aid in aids


# ---------------------------------------------------------------------------
# Step 5: A issues a credential to B's AID
# ---------------------------------------------------------------------------

@pytest.fixture(scope="module")
def cross_instance_credential(agent_a, identity_a, identity_b, b_resolves_a, a_resolves_b):
    """A issues a credential to B — cross-instance issuance."""
    r = requests.post(
        f"{agent_a}/api/credential/issue",
        json={
            "claims": {
                "name":           "Bob Holder",
                "degree":         "Master of Science",
                "graduationYear": 2025,
            },
            "schema_said": SCHEMA_SAID,
            "holder_aid":  identity_b.aid,
        },
        timeout=TIMEOUT,
    )
    assert r.status_code == 201, (
        f"Cross-instance credential issuance failed: {r.status_code} {r.text}"
    )
    return r.json()


def test_cross_instance_credential_said(cross_instance_credential):
    said = cross_instance_credential.get("acdc_said", "")
    assert said.startswith("E")
    assert len(said) == 44


def test_cross_instance_credential_holder_is_b(cross_instance_credential, identity_b):
    body = cross_instance_credential.get("acdc_body", {})
    a_block = body.get("a", {})
    holder = a_block.get("i", "") if isinstance(a_block, dict) else ""
    assert holder == identity_b.aid, (
        f"Credential holder AID mismatch.\n"
        f"Expected: {identity_b.aid}\nGot: {holder}"
    )


def test_cross_instance_credential_anchored_in_a_kel(agent_a, cross_instance_credential):
    """The credential's IXN seal must be in instance A's KEL."""
    kel_body = requests.get(f"{agent_a}/api/kel", timeout=TIMEOUT).json()
    acdc_said = cross_instance_credential["acdc_said"]
    events    = kel_body.get("kel", [])
    found = False
    for e in events:
        evt = e if isinstance(e, dict) and "t" in e else e.get("event", e)
        if evt.get("t") == "ixn":
            seals = evt.get("a", [])
            if any(s.get("d") == acdc_said for s in seals if isinstance(s, dict)):
                found = True
                break
    assert found, (
        f"Credential SAID ({acdc_said}) not found in any IXN seal in A's KEL"
    )


# ---------------------------------------------------------------------------
# Step 6 + 7: B presents, then A (or B) verifies
# ---------------------------------------------------------------------------

@pytest.fixture(scope="module")
def b_presentation(agent_b, cross_instance_credential, identity_b):
    r = requests.post(
        f"{agent_b}/api/credential/present",
        json={
            "acdc_said":  cross_instance_credential["acdc_said"],
            "holder_aid": identity_b.aid,
            "issuer_aid": cross_instance_credential.get("aid", ""),
        },
        timeout=TIMEOUT,
    )
    assert r.status_code == 201, f"B presentation failed: {r.status_code} {r.text}"
    return r.json()


def test_b_presentation_said(b_presentation):
    pres_said = b_presentation.get("presentation_said", "")
    assert pres_said.startswith("E")
    assert len(pres_said) == 44


def test_cross_instance_verification_passes(agent_b, cross_instance_credential,
                                             identity_b, b_presentation):
    """B verifies A's credential — the core interop proof."""
    r = requests.post(
        f"{agent_b}/api/credential/verify",
        json={
            "acdc_json":          cross_instance_credential.get("acdc_body", {}),
            "holder_aid":         identity_b.aid,
            "presentation_said":  b_presentation.get("pres_said_b64", ""),
            "holder_public_key":  identity_b.cesr_pk0,
            "trusted_schema_saids": [SCHEMA_SAID],
        },
        timeout=TIMEOUT,
    )
    assert r.status_code == 200, f"Verification failed: {r.status_code} {r.text}"
    body = r.json()
    assert body.get("verified") is True, (
        f"Cross-instance credential verification FAILED.\n"
        f"Checks: {body.get('checks')}\n"
        f"Errors: {body.get('errors')}\n\n"
        "This indicates a KERI interoperability issue. "
        "The KEL from instance A was resolved by B, but credential verification failed."
    )
