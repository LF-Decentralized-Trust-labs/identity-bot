"""
Phase 3 — OOBI Resolution + KEL Validation interoperability tests.

Verifies:
  - A KEL (Key Event Log) is a properly sequenced chain: icp → ixn → rot
  - Each event's 'p' (prior) field matches the previous event's SAID
  - All event signatures verify against the correct key at each sequence number
  - An OOBI response payload (JSON with KEL) round-trips correctly
  - A tampered KEL event is detected via hash chain break
  - A KEL entry with a wrong signature is detected
"""

import base64
import copy
import json
import pytest
import pysodium
from keri.core import coring, eventing
from keri.core.coring import MtrDex

from conftest import SEED_ISSUER, derive_key


# ---------------------------------------------------------------------------
# Module-scoped fixture: a complete 3-event KEL
# ---------------------------------------------------------------------------

@pytest.fixture(scope="module")
def kel():
    pk0, sk0 = derive_key(SEED_ISSUER, 0)
    pk1, sk1 = derive_key(SEED_ISSUER, 1)
    pk2, sk2 = derive_key(SEED_ISSUER, 2)

    vf0 = coring.Verfer(raw=pk0, code=MtrDex.Ed25519)
    vf1 = coring.Verfer(raw=pk1, code=MtrDex.Ed25519)
    d1  = coring.Diger(raw=pk1, code=MtrDex.Blake3_256)
    d2  = coring.Diger(raw=pk2, code=MtrDex.Blake3_256)

    icp = eventing.incept(keys=[vf0.qb64], ndigs=[d1.qb64], code=MtrDex.Blake3_256)
    ixn = eventing.interact(pre=icp.pre, dig=icp.said, sn=1, data=[])
    rot = eventing.rotate(
        pre=icp.pre, keys=[vf1.qb64], dig=ixn.said, ndigs=[d2.qb64], sn=2
    )

    return [
        {
            "event":   icp.ked,
            "raw_b64": base64.b64encode(icp.raw).decode(),
            "sig_b64": base64.b64encode(pysodium.crypto_sign_detached(icp.raw, sk0)).decode(),
            "verfer":  vf0.qb64,
        },
        {
            "event":   ixn.ked,
            "raw_b64": base64.b64encode(ixn.raw).decode(),
            "sig_b64": base64.b64encode(pysodium.crypto_sign_detached(ixn.raw, sk0)).decode(),
            "verfer":  vf0.qb64,
        },
        {
            "event":   rot.ked,
            "raw_b64": base64.b64encode(rot.raw).decode(),
            "sig_b64": base64.b64encode(pysodium.crypto_sign_detached(rot.raw, sk1)).decode(),
            "verfer":  vf1.qb64,
        },
    ]


# ---------------------------------------------------------------------------
# Step 1: KEL construction and structure
# ---------------------------------------------------------------------------

def test_kel_has_three_events(kel):
    assert len(kel) == 3


def test_kel_event_types(kel):
    assert kel[0]["event"].get("t") == "icp"
    assert kel[1]["event"].get("t") == "ixn"
    assert kel[2]["event"].get("t") == "rot"


def test_kel_aid_consistent_across_events(kel):
    aids = [e["event"]["i"] for e in kel]
    assert aids[0] == aids[1] == aids[2]


def test_kel_sequence_numbers_are_contiguous(kel):
    sns = [e["event"].get("s") for e in kel]
    assert sns == ["0", "1", "2"]


# ---------------------------------------------------------------------------
# Step 2: Hash chain validation
# ---------------------------------------------------------------------------

def test_ixn_prior_matches_icp_said(kel):
    icp_said = kel[0]["event"].get("d")
    ixn_prior = kel[1]["event"].get("p")
    assert ixn_prior == icp_said, f"ICP SAID: {icp_said}\nIXN prior: {ixn_prior}"


def test_rot_prior_matches_ixn_said(kel):
    ixn_said = kel[1]["event"].get("d")
    rot_prior = kel[2]["event"].get("p")
    assert rot_prior == ixn_said, f"IXN SAID: {ixn_said}\nROT prior: {rot_prior}"


# ---------------------------------------------------------------------------
# Step 3: All event signatures verify
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("entry_idx", [0, 1, 2])
def test_kel_event_signature_verifies(kel, entry_idx):
    entry = kel[entry_idx]
    raw = base64.b64decode(entry["raw_b64"])
    sig = base64.b64decode(entry["sig_b64"])
    vf  = coring.Verfer(qb64=entry["verfer"])
    assert vf.verify(sig=sig, ser=raw), (
        f"Signature failed for event sn={entry['event'].get('s')} ({entry['event'].get('t')})"
    )


# ---------------------------------------------------------------------------
# Step 4: OOBI response payload round-trip
# ---------------------------------------------------------------------------

def test_oobi_payload_round_trip(kel):
    aid = kel[0]["event"]["i"]
    payload = json.dumps({
        "pre":     aid,
        "kel":     [e["event"] for e in kel],
        "sigs":    [e["sig_b64"] for e in kel],
        "verfers": [e["verfer"] for e in kel],
    })
    parsed = json.loads(payload)
    assert parsed["pre"] == aid
    assert len(parsed["kel"]) == 3
    assert [e.get("t") for e in parsed["kel"]] == ["icp", "ixn", "rot"]


# ---------------------------------------------------------------------------
# Step 5: Tampered KEL is detected (hash chain breaks)
# ---------------------------------------------------------------------------

def test_tampered_kel_fails_hash_chain(kel):
    tampered = copy.deepcopy([e["event"] for e in kel])
    tampered[1]["p"] = "ETAMPEREDPRIORXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX"

    def hash_chain_valid(events):
        for i in range(1, len(events)):
            if events[i].get("p") != events[i - 1].get("d"):
                return False
        return True

    assert hash_chain_valid([e["event"] for e in kel]), "Original KEL should pass"
    assert not hash_chain_valid(tampered), "Tampered KEL should fail"


# ---------------------------------------------------------------------------
# Step 6: Wrong-signature detection
# ---------------------------------------------------------------------------

def test_correct_sig_verifies(kel):
    entry = kel[0]
    raw = base64.b64decode(entry["raw_b64"])
    sig = base64.b64decode(entry["sig_b64"])
    vf  = coring.Verfer(qb64=entry["verfer"])
    assert vf.verify(sig=sig, ser=raw)


def test_wrong_sig_rejected(kel):
    entry = kel[0]
    raw = base64.b64decode(entry["raw_b64"])
    vf  = coring.Verfer(qb64=entry["verfer"])

    pk_bad, sk_bad = pysodium.crypto_sign_seed_keypair(bytes([0xff] * 32))
    bad_sig = pysodium.crypto_sign_detached(raw, sk_bad)

    assert not vf.verify(sig=bad_sig, ser=raw)
