"""
Phase 7 — KERL + Witness Receipts interoperability tests.

Verifies:
  - Witness receipts are CESR-encoded Ed25519 signatures over the event SAID
  - Multiple witness receipts accumulate correctly
  - Threshold check (n-of-m) counts only trusted witnesses
  - Untrusted witness receipts are excluded from threshold count
  - Insufficient receipts correctly fail threshold
  - KERL entry structure combines event + receipts + threshold status
  - Tampered receipts (wrong event SAID) are detected
"""

import pytest
import pysodium
from keri.core import coring, eventing
from keri.core.coring import MtrDex

from conftest import derive_key

# Witness seeds — deterministic, never change
_WITNESS_SEEDS = {
    "w1": bytes([10] * 32),
    "w2": bytes([20] * 32),
    "w3": bytes([30] * 32),
    "w4": bytes([40] * 32),
    "untrusted": bytes([99] * 32),
}

WITNESS_THRESHOLD = 3  # require 3-of-4 witnesses


# ---------------------------------------------------------------------------
# Module-scoped fixtures
# ---------------------------------------------------------------------------

def _make_witness(seed):
    pk, sk = derive_key(seed, 0)
    pk1, _ = derive_key(seed, 1)
    vf  = coring.Verfer(raw=pk, code=MtrDex.Ed25519)
    d1  = coring.Diger(raw=pk1, code=MtrDex.Blake3_256)
    icp = eventing.incept(keys=[vf.qb64], ndigs=[d1.qb64], code=MtrDex.Blake3_256)
    return {"aid": icp.pre, "pk": pk, "sk": sk, "verfer": vf}


@pytest.fixture(scope="module")
def witnesses():
    return {name: _make_witness(seed) for name, seed in _WITNESS_SEEDS.items()}


@pytest.fixture(scope="module")
def controller_icp(issuer):
    """Re-use the issuer AID as the controller whose event receives receipts."""
    return issuer["icp"]


@pytest.fixture(scope="module")
def event_said(controller_icp):
    return controller_icp.said


@pytest.fixture(scope="module")
def receipts(witnesses, event_said):
    """All receipts (4 trusted + 1 untrusted)."""
    def make_receipt(w):
        sig = pysodium.crypto_sign_detached(event_said.encode(), w["sk"])
        cigar = coring.Cigar(raw=sig, code=MtrDex.Ed25519_Sig)
        return {"witness_aid": w["aid"], "cesr_sig": cigar.qb64, "raw_sig": sig, "verfer": w["verfer"]}

    return [
        make_receipt(witnesses["w1"]),
        make_receipt(witnesses["w2"]),
        make_receipt(witnesses["w3"]),
        make_receipt(witnesses["w4"]),
        make_receipt(witnesses["untrusted"]),
    ]


@pytest.fixture(scope="module")
def trusted_witness_aids(witnesses):
    return {witnesses[k]["aid"] for k in ("w1", "w2", "w3", "w4")}


# ---------------------------------------------------------------------------
# Step 1: Witness receipt structure
# ---------------------------------------------------------------------------

def test_witness_receipt_cesr_prefix(receipts):
    assert receipts[0]["cesr_sig"].startswith("0B")


def test_witness_receipt_cesr_length(receipts):
    assert len(receipts[0]["cesr_sig"]) == 88


def test_witness_receipt_verifies(receipts, event_said):
    r = receipts[0]
    assert r["verfer"].verify(sig=r["raw_sig"], ser=event_said.encode())


# ---------------------------------------------------------------------------
# Step 2: Multiple receipts accumulate
# ---------------------------------------------------------------------------

def test_receipt_count(receipts):
    assert len(receipts) == 5  # 4 trusted + 1 untrusted


@pytest.mark.parametrize("idx", [0, 1, 2, 3])
def test_trusted_receipt_verifies(receipts, event_said, idx):
    r = receipts[idx]
    assert r["verfer"].verify(sig=r["raw_sig"], ser=event_said.encode())


# ---------------------------------------------------------------------------
# Step 3: Threshold check (3-of-4)
# ---------------------------------------------------------------------------

def _count_valid(receipts, trusted_aids, event_said_str, threshold):
    valid = sum(
        1 for r in receipts
        if r["witness_aid"] in trusted_aids
        and r["verfer"].verify(sig=r["raw_sig"], ser=event_said_str.encode())
    )
    return valid, valid >= threshold


def test_threshold_met_with_4_trusted_receipts(receipts, trusted_witness_aids, event_said):
    count, met = _count_valid(receipts, trusted_witness_aids, event_said, WITNESS_THRESHOLD)
    assert count == 4, f"Expected 4, got {count}"
    assert met


def test_untrusted_receipt_excluded_from_threshold(
    receipts, witnesses, trusted_witness_aids, event_said
):
    count, _ = _count_valid(receipts, trusted_witness_aids, event_said, WITNESS_THRESHOLD)
    untrusted_count = sum(
        1 for r in receipts if r["witness_aid"] == witnesses["untrusted"]["aid"]
    )
    # 1 untrusted receipt exists but count of trusted valid receipts is still 4
    assert untrusted_count == 1
    assert count == 4


# ---------------------------------------------------------------------------
# Step 4: Threshold fails with insufficient receipts
# ---------------------------------------------------------------------------

def test_two_receipts_do_not_meet_threshold_of_3(
    receipts, trusted_witness_aids, event_said
):
    only_two = receipts[:2]
    count, met = _count_valid(only_two, trusted_witness_aids, event_said, WITNESS_THRESHOLD)
    assert not met, f"Expected threshold NOT met, but count={count}"


# ---------------------------------------------------------------------------
# Step 5: KERL entry construction
# ---------------------------------------------------------------------------

def test_kerl_entry_has_event_said(controller_icp, receipts, trusted_witness_aids, event_said):
    count, met = _count_valid(receipts, trusted_witness_aids, event_said, WITNESS_THRESHOLD)
    entry = {
        "event_said":    event_said,
        "event_type":    controller_icp.ked.get("t"),
        "sn":            controller_icp.ked.get("s"),
        "receipts":      [r for r in receipts if r["witness_aid"] in trusted_witness_aids],
        "threshold_met": met,
    }
    assert bool(entry["event_said"])
    assert len(entry["receipts"]) == 4
    assert entry["threshold_met"] is True


# ---------------------------------------------------------------------------
# Step 6: Tampered receipt detection
# ---------------------------------------------------------------------------

def test_tampered_receipt_rejected(witnesses, event_said):
    wrong_said = "EDIFFERENTEVENTXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX"[:44]
    w1 = witnesses["w1"]
    tampered_sig = pysodium.crypto_sign_detached(wrong_said.encode(), w1["sk"])
    assert not w1["verfer"].verify(sig=tampered_sig, ser=event_said.encode())


def test_tampered_receipt_verifies_its_own_message(witnesses):
    wrong_said = "EDIFFERENTEVENTXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX"[:44]
    w1 = witnesses["w1"]
    tampered_sig = pysodium.crypto_sign_detached(wrong_said.encode(), w1["sk"])
    assert w1["verfer"].verify(sig=tampered_sig, ser=wrong_said.encode())
