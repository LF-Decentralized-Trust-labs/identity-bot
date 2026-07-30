"""A KEL must belong to the identity that claims it.

Validating a key event log proves the events are consistent with each other:
sequence numbers run in order, the hash chain is intact, signatures verify
against the keys the events declare. A forger satisfies all of that trivially,
because they supply both the keys and the signatures.

What makes a chain SOMEBODY'S chain is that its inception event derives their
AID. A self-addressing identifier is the Blake3 SAID of its own inception, so
producing an inception containing your keys that derives another person's AID
means finding a hash collision.

These tests hold the validator to that. Without it, a wholly forged KEL passes
for any AID an attacker names — which matters most exactly where it is least
visible: resolving a contact's current key from an endpoint somebody else
controls.
"""

from __future__ import annotations

import json
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from keri.core import coring, eventing  # noqa: E402
from keri.core.coring import MtrDex  # noqa: E402

import server as driver  # noqa: E402


def make_identity(seed_byte: int):
    """Build a real inception event and a signed one-event KEL for it."""
    signer = coring.Signer(raw=bytes([seed_byte]) * 32, code=MtrDex.Ed25519_Seed, transferable=True)
    nxt = coring.Signer(raw=bytes([seed_byte + 1]) * 32, code=MtrDex.Ed25519_Seed, transferable=True)
    srdr = eventing.incept(
        keys=[signer.verfer.qb64],
        ndigs=[coring.Diger(ser=nxt.verfer.qb64b, code=MtrDex.Blake3_256).qb64],
        code=MtrDex.Blake3_256,
    )
    kel = [{
        "event_json": json.dumps(srdr.ked),
        "cesr_signature": signer.sign(srdr.raw).qb64,
        "public_key": signer.verfer.qb64,
        "event_type": "icp",
        "sequence_number": 0,
    }]
    return srdr.ked, kel


class KELBindingTest(unittest.TestCase):
    def setUp(self):
        self.victim_ked, self.victim_kel = make_identity(0)
        self.attacker_ked, self.attacker_kel = make_identity(9)

    def test_a_genuine_kel_verifies(self):
        """The baseline. If this fails the validator is refusing real chains."""
        result = driver._validate_kel_events(self.victim_kel, self.victim_ked["i"])
        self.assertTrue(
            result["kel_verified"],
            f"a genuine KEL was refused: {result['validation_errors']}",
        )
        self.assertEqual(result["current_public_key"], self.victim_ked["k"][0])

    def test_a_forged_kel_cannot_claim_another_identity(self):
        """The attack this exists to stop.

        The attacker's chain is internally perfect — their own keys, their own
        valid signatures. The only thing wrong with it is whose it is.
        """
        result = driver._validate_kel_events(self.attacker_kel, self.victim_ked["i"])
        self.assertFalse(
            result["kel_verified"],
            "an attacker's own KEL was accepted as the victim's",
        )
        self.assertEqual(
            result["current_public_key"], "",
            "a refused KEL must not report a current key — that is the value "
            "a caller would go on to trust",
        )

    def test_swapping_keys_into_a_real_inception_is_caught(self):
        """The subtler attack: keep the victim's AID, substitute the keys.

        This is what re-derivation catches and a plain identifier comparison
        does not.
        """
        tampered = json.loads(self.victim_kel[0]["event_json"])
        tampered["k"] = self.attacker_ked["k"]
        kel = [dict(self.victim_kel[0], event_json=json.dumps(tampered))]

        result = driver._validate_kel_events(kel, self.victim_ked["i"])
        self.assertFalse(result["kel_verified"], "substituted keys were accepted")
        self.assertTrue(
            any("re-derive" in e for e in result["validation_errors"]),
            f"expected a derivation mismatch, got {result['validation_errors']}",
        )

    def test_validating_without_an_aid_is_refused(self):
        """An unbound validation answers a question nobody asked.

        'These events are consistent' is not useful on its own, and returning
        success for it invites callers to treat it as 'this is who they say
        they are'.
        """
        result = driver._validate_kel_events(self.victim_kel, "")
        self.assertFalse(result["kel_verified"])

    def test_later_events_cannot_belong_to_someone_else(self):
        """A genuine inception must not have another identity's events spliced on."""
        foreign = json.loads(self.attacker_kel[0]["event_json"])
        foreign["s"] = "1"
        kel = self.victim_kel + [dict(self.attacker_kel[0], event_json=json.dumps(foreign),
                                      event_type="ixn", sequence_number=1)]

        result = driver._validate_kel_events(kel, self.victim_ked["i"])
        self.assertFalse(result["kel_verified"], "a spliced foreign event was accepted")

    def test_an_empty_kel_is_refused(self):
        result = driver._validate_kel_events([], self.victim_ked["i"])
        self.assertFalse(result["kel_verified"])


if __name__ == "__main__":
    unittest.main()
