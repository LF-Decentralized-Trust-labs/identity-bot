"""A witness set has to be changeable, or it is the set you die with.

An identity names its witnesses at inception. Those witnesses are what makes
duplicity detectable, and what a stranded counterparty asks when the address
they hold stops working. Which people you rely on for that should be able to
change: providers close, friends' agents come online, and an identity that
bootstrapped on somebody else's infrastructure should be able to grow off it.

In KERI a witness change travels in a rotation event, as `br` (removed) and `ba`
(added) against the set the identity already has. The driver passed neither, so
the set was fixed at birth.

These tests hold the driver to actually amending it, and to keeping the
threshold honest while it does — a threshold left behind by a shrinking set
eventually cannot be met, and an identity that cannot meet its own threshold
cannot finalise anything ever again.
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


def incept_with(witnesses, toad=None):
    """Build a real inception naming a witness set, and register it."""
    signer = coring.Signer(raw=b"\x01" * 32, code=MtrDex.Ed25519_Seed, transferable=True)
    nxt = coring.Signer(raw=b"\x02" * 32, code=MtrDex.Ed25519_Seed, transferable=True)
    result = driver.create_inception_event(
        signer.verfer.qb64,
        coring.Diger(ser=nxt.verfer.qb64b, code=MtrDex.Blake3_256).qb64,
        witnesses=witnesses,
        toad=toad,
    )
    name = "rotating-identity"
    driver._identities[name] = {
        "aid": result["aid"],
        "public_key": result["public_key"],
        "next_key_digest": result["next_key_digest"],
        "kel": [result["inception_event"]],
        # Read off the event, exactly as the driver does, so the fixture cannot
        # disagree with what was actually incepted.
        "witnesses": driver._wits_of_event(result["inception_event"])[0],
        "toad": driver._wits_of_event(result["inception_event"])[1],
        "sequence_number": 0,
        "last_said": result.get("said", ""),
    }
    return name, result


class WitnessRotationTest(unittest.TestCase):
    def setUp(self):
        driver._identities.clear()
        self.wits = ["EWitOne", "EWitTwo", "EWitThree"]
        self.seed = 10

    def tearDown(self):
        driver._identities.clear()

    def rotate(self, name, **body):
        """Drive the rotation route the way an HTTP caller would.

        Fresh keys are supplied every time because a rotation is a key
        rotation first; changing witnesses rides along on it rather than
        replacing it.
        """
        self.seed += 1
        cur = coring.Signer(raw=bytes([self.seed]) * 32, code=MtrDex.Ed25519_Seed, transferable=True)
        nxt = coring.Signer(raw=bytes([self.seed + 1]) * 32, code=MtrDex.Ed25519_Seed, transferable=True)
        payload = {
            "name": name,
            "new_public_key": cur.verfer.qb64,
            "new_next_public_key": nxt.verfer.qb64,
            **body,
        }
        with driver.app.test_request_context("/rotation", method="POST", json=payload):
            response, status = driver.rotation()
            return json.loads(response.get_data()), status

    def test_an_inception_records_its_witnesses(self):
        """The baseline the rest depends on: the set has to be remembered
        somewhere, or a rotation has nothing to amend."""
        name, _ = incept_with(self.wits)
        self.assertEqual(driver._identities[name]["witnesses"], self.wits)

    def test_a_witness_can_be_removed(self):
        name, _ = incept_with(self.wits)
        body, status = self.rotate(name, witness_cuts=["EWitTwo"])
        self.assertEqual(status, 200, body)

        event = body["rotation_event"]
        self.assertIn("EWitTwo", event.get("br", []),
                      "the removal is not recorded in the event")
        self.assertNotIn("EWitTwo", driver._identities[name]["witnesses"])

    def test_a_witness_can_be_added(self):
        name, _ = incept_with(self.wits)
        body, status = self.rotate(name, witness_adds=["EWitFour"])
        self.assertEqual(status, 200, body)

        self.assertIn("EWitFour", body["rotation_event"].get("ba", []))
        self.assertIn("EWitFour", driver._identities[name]["witnesses"])

    def test_a_witness_already_present_is_not_added_twice(self):
        """Counting a witness twice would inflate the threshold while adding no
        independent observer — stronger-looking and actually weaker."""
        name, _ = incept_with(self.wits)
        body, status = self.rotate(name, witness_adds=["EWitOne"])
        self.assertEqual(status, 200, body)
        self.assertEqual(
            driver._identities[name]["witnesses"].count("EWitOne"), 1)

    def test_removing_a_witness_that_is_not_there_is_ignored(self):
        name, _ = incept_with(self.wits)
        body, status = self.rotate(name, witness_cuts=["ENeverAWitness"])
        self.assertEqual(status, 200, body)
        self.assertEqual(driver._identities[name]["witnesses"], self.wits)

    def test_the_threshold_follows_a_shrinking_set(self):
        """A threshold left behind by a shrinking set eventually cannot be met,
        and an identity that cannot meet its own threshold can never finalise
        another event."""
        name, _ = incept_with(self.wits)          # 3 witnesses, threshold 2
        self.rotate(name, witness_cuts=["EWitTwo", "EWitThree"])

        identity = driver._identities[name]
        self.assertEqual(len(identity["witnesses"]), 1)
        self.assertLessEqual(identity["toad"], len(identity["witnesses"]),
                             "the threshold outran the witnesses left to meet it")

    def test_a_threshold_above_the_remaining_witnesses_is_refused(self):
        name, _ = incept_with(self.wits)
        body, status = self.rotate(name, witness_cuts=["EWitTwo"], toad=5)
        self.assertEqual(status, 400, body)
        self.assertIn("threshold", body.get("error", "").lower())

    def test_a_plain_key_rotation_leaves_the_witnesses_alone(self):
        """Rotating keys is the common case and must not disturb who is
        watching."""
        name, _ = incept_with(self.wits)
        body, status = self.rotate(name)
        self.assertEqual(status, 200, body)
        self.assertEqual(driver._identities[name]["witnesses"], self.wits)

    def test_the_set_can_be_replayed_from_the_events(self):
        """A reload should work the set out rather than be told it: the events
        are the source of truth, and a caller passing it could pass a stale one.
        """
        name, result = incept_with(self.wits)
        self.rotate(name, witness_cuts=["EWitOne"], witness_adds=["EWitFour"])

        replayed, _ = driver._witnesses_from_kel(driver._identities[name]["kel"])
        self.assertEqual(sorted(replayed), sorted(driver._identities[name]["witnesses"]))
        self.assertNotIn("EWitOne", replayed)
        self.assertIn("EWitFour", replayed)


if __name__ == "__main__":
    unittest.main()
