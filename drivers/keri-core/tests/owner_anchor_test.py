"""An identity names its owner in the event that creates it.

Some identities answer to somebody other than themselves. Whoever brought
it into being and answers for it, and that has to be true of the identity too —
otherwise the software running such an identity holds the only key to it, and
the identity answers to nobody.

Recording the owner in a file beside the database was not enough. A file can be
rewritten by anyone who can write it, silently, and cannot be read by anyone who
is not on that machine. So the owner goes in the inception event's own `a`
field.

That placement is the whole point, and these tests exist to hold it there. A
self-addressing identifier is the digest of its own inception event, so an
anchor is part of what the identifier IS. Ownership cannot be added, removed or
altered afterwards without producing a different identity.
"""

from __future__ import annotations

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import server as driver  # noqa: E402

KEY = "DKey1AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
NEXT = "EDig1AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
OWNER = "EOwnerPairwiseAID_AAAAAAAAAAAAAAAAAAAAAAAA"
OTHER = "EDifferentOwnerAAAAAAAAAAAAAAAAAAAAAAAAAAAA"


def owner_seal(aid: str) -> dict:
    return {"i": aid, "r": "owner"}


class OwnerAnchorTest(unittest.TestCase):
    def test_the_owner_is_written_into_the_event(self):
        result = driver.create_inception_event(KEY, NEXT, anchors=[owner_seal(OWNER)])
        self.assertEqual(
            result["inception_event"].get("a"), [owner_seal(OWNER)],
            "the owner is not in the event, so nothing outside this machine can read it",
        )

    def test_a_different_owner_is_a_different_identity(self):
        """The property everything else rests on.

        If the same keys with a different owner produced the same identifier,
        the anchor would be decoration — someone could claim any identity
        was theirs and the identifier would agree.
        """
        mine = driver.create_inception_event(KEY, NEXT, anchors=[owner_seal(OWNER)])
        theirs = driver.create_inception_event(KEY, NEXT, anchors=[owner_seal(OTHER)])
        self.assertNotEqual(
            mine["aid"], theirs["aid"],
            "two different owners produced the same identifier — the anchor is not binding",
        )

    def test_removing_the_owner_is_a_different_identity(self):
        """Ownership cannot be dropped and the identity kept."""
        owned = driver.create_inception_event(KEY, NEXT, anchors=[owner_seal(OWNER)])
        unowned = driver.create_inception_event(KEY, NEXT)
        self.assertNotEqual(
            owned["aid"], unowned["aid"],
            "an identity kept its identifier after its owner was removed",
        )

    def test_the_same_owner_and_keys_are_the_same_identity(self):
        """Derivation must be deterministic, or an identity could not be
        recovered from what it was made of."""
        first = driver.create_inception_event(KEY, NEXT, anchors=[owner_seal(OWNER)])
        again = driver.create_inception_event(KEY, NEXT, anchors=[owner_seal(OWNER)])
        self.assertEqual(first["aid"], again["aid"])

    def test_an_identity_without_an_anchor_still_works(self):
        """Individuals do not use this path.

        A person's agent is a delegated identity: its delegator is already named
        in the event, so it needs no separate anchor. Requiring one here would
        break that.
        """
        result = driver.create_inception_event(KEY, NEXT)
        self.assertTrue(result["aid"].startswith("E"))
        self.assertIn(result["inception_event"].get("a"), ([], None))

    def test_owner_and_witnesses_coexist(self):
        """An identity has both, and neither may displace the other."""
        result = driver.create_inception_event(
            KEY, NEXT,
            witnesses=["EWitOne", "EWitTwo"],
            anchors=[owner_seal(OWNER)],
        )
        event = result["inception_event"]
        self.assertEqual(event.get("a"), [owner_seal(OWNER)], "the owner was lost")
        self.assertEqual(event.get("b"), ["EWitOne", "EWitTwo"], "the witnesses were lost")


if __name__ == "__main__":
    unittest.main()
