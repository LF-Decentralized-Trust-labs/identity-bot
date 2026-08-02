"""What /generate-multisig-event is allowed to return.

An inception built here is a real KERI event. Anything else used to be an
ad-hoc JSON object — {type, aids, threshold, keys} — digested and returned
under the field names "said" and "pre", in exactly the same response shape as
the real branch. No t, no s, no p, no kt, no n: nothing that makes an event
verifiable, orderable, or attachable to a log.

The danger was never that rotation was missing. It is built properly elsewhere,
by /rotate, which is what the ownership ceremony calls. The danger was a second
path under the name that reads like the primary API, returning something a
caller could not distinguish from an event.

So the rule these tests hold: what comes back is either a real event or an
error. Never a convincing shape.
"""

import json
import unittest
import base64

from server import app


def post(payload):
    with app.test_client() as c:
        return c.post("/generate-multisig-event", json=payload)


KEYS = ["DIfxtNIe0BvNN72PK0rMca1zY-jiXIcvtAjlCt1eJfzw"]
NEXT = ["DGY1-SkJhUzfeiLUFEGvm2PRlFnTJbiqkiLKbPPAl8qV"]


class MultisigEventShape(unittest.TestCase):
    def test_an_inception_is_a_real_event(self):
        r = post({
            "aids": ["EX"], "threshold": 1,
            "current_keys": KEYS, "next_keys": NEXT,
            "event_type": "inception",
        })
        self.assertEqual(r.status_code, 200, r.get_data(as_text=True))
        body = r.get_json()
        event = json.loads(base64.b64decode(body["raw_bytes_b64"]))

        # The fields that make it an event rather than a shape.
        for field in ("v", "t", "d", "i", "s", "kt", "k", "nt", "n"):
            self.assertIn(field, event, f"an inception with no {field!r} is not an event")
        self.assertEqual(event["t"], "icp")
        # The SAID reported must be the identifier the event derives, not a
        # digest of something else that happens to be the same length.
        self.assertEqual(body["said"], event["i"])

    def test_a_rotation_is_refused_rather_than_invented(self):
        r = post({
            "aids": ["EX"], "threshold": 2,
            "current_keys": KEYS, "next_keys": NEXT,
            "event_type": "rotation",
        })
        self.assertEqual(
            r.status_code, 400,
            "a rotation asked of the inception builder came back 200 — if it "
            "returned a body, check it is not a digest of an invented object",
        )
        body = r.get_json()
        self.assertIn("error", body)
        # The error has to say where rotation actually lives, or the next person
        # to hit it reimplements the thing that was just removed.
        self.assertIn("/rotate", body["error"])

    def test_nothing_that_is_not_an_inception_returns_a_said(self):
        # The specific harm: "said" and "pre" mean something in KERI, and a
        # caller reading them off a non-event would be treating a digest of our
        # own JSON as an identifier.
        for kind in ("rotation", "rot", "interaction", "ixn", "delegated-rotation"):
            r = post({
                "aids": ["EX"], "threshold": 1,
                "current_keys": KEYS, "next_keys": NEXT,
                "event_type": kind,
            })
            body = r.get_json() or {}
            self.assertNotIn(
                "said", body,
                f"{kind!r} came back carrying a 'said', which a caller would read "
                f"as an event identifier",
            )
            self.assertNotIn("pre", body, f"{kind!r} came back carrying a 'pre'")


if __name__ == "__main__":
    unittest.main()
