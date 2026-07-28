"""Stateless KERI operations, so one driver can serve many agents.

Why this exists
---------------

The driver as written keeps every identity it has ever seen in a module-level
dict. That is fine when there is one driver per agent — the dict holds exactly
one tenant's material and dies with them. It is the wrong shape the moment a
driver is shared, because "shared" and "remembers everyone" together mean one
process holding many people's key state, and a bug anywhere in it is a bug that
crosses between them.

So the shared path does not remember. Every call carries the identity state it
needs and returns the state that results; the agent holds it in between. The
driver becomes a function from state and inputs to new state, with nothing left
behind when the request ends.

That is not a stylistic preference. It is what makes a pooled driver safe to
share at all: there is no cross-tenant state to leak because there is no
retained state, and an operation cannot see another tenant's identity because
the only identity in scope is the one the caller passed in.

What a caller holds
-------------------

The whole of an identity's driver-side state is small and explicit:

    {
      "aid":             "E...",   # the identifier
      "public_key":      "D...",   # current signing key
      "next_key_digest": "E...",   # commitment to the next key
      "sequence_number": 0,        # last event's sequence number
      "last_said":       "E...",   # SAID of the last event, the next event's `dig`
      "kel":             [ ... ]   # the events themselves
    }

An agent stores that, sends it, and replaces it with what comes back. Nothing
here is secret — no private key is ever sent to the driver, in this mode or the
stateful one — so a caller keeping it is keeping public material.
"""

from keri.core import coring, eventing
from keri.core.coring import MtrDex


class StatelessError(Exception):
    """A refusal that carries wording for the caller."""


def _require(state, *fields):
    """Refuses a state that cannot support the operation.

    Explicitly rather than by KeyError: a missing field here means the caller
    sent something other than a state this driver produced, and saying so beats
    a traceback about a dictionary.
    """
    missing = [f for f in fields if not state.get(f)]
    if missing:
        raise StatelessError(
            f"identity state is missing {', '.join(missing)} — "
            "send back the state this driver returned, unchanged"
        )


def _extract_raw_key(cesr_key: str) -> bytes:
    """Raw 32 bytes from a CESR qb64 key, or from bare base64."""
    from base64 import urlsafe_b64decode

    if not cesr_key:
        raise StatelessError("a key is required")
    candidate = cesr_key[1:] if len(cesr_key) == 44 and cesr_key[0] in "BD" else cesr_key
    padded = candidate + "=" * (-len(candidate) % 4)
    try:
        raw = urlsafe_b64decode(padded)
    except Exception as exc:  # noqa: BLE001 — the message is what matters here
        raise StatelessError(f"key is not valid base64: {exc}") from exc
    if len(raw) != 32:
        raise StatelessError(f"key must be 32 bytes, got {len(raw)}")
    return raw


def incept(public_key: str, next_public_key: str) -> dict:
    """Creates an identity. Returns the event and the state to keep.

    Takes no prior state because there is none — this is where an identity
    begins.
    """
    verfer = coring.Verfer(raw=_extract_raw_key(public_key), code=MtrDex.Ed25519)
    diger = coring.Diger(raw=_extract_raw_key(next_public_key), code=MtrDex.Blake3_256)

    serder = eventing.incept(keys=[verfer.qb64], ndigs=[diger.qb64])
    event = serder.ked

    return {
        "event": event,
        "said": serder.said,
        "raw": serder.raw.decode("utf-8"),
        "state": {
            "aid": serder.pre,
            "public_key": verfer.qb64,
            "next_key_digest": diger.qb64,
            "sequence_number": 0,
            "last_said": serder.said,
            "kel": [event],
        },
    }


def rotate(state: dict, new_public_key: str, new_next_public_key: str, seal_data=None) -> dict:
    """Rotates to a new key, from the state the caller passed in.

    The chain is what makes this safe to do statelessly: the new event names the
    previous event's SAID, so a caller cannot skip, reorder or replay one
    without producing a KEL that fails to verify — which any reader will catch,
    including a reader who is not this driver.
    """
    _require(state, "aid", "last_said")

    verfer = coring.Verfer(raw=_extract_raw_key(new_public_key), code=MtrDex.Ed25519)
    diger = coring.Diger(raw=_extract_raw_key(new_next_public_key), code=MtrDex.Blake3_256)

    sn = int(state.get("sequence_number", 0)) + 1
    serder = eventing.rotate(
        pre=state["aid"],
        keys=[verfer.qb64],
        dig=state["last_said"],
        ndigs=[diger.qb64],
        sn=sn,
        data=seal_data or [],
    )
    event = serder.ked

    return {
        "event": event,
        "said": serder.said,
        "raw": serder.raw.decode("utf-8"),
        "state": {
            **state,
            "public_key": verfer.qb64,
            "next_key_digest": diger.qb64,
            "sequence_number": sn,
            "last_said": serder.said,
            "kel": list(state.get("kel", [])) + [event],
        },
    }


def interact(state: dict, seal_data=None) -> dict:
    """Anchors data in the identity's log without changing keys."""
    _require(state, "aid", "last_said")

    sn = int(state.get("sequence_number", 0)) + 1
    serder = eventing.interact(
        pre=state["aid"],
        dig=state["last_said"],
        sn=sn,
        data=seal_data or [],
    )
    event = serder.ked

    return {
        "event": event,
        "said": serder.said,
        "raw": serder.raw.decode("utf-8"),
        "state": {
            **state,
            "sequence_number": sn,
            "last_said": serder.said,
            "kel": list(state.get("kel", [])) + [event],
        },
    }


def delegated_incept(
    delegator_state: dict,
    public_key: str,
    next_public_key: str,
) -> dict:
    """Issues a delegated identity, and anchors it in the delegator's log.

    Both sides come back: the new delegated identity's state, and the
    delegator's state advanced by the anchoring event. A caller that stores only
    one of them has a delegation that will not verify, so they are returned
    together rather than in two calls.
    """
    _require(delegator_state, "aid", "last_said")

    verfer = coring.Verfer(raw=_extract_raw_key(public_key), code=MtrDex.Ed25519)
    diger = coring.Diger(raw=_extract_raw_key(next_public_key), code=MtrDex.Blake3_256)

    dip = eventing.delcept(
        keys=[verfer.qb64],
        delpre=delegator_state["aid"],
        ndigs=[diger.qb64],
    )

    # The delegation is only verifiable because the delegator's own log points
    # at it. Anchoring is part of issuing, not a follow-up somebody might skip.
    seal = {"i": dip.pre, "s": "0", "d": dip.said}
    anchor_sn = int(delegator_state.get("sequence_number", 0)) + 1
    anchor = eventing.interact(
        pre=delegator_state["aid"],
        dig=delegator_state["last_said"],
        sn=anchor_sn,
        data=[seal],
    )

    return {
        "dip_event": dip.ked,
        "dip_said": dip.said,
        "delegator_anchor": anchor.ked,
        "delegated_state": {
            "aid": dip.pre,
            "public_key": verfer.qb64,
            "next_key_digest": diger.qb64,
            "sequence_number": 0,
            "last_said": dip.said,
            "kel": [dip.ked],
            "delegator_aid": delegator_state["aid"],
        },
        "delegator_state": {
            **delegator_state,
            "sequence_number": anchor_sn,
            "last_said": anchor.said,
            "kel": list(delegator_state.get("kel", [])) + [anchor.ked],
        },
    }
