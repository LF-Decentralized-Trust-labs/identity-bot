"""The properties a shared driver has to have, tested rather than asserted."""

import base64
import os

import pytest

import stateless


def key() -> str:
    """A CESR-ish qb64 verkey over random bytes. Content does not matter here;
    only that it is 32 bytes and distinct per call."""
    return "D" + base64.urlsafe_b64encode(os.urandom(32)).decode().rstrip("=")[:43]


def new_identity():
    return stateless.incept(key(), key())


def test_inception_returns_everything_needed_to_continue():
    r = new_identity()
    s = r["state"]
    # A caller has to be able to rotate later using only what came back.
    for field in ("aid", "public_key", "next_key_digest", "sequence_number", "last_said", "kel"):
        assert field in s, f"state is missing {field}"
    assert s["sequence_number"] == 0
    assert s["last_said"] == r["said"]
    assert len(s["kel"]) == 1


def test_nothing_is_retained_between_calls():
    """The property the whole design rests on.

    Two identities are created and neither is passed to the other's operation.
    If the module retained anything, the second call could see the first.
    """
    first = new_identity()["state"]
    second = new_identity()["state"]

    assert first["aid"] != second["aid"]

    # Rotating the second must not advance or reference the first.
    rotated = stateless.rotate(second, key(), key())
    assert rotated["state"]["aid"] == second["aid"]
    assert first["aid"] not in str(rotated["event"])

    # And the first is untouched — the caller still holds exactly what it had.
    assert first["sequence_number"] == 0
    assert len(first["kel"]) == 1


def test_nothing_accumulates_across_many_tenants():
    """A shared driver must not grow as tenants use it.

    Tested as the property rather than the structure: take the size of every
    module-level container, put fifty identities through, and require that
    nothing got bigger. A registry added later fails this even if it is named
    innocently, and an imported constant does not fail it for existing.
    """
    def sizes():
        return {
            name: len(value)
            for name, value in vars(stateless).items()
            if isinstance(value, (dict, list, set))
        }

    before = sizes()
    for _ in range(50):
        s = stateless.incept(key(), key())["state"]
        s = stateless.rotate(s, key(), key())["state"]
        stateless.interact(s, [{"n": 1}])
    after = sizes()

    grew = {n: (before.get(n, 0), after[n]) for n in after if after[n] > before.get(n, 0)}
    assert not grew, f"the driver accumulated state across tenants: {grew}"


def test_rotation_chains_to_the_previous_event():
    s = new_identity()["state"]
    r1 = stateless.rotate(s, key(), key())
    assert r1["event"]["p"] == s["last_said"], "rotation must name the previous event"
    assert r1["state"]["sequence_number"] == 1

    r2 = stateless.rotate(r1["state"], key(), key())
    assert r2["event"]["p"] == r1["said"]
    assert r2["state"]["sequence_number"] == 2
    assert len(r2["state"]["kel"]) == 3


def test_a_caller_cannot_advance_someone_elses_identity():
    """Passing tenant A's state to an operation affects only A.

    This is the isolation claim stated as a test: there is no shared index to
    reach into, so the only identity an operation can touch is the one handed
    to it.
    """
    a = new_identity()["state"]
    b = new_identity()["state"]

    advanced = stateless.rotate(a, key(), key())["state"]

    assert advanced["aid"] == a["aid"]
    assert b["sequence_number"] == 0
    assert b["last_said"] != advanced["last_said"]


def test_interact_anchors_without_changing_keys():
    s = new_identity()["state"]
    out = stateless.interact(s, [{"note": "anything"}])
    assert out["state"]["public_key"] == s["public_key"], "interact must not rotate"
    assert out["state"]["sequence_number"] == 1
    assert out["event"]["t"] == "ixn"


def test_delegation_returns_both_sides():
    """A caller that stored only one side would hold a delegation that cannot
    verify, so both come back from one call."""
    delegator = new_identity()["state"]
    out = stateless.delegated_incept(delegator, key(), key())

    assert out["dip_event"]["t"] == "dip"
    assert out["dip_event"]["di"] == delegator["aid"], "the dip must name its delegator"
    assert out["delegated_state"]["delegator_aid"] == delegator["aid"]

    # The delegator advanced, and its new event anchors the delegation.
    assert out["delegator_state"]["sequence_number"] == delegator["sequence_number"] + 1
    anchor = out["delegator_anchor"]
    assert anchor["t"] == "ixn"
    assert any(seal.get("d") == out["dip_said"] for seal in anchor["a"]), \
        "the delegator's log must anchor the delegation"


def test_delegated_identity_is_not_its_delegator():
    delegator = new_identity()["state"]
    out = stateless.delegated_incept(delegator, key(), key())
    assert out["delegated_state"]["aid"] != delegator["aid"]


def test_state_that_did_not_come_from_here_is_refused():
    """A missing field means the caller sent something other than our state.
    Saying so beats a traceback about a dictionary."""
    with pytest.raises(stateless.StatelessError) as e:
        stateless.rotate({"aid": "EONLY"}, key(), key())
    assert "last_said" in str(e.value)

    with pytest.raises(stateless.StatelessError):
        stateless.interact({}, [])

    with pytest.raises(stateless.StatelessError):
        stateless.delegated_incept({"aid": "EONLY"}, key(), key())


def test_a_bad_key_is_refused_with_a_reason():
    with pytest.raises(stateless.StatelessError) as e:
        stateless.incept("not-a-key", key())
    assert "32 bytes" in str(e.value) or "base64" in str(e.value)

    with pytest.raises(stateless.StatelessError):
        stateless.incept("", key())


def test_the_same_inputs_produce_the_same_identity():
    """Determinism, so a retry is not a second identity."""
    pub, nxt = key(), key()
    assert stateless.incept(pub, nxt)["state"]["aid"] == stateless.incept(pub, nxt)["state"]["aid"]
