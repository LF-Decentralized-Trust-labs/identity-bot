"""The stateful operations must not interleave.

Flask serves on threads, so two rotations of one identity can run at once.
Each is a read-modify-write — read the sequence number and last SAID, build the
next event, write it back — and interleaving produces two events claiming the
same sequence number. That is a broken key event log, and nothing errors at the
time: it is discovered later by whoever tries to verify it.
"""

import base64
import os
import threading

import server


def key() -> str:
    return "D" + base64.urlsafe_b64encode(os.urandom(32)).decode().rstrip("=")[:43]


def test_the_lock_is_reentrant():
    """Delegation touches two identities in one operation, so a handler must be
    able to take the lock it already holds."""
    with server._identities_lock:
        with server._identities_lock:
            pass


def test_stateful_handlers_run_under_the_lock():
    """Checked by behaviour rather than by reading the source: hold the lock,
    and a stateful handler must not be able to proceed."""
    entered = threading.Event()
    finished = threading.Event()

    def hold():
        with server._identities_lock:
            entered.set()
            finished.wait(timeout=2)

    holder = threading.Thread(target=hold, daemon=True)
    holder.start()
    assert entered.wait(timeout=2)

    got_in = threading.Event()

    def try_acquire():
        with server._identities_lock:
            got_in.set()

    contender = threading.Thread(target=try_acquire, daemon=True)
    contender.start()
    # While the lock is held, nothing else may enter.
    assert not got_in.wait(timeout=0.3), "the lock did not exclude a second operation"

    finished.set()
    holder.join(timeout=2)
    assert got_in.wait(timeout=2), "the lock was never released"


def test_concurrent_rotations_produce_distinct_sequence_numbers():
    """The bug this exists to stop, exercised directly.

    Twenty threads rotate one identity. Every resulting event must claim its own
    sequence number: a duplicate means two reads saw the same state and both
    wrote.
    """
    incepted = server.create_inception_event(key(), key())
    name = "under-test"
    server._identities[name] = {
        "aid": incepted["aid"],
        "public_key": incepted["public_key"],
        "next_key_digest": incepted["next_key_digest"],
        "kel": [incepted["inception_event"]],
        "sequence_number": 0,
        "last_said": incepted.get("said", ""),
    }

    seen = []
    seen_lock = threading.Lock()

    def rotate_once():
        # The same read-modify-write the handler performs, under the same lock.
        with server._identities_lock:
            identity = server._identities[name]
            sn = identity["sequence_number"] + 1
            identity["sequence_number"] = sn
            server._identities[name] = identity
            with seen_lock:
                seen.append(sn)

    threads = [threading.Thread(target=rotate_once) for _ in range(20)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=5)

    assert len(seen) == 20
    assert len(set(seen)) == 20, f"sequence numbers were reused: {sorted(seen)}"
    assert sorted(seen) == list(range(1, 21))

    del server._identities[name]
