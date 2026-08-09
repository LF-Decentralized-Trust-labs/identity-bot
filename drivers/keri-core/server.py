"""
KERI Core Driver — Internal HTTP microservice for KERI protocol operations.

This driver uses the WebOfTrust keripy reference library (v1.1.17+) as a HARD
requirement. If keripy is not installed or libsodium is not available, the
driver will refuse to start rather than produce non-interoperable output.

Runs on 127.0.0.1:9999 by default (never exposed publicly).
Go spawns this as a child process and kills it on exit.

Endpoints (Stateful — require identity state):
    GET  /status       — Driver health and library info
    POST /inception    — Create a KERI inception event; returns raw_bytes_b64 for Dart to sign
    POST /rotation     — Rotate keys for an existing AID
    POST /sign         — Returns 501: signing is done on the controller device (ADR-014)
    GET  /kel          — Retrieve the Key Event Log for an AID
    POST /verify       — Verify a signature (accepts raw base64 or CESR '0B...' format)

Endpoints (Stateless — public data only, no private keys):
    POST /cesr-encode           — Wrap raw 64-byte Ed25519 sig in CESR Cigar ('0B...' 88 chars)
    POST /format-credential     — Format an ACDC credential for signing
    POST /resolve-oobi          — Resolve an OOBI URL to endpoints
    POST /generate-multisig-event — Generate a multisig KERI event
    POST /delegated-inception — Create a KERI delegated inception (dip) event
    POST /delegated-rotation — Perform delegated rotation for a dip AID (reuses rotation logic)

CESR signing chain (proven by tests/keri_interop_test.py):
    Dart signs raw bytes with ed25519_edwards
    → raw 64-byte signature sent to /cesr-encode
    → coring.Cigar(raw=sig, code=MtrDex.Ed25519_Sig).qb64 = '0B...' (88 chars)
    → keripy verifier accepts this output identically to its native signer.sign()
"""

import os
import sys
import time
import ctypes
import ctypes.util
import base64
import functools
import json
import threading
import tempfile
import shutil

try:
    import requests as _requests
    _REQUESTS_AVAILABLE = True
except ImportError:
    _REQUESTS_AVAILABLE = False

# ---------------------------------------------------------------------------
# libsodium detection (Nix environments don't always expose it to find_library)
# ---------------------------------------------------------------------------

def _ensure_libsodium():
    if ctypes.util.find_library("sodium"):
        return

    if sys.platform == "win32":
        script_dir = os.path.dirname(os.path.abspath(__file__))
        search_dirs = [
            script_dir,
            os.path.join(script_dir, "..", "python"),
            os.path.join(script_dir, ".."),
        ]
        for d in search_dirs:
            dll_path = os.path.join(d, "libsodium.dll")
            if os.path.isfile(dll_path):
                try:
                    ctypes.CDLL(dll_path)
                    os.environ["PATH"] = d + ";" + os.environ.get("PATH", "")
                    return
                except OSError:
                    continue
        return

    found_path = None
    for so_name in ["libsodium.so.26", "libsodium.so.23", "libsodium.so"]:
        try:
            ctypes.CDLL(so_name)
            with open(f"/proc/{os.getpid()}/maps") as f:
                for line in f:
                    if "sodium" in line:
                        parts = line.strip().split()
                        if len(parts) >= 6:
                            found_path = parts[-1]
                            break
            break
        except OSError:
            continue
    if found_path:
        ctypes.util.find_library = lambda name, _orig=ctypes.util.find_library, _path=found_path: (
            _path if name in ("sodium", "libsodium") else _orig(name)
        )

_ensure_libsodium()

# ---------------------------------------------------------------------------
# Windows: patch SysLogHandler before keri / hio import
#
# keripy → hio → ogling sets up a SysLogHandler(address="/dev/log") which
# tries socket.socket(socket.AF_UNIX, ...).  On Windows Store Python,
# socket.AF_UNIX is absent → AttributeError on import.
#
# Fix: (1) stub socket.AF_UNIX so attribute lookups pass; (2) patch only the
# socket-creation methods on SysLogHandler while keeping all the class-level
# LOG_* constants intact (hio's Ogler accesses e.g. SysLogHandler.LOG_LOCAL0).
# ---------------------------------------------------------------------------

if sys.platform == "win32":
    import socket as _socket
    import logging as _logging
    import logging.handlers as _lh

    if not hasattr(_socket, "AF_UNIX"):
        _socket.AF_UNIX = 1  # dummy value; prevents AttributeError on attribute access

    _orig_syslog_init = _lh.SysLogHandler.__init__

    def _win_syslog_init(self, address=("localhost", _lh.SYSLOG_UDP_PORT),
                         facility=_lh.SysLogHandler.LOG_USER, socktype=None):
        """No-socket init: sets up all attributes but never creates a socket."""
        _logging.Handler.__init__(self)
        self.address = address
        self.facility = facility
        self.socktype = socktype
        self.unixsocket = False
        self.socket = None
        self.ident = ""
        self.append_nul = True

    _lh.SysLogHandler.__init__ = _win_syslog_init
    _lh.SysLogHandler.createSocket = lambda self: None
    _lh.SysLogHandler.emit = lambda self, record: None
    _lh.SysLogHandler.close = lambda self: _logging.Handler.close(self)

# ---------------------------------------------------------------------------
# keripy — hard requirement (no fallback)
# ---------------------------------------------------------------------------

from keri.core import coring, eventing, serdering
from keri.core.coring import MtrDex
from keri.core.eventing import TraitDex
from keri.vdr import eventing as veventing

from flask import Flask, request, jsonify

app = Flask(__name__)
start_time = time.time()

# ---------------------------------------------------------------------------
# In-memory state for managed identities (stateful operations)
# ---------------------------------------------------------------------------

_identities = {}

# Flask serves requests on threads, so two operations on the same identity can
# run at once. Every stateful operation here is a read-modify-write — read the
# identity, build the next event from its sequence number and last SAID, write
# it back — and two of those interleaving produce two events claiming the same
# sequence number, which is a broken key event log rather than an error anybody
# would see at the time.
#
# The lock is held across a whole operation, not around each dictionary access:
# locking the reads and writes individually would still allow the read of one
# request and the write of another to interleave, which is the actual bug.
#
# One lock rather than one per identity, deliberately. A driver serves one
# agent, so contention is not a real cost, and a single lock cannot deadlock
# against itself the way a lock-per-key scheme can once an operation touches
# two identities — which delegation does, since it advances both the delegator
# and the new delegate.
_identities_lock = threading.RLock()


def serialized(handler):
    """Runs a stateful handler under the identities lock.

    Applied to the operations that read an identity and write it back. Read-only
    endpoints are left alone: a single dictionary lookup is atomic, and blocking
    reads behind writes would slow the common path to protect nothing.
    """

    @functools.wraps(handler)
    def guarded(*args, **kwargs):
        with _identities_lock:
            return handler(*args, **kwargs)

    return guarded

# ---------------------------------------------------------------------------
# KERI protocol helpers
# ---------------------------------------------------------------------------

def _b64url_decode(s: str) -> bytes:
    padding = 4 - len(s) % 4
    if padding != 4:
        s += "=" * padding
    return base64.urlsafe_b64decode(s)


def _extract_raw_key(cesr_key: str) -> bytes:
    if cesr_key[0] in ("B", "D") and len(cesr_key) > 1:
        # CESR 1-char code with 1 lead zero byte:
        # qb64 = code + base64url('\x00' + raw_32)[1:]
        # To recover raw_32: restore the dropped first base64 char ('A' for a zero lead byte),
        # decode to 33 bytes, then strip the lead byte.
        raw_with_lead = _b64url_decode("A" + cesr_key[1:])  # 33 bytes: '\x00' + raw_32
        return raw_with_lead[1:]                             # 32 bytes: raw_32
    return _b64url_decode(cesr_key)


def create_hybrid_inception_event(use_synthetic: bool = False) -> dict:
    from pqc.hybrid_inception import (
        build_hybrid_inception,
        generate_hybrid_key_material,
        synthetic_hybrid_key_material,
    )

    material = (
        synthetic_hybrid_key_material(seed=0)
        if use_synthetic
        else generate_hybrid_key_material()
    )
    return build_hybrid_inception(material)


def _keri_version() -> str:
    try:
        import keri
        return getattr(keri, "__version__", "unknown")
    except Exception:
        return "unavailable"


def _check_keri_api() -> None:
    """Fail at startup if keripy is not the version this driver is written for.

    The failure this prevents is a confusing one. An older keripy has
    eventing.incept(keys, sith, nxt, ...) rather than (keys, isith, ndigs,
    nsith, ...), so the driver starts fine, serves /status happily, and then
    fails one specific call with "incept() got an unexpected keyword argument
    'isith'" — which reads as a bug in the caller rather than as the wrong
    library being installed. Better to refuse to start and say so.
    """
    import inspect
    from keri.core import eventing

    params = set(inspect.signature(eventing.incept).parameters)
    missing = {"isith", "ndigs", "nsith"} - params
    if missing:
        sys.exit(
            "FATAL: this driver needs keripy with %s on eventing.incept, and the "
            "installed keripy (%s) does not have them. Point KERI_DRIVER_PYTHON at "
            "an interpreter with keri==1.1.17."
            % (", ".join(sorted(missing)), _keri_version())
        )


def create_inception_event(
    public_key: str,
    next_public_key: str,
    witnesses: list | None = None,
    toad: int | None = None,
    anchors: list | None = None,
    keys: list | None = None,
    next_keys: list | None = None,
    isith: str | None = None,
    nsith: str | None = None,
) -> dict:
    """Build the inception event, optionally designating witnesses.

    Witnesses are named in the event itself — the `b` field, with the threshold
    in `bt`. That is worth stating plainly because it decides a design question
    elsewhere: a controller's witnesses are PUBLIC by protocol, so nothing about
    witnessing can be kept private, and any scheme that assumed otherwise was
    assuming something the protocol does not offer.

    An identity with no witnesses is valid and is what we produced until now. It
    simply has nobody to detect duplicity on its behalf, so a second conflicting
    version of its history has nothing to contradict it.
    """
    pub_bytes = _extract_raw_key(public_key)
    next_bytes = _extract_raw_key(next_public_key)

    verfer = coring.Verfer(raw=pub_bytes, code=MtrDex.Ed25519)
    diger = coring.Diger(raw=next_bytes, code=MtrDex.Blake3_256)

    wits = list(witnesses or [])
    # Threshold of accountable duplicity. Defaults to a simple majority, which
    # is the usual KERI guidance: enough that a minority of unavailable or
    # dishonest witnesses cannot stall or forge, without requiring all of them
    # to be reachable at once.
    if wits:
        bt = toad if toad is not None else (len(wits) // 2) + 1
    else:
        bt = 0

    # Anchors go in the event's own `a` field, which means they are part of
    # what the identifier is derived from: a self-addressing AID is the digest
    # of this event, so an anchor cannot be added, removed or altered later
    # without producing a different identifier.
    #
    # That is the whole reason to put ownership here rather than in a record
    # beside the database. A file saying who owns an identity can be rewritten
    # by anyone who can write the file, silently, and cannot be read by anybody
    # who is not on that machine. This can be neither.
    # A signing threshold, for an identity controlled by more than one key.
    #
    # An identity may be controlled by more than one key, and at founding there
    # is usually exactly one — so this is a one-of-one multi-signature identity
    # rather than a single-key one. The distinction matters because the two are different
    # KERI identities: a one-of-one can rotate to two-of-three by adding keys and
    # raising the threshold, and a single-key identity that never declared a
    # threshold has to be re-founded to become one. Founding one-of-one is what
    # makes the growth path a rotation rather than a restart.
    #
    # Omitted entirely when unset, so every existing caller produces byte-for-byte
    # the same event it did before — keripy defaults both to 1, and passing "1"
    # explicitly is NOT the same event as passing nothing.
    key_list = [k.strip() for k in (keys or []) if k and k.strip()] or [verfer.qb64]
    ndig_list = [d.strip() for d in (next_keys or []) if d and d.strip()] or [diger.qb64]

    incept_args = {
        "keys": key_list,
        "ndigs": ndig_list,
        "wits": wits,
        "toad": bt,
        "data": list(anchors or []),
        "code": MtrDex.Blake3_256,
    }
    if isith is not None:
        incept_args["isith"] = str(isith)
    if nsith is not None:
        incept_args["nsith"] = str(nsith)

    serder = eventing.incept(**incept_args)

    return {
        "aid": serder.pre,
        "said": serder.said,
        "inception_event": serder.ked,
        # raw_bytes_b64: the exact bytes the controller must sign with its Ed25519 key.
        # Dart: base64.decode(raw_bytes_b64) → sign → /cesr-encode → attach CESR sig.
        "raw_bytes_b64": base64.b64encode(serder.raw).decode(),
        "public_key": verfer.qb64,
        "next_key_digest": diger.qb64,
    }

# ---------------------------------------------------------------------------
# HTTP routes — Status
# ---------------------------------------------------------------------------

@app.route("/status", methods=["GET"])
def status():
    uptime = time.time() - start_time
    return jsonify({
        "status": "active",
        "driver": "keri-core",
        "version": "0.1.0",
        "keri_library": "keripy",
        # Reported so a client adopting an already-running driver can tell
        # WHICH driver it adopted. Without these, editing this file and
        # restarting an agent looks like it took effect when the agent may have
        # adopted somebody else's driver running older code — a silent no-op
        # that reads as a failed change.
        "keri_version": _keri_version(),
        "script_path": os.path.abspath(__file__),
        "uptime": f"{uptime:.0f}s",
        "endpoints": [
            "GET /status",
            "POST /inception",
            "POST /rotation",
            "POST /delegated-inception",
            "POST /delegated-rotation",
            "POST /sign",
            "POST /sign-for-name",
            "GET /kel",
            "POST /verify",
            "POST /cesr-encode",
            "POST /format-credential",
            "POST /resolve-oobi",
            "POST /generate-multisig-event",
        ],
    })

# ---------------------------------------------------------------------------
# HTTP routes — Stateful KERI operations
# ---------------------------------------------------------------------------

@app.route("/hybrid-inception", methods=["POST"])
@serialized
def hybrid_inception():
    data = request.get_json(silent=True) or {}
    use_synthetic = bool(data.get("synthetic", False))

    try:
        result = create_hybrid_inception_event(use_synthetic=use_synthetic)

        name = data.get("name", result["aid"])
        _identities[name] = {
            "aid": result["aid"],
            "public_key": result["public_key"],
            "next_key_digest": result["next_key_digest"],
            "kel": [result["inception_event"]],
            # Read back off the event rather than from the request. Inception
            # computes a threshold when the caller does not supply one, so the
            # requested value and the real one differ exactly when nobody asked
            # — and storing the requested one would leave the identity holding a
            # threshold its own event does not agree with.
            "witnesses": _wits_of_event(result["inception_event"])[0],
            "toad": _wits_of_event(result["inception_event"])[1],
            "sequence_number": 0,
            "last_said": result.get("said", ""),
            "cipher_suite": result.get("cipher_suite", "IA-HYBRID-1"),
        }

        return jsonify(result), 201
    except Exception as e:
        return jsonify({"error": f"Hybrid inception failed: {str(e)}"}), 500


@app.route("/inception", methods=["POST"])
@serialized
def inception():
    data = request.get_json()
    if not data:
        return jsonify({"error": "Request body required"}), 400

    public_key = data.get("public_key", "")
    next_public_key = data.get("next_public_key", "")

    if not public_key or not next_public_key:
        return jsonify({"error": "public_key and next_public_key are required"}), 400

    try:
        result = create_inception_event(
            public_key,
            next_public_key,
            witnesses=data.get("witnesses"),
            toad=data.get("toad"),
            anchors=data.get("anchors"),
            keys=data.get("keys"),
            next_keys=data.get("next_keys"),
            isith=data.get("isith"),
            nsith=data.get("nsith"),
        )

        name = data.get("name", result["aid"])
        _identities[name] = {
            "aid": result["aid"],
            "public_key": result["public_key"],
            "next_key_digest": result["next_key_digest"],
            "kel": [result["inception_event"]],
            # Kept so a rotation can amend the set rather than being handed it.
            # A caller supplying the current witnesses would be a caller able to
            # get them wrong.
            "witnesses": list(data.get("witnesses") or []),
            "toad": data.get("toad") or 0,
            "sequence_number": 0,
            # last_said tracks the SAID of the most recent event (used as 'dig' in next event)
            "last_said": result.get("said", ""),
        }

        return jsonify(result), 201
    except Exception as e:
        return jsonify({"error": f"Inception failed: {str(e)}"}), 500


@app.route("/rotation", methods=["POST"])
@serialized
def rotation():
    data = request.get_json()
    if not data:
        return jsonify({"error": "Request body required"}), 400

    name = data.get("name", "")
    new_public_key = data.get("new_public_key", "")
    new_next_public_key = data.get("new_next_public_key", "")
    seal_data = data.get("data", [])

    if not name:
        return jsonify({"error": "name is required"}), 400
    # A rotation names its new keys one of two ways: a single key, which is the
    # ordinary case, or a whole SET, which is how an identity comes to be
    # controlled by several people. Requiring the single form even when a set is
    # given would make the second impossible.
    key_set = [k for k in (data.get("keys") or []) if k and str(k).strip()]
    # DIGESTS, not keys — what a rotation commits to is the digest of each
    # successor, never the successor itself. Named for what it holds, because
    # the two are both opaque strings and mistaking one for the other produces
    # an identity nobody can ever rotate.
    next_digest_set = [d for d in (data.get("next_key_digests") or []) if d and str(d).strip()]
    if key_set or next_digest_set:
        if not key_set or not next_digest_set:
            return jsonify({"error":
                "a rotation to a key set needs both keys and next_key_digests — one "
                "without the other leaves an identity that can never rotate again"}), 400
        # The first key of the set answers "the" public key for everything
        # downstream that reports one. The next-key field is left alone: it holds
        # a public key, and these are digests.
        new_public_key = new_public_key or key_set[0]
    elif not new_public_key or not new_next_public_key:
        return jsonify({"error": "new_public_key and new_next_public_key are required"}), 400

    identity = _identities.get(name)
    if not identity:
        return jsonify({"error": f"No identity found with name: {name}"}), 404

    try:
        new_verfer = coring.Verfer(raw=_extract_raw_key(new_public_key), code=MtrDex.Ed25519)

        # The successor is given either as a KEY, which is digested here, or as
        # a DIGEST already, which is what a rotation to a key set sends — each
        # owner commits the digest of their own successor and never publishes
        # the key itself. Digesting a digest would commit to something no
        # future rotation could ever produce.
        new_diger = None
        if new_next_public_key:
            new_diger = coring.Diger(raw=_extract_raw_key(new_next_public_key),
                                     code=MtrDex.Blake3_256)
        elif next_digest_set:
            new_diger = coring.Diger(qb64=next_digest_set[0])
        else:
            return jsonify({"error":
                "a rotation must commit to a successor, or the identity can never "
                "rotate again"}), 400

        sn = identity["sequence_number"] + 1
        prev_said = identity.get("last_said", "")

        # Witness changes travel in a rotation event, as br (removed) and ba
        # (added) against the set the identity already has. Until now this call
        # passed none of them, so there was no way to add or remove a witness on
        # a live identity at all — the set an identity was born with was the set
        # it died with.
        current_wits = list(identity.get("witnesses") or [])
        cuts = [w for w in (data.get("witness_cuts") or []) if w in current_wits]
        adds = [w for w in (data.get("witness_adds") or []) if w not in current_wits]

        # What the set will be once this event applies.
        next_wits = [w for w in current_wits if w not in cuts] + adds

        # A threshold has to move with the set it counts. Left alone, removing
        # witnesses eventually makes it unreachable and the identity can no
        # longer finalise anything; a majority keeps duplicity detectable while
        # tolerating the largest number of absent or dishonest witnesses.
        if data.get("toad") is not None:
            bt = int(data["toad"])
        elif cuts or adds:
            bt = (len(next_wits) // 2) + 1 if next_wits else 0
        else:
            bt = identity.get("toad") or 0

        if next_wits and bt > len(next_wits):
            return jsonify({"error":
                f"threshold {bt} exceeds the {len(next_wits)} witnesses that would remain, "
                "which would leave the identity unable to finalise any event"}), 400

        # A rotation may change WHO CONTROLS the identity, not merely which key
        # it uses. That is what turns an identity controlled by one party into
        # one controlled by several: the key set grows and the threshold rises,
        # in a single event, without the identifier changing.
        #
        # It is also the only place a threshold can be introduced. An identity
        # founded by one person is already one-of-one — keripy writes kt:"1"
        # whether or not anybody asked — so nothing about founding needs to
        # anticipate this. The growth happens here or nowhere.
        rotate_keys = list(key_set)
        rotate_ndigs = list(next_digest_set)
        isith = data.get("isith")
        nsith = data.get("nsith")

        rotate_args = {
            "pre": identity["aid"],
            "keys": rotate_keys or [new_verfer.qb64],
            "dig": prev_said,
            "ndigs": rotate_ndigs or [new_diger.qb64],
            "sn": sn,
            "wits": current_wits,
            "cuts": cuts,
            "adds": adds,
            "toad": bt if (cuts or adds or next_wits) else None,
            "data": seal_data,
        }
        if isith is not None:
            rotate_args["isith"] = str(isith)
        if nsith is not None:
            rotate_args["nsith"] = str(nsith)

        serder = eventing.rotate(**rotate_args)

        # Recorded from the EVENT, not from the single key that was passed in.
        # After a rotation to more than one key, "the public key" is the first of
        # several and the stored state has to say so, or a later rotation builds
        # its next event from a key set of one and silently drops the others.
        current_keys = list(serder.ked.get("k") or [new_verfer.qb64])
        current_ndigs = list(serder.ked.get("n") or [new_diger.qb64])

        identity["public_key"] = current_keys[0]
        identity["next_key_digest"] = current_ndigs[0] if current_ndigs else ""
        identity["keys"] = current_keys
        identity["next_key_digests"] = current_ndigs
        identity["isith"] = serder.ked.get("kt")
        identity["nsith"] = serder.ked.get("nt")
        identity["witnesses"] = next_wits
        identity["toad"] = bt
        identity["sequence_number"] = sn
        identity["last_said"] = serder.said
        identity["kel"].append(serder.ked)

        return jsonify({
            "aid": identity["aid"],
            "new_public_key": current_keys[0],
            "new_next_key_digest": current_ndigs[0] if current_ndigs else "",
            "keys": current_keys,
            "next_key_digests": current_ndigs,
            "isith": serder.ked.get("kt"),
            "nsith": serder.ked.get("nt"),
            "rotation_event": serder.ked,
            "said": serder.said,
            # raw_bytes_b64: sign these with the PRE-ROTATED key (index 1 from mnemonic)
            "raw_bytes_b64": base64.b64encode(serder.raw).decode(),
            "sequence_number": sn,
        }), 200
    except Exception as e:
        return jsonify({"error": f"Rotation failed: {str(e)}"}), 500


@app.route("/delegated-inception", methods=["POST"])
@serialized
def delegated_inception():
    data = request.get_json()
    if not data:
        return jsonify({"error": "Request body required"}), 400

    public_key = data.get("public_key", "")
    next_public_key = data.get("next_public_key", "")
    name = data.get("name", "")
    delegator_name = data.get("delegator_name", "")

    if not all([public_key, next_public_key, delegator_name]):
        return jsonify({"error": "public_key, next_public_key, delegator_name required"}), 400

    if delegator_name not in _identities:
        return jsonify({"error": f"delegator '{delegator_name}' not found — inception required first"}), 404

    try:
        delegator = _identities[delegator_name]
        delegator_aid = delegator["aid"]

        pub_bytes = _extract_raw_key(public_key)
        next_bytes = _extract_raw_key(next_public_key)

        verfer = coring.Verfer(raw=pub_bytes, code=MtrDex.Ed25519)
        diger = coring.Diger(raw=next_bytes, code=MtrDex.Blake3_256)

        # dip event: delegated inception referencing the delegator prefix.
        # keripy 1.1.17: eventing.delcept() — verify the name in keri/core/eventing.py
        serder = eventing.delcept(
            keys=[verfer.qb64],
            delpre=delegator_aid,
            ndigs=[diger.qb64],
            code=MtrDex.Blake3_256,
        )

        asset_aid = serder.pre
        asset_name = name if name else asset_aid

        _identities[asset_name] = {
            "aid": asset_aid,
            "public_key": verfer.qb64,
            "next_key_digest": diger.qb64,
            "kel": [serder.ked],
            "sequence_number": 0,
            "last_said": serder.said,
            "delegator_aid": delegator_aid,
        }

        # Delegator anchors the delegation with an interaction event (ixn).
        delegator_seqno = delegator.get("sequence_number", 0) + 1
        seal = eventing.SealEvent(i=asset_aid, s="0", d=serder.said)
        delegator_ixn_serder = eventing.interact(
            pre=delegator_aid,
            dig=delegator["last_said"],
            sn=delegator_seqno,
            data=[seal._asdict()],
        )
        delegator["kel"].append(delegator_ixn_serder.ked)
        delegator["sequence_number"] = delegator_seqno
        delegator["last_said"] = delegator_ixn_serder.said
        _identities[delegator_name] = delegator

        return jsonify({
            "aid": asset_aid,
            "delegator_aid": delegator_aid,
            "said": serder.said,
            "dip_event": serder.ked,
            "delegator_ixn": delegator_ixn_serder.ked,
            "raw_bytes_b64": base64.b64encode(serder.raw).decode(),
            "public_key": verfer.qb64,
            "next_key_digest": diger.qb64,
        }), 201

    except Exception as e:
        return jsonify({"error": f"Delegated inception failed: {str(e)}"}), 500


@app.route("/delegated-rotation", methods=["POST"])
@serialized
def delegated_rotation():
    data = request.get_json()
    if not data:
        return jsonify({"error": "Request body required"}), 400
    name = data.get("name", "")
    if not name or name not in _identities:
        return jsonify({"error": f"identity '{name}' not found"}), 404
    identity = _identities[name]
    if "delegator_aid" not in identity:
        return jsonify({"error": f"'{name}' is not a delegated AID; use /rotation"}), 400
    # Delegate to the existing rotation logic — forward internally.
    # Copy the /rotation handler body here (same key-rotation logic, same response shape).
    # The delegator_aid field distinguishes it from a standalone rotation for audit purposes.
    return rotation()  # reuse the /rotation handler directly


@app.route("/interact", methods=["POST"])
def interact():
    """Create a KERI interaction (IXN) event anchoring external data in the KEL.

    Request JSON:
        name          (str)  — identity name (AID or label)
        data          (list) — list of seal dicts to anchor, e.g. [{"d": "<SAID>"}]

    Returns:
        ixn_event     (dict) — the serialized IXN event body
        raw_bytes_b64 (str)  — base64 of event bytes; sign with current key then /cesr-encode
        said          (str)  — SAID of the IXN event
        sequence_number (int)
    """
    data = request.get_json()
    if not data:
        return jsonify({"error": "Request body required"}), 400

    name = data.get("name", "")
    seal_data = data.get("data", [])

    if not name:
        return jsonify({"error": "name is required"}), 400

    identity = _identities.get(name)
    if not identity:
        return jsonify({"error": f"No identity found with name: {name}"}), 404

    try:
        sn = identity["sequence_number"] + 1
        prev_said = identity.get("last_said", "")

        serder = eventing.interact(
            pre=identity["aid"],
            dig=prev_said,
            sn=sn,
            data=seal_data,
        )

        identity["sequence_number"] = sn
        identity["last_said"] = serder.said
        identity["kel"].append(serder.ked)

        return jsonify({
            "aid": identity["aid"],
            "ixn_event": serder.ked,
            # raw_bytes_b64: sign these with the CURRENT signing key then call /cesr-encode
            "raw_bytes_b64": base64.b64encode(serder.raw).decode(),
            "said": serder.said,
            "sequence_number": sn,
        }), 201
    except Exception as e:
        return jsonify({"error": f"Interact failed: {str(e)}"}), 500


# ── Endpoint records: where an identity currently is ─────────────────────────
#
# An OOBI is a URL, and a URL handed to somebody persists in their store long
# after it stops working. When a relay is left, shut down, or an allocation
# expires, every counterparty holding that string is stranded — the relationship
# breaks from an infrastructure change neither party made.
#
# KERI's answer is that the controller SIGNS where it currently is, and
# witnesses carry the record. A counterparty that cannot reach the address it
# has already holds the KEL, and the KEL names the witnesses, so it can ask them
# for the current one. That makes witnesses the stable anchor and relay
# addresses disposable — which is what allows an identity to move between
# providers, or use several at once, without a migration.
#
# Two record types, both plain signed reply messages:
#
#   /end/role/add   this endpoint provider acts for me in this role
#   /loc/scheme     that provider is reachable at this URL
#
# Both are built with keripy's own reply() so the SAID and serialisation are the
# reference implementation's, never ours. As everywhere else in this driver, the
# raw bytes come back for the caller to sign — this process holds no keys.


@app.route("/endpoint/role", methods=["POST"])
def endpoint_role():
    """Authorize (or revoke) an endpoint provider in a role.

    Request JSON:
        cid   (str)  — the controller AID making the statement
        eid   (str)  — the endpoint provider's AID
        role  (str)  — controller | agent | mailbox | witness | watcher
        allow (bool) — True authorizes, False revokes. Default True.

    Returns:
        rpy_event     (dict) — the reply message body
        raw_bytes_b64 (str)  — base64 of the bytes to sign, then /cesr-encode
        said          (str)
        route         (str)  — /end/role/add or /end/role/cut
    """
    data = request.get_json()
    if not data:
        return jsonify({"error": "Request body required"}), 400

    cid = data.get("cid", "")
    eid = data.get("eid", "")
    role = data.get("role", "controller")
    allow = data.get("allow", True)

    if not cid or not eid:
        return jsonify({"error": "cid and eid are required"}), 400

    # Revoking matters as much as granting. An endpoint that simply goes quiet
    # is indistinguishable from one that is briefly down, so a provider that is
    # no longer ours has to be said so explicitly rather than left to rot.
    route = "/end/role/add" if allow else "/end/role/cut"

    try:
        serder = eventing.reply(
            route=route,
            data={"cid": cid, "role": role, "eid": eid},
        )
        return jsonify({
            "cid": cid,
            "eid": eid,
            "role": role,
            "route": route,
            "rpy_event": serder.ked,
            "raw_bytes_b64": base64.b64encode(serder.raw).decode(),
            "said": serder.said,
        }), 201
    except Exception as e:
        return jsonify({"error": f"Endpoint role reply failed: {str(e)}"}), 500


@app.route("/endpoint/location", methods=["POST"])
def endpoint_location():
    """State the URL at which an endpoint provider is reachable.

    Request JSON:
        eid    (str) — the endpoint provider's AID (often the controller itself)
        url    (str) — the current URL. Empty nullifies the location.
        scheme (str) — url scheme, default https

    Returns:
        rpy_event     (dict)
        raw_bytes_b64 (str)  — base64 of the bytes to sign, then /cesr-encode
        said          (str)
    """
    data = request.get_json()
    if not data:
        return jsonify({"error": "Request body required"}), 400

    eid = data.get("eid", "")
    url = data.get("url", "")
    scheme = data.get("scheme", "https")

    if not eid:
        return jsonify({"error": "eid is required"}), 400

    # An empty url is meaningful rather than missing: it nullifies the location,
    # which is how an identity says "not here any more" instead of leaving a
    # dead address published.
    try:
        serder = eventing.reply(
            route="/loc/scheme",
            data={"eid": eid, "scheme": scheme, "url": url},
        )
        return jsonify({
            "eid": eid,
            "url": url,
            "scheme": scheme,
            "route": "/loc/scheme",
            "rpy_event": serder.ked,
            "raw_bytes_b64": base64.b64encode(serder.raw).decode(),
            "said": serder.said,
        }), 201
    except Exception as e:
        return jsonify({"error": f"Endpoint location reply failed: {str(e)}"}), 500


@app.route("/cesr-encode", methods=["POST"])
def cesr_encode():
    """Stateless: wrap a raw Ed25519 signature in CESR Cigar encoding ('0B...' 88 chars).

    Accepts JSON: { "raw_sig_b64": "<standard base64 of 64 raw sig bytes>" }
    Returns JSON: { "cesr_sig": "0B...", "length": 88 }

    This is the bridge between Dart's ed25519_edwards raw output and the CESR
    format required by the KERI protocol. Proven equivalent to keripy's native
    signer.sign() output by tests/keri_interop_test.py.
    """
    data = request.get_json()
    if not data:
        return jsonify({"error": "Request body required"}), 400

    raw_sig_b64 = data.get("raw_sig_b64", "")
    if not raw_sig_b64:
        return jsonify({"error": "raw_sig_b64 is required"}), 400

    try:
        raw_sig = base64.b64decode(raw_sig_b64)
        if len(raw_sig) != 64:
            return jsonify({"error": f"Ed25519 signature must be 64 bytes, got {len(raw_sig)}"}), 400

        cigar = coring.Cigar(raw=raw_sig, code=MtrDex.Ed25519_Sig)
        cesr_sig = cigar.qb64

        return jsonify({
            "cesr_sig": cesr_sig,
            "length": len(cesr_sig),
        }), 200
    except Exception as e:
        return jsonify({"error": f"CESR encoding failed: {str(e)}"}), 500


@app.route("/sign", methods=["POST"])
def sign():
    # Signing is intentionally not implemented in the Python driver.
    #
    # Private keys never leave the controller device. All signing is performed
    # locally in Dart (desktop) or via the Rust KERI bridge (mobile).
    # Passing private key material to this process would violate the key
    # custody invariant established in ADR-014.
    #
    # If this endpoint is called, it means a code path is incorrectly routing
    # signing through the backend. Fix the caller, not this endpoint.
    return jsonify({
        "error": "Signing is not handled by the KERI driver. Sign locally on the controller device.",
        "see": "ADR-014: Key Custody invariant — private keys never leave the controller device.",
    }), 501


@app.route("/kel", methods=["GET"])
def get_kel():
    name = request.args.get("name", "")
    if not name:
        return jsonify({"error": "name query parameter is required"}), 400

    identity = _identities.get(name)
    if not identity:
        return jsonify({"error": f"No identity found with name: {name}"}), 404

    return jsonify({
        "aid": identity["aid"],
        "kel": identity["kel"],
        "sequence_number": identity["sequence_number"],
        "event_count": len(identity["kel"]),
    }), 200


@app.route("/verify", methods=["POST"])
def verify():
    data = request.get_json()
    if not data:
        return jsonify({"error": "Request body required"}), 400

    payload_b64 = data.get("data", "")
    signature_b64 = data.get("signature", "")
    public_key = data.get("public_key", "")

    if not payload_b64 or not signature_b64 or not public_key:
        return jsonify({"error": "data, signature, and public_key are required"}), 400

    try:
        payload_bytes = base64.b64decode(payload_b64)
        raw_key = _extract_raw_key(public_key)
        verfer = coring.Verfer(raw=raw_key, code=MtrDex.Ed25519)

        # Accept either CESR '0B...' format or plain base64 raw bytes.
        # CESR Cigar: strip the 2-char '0B' code prefix, then base64url-decode the rest.
        if signature_b64.startswith("0B") and len(signature_b64) == 88:
            cigar = coring.Cigar(qb64=signature_b64)
            signature_bytes = cigar.raw
        else:
            signature_bytes = base64.b64decode(signature_b64)

        if len(signature_bytes) != 64:
            return jsonify({"error": f"Signature must be 64 bytes, got {len(signature_bytes)}"}), 400

        import pysodium
        try:
            pysodium.crypto_sign_verify_detached(signature_bytes, payload_bytes, raw_key)
            valid = True
        except Exception:
            valid = False

        return jsonify({
            "valid": valid,
            "public_key": verfer.qb64,
        }), 200
    except Exception as e:
        return jsonify({"error": f"Verification failed: {str(e)}"}), 500

# ---------------------------------------------------------------------------
# HTTP routes — Stateless KERI operations (no private keys, public data only)
# ---------------------------------------------------------------------------

def _format_acdc(issuer_aid: str, schema_said: str, claims: dict, edges: dict = None, registry_said: str = None) -> dict:
    """Format an ACDC credential body with self-addressing SAIDs.

    Computes the attribute block SAID first (embedded as 'a.d'), then optionally
    the edges block SAID (embedded as 'e.d'), then the top-level credential SAID
    (embedded as 'd'). All SAIDs use Blake3_256.

    edges (optional): dict of named edge entries following ACDC spec, e.g.:
        {"guardianship": {"n": "<parent-credential-SAID>", "s": "<schema-SAID>"}}
    When provided, the edges block is included as the 'e' field in the ACDC body,
    with a self-addressing 'd' SAID computed from the block content.

    Returns dict with: acdc_body, acdc_said, acdc_json_b64
    """
    attr_block = dict(claims)
    attr_block.setdefault("d", "")

    # Step 1: compute attribute block SAID
    attr_json = json.dumps(attr_block, separators=(",", ":")).encode()
    attr_diger = coring.Diger(ser=attr_json, code=MtrDex.Blake3_256)
    attr_block["d"] = attr_diger.qb64

    # Step 2: build ACDC body — include the registry ref (ri) and edges if provided.
    # Per ACDC field order, ri sits after i and before s.
    acdc_body = {
        "v": "ACDC10JSON000000_",
        "d": "",
        "i": issuer_aid,
    }
    if registry_said:
        acdc_body["ri"] = registry_said
    acdc_body["s"] = schema_said
    acdc_body["a"] = attr_block

    if edges:
        # Build edges block with self-addressing SAID per ACDC spec:
        # {"d": "", <label>: {"n": "<SAID>", "s": "<schemaSAID>"}, ...}
        edges_block = {"d": ""}
        edges_block.update(edges)
        edges_json = json.dumps(edges_block, separators=(",", ":")).encode()
        edges_diger = coring.Diger(ser=edges_json, code=MtrDex.Blake3_256)
        edges_block["d"] = edges_diger.qb64
        acdc_body["e"] = edges_block

    # Step 3: compute top-level SAID
    acdc_json_v1 = json.dumps(acdc_body, separators=(",", ":")).encode()
    acdc_diger = coring.Diger(ser=acdc_json_v1, code=MtrDex.Blake3_256)
    acdc_body["d"] = acdc_diger.qb64

    acdc_json_final = json.dumps(acdc_body, separators=(",", ":")).encode()
    return {
        "acdc_body": acdc_body,
        "acdc_said": acdc_diger.qb64,
        "acdc_json_b64": base64.b64encode(acdc_json_final).decode(),
    }


@app.route("/format-credential", methods=["POST"])
def format_credential():
    data = request.get_json()
    if not data:
        return jsonify({"error": "Request body required"}), 400

    claims = data.get("claims", {})
    schema_said = data.get("schema_said", "")
    issuer_aid = data.get("issuer_aid", "")

    if not claims or not schema_said or not issuer_aid:
        return jsonify({"error": "claims, schema_said, and issuer_aid are required"}), 400

    try:
        result = _format_acdc(issuer_aid, schema_said, claims)
        final_json = base64.b64decode(result["acdc_json_b64"])
        return jsonify({
            "raw_bytes_b64": result["acdc_json_b64"],
            "said": result["acdc_said"],
            "size": len(final_json),
        }), 200
    except Exception as e:
        return jsonify({"error": f"Format credential failed: {str(e)}"}), 500


@app.route("/registry/incept", methods=["POST"])
def registry_incept():
    """Incept a backerless credential registry (a TEL) for an issuer and anchor it
    in the issuer's KEL. Backerless (NoBackers) — self-anchored, no witnesses.

    Request JSON: name (issuer identity name)
    Returns: registry_said, vcp_event, vcp_json_b64, ixn_* (the anchoring interaction).
    """
    data = request.get_json() or {}
    name = data.get("name", "")
    if not name:
        return jsonify({"error": "name is required"}), 400
    identity = _identities.get(name)
    if not identity:
        return jsonify({"error": f"No identity found with name: {name}"}), 404
    try:
        vcp = veventing.incept(pre=identity["aid"], cnfg=[TraitDex.NoBackers], code=MtrDex.Blake3_256)
        regk = vcp.pre  # registry identifier

        # Anchor the registry inception SAID in the issuer KEL.
        sn = identity["sequence_number"] + 1
        seal = {"i": regk, "s": "0", "d": vcp.said}
        ixn_serder = eventing.interact(
            pre=identity["aid"],
            dig=identity.get("last_said", ""),
            sn=sn,
            data=[seal],
        )
        identity["sequence_number"] = sn
        identity["last_said"] = ixn_serder.said
        identity["kel"].append(ixn_serder.ked)

        return jsonify({
            "registry_said": regk,
            "vcp_said": vcp.said,
            "vcp_event": vcp.ked,
            "vcp_json_b64": base64.b64encode(vcp.raw).decode(),
            "ixn_raw_bytes_b64": base64.b64encode(ixn_serder.raw).decode(),
            "ixn_said": ixn_serder.said,
            "ixn_event": ixn_serder.ked,
            "sequence_number": sn,
        }), 201
    except Exception as e:
        return jsonify({"error": f"Registry inception failed: {str(e)}"}), 500


@app.route("/credential/revoke", methods=["POST"])
def credential_revoke():
    """Revoke a registry-backed credential: build a TEL revocation (rev) event and
    anchor it in the issuer's KEL. The rev anchor seal ({i: acdc_said, s: "1", ...})
    in the issuer's signed KEL IS the revocation proof — no separate channel needed.

    Request JSON: name, acdc_said, registry_said, iss_said (SAID of the prior iss event)
    Returns: rev_said, rev_event, ixn_* (the anchoring interaction).
    """
    data = request.get_json() or {}
    name = data.get("name", "")
    acdc_said = data.get("acdc_said", "")
    registry_said = data.get("registry_said", "")
    iss_said = data.get("iss_said", "")
    if not all([name, acdc_said, registry_said, iss_said]):
        return jsonify({"error": "name, acdc_said, registry_said, iss_said are required"}), 400
    identity = _identities.get(name)
    if not identity:
        return jsonify({"error": f"No identity found with name: {name}"}), 404
    try:
        rev_serder = veventing.revoke(vcdig=acdc_said, regk=registry_said, dig=iss_said)
        sn = identity["sequence_number"] + 1
        seal = {"i": acdc_said, "s": "1", "d": rev_serder.said}
        ixn_serder = eventing.interact(
            pre=identity["aid"],
            dig=identity.get("last_said", ""),
            sn=sn,
            data=[seal],
        )
        identity["sequence_number"] = sn
        identity["last_said"] = ixn_serder.said
        identity["kel"].append(ixn_serder.ked)

        return jsonify({
            "rev_said": rev_serder.said,
            "rev_event": rev_serder.ked,
            "ixn_raw_bytes_b64": base64.b64encode(ixn_serder.raw).decode(),
            "ixn_said": ixn_serder.said,
            "ixn_event": ixn_serder.ked,
            "sequence_number": sn,
        }), 201
    except Exception as e:
        return jsonify({"error": f"Credential revocation failed: {str(e)}"}), 500


@app.route("/credential/issue", methods=["POST"])
def credential_issue():
    """Issue an ACDC credential anchored in the issuer's KEL via an IXN event.

    Request JSON:
        name        (str)  — issuer identity name
        claims      (dict) — credential attribute claims (holder_aid, etc.)
        schema_said (str)  — SAID of the credential schema
        holder_aid  (str)  — AID of the credential subject/holder
        edges       (dict, optional) — ACDC edge block entries for credential chaining:
                    {"<label>": {"n": "<parent-credential-SAID>", "s": "<schema-SAID>"}}

    Returns:
        acdc_said       (str)  — self-addressing SAID of the ACDC credential
        acdc_json_b64   (str)  — base64 of the serialized ACDC credential
        acdc_body       (dict) — parsed ACDC credential
        ixn_raw_bytes_b64 (str) — base64 IXN event bytes; sign with current key then /cesr-encode
        ixn_said        (str)  — SAID of the anchoring IXN event
        sequence_number (int)
    """
    data = request.get_json()
    if not data:
        return jsonify({"error": "Request body required"}), 400

    name = data.get("name", "")
    claims = data.get("claims", {})
    schema_said = data.get("schema_said", "")
    holder_aid = data.get("holder_aid", "")
    edges = data.get("edges") or None  # optional; None means no edges block
    registry_said = data.get("registry_said") or None  # optional; enables TEL-backed issuance

    if not name:
        return jsonify({"error": "name is required"}), 400
    if not claims or not schema_said:
        return jsonify({"error": "claims and schema_said are required"}), 400

    identity = _identities.get(name)
    if not identity:
        return jsonify({"error": f"No identity found with name: {name}"}), 404

    try:
        # Step 1: format ACDC with full SAID computation (registry ref + edges if provided)
        credential = _format_acdc(identity["aid"], schema_said, claims, edges=edges, registry_said=registry_said)
        acdc_said = credential["acdc_said"]

        # Step 2: when the credential is registry-backed, build a TEL issuance (iss)
        # event and anchor ITS said with an {i,s,d} seal; otherwise keep the legacy
        # {d: acdc_said} anchor seal.
        iss_said = None
        if registry_said:
            iss_serder = veventing.issue(vcdig=acdc_said, regk=registry_said)
            iss_said = iss_serder.said
            seal = {"i": acdc_said, "s": "0", "d": iss_said}
        else:
            seal = {"d": acdc_said}

        sn = identity["sequence_number"] + 1
        prev_said = identity.get("last_said", "")
        ixn_serder = eventing.interact(
            pre=identity["aid"],
            dig=prev_said,
            sn=sn,
            data=[seal],
        )

        identity["sequence_number"] = sn
        identity["last_said"] = ixn_serder.said
        identity["kel"].append(ixn_serder.ked)

        resp = {
            "aid": identity["aid"],
            "acdc_said": acdc_said,
            "acdc_json_b64": credential["acdc_json_b64"],
            "acdc_body": credential["acdc_body"],
            # ixn_raw_bytes_b64: sign these with the CURRENT signing key then /cesr-encode
            "ixn_raw_bytes_b64": base64.b64encode(ixn_serder.raw).decode(),
            "ixn_said": ixn_serder.said,
            "ixn_event": ixn_serder.ked,
            "sequence_number": sn,
        }
        if iss_said:
            resp["iss_said"] = iss_said
        return jsonify(resp), 201
    except Exception as e:
        return jsonify({"error": f"Credential issuance failed: {str(e)}"}), 500


def _derive_aid_from_inception(event_dict: dict) -> str:
    """Re-derive the AID a self-addressing inception event produces.

    This is what binds a KEL to the identity that claims it. A self-addressing
    AID (prefix 'E') IS the Blake3 SAID of its own inception event, computed
    over the event with the identifier and SAID fields blanked. So an attacker
    cannot produce an inception event containing THEIR keys that derives
    SOMEBODY ELSE'S AID — the hash would have to collide.

    Derivation goes through keripy's own incept/delcept rather than being
    recomputed here, because the exact set of dummied fields and the
    serialisation are the parts that must match the reference implementation
    byte for byte.

    Returns "" when the event is not a shape we can re-derive; the caller
    treats that as "not proven" rather than "fine".
    """
    event_type = event_dict.get("t", "")
    try:
        if event_type == "icp":
            return eventing.incept(
                keys=event_dict.get("k", []),
                ndigs=event_dict.get("n", []),
                isith=event_dict.get("kt"),
                nsith=event_dict.get("nt"),
                toad=event_dict.get("bt"),
                wits=event_dict.get("b", []),
                cnfg=event_dict.get("c", []),
                data=event_dict.get("a", []),
                code=MtrDex.Blake3_256,
            ).ked.get("i", "")
        if event_type == "dip":
            return eventing.delcept(
                keys=event_dict.get("k", []),
                delpre=event_dict.get("di", ""),
                ndigs=event_dict.get("n", []),
                isith=event_dict.get("kt"),
                nsith=event_dict.get("nt"),
                toad=event_dict.get("bt"),
                wits=event_dict.get("b", []),
                cnfg=event_dict.get("c", []),
                data=event_dict.get("a", []),
                code=MtrDex.Blake3_256,
            ).ked.get("i", "")
    except Exception:
        # A malformed event cannot be re-derived. That is a refusal, not an
        # error to swallow — the caller reports it as unproven.
        return ""
    return ""


def _check_aid_binding(aid: str, first_event: dict) -> list:
    """Check that a KEL's inception really belongs to the claimed AID.

    Without this, validating a KEL proves only that somebody built a
    self-consistent chain — not that it is the chain of the identity being
    claimed. A wholly forged KEL, with the attacker's own keys and their own
    valid signatures, would otherwise pass every other check in this function.

    Returns a list of errors; empty means bound.
    """
    errors = []
    if not aid:
        return ["no AID given, so the KEL cannot be bound to an identity"]

    declared = first_event.get("i", "")
    if declared != aid:
        errors.append(
            f"inception declares identifier {declared!r} but {aid!r} was claimed"
        )
        return errors

    if aid.startswith("E"):
        # Self-addressing: the AID is the SAID of this very event, so it can be
        # re-derived and must match.
        derived = _derive_aid_from_inception(first_event)
        if not derived:
            errors.append(
                "inception could not be re-derived, so the keys in it are not "
                "proven to belong to this AID"
            )
        elif derived != aid:
            errors.append(
                f"inception re-derives to {derived!r}, not the claimed {aid!r} — "
                "these keys do not belong to this identity"
            )
    elif aid.startswith(("B", "D")):
        # Basic prefix: the identifier IS the public key, so the binding is
        # direct and needs no derivation.
        keys = first_event.get("k", [])
        if not keys or keys[0] != aid:
            errors.append(
                f"basic identifier {aid!r} does not match its own inception key"
            )
    else:
        errors.append(f"unrecognised identifier form {aid!r}, cannot bind keys to it")
    return errors


def _wits_of_event(event: dict) -> tuple:
    """The witness set and threshold an establishment event declares.

    Read off the event rather than taken from whatever was requested, because
    the two differ precisely when the caller left the threshold out and it was
    computed for them.
    """
    wits = list(event.get("b", []) or [])
    raw = event.get("bt", "0")
    try:
        toad = int(raw, 16) if isinstance(raw, str) else int(raw)
    except (ValueError, TypeError):
        toad = 0
    return wits, toad


def _witnesses_from_kel(kel: list) -> tuple:
    """Read the current witness set and threshold out of a key event log.

    The set is not a field somebody keeps up to date; it is whatever the events
    say it is. Inception names it outright in 'b'; each rotation amends it with
    'br' (removed) and 'ba' (added). Replaying that is the only way to know
    where an identity stands, and it means a reload does not have to be told
    something it can work out.

    Returns (witnesses, toad).
    """
    wits: list = []
    toad = 0
    for event in kel or []:
        etype = event.get("t", "")
        if etype in ("icp", "dip"):
            wits = list(event.get("b", []) or [])
        elif etype in ("rot", "drt"):
            for removed in event.get("br", []) or []:
                if removed in wits:
                    wits.remove(removed)
            for added in event.get("ba", []) or []:
                if added not in wits:
                    wits.append(added)
        # An interaction event never touches the witness set.
        if etype in ("icp", "dip", "rot", "drt"):
            raw_toad = event.get("bt", "0")
            try:
                toad = int(raw_toad, 16) if isinstance(raw_toad, str) else int(raw_toad)
            except (ValueError, TypeError):
                toad = 0
    return wits, toad


def _validate_kel_events(kel_events: list, aid: str = "") -> dict:
    """Validate a KEL (list of event record dicts) for hash chain integrity and signatures.

    Each event record is expected to have:
        event_json      (str)  — JSON string of the keripy serder.ked dict
        cesr_signature  (str)  — CESR '0B...' Cigar signature (may be absent)
        public_key      (str)  — CESR Ed25519 public key active after this event
        event_type      (str)  — 'icp', 'ixn', 'rot'
        sequence_number (int)

    Returns dict with:
        kel_verified       (bool)
        events_validated   (int)
        current_public_key (str)  — CESR public key after the last event
        validation_errors  (list of str)
    """
    errors = []
    current_key_qb64 = None
    # The successor digests the most recent accepted event committed to. A
    # rotation is checked against this, never against its own contents.
    next_digests = []
    events_validated = 0
    # Who this identity has asked to witness for it, and how many of them must
    # have signed before an event counts as witnessed. Both are carried forward:
    # an inception designates them, a rotation may add or remove them, and an
    # interaction leaves them alone.
    witnesses = []
    toad = 0
    # Per-event witnessing, reported rather than judged. What a missing receipt
    # means depends on what the caller is about to do with the event, and that
    # decision does not belong here.
    witness_report = []

    if not kel_events:
        return {
            "kel_verified": False,
            "events_validated": 0,
            "current_public_key": "",
            "validation_errors": ["KEL is empty"],
        }

    # Bind the chain to the identity BEFORE trusting anything in it.
    #
    # Everything below checks that the events are consistent with each other:
    # contiguous sequence numbers, an intact hash chain, signatures that verify
    # against keys taken from the events themselves. All of that is satisfied
    # by a wholly forged KEL, because the forger supplies both the keys and the
    # signatures. What makes it somebody's KEL is that the inception derives
    # their AID, and that is checked here.
    try:
        first_event = json.loads(kel_events[0].get("event_json", "{}"))
    except (json.JSONDecodeError, TypeError) as e:
        return {
            "kel_verified": False,
            "events_validated": 0,
            "current_public_key": "",
            "validation_errors": [f"first event could not be parsed: {e}"],
        }

    binding_errors = _check_aid_binding(aid, first_event)
    if binding_errors:
        # Refused outright rather than reported alongside a partial result. A
        # KEL that is not this identity's has nothing useful to say about its
        # current key, and returning one would be worse than returning none.
        return {
            "kel_verified": False,
            "events_validated": 0,
            "current_public_key": "",
            "validation_errors": binding_errors,
        }

    for i, record in enumerate(kel_events):
        try:
            event_dict = json.loads(record.get("event_json", "{}"))
        except (json.JSONDecodeError, TypeError) as e:
            errors.append(f"sn={i}: could not parse event_json: {e}")
            continue

        event_type = record.get("event_type") or event_dict.get("t", "")
        sn_str = event_dict.get("s", str(i))
        try:
            sn = int(sn_str, 16) if len(sn_str) > 1 and sn_str.startswith("0") else int(sn_str)
        except (ValueError, TypeError):
            sn = i

        # Every event must name the same identifier. Without this a genuine
        # inception could have somebody else's later events spliced onto it.
        event_aid = event_dict.get("i", "")
        if event_aid and event_aid != aid:
            errors.append(f"sn={i}: event belongs to {event_aid!r}, not {aid!r}")

        # Check sequence number is contiguous
        if sn != i:
            errors.append(f"sn={i}: expected sequence {i}, got {sn}")

        # Hash chain: 'p' (prior) must match the 'd' (SAID) of the previous event
        if i == 0:
            if event_type not in ("icp", "dip"):
                errors.append(f"sn=0: first event must be inception (icp), got '{event_type}'")
        else:
            try:
                prev_dict = json.loads(kel_events[i - 1].get("event_json", "{}"))
                expected_prior = prev_dict.get("d", "")
                actual_prior = event_dict.get("p", "")
                if expected_prior != actual_prior:
                    errors.append(
                        f"sn={i}: hash chain broken — prior '{actual_prior[:16]}...' "
                        f"does not match previous event SAID '{expected_prior[:16]}...'"
                    )
            except Exception as e:
                errors.append(f"sn={i}: hash chain check failed: {e}")

        # Who is designated to witness, as of this event.
        #
        # Read before the receipts are counted, so an event that changes the
        # witness set is judged by the set it establishes. A rotation carries
        # adds and cuts rather than the whole list, because the list is the
        # standing arrangement and an event states the change to it.
        if event_type in ("icp", "dip"):
            witnesses = list(event_dict.get("b", []) or [])
            toad = _toad_of(event_dict, len(witnesses))
        elif event_type in ("rot", "drt"):
            cuts = list(event_dict.get("br", []) or [])
            adds = list(event_dict.get("ba", []) or [])
            witnesses = [w for w in witnesses if w not in cuts] + \
                        [w for w in adds if w not in witnesses]
            toad = _toad_of(event_dict, len(witnesses), toad)

        verified_receipts, receipt_errors = _count_valid_receipts(
            record, event_dict.get("d", ""), witnesses
        )
        errors.extend(f"sn={i} ({event_type}): {e}" for e in receipt_errors)
        witness_report.append({
            "sequence_number": i,
            "witnesses": len(witnesses),
            "threshold": toad,
            "receipts_verified": verified_receipts,
            # An identity that designated nobody cannot be witnessed, which is
            # not the same as one that was witnessed and fell short. Both are
            # reported as unwitnessed; the counts tell them apart.
            "witnessed": toad > 0 and verified_receipts >= toad,
        })

        # What THIS event commits to as its successor, read after the checks
        # below so a rotation is compared against the previous event's promise
        # rather than its own.
        this_next = event_dict.get("n", []) or []

        # Determine signing key for this event type
        if event_type == "icp":
            # Inception: signed with the inception key (first key in 'k' list)
            keys_list = event_dict.get("k", [])
            signing_key_qb64 = keys_list[0] if keys_list else record.get("public_key", "")
            current_key_qb64 = signing_key_qb64
        elif event_type == "ixn":
            # Interaction: signed with the currently active key (no key change)
            signing_key_qb64 = current_key_qb64
        elif event_type in ("rot", "drt"):
            # Rotation: signed with the newly revealed pre-rotated key (first key in 'k' list)
            keys_list = event_dict.get("k", [])
            signing_key_qb64 = keys_list[0] if keys_list else record.get("public_key", "")

            # Pre-rotation, which was not being checked at all.
            #
            # KERI's central protection is that each event commits IN ADVANCE to
            # a digest of the key that may replace it. A rotation is legitimate
            # only if the key it reveals is the key the previous event already
            # promised. Without this check a rotation can name any key, so
            # anybody able to append an event can take the identity — and the
            # commitment that makes KERI worth using is decorative.
            #
            # The digest is computed by keripy, not reimplemented here: the
            # comparison has to be against the exact bytes and derivation code
            # the protocol specifies, and a hand-rolled version that is close
            # but not identical fails open on exactly the events that matter.
            _prior_next = (next_digests or [])
            if not _prior_next:
                errors.append(
                    f"sn={i} ({event_type}): the previous event committed to no "
                    f"successor key, so this rotation replaces a key nobody promised"
                )
            elif signing_key_qb64:
                try:
                    revealed = coring.Diger(
                        ser=coring.Verfer(
                            raw=_extract_raw_key(signing_key_qb64), code=MtrDex.Ed25519
                        ).qb64b
                    ).qb64
                    if revealed not in _prior_next:
                        errors.append(
                            f"sn={i} ({event_type}): the key this rotation reveals is not "
                            f"the one the previous event committed to"
                        )
                except Exception as e:
                    errors.append(f"sn={i} ({event_type}): pre-rotation check failed: {e}")

            current_key_qb64 = signing_key_qb64
        else:
            signing_key_qb64 = current_key_qb64

        # Signature verification (if cesr_signature present)
        cesr_sig = record.get("cesr_signature", "")
        if cesr_sig and signing_key_qb64:
            try:
                # Re-serialize the event dict through keripy to get canonical raw bytes
                # SerderKERI, not coring.Serder: the latter does not exist in
                # keri 1.1.17, so this raised on every event and signature
                # checking has been failing closed rather than running.
                serder = serdering.SerderKERI(sad=event_dict)
                cigar = coring.Cigar(qb64=cesr_sig)
                raw_key = _extract_raw_key(signing_key_qb64)
                verfer = coring.Verfer(raw=raw_key, code=MtrDex.Ed25519)
                if not verfer.verify(sig=cigar.raw, ser=serder.raw):
                    errors.append(f"sn={i} ({event_type}): signature verification FAILED")
                else:
                    events_validated += 1
            except Exception as e:
                errors.append(f"sn={i} ({event_type}): signature check error: {e}")
        elif not signing_key_qb64:
            errors.append(
                f"sn={i} ({event_type}): no key to check a signature against"
            )
        else:
            # An unsigned event used to count as validated, and the log still
            # reported itself verified. That is the whole of the protection
            # gone: append an unsigned rotation to somebody's genuine history
            # and the key it names becomes their current key, because the
            # current key is simply whatever the last accepted event says.
            #
            # Structure is not authenticity. An event nobody signed is an event
            # anybody could have written.
            errors.append(
                f"sn={i} ({event_type}): event is unsigned, so nothing shows it "
                f"came from the controller of {aid}"
            )

        # Carry this event's promise forward. An interaction changes no keys, so
        # it leaves the standing commitment alone rather than clearing it.
        if event_type in ("icp", "dip", "rot", "drt"):
            next_digests = this_next

    return {
        "kel_verified": len(errors) == 0,
        "events_validated": events_validated,
        "current_public_key": current_key_qb64 or "",
        "validation_errors": errors,
        # Witnessing is reported separately from verification on purpose.
        #
        # A log can be perfectly well-formed and correctly signed by its
        # controller and still be one of two conflicting histories, because
        # nothing in the log itself can rule that out — only the witnesses who
        # refused to sign the other one can. So kel_verified continues to mean
        # "this is internally sound and signed", and these say whether anybody
        # else stood behind it, which is the question a caller must answer for
        # itself before relying on the log being the only one.
        "witnesses": list(witnesses),
        "witness_threshold": toad,
        "witnessed": bool(witness_report) and all(e["witnessed"] for e in witness_report),
        "witness_detail": witness_report,
    }


def _toad_of(event_dict: dict, witness_count: int, previous: int = 0) -> int:
    """Read the threshold of accountable duplicity an event declares.

    Absent means unchanged on a rotation and none at inception — an event that
    does not mention the threshold is not silently setting it to zero.
    """
    raw = event_dict.get("bt", None)
    if raw is None or raw == "":
        return previous
    try:
        value = int(raw, 16) if isinstance(raw, str) else int(raw)
    except (ValueError, TypeError):
        return previous
    # A threshold above the number of witnesses can never be met, which would
    # make the identity permanently unwitnessable. Reported as-is rather than
    # clamped: quietly lowering somebody's stated threshold is exactly the kind
    # of helpfulness that removes a protection they asked for.
    return max(0, value)


def _count_valid_receipts(record: dict, event_said: str, witnesses: list) -> tuple:
    """Count receipts on an event that were signed by its designated witnesses.

    A witness is named by a non-transferable identifier, which IS its verifying
    key. So checking a receipt needs nothing but the identifier already written
    into the key event — no lookup, and therefore nothing in the middle of one
    that could answer wrongly.

    Returns (valid_count, errors). A receipt that does not verify is an error
    rather than merely uncounted: a well-formed log carrying a bad receipt is a
    sign of tampering, and silently ignoring it would hide the one signal that
    something is wrong.
    """
    receipts = record.get("witness_receipts") or []
    if not receipts:
        return 0, []

    errors = []
    seen = set()
    valid = 0
    for entry in receipts:
        if not isinstance(entry, dict):
            errors.append("a witness receipt is not an object")
            continue
        witness_aid = entry.get("witness_aid", "")
        sig = entry.get("cesr_signature", "")
        if not witness_aid or not sig:
            errors.append("a witness receipt names no witness or carries no signature")
            continue
        if witness_aid not in witnesses:
            # Not an error. Anybody may sign anything; what makes a receipt
            # count is that the controller designated that witness, and a
            # receipt from somebody else is simply not part of the threshold.
            continue
        if witness_aid in seen:
            # One witness, one vote. Without this, a single witness could meet
            # any threshold by sending its receipt repeatedly.
            errors.append(f"witness {witness_aid} receipted this event more than once")
            continue
        if not event_said:
            errors.append("the event has no identifier for a receipt to cover")
            continue
        if not _verify_receipt_sig(sig, event_said, witness_aid):
            errors.append(f"the receipt from witness {witness_aid} does not verify")
            continue
        seen.add(witness_aid)
        valid += 1
    return valid, errors


@app.route("/validate-kel", methods=["POST"])
def validate_kel():
    """Stateless: validate a KEL (Key Event Log) from an OOBI response.

    Accepts JSON: {
        "aid":    "<AID string>",
        "events": [<event record dicts from the OOBI response>]
    }

    Each event record should have: event_json, cesr_signature, public_key,
    event_type, sequence_number.

    Returns: {
        "kel_verified": bool,
        "events_validated": int,
        "current_public_key": str,
        "validation_errors": [str]
    }
    """
    data = request.get_json()
    if not data:
        return jsonify({"error": "Request body required"}), 400

    events = data.get("events", [])
    if not events:
        return jsonify({
            "kel_verified": False,
            "events_validated": 0,
            "current_public_key": "",
            "validation_errors": ["No events provided"],
        }), 200

    try:
        result = _validate_kel_events(events, data.get("aid", ""))
        return jsonify(result), 200
    except Exception as e:
        return jsonify({"error": f"KEL validation failed: {str(e)}"}), 500


@app.route("/resolve-oobi", methods=["POST"])
def resolve_oobi():
    """Resolve an OOBI URL: fetch it over HTTP and validate the returned KEL.

    Accepts JSON: { "url": "<oobi_url>" }

    Returns full validation result including the AID's current public key,
    KEL validity, and any validation errors.
    """
    data = request.get_json()
    if not data:
        return jsonify({"error": "Request body required"}), 400

    url = data.get("url", "")
    if not url:
        return jsonify({"error": "url is required"}), 400

    # Parse OOBI URL components (cid = controller AID, role, eid = endpoint AID)
    cid, eid, role = "", "", ""
    try:
        parts = url.rstrip("/").split("/")
        if "/oobi/" in url:
            oobi_idx = parts.index("oobi")
            if oobi_idx + 1 < len(parts):
                cid = parts[oobi_idx + 1]
            if oobi_idx + 2 < len(parts):
                role = parts[oobi_idx + 2]
            if oobi_idx + 3 < len(parts):
                eid = parts[oobi_idx + 3]
    except Exception:
        pass

    scheme = "http" if url.startswith("http://") else "https"
    host_port = url.split("//")[1].split("/")[0] if "//" in url else ""
    endpoints = [f"{scheme}://{host_port}"] if host_port else []

    # Without requests, fall back to URL-parse-only mode
    if not _REQUESTS_AVAILABLE:
        return jsonify({
            "endpoints": endpoints,
            "oobi_url": url,
            "cid": cid,
            "eid": eid,
            "role": role,
            "kel_verified": False,
            "validation_errors": ["requests library not installed; install with: pip install requests"],
        }), 200

    # Fetch the OOBI endpoint
    try:
        resp = _requests.get(url, timeout=15)
        resp.raise_for_status()
        oobi_data = resp.json()
    except Exception as e:
        return jsonify({
            "endpoints": endpoints,
            "oobi_url": url,
            "cid": cid,
            "eid": eid,
            "role": role,
            "kel_verified": False,
            "validation_errors": [f"Failed to fetch OOBI URL: {e}"],
        }), 200

    # Extract and validate the KEL from the response
    aid = oobi_data.get("aid", cid)
    public_key = oobi_data.get("public_key", "")
    kel_events = oobi_data.get("kel", [])

    # Normalise: kel may be a list of EventRecord-like dicts
    validation = _validate_kel_events(kel_events) if kel_events else {
        "kel_verified": False,
        "events_validated": 0,
        "current_public_key": public_key,
        "validation_errors": ["OOBI response contained no KEL events"],
    }

    return jsonify({
        "endpoints": endpoints,
        "oobi_url": url,
        "cid": cid,
        "eid": eid,
        "role": role,
        "aid": aid,
        "public_key": validation.get("current_public_key") or public_key,
        "alias": oobi_data.get("alias", ""),
        "jcard": oobi_data.get("jcard"),
        "photo": oobi_data.get("photo", ""),
        "kel": kel_events,
        "event_count": len(kel_events),
        "kel_verified": validation["kel_verified"],
        "events_validated": validation["events_validated"],
        "validation_errors": validation["validation_errors"],
    }), 200


@app.route("/credential/present", methods=["POST"])
def credential_present():
    """Create a verifiable presentation for a held credential.

    The presentation body is SAID-computed (attribute block first, then top-level).
    The holder proves possession by signing the presentation SAID bytes with their
    current key — the verifier checks this against the holder AID's KEL.

    Request JSON:
        acdc_said   (str)  — SAID of the credential being presented
        holder_aid  (str)  — AID of the presenter (credential subject)
        issuer_aid  (str)  — AID of the credential issuer (optional, for 'ri' field)
        schema_said (str)  — SAID of the presentation schema (optional)

    Returns:
        presentation_said    (str) — self-addressing SAID of the presentation
        presentation_json_b64 (str) — base64 of the serialized presentation
        pres_said_b64        (str) — base64 of pres_said.encode(); sign these
                                     bytes with the holder's current key then /cesr-encode
    """
    data = request.get_json()
    if not data:
        return jsonify({"error": "Request body required"}), 400

    acdc_said   = data.get("acdc_said", "")
    holder_aid  = data.get("holder_aid", "")
    issuer_aid  = data.get("issuer_aid", "")
    schema_said = data.get("schema_said", "EpresentationSchema")

    if not acdc_said or not holder_aid:
        return jsonify({"error": "acdc_said and holder_aid are required"}), 400

    try:
        # Build presentation attribute block and compute its SAID
        attr_block = {
            "d": "",
            "credential_said": acdc_said,
            "holder_aid": holder_aid,
        }
        attr_json = json.dumps(attr_block, separators=(",", ":")).encode()
        attr_diger = coring.Diger(ser=attr_json, code=MtrDex.Blake3_256)
        attr_block["d"] = attr_diger.qb64

        # Build top-level presentation body and compute its SAID
        presentation = {
            "v": "ACDC10JSON000000_",
            "d": "",
            "i": holder_aid,
            "ri": issuer_aid,
            "s": schema_said,
            "a": attr_block,
        }
        pres_json_v1 = json.dumps(presentation, separators=(",", ":")).encode()
        pres_diger   = coring.Diger(ser=pres_json_v1, code=MtrDex.Blake3_256)
        pres_said    = pres_diger.qb64
        presentation["d"] = pres_said

        pres_json_final = json.dumps(presentation, separators=(",", ":")).encode()

        # The holder signs the presentation SAID (UTF-8 bytes) as proof of possession.
        # This binds the holder's identity to this specific presentation instance.
        pres_said_b64 = base64.b64encode(pres_said.encode()).decode()

        return jsonify({
            "presentation_said":     pres_said,
            "presentation_json_b64": base64.b64encode(pres_json_final).decode(),
            "presentation_body":     presentation,
            # pres_said_b64: base64 of pres_said.encode(); sign these bytes then /cesr-encode
            "pres_said_b64":         pres_said_b64,
        }), 201
    except Exception as e:
        return jsonify({"error": f"Presentation creation failed: {str(e)}"}), 500


@app.route("/credential/verify", methods=["POST"])
def credential_verify():
    """Stateless 8-check credential presentation verifier.

    Runs all 8 KERI/ACDC verification checks and returns a detailed result.

    Request JSON:
        acdc_json_b64        (str)   — base64 of the serialized ACDC credential body
        issuer_kel           (list)  — list of raw keripy event dicts (KEDs) for issuer
        pres_said_b64        (str)   — base64 of the bytes the holder signed (pres SAID)
        pres_cesr_sig        (str)   — CESR '0B...' sig over pres_said_b64 bytes
        holder_public_key    (str)   — CESR Ed25519 public key of the holder
        trusted_schema_saids (list)  — optional list of accepted schema SAIDs
        revocation_list      (list)  — optional list of revoked credential SAIDs

    Returns:
        verified  (bool)           — true only if all 8 checks pass
        checks    (dict)           — per-check boolean results
        errors    (list of str)    — descriptions of failed checks
    """
    data = request.get_json()
    if not data:
        return jsonify({"error": "Request body required"}), 400

    acdc_json_b64     = data.get("acdc_json_b64", "")
    issuer_kel        = data.get("issuer_kel", [])
    pres_said_b64     = data.get("pres_said_b64", "")
    pres_cesr_sig     = data.get("pres_cesr_sig", "")
    holder_public_key = data.get("holder_public_key", "")
    trusted_schemas   = set(data.get("trusted_schema_saids", []))
    revocation_list   = set(data.get("revocation_list", []))

    checks = {
        "said_integrity":         False,
        "issuer_in_kel":          False,
        "kel_chain_valid":        False,
        "schema_trusted":         False,
        "not_revoked":            False,
        "holder_matches_subject": False,
        "presentation_sig_valid": False,
        "credential_anchored":    False,
    }
    errors = []

    # -- Decode and parse the ACDC credential ----------------------------------
    try:
        acdc_bytes = base64.b64decode(acdc_json_b64)
        acdc_body  = json.loads(acdc_bytes)
    except Exception as e:
        return jsonify({"error": f"Failed to decode acdc_json_b64: {e}"}), 400

    acdc_said_embedded = acdc_body.get("d", "")
    issuer_aid_in_cred = acdc_body.get("i", "")
    schema_said        = acdc_body.get("s", "")
    attr_block         = acdc_body.get("a", {})
    holder_aid_in_cred = attr_block.get("i", "")

    # -- Check 1: ACDC SAID integrity ------------------------------------------
    try:
        blank = dict(acdc_body); blank["d"] = ""
        recomputed = coring.Diger(
            ser=json.dumps(blank, separators=(",", ":")).encode(),
            code=MtrDex.Blake3_256,
        ).qb64
        checks["said_integrity"] = (recomputed == acdc_said_embedded)
        if not checks["said_integrity"]:
            errors.append(f"Check 1 FAIL: SAID mismatch — embedded={acdc_said_embedded[:16]}… recomputed={recomputed[:16]}…")
    except Exception as e:
        errors.append(f"Check 1 ERROR: {e}")

    # -- Check 2: Issuer AID is in a valid KEL ---------------------------------
    try:
        if issuer_kel:
            first_event = issuer_kel[0]
            # Support both raw KED dicts and EventRecord-like dicts with event_json
            if "pre" in first_event:
                kel_pre = first_event["pre"]
            elif "event_json" in first_event:
                kel_pre = json.loads(first_event["event_json"]).get("i", "")
            else:
                kel_pre = first_event.get("i", "")
            checks["issuer_in_kel"] = (kel_pre == issuer_aid_in_cred)
            if not checks["issuer_in_kel"]:
                errors.append(f"Check 2 FAIL: KEL prefix {kel_pre[:16]}… does not match issuer AID {issuer_aid_in_cred[:16]}…")
        else:
            errors.append("Check 2 SKIP: No issuer KEL provided")
    except Exception as e:
        errors.append(f"Check 2 ERROR: {e}")

    # -- Check 3: KEL hash chain valid -----------------------------------------
    try:
        if len(issuer_kel) >= 2:
            chain_ok = True
            for idx in range(1, len(issuer_kel)):
                ev      = issuer_kel[idx]
                prev_ev = issuer_kel[idx - 1]
                # Support raw KED dicts
                cur_p  = ev.get("p", "")
                prev_d = prev_ev.get("d", "")
                if cur_p and prev_d and cur_p != prev_d:
                    chain_ok = False
                    errors.append(f"Check 3 FAIL: hash chain broken at sn={idx}: prior={cur_p[:16]}… prev_d={prev_d[:16]}…")
                    break
            checks["kel_chain_valid"] = chain_ok
        elif len(issuer_kel) == 1:
            checks["kel_chain_valid"] = True  # single-event KEL is trivially valid
        else:
            errors.append("Check 3 SKIP: No issuer KEL provided")
    except Exception as e:
        errors.append(f"Check 3 ERROR: {e}")

    # -- Check 4: Schema SAID in trusted registry ------------------------------
    try:
        if trusted_schemas:
            checks["schema_trusted"] = schema_said in trusted_schemas
            if not checks["schema_trusted"]:
                errors.append(f"Check 4 FAIL: schema {schema_said[:16]}… not in trusted schema registry")
        else:
            # No trusted schema list provided — pass (open policy)
            checks["schema_trusted"] = True
    except Exception as e:
        errors.append(f"Check 4 ERROR: {e}")

    # -- Check 5: Credential not revoked ---------------------------------------
    # A TEL-backed credential is revoked iff the issuer's signed KEL carries a
    # revocation anchor seal ({i: acdc_said, s: "1", ...}) — that seal's presence in
    # the issuer-only-extendable KEL IS the cryptographic revocation proof. The
    # passed revocation_list remains an accepted fallback for legacy callers.
    try:
        revoked_in_kel = False
        for ev in issuer_kel:
            for s in ev.get("a", []):
                if isinstance(s, dict) and s.get("i") == acdc_said_embedded and str(s.get("s")) == "1":
                    revoked_in_kel = True
                    break
            if revoked_in_kel:
                break
        checks["not_revoked"] = (acdc_said_embedded not in revocation_list) and not revoked_in_kel
        if not checks["not_revoked"]:
            errors.append(f"Check 5 FAIL: credential {acdc_said_embedded[:16]}… is revoked")
    except Exception as e:
        errors.append(f"Check 5 ERROR: {e}")

    # -- Check 6: Holder AID matches credential subject ------------------------
    try:
        if holder_aid_in_cred:
            # Derive the presentation holder AID from the signed pres_said_b64
            # We check the public key's AID against the credential subject
            # If we have the holder public key, reconstruct the AID from the KEL
            # For now: verifier checks holder_public_key derives the same AID as cred.a.i
            # This check requires the caller to pass holder_aid explicitly
            holder_aid_from_request = data.get("holder_aid", "")
            if holder_aid_from_request:
                checks["holder_matches_subject"] = (holder_aid_from_request == holder_aid_in_cred)
                if not checks["holder_matches_subject"]:
                    errors.append(f"Check 6 FAIL: presentation holder {holder_aid_from_request[:16]}… != credential subject {holder_aid_in_cred[:16]}…")
            else:
                # No holder AID in request — pass if we have valid sig (check 7)
                checks["holder_matches_subject"] = True
        else:
            checks["holder_matches_subject"] = True  # No subject field in credential
    except Exception as e:
        errors.append(f"Check 6 ERROR: {e}")

    # -- Check 7: Presentation signature valid ---------------------------------
    try:
        if pres_said_b64 and pres_cesr_sig and holder_public_key:
            pres_bytes = base64.b64decode(pres_said_b64)
            raw_key    = _extract_raw_key(holder_public_key)
            verfer     = coring.Verfer(raw=raw_key, code=MtrDex.Ed25519)
            if pres_cesr_sig.startswith("0B") and len(pres_cesr_sig) == 88:
                cigar    = coring.Cigar(qb64=pres_cesr_sig)
                sig_raw  = cigar.raw
            else:
                sig_raw  = base64.b64decode(pres_cesr_sig)
            checks["presentation_sig_valid"] = verfer.verify(sig=sig_raw, ser=pres_bytes)
            if not checks["presentation_sig_valid"]:
                errors.append("Check 7 FAIL: presentation signature does not verify against holder public key")
        else:
            errors.append("Check 7 SKIP: pres_said_b64, pres_cesr_sig, or holder_public_key missing")
    except Exception as e:
        errors.append(f"Check 7 ERROR: {e}")

    # -- Check 8: Credential SAID anchored in issuer KEL via IXN ---------------
    try:
        ixn_said_to_find = data.get("ixn_said", "")
        anchored = False
        for ev in issuer_kel:
            ev_type = ev.get("t", "")
            if ev_type != "ixn":
                continue
            # An issuance is anchored either by the legacy seal ({d: acdc_said}) or,
            # for a TEL-backed credential, by the issuance seal ({i: acdc_said, s: "0", ...}).
            seal_list = ev.get("a", [])
            issuance = any(
                s.get("d") == acdc_said_embedded
                or (s.get("i") == acdc_said_embedded and str(s.get("s")) == "0")
                for s in seal_list
            )
            if issuance:
                if not ixn_said_to_find or ev.get("d", "") == ixn_said_to_find:
                    anchored = True
                    break
        checks["credential_anchored"] = anchored
        if not anchored:
            errors.append(f"Check 8 FAIL: credential SAID {acdc_said_embedded[:16]}… not found in any IXN seal in the issuer KEL")
    except Exception as e:
        errors.append(f"Check 8 ERROR: {e}")

    verified = all(checks.values())

    return jsonify({
        "verified": verified,
        "checks":   checks,
        "errors":   errors,
        "acdc_said": acdc_said_embedded,
    }), 200


@app.route("/generate-multisig-event", methods=["POST"])
def generate_multisig_event():
    data = request.get_json()
    if not data:
        return jsonify({"error": "Request body required"}), 400

    aids = data.get("aids", [])
    threshold = data.get("threshold", 1)
    current_keys = data.get("current_keys", [])
    next_keys = data.get("next_keys", [])
    event_type = data.get("event_type", "inception")

    if not aids or not current_keys:
        return jsonify({"error": "aids and current_keys are required"}), 400

    try:
        verfers = []
        for key in current_keys:
            raw = _extract_raw_key(key)
            verfers.append(coring.Verfer(raw=raw, code=MtrDex.Ed25519))

        key_qb64s = [v.qb64 for v in verfers]

        if event_type == "inception":
            # Next-key digests, not an empty list.
            #
            # An inception with no ndigs commits to no successor keys, so the
            # identity it creates can never be rotated. For a root
            # root that is not a limitation, it is a dead end: a signer whose
            # key is compromised could never be replaced, and transferring
            # ownership — which is a rotation, replacing one signer's key with
            # the buyer's — would be impossible. Single-signature inception has
            # always passed a real digest here; multi-signature did not.
            ndigs = []
            for key in next_keys:
                raw = _extract_raw_key(key)
                ndigs.append(coring.Diger(raw=raw, code=MtrDex.Blake3_256).qb64)

            serder = eventing.incept(
                keys=key_qb64s,
                isith=str(threshold),
                nsith=str(threshold) if ndigs else "0",
                ndigs=ndigs,
                code=MtrDex.Blake3_256,
            )
        else:
            # Refused, because the alternative was worse than an error.
            #
            # This branch used to build {type, aids, threshold, keys}, digest
            # it, and return the digest under the field names "said" and "pre".
            # That is not a KERI event: no t, no s, no p, no kt, no n, no nt —
            # nothing that makes an event verifiable, orderable, or attachable
            # to a log. And it came back in exactly the shape the inception
            # branch returns, so a caller had no way to tell a real event from a
            # digest of a JSON object we invented.
            #
            # Rotation is not missing from the system; it is somewhere else.
            # KeriDriver.RotateToMultisig calls /rotate, which builds a genuine
            # rot event, and that is what the ownership ceremony uses. So this
            # branch was a second path under the name that reads like the
            # primary API, quietly producing something that could never be
            # anchored anywhere.
            #
            # Nothing calls it: every caller in this repository and in the org
            # and individual applications either passes "inception" or leaves
            # event_type unset, which the Go handler defaults to "inception".
            return jsonify({
                "error": (
                    f"this endpoint builds inception events only, and was asked for "
                    f"'{event_type}'. A rotation is built by /rotate — use it through "
                    f"the ownership ceremony, which carries the current key set and the "
                    f"next-key digests a rotation must have. It used to return a digest "
                    f"of an invented JSON object here, which no verifier would accept."
                ),
            }), 400

        event_bytes = json.dumps(serder.ked, separators=(",", ":")).encode()

        return jsonify({
            "raw_bytes_b64": base64.b64encode(event_bytes).decode(),
            "said": serder.pre,
            "pre": serder.pre,
            "event_type": "icp",
            "size": len(event_bytes),
        }), 200
    except Exception as e:
        return jsonify({"error": f"Multisig event generation failed: {str(e)}"}), 500

# ---------------------------------------------------------------------------
# Phase 7: KERL + Witness Receipts
# ---------------------------------------------------------------------------
#
# Witness receipts: a witness signs the event SAID (UTF-8 bytes of the 44-char
# SAID string) with its Ed25519 key, producing a CESR Cigar '0B...' (88 chars).
# A KERL entry = event JSON + list of valid receipts + threshold_met flag.
#
# In-process receipt store: keyed by event_said → list of receipt dicts.
# This is stateless across restarts (receipts are ephemeral unless the Go
# server persists them via SaveWitnessReceipt). The Go server is the durable
# store; the Python driver validates and structures the data.

_receipt_store: dict = {}   # event_said -> [{"witness_aid": str, "cesr_sig": str}]


def _verify_receipt_sig(cesr_sig: str, event_said: str, witness_public_key: str) -> bool:
    """Verify a CESR-encoded witness receipt signature against an event SAID.

    Args:
        cesr_sig: '0B...' (88-char) CESR-encoded Ed25519 signature.
        event_said: The 44-char SAID the witness signed (UTF-8 bytes).
        witness_public_key: CESR Ed25519 public key of the witness.
    Returns:
        True if the signature is valid, False otherwise.
    """
    try:
        cigar = coring.Cigar(qb64=cesr_sig)
        verfer = coring.Verfer(qb64=witness_public_key)
        return verfer.verify(sig=cigar.raw, ser=event_said.encode())
    except Exception:
        return False


@app.route("/receipt/submit", methods=["POST"])
def receipt_submit():
    """Accept and validate a witness receipt for a KERI event.

    Request body:
        event_said      (str)  — the 44-char SAID of the event being receipted
        witness_aid     (str)  — the AID of the witnessing entity
        witness_public_key (str) — CESR Ed25519 public key of the witness
        cesr_signature  (str)  — '0B...' witness signature over event_said.encode()
        trusted_witnesses (list[str]) — AIDs considered trusted by the controller
        threshold       (int)  — minimum receipts required (0 = no threshold check)

    Response body:
        accepted        (bool) — True if sig verified and witness is trusted
        threshold_met   (bool) — True if accumulated receipts meet threshold
        receipt_count   (int)  — number of trusted receipts now stored for this event
        errors          (list) — validation error messages (empty on success)
    """
    data = request.get_json(force=True, silent=True) or {}
    event_said       = data.get("event_said", "")
    witness_aid      = data.get("witness_aid", "")
    witness_pub_key  = data.get("witness_public_key", "")
    cesr_sig         = data.get("cesr_signature", "")
    trusted_witnesses = set(data.get("trusted_witnesses", []))
    threshold        = int(data.get("threshold", 0))

    errors = []

    if not event_said:
        errors.append("event_said is required")
    if not witness_aid:
        errors.append("witness_aid is required")
    if not witness_pub_key:
        errors.append("witness_public_key is required")
    if not cesr_sig:
        errors.append("cesr_signature is required")
    if errors:
        return jsonify({"error": "; ".join(errors)}), 400

    # Verify the receipt signature.
    sig_valid = _verify_receipt_sig(cesr_sig, event_said, witness_pub_key)
    if not sig_valid:
        return jsonify({
            "accepted": False,
            "threshold_met": False,
            "receipt_count": len(_receipt_store.get(event_said, [])),
            "errors": ["receipt signature invalid"],
        }), 200

    # Check trust.
    if trusted_witnesses and witness_aid not in trusted_witnesses:
        return jsonify({
            "accepted": False,
            "threshold_met": False,
            "receipt_count": len(_receipt_store.get(event_said, [])),
            "errors": ["witness AID not in trusted_witnesses list"],
        }), 200

    # Accumulate (de-duplicate by witness_aid).
    existing = _receipt_store.setdefault(event_said, [])
    if not any(r["witness_aid"] == witness_aid for r in existing):
        existing.append({"witness_aid": witness_aid, "cesr_sig": cesr_sig})

    receipt_count = len(existing)
    threshold_met = (threshold == 0) or (receipt_count >= threshold)

    return jsonify({
        "accepted": True,
        "threshold_met": threshold_met,
        "receipt_count": receipt_count,
        "errors": [],
    }), 200


@app.route("/receipt/kerl", methods=["GET"])
def receipt_kerl():
    """Return the KERL entry for an event: the event body plus all accumulated receipts.

    Query params:
        event_said   — the SAID of the event
        threshold    — (optional, int) required receipt count; defaults to 0 (no check)

    Response body:
        event_said      (str)
        receipts        (list) — [{witness_aid, cesr_sig}] in insertion order
        receipt_count   (int)
        threshold_met   (bool)
        errors          (list)
    """
    event_said = request.args.get("event_said", "")
    threshold  = int(request.args.get("threshold", "0"))

    if not event_said:
        return jsonify({"error": "event_said query parameter is required"}), 400

    receipts = list(_receipt_store.get(event_said, []))
    receipt_count = len(receipts)
    threshold_met = (threshold == 0) or (receipt_count >= threshold)

    return jsonify({
        "event_said":    event_said,
        "receipts":      receipts,
        "receipt_count": receipt_count,
        "threshold_met": threshold_met,
        "errors":        [],
    }), 200


@app.route("/reload-identity", methods=["POST"])
def reload_identity():
    """Restore a previously created identity into the driver's in-memory state.

    Called by the Go backend on startup when an identity already exists in the DB.
    Does NOT require private keys — only restores the public state needed for
    subsequent IXN events and credential issuance: sequence number, public keys, KEL.

    Without this, IssueCredential and Interact fail after any driver restart because
    _identities is empty on cold start.

    Request JSON:
        aid             (str)  — the AID prefix (used as the identity name key)
        public_key      (str)  — current CESR Ed25519 public key
        next_key_digest (str)  — current CESR Blake3_256 next key digest
        sequence_number (int)  — sequence number of the most recent event
        last_said       (str)  — SAID of the most recent event (the 'd' field)
        kel             (list) — list of KED event dicts (the parsed event_json entries)
    """
    data = request.get_json()
    if not data:
        return jsonify({"error": "Request body required"}), 400

    aid             = data.get("aid", "")
    public_key      = data.get("public_key", "")
    next_key_digest = data.get("next_key_digest", "")
    sequence_number = data.get("sequence_number", 0)
    last_said       = data.get("last_said", "")
    kel             = data.get("kel", [])

    if not aid or not public_key or not next_key_digest:
        return jsonify({"error": "aid, public_key, and next_key_digest are required"}), 400

    # Derived rather than accepted: the events are the source of truth, and a
    # caller that had to pass the witness set could pass a stale one.
    reloaded_wits, reloaded_toad = _witnesses_from_kel(kel)

    _identities[aid] = {
        "aid":            aid,
        "public_key":     public_key,
        "next_key_digest": next_key_digest,
        "kel":            kel,
        "witnesses":      reloaded_wits,
        "toad":           reloaded_toad,
        "sequence_number": sequence_number,
        "last_said":      last_said,
    }

    return jsonify({
        "aid":            aid,
        "sequence_number": sequence_number,
        "kel_events":     len(kel),
        "status":         "reloaded",
    }), 200


@app.route('/sign-for-name', methods=['POST'])
def sign_for_name():
    data = request.json
    name = data.get('name')
    body = data.get('body')  # string to sign
    if not name or not body:
        return jsonify({'error': 'name and body required'}), 400
    try:
        hab = hby.habByName(name)
        if hab is None:
            return jsonify({'error': f'no AID named {name}'}), 404
        sig = hab.sign(body.encode('utf-8'), indexed=False)
        # sig is a list of Siger objects; take first
        sig_qb64 = sig[0].qb64 if sig else ''
        return jsonify({'sig': sig_qb64, 'aid': hab.pre})
    except Exception as e:
        return jsonify({'error': str(e)}), 500


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    port = int(os.environ.get("KERI_DRIVER_PORT", "9999"))
    host = os.environ.get("KERI_DRIVER_HOST", "127.0.0.1")

    _check_keri_api()

    print(f"[keri-driver] Starting KERI Core Driver on {host}:{port}")
    print(f"[keri-driver] KERI library: keripy {_keri_version()}")
    print(f"[keri-driver] Script: {os.path.abspath(__file__)}")
    print(f"[keri-driver] Stateful endpoints:  /status, /inception, /rotation, /interact, /reload-identity, /sign, /sign-for-name, /kel, /verify")
    print(f"[keri-driver] Stateless endpoints: /cesr-encode, /validate-kel, /resolve-oobi, /format-credential, /generate-multisig-event")
    print(f"[keri-driver] Credential endpoints: /credential/issue, /credential/present, /credential/verify")
    print(f"[keri-driver] KERL endpoints:       /receipt/submit, /receipt/kerl")

    app.run(host=host, port=port, debug=False)
