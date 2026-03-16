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
import json
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

from keri.core import coring, eventing
from keri.core.coring import MtrDex

from flask import Flask, request, jsonify

app = Flask(__name__)
start_time = time.time()

# ---------------------------------------------------------------------------
# In-memory state for managed identities (stateful operations)
# ---------------------------------------------------------------------------

_identities = {}

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
        return _b64url_decode(cesr_key[1:])
    return _b64url_decode(cesr_key)


def create_inception_event(public_key: str, next_public_key: str) -> dict:
    pub_bytes = _extract_raw_key(public_key)
    next_bytes = _extract_raw_key(next_public_key)

    verfer = coring.Verfer(raw=pub_bytes, code=MtrDex.Ed25519)
    diger = coring.Diger(raw=next_bytes, code=MtrDex.Blake3_256)

    serder = eventing.incept(
        keys=[verfer.qb64],
        ndigs=[diger.qb64],
        code=MtrDex.Blake3_256,
    )

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
        "uptime": f"{uptime:.0f}s",
    })

# ---------------------------------------------------------------------------
# HTTP routes — Stateful KERI operations
# ---------------------------------------------------------------------------

@app.route("/inception", methods=["POST"])
def inception():
    data = request.get_json()
    if not data:
        return jsonify({"error": "Request body required"}), 400

    public_key = data.get("public_key", "")
    next_public_key = data.get("next_public_key", "")

    if not public_key or not next_public_key:
        return jsonify({"error": "public_key and next_public_key are required"}), 400

    try:
        result = create_inception_event(public_key, next_public_key)

        name = data.get("name", result["aid"])
        _identities[name] = {
            "aid": result["aid"],
            "public_key": result["public_key"],
            "next_key_digest": result["next_key_digest"],
            "kel": [result["inception_event"]],
            "sequence_number": 0,
            # last_said tracks the SAID of the most recent event (used as 'dig' in next event)
            "last_said": result.get("said", ""),
        }

        return jsonify(result), 201
    except Exception as e:
        return jsonify({"error": f"Inception failed: {str(e)}"}), 500


@app.route("/rotation", methods=["POST"])
def rotation():
    data = request.get_json()
    if not data:
        return jsonify({"error": "Request body required"}), 400

    name = data.get("name", "")
    new_public_key = data.get("new_public_key", "")
    new_next_public_key = data.get("new_next_public_key", "")

    if not name:
        return jsonify({"error": "name is required"}), 400
    if not new_public_key or not new_next_public_key:
        return jsonify({"error": "new_public_key and new_next_public_key are required"}), 400

    identity = _identities.get(name)
    if not identity:
        return jsonify({"error": f"No identity found with name: {name}"}), 404

    try:
        new_pub_bytes = _extract_raw_key(new_public_key)
        new_next_bytes = _extract_raw_key(new_next_public_key)

        new_verfer = coring.Verfer(raw=new_pub_bytes, code=MtrDex.Ed25519)
        new_diger = coring.Diger(raw=new_next_bytes, code=MtrDex.Blake3_256)

        sn = identity["sequence_number"] + 1
        prev_said = identity.get("last_said", "")

        serder = eventing.rotate(
            pre=identity["aid"],
            keys=[new_verfer.qb64],
            dig=prev_said,
            ndigs=[new_diger.qb64],
            sn=sn,
        )

        identity["public_key"] = new_verfer.qb64
        identity["next_key_digest"] = new_diger.qb64
        identity["sequence_number"] = sn
        identity["last_said"] = serder.said
        identity["kel"].append(serder.ked)

        return jsonify({
            "aid": identity["aid"],
            "new_public_key": new_verfer.qb64,
            "new_next_key_digest": new_diger.qb64,
            "rotation_event": serder.ked,
            # raw_bytes_b64: sign these with the PRE-ROTATED key (index 1 from mnemonic)
            "raw_bytes_b64": base64.b64encode(serder.raw).decode(),
            "sequence_number": sn,
        }), 200
    except Exception as e:
        return jsonify({"error": f"Rotation failed: {str(e)}"}), 500


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

def _format_acdc(issuer_aid: str, schema_said: str, claims: dict) -> dict:
    """Format an ACDC credential body with self-addressing SAIDs.

    Computes the attribute block SAID first (embedded as 'a.d'), then the
    top-level credential SAID (embedded as 'd'). Both use Blake3_256.

    Returns dict with: acdc_body, acdc_said, acdc_json_b64
    """
    attr_block = dict(claims)
    attr_block.setdefault("d", "")

    # Step 1: compute attribute block SAID
    attr_json = json.dumps(attr_block, separators=(",", ":")).encode()
    attr_diger = coring.Diger(ser=attr_json, code=MtrDex.Blake3_256)
    attr_block["d"] = attr_diger.qb64

    # Step 2: build ACDC body and compute top-level SAID
    acdc_body = {
        "v": "ACDC10JSON000000_",
        "d": "",
        "i": issuer_aid,
        "s": schema_said,
        "a": attr_block,
    }
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


@app.route("/credential/issue", methods=["POST"])
def credential_issue():
    """Issue an ACDC credential anchored in the issuer's KEL via an IXN event.

    Request JSON:
        name        (str)  — issuer identity name
        claims      (dict) — credential attribute claims (holder_aid, etc.)
        schema_said (str)  — SAID of the credential schema
        holder_aid  (str)  — AID of the credential subject/holder

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

    if not name:
        return jsonify({"error": "name is required"}), 400
    if not claims or not schema_said:
        return jsonify({"error": "claims and schema_said are required"}), 400

    identity = _identities.get(name)
    if not identity:
        return jsonify({"error": f"No identity found with name: {name}"}), 404

    try:
        # Step 1: format ACDC with full SAID computation
        credential = _format_acdc(identity["aid"], schema_said, claims)
        acdc_said = credential["acdc_said"]

        # Step 2: create IXN anchoring the credential SAID in the issuer's KEL
        sn = identity["sequence_number"] + 1
        prev_said = identity.get("last_said", "")
        seal = {"d": acdc_said}

        ixn_serder = eventing.interact(
            pre=identity["aid"],
            dig=prev_said,
            sn=sn,
            data=[seal],
        )

        identity["sequence_number"] = sn
        identity["last_said"] = ixn_serder.said
        identity["kel"].append(ixn_serder.ked)

        return jsonify({
            "aid": identity["aid"],
            "acdc_said": acdc_said,
            "acdc_json_b64": credential["acdc_json_b64"],
            "acdc_body": credential["acdc_body"],
            # ixn_raw_bytes_b64: sign these with the CURRENT signing key then /cesr-encode
            "ixn_raw_bytes_b64": base64.b64encode(ixn_serder.raw).decode(),
            "ixn_said": ixn_serder.said,
            "ixn_event": ixn_serder.ked,
            "sequence_number": sn,
        }), 201
    except Exception as e:
        return jsonify({"error": f"Credential issuance failed: {str(e)}"}), 500


def _validate_kel_events(kel_events: list) -> dict:
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
    events_validated = 0

    if not kel_events:
        return {
            "kel_verified": False,
            "events_validated": 0,
            "current_public_key": "",
            "validation_errors": ["KEL is empty"],
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
            current_key_qb64 = signing_key_qb64
        else:
            signing_key_qb64 = current_key_qb64

        # Signature verification (if cesr_signature present)
        cesr_sig = record.get("cesr_signature", "")
        if cesr_sig and signing_key_qb64:
            try:
                # Re-serialize the event dict through keripy to get canonical raw bytes
                serder = coring.Serder(ked=event_dict)
                cigar = coring.Cigar(qb64=cesr_sig)
                raw_key = _extract_raw_key(signing_key_qb64)
                verfer = coring.Verfer(raw=raw_key, code=MtrDex.Ed25519)
                if not verfer.verify(sig=cigar.raw, ser=serder.raw):
                    errors.append(f"sn={i} ({event_type}): signature verification FAILED")
                else:
                    events_validated += 1
            except Exception as e:
                errors.append(f"sn={i} ({event_type}): signature check error: {e}")
        else:
            # No signature present — structural-only check passed
            events_validated += 1

    return {
        "kel_verified": len(errors) == 0,
        "events_validated": events_validated,
        "current_public_key": current_key_qb64 or "",
        "validation_errors": errors,
    }


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
        result = _validate_kel_events(events)
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


@app.route("/generate-multisig-event", methods=["POST"])
def generate_multisig_event():
    data = request.get_json()
    if not data:
        return jsonify({"error": "Request body required"}), 400

    aids = data.get("aids", [])
    threshold = data.get("threshold", 1)
    current_keys = data.get("current_keys", [])
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
            serder = eventing.incept(
                keys=key_qb64s,
                isith=str(threshold),
                nsith=str(threshold),
                ndigs=[],
                code=MtrDex.Blake3_256,
            )
        else:
            event_data = {
                "type": event_type,
                "aids": aids,
                "threshold": threshold,
                "keys": key_qb64s,
            }
            event_json = json.dumps(event_data, separators=(",", ":")).encode()
            serder_diger = coring.Diger(ser=event_json, code=MtrDex.Blake3_256)

            return jsonify({
                "raw_bytes_b64": base64.b64encode(event_json).decode(),
                "said": serder_diger.qb64,
                "pre": serder_diger.qb64,
                "event_type": event_type,
                "size": len(event_json),
            }), 200

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
# Entry point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    port = int(os.environ.get("KERI_DRIVER_PORT", "9999"))
    host = os.environ.get("KERI_DRIVER_HOST", "127.0.0.1")

    print(f"[keri-driver] Starting KERI Core Driver on {host}:{port}")
    print(f"[keri-driver] KERI library: keripy (reference)")
    print(f"[keri-driver] Stateful endpoints:  /status, /inception, /rotation, /interact, /sign, /kel, /verify")
    print(f"[keri-driver] Stateless endpoints: /cesr-encode, /validate-kel, /resolve-oobi, /format-credential, /generate-multisig-event")
    print(f"[keri-driver] Credential endpoints: /credential/issue")

    app.run(host=host, port=port, debug=False)
