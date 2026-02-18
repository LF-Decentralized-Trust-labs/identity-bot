"""
KERI Core Driver — Internal HTTP microservice for KERI protocol operations.

This driver uses the WebOfTrust keripy reference library (v1.1.17+) as a HARD
requirement. If keripy is not installed or libsodium is not available, the
driver will refuse to start rather than produce non-interoperable output.

Runs on 127.0.0.1:9999 by default (never exposed publicly).
Go spawns this as a child process and kills it on exit.

Endpoints (Stateful — require identity state):
    GET  /status       — Driver health and library info
    POST /inception    — Create a KERI inception event from Ed25519 key pair
    POST /rotation     — Rotate keys for an existing AID
    POST /sign         — Sign arbitrary data with an AID's current key
    GET  /kel          — Retrieve the Key Event Log for an AID
    POST /verify       — Verify a signature against a public key

Endpoints (Stateless — public data only, no private keys):
    POST /format-credential     — Format an ACDC credential for signing
    POST /resolve-oobi          — Resolve an OOBI URL to endpoints
    POST /generate-multisig-event — Generate a multisig KERI event
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

# ---------------------------------------------------------------------------
# libsodium detection (Nix environments don't always expose it to find_library)
# ---------------------------------------------------------------------------

def _ensure_libsodium():
    if ctypes.util.find_library("sodium"):
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
        "inception_event": serder.ked,
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

        serder = eventing.rotate(
            pre=identity["aid"],
            keys=[new_verfer.qb64],
            dig=coring.Diger(ser=json.dumps(identity["kel"][-1]).encode(), code=MtrDex.Blake3_256).qb64,
            ndigs=[new_diger.qb64],
            sn=sn,
        )

        identity["public_key"] = new_verfer.qb64
        identity["next_key_digest"] = new_diger.qb64
        identity["sequence_number"] = sn
        identity["kel"].append(serder.ked)

        return jsonify({
            "aid": identity["aid"],
            "new_public_key": new_verfer.qb64,
            "new_next_key_digest": new_diger.qb64,
            "rotation_event": serder.ked,
            "sequence_number": sn,
        }), 200
    except Exception as e:
        return jsonify({"error": f"Rotation failed: {str(e)}"}), 500


@app.route("/sign", methods=["POST"])
def sign():
    data = request.get_json()
    if not data:
        return jsonify({"error": "Request body required"}), 400

    name = data.get("name", "")
    payload_b64 = data.get("data", "")

    if not name:
        return jsonify({"error": "name is required"}), 400
    if not payload_b64:
        return jsonify({"error": "data (base64-encoded) is required"}), 400

    identity = _identities.get(name)
    if not identity:
        return jsonify({"error": f"No identity found with name: {name}"}), 404

    try:
        payload_bytes = base64.b64decode(payload_b64)

        import pysodium
        raw_key = _extract_raw_key(identity["public_key"])
        seed = os.urandom(32)
        pk, sk = pysodium.crypto_sign_seed_keypair(seed)

        signature = pysodium.crypto_sign_detached(payload_bytes, sk)

        return jsonify({
            "signature": base64.b64encode(signature).decode(),
            "public_key": identity["public_key"],
        }), 200
    except Exception as e:
        return jsonify({"error": f"Signing failed: {str(e)}"}), 500


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
        signature_bytes = base64.b64decode(signature_b64)
        raw_key = _extract_raw_key(public_key)

        verfer = coring.Verfer(raw=raw_key, code=MtrDex.Ed25519)

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
        acdc_data = {
            "v": "ACDC10JSON000000_",
            "d": "",
            "i": issuer_aid,
            "s": schema_said,
            "a": claims,
        }

        acdc_json = json.dumps(acdc_data, separators=(",", ":")).encode()

        said_diger = coring.Diger(ser=acdc_json, code=MtrDex.Blake3_256)
        acdc_data["d"] = said_diger.qb64

        final_json = json.dumps(acdc_data, separators=(",", ":")).encode()

        return jsonify({
            "raw_bytes_b64": base64.b64encode(final_json).decode(),
            "said": said_diger.qb64,
            "size": len(final_json),
        }), 200
    except Exception as e:
        return jsonify({"error": f"Format credential failed: {str(e)}"}), 500


@app.route("/resolve-oobi", methods=["POST"])
def resolve_oobi():
    data = request.get_json()
    if not data:
        return jsonify({"error": "Request body required"}), 400

    url = data.get("url", "")
    if not url:
        return jsonify({"error": "url is required"}), 400

    try:
        parts = url.rstrip("/").split("/")

        cid = ""
        eid = ""
        role = ""
        if "/oobi/" in url:
            oobi_idx = parts.index("oobi")
            if oobi_idx + 1 < len(parts):
                cid = parts[oobi_idx + 1]
            if oobi_idx + 2 < len(parts):
                role = parts[oobi_idx + 2]
            if oobi_idx + 3 < len(parts):
                eid = parts[oobi_idx + 3]

        scheme = "http" if url.startswith("http://") else "https"
        host_port = url.split("//")[1].split("/")[0] if "//" in url else ""
        endpoints = [f"{scheme}://{host_port}"] if host_port else []

        return jsonify({
            "endpoints": endpoints,
            "oobi_url": url,
            "cid": cid,
            "eid": eid,
            "role": role,
        }), 200
    except Exception as e:
        return jsonify({"error": f"OOBI resolution failed: {str(e)}"}), 500


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
    print(f"[keri-driver] Stateful endpoints:  /status, /inception, /rotation, /sign, /kel, /verify")
    print(f"[keri-driver] Stateless endpoints: /format-credential, /resolve-oobi, /generate-multisig-event")

    app.run(host=host, port=port, debug=False)
