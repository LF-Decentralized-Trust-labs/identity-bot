"""
KERI Core Driver — Internal HTTP microservice for KERI protocol operations.

This driver uses the WebOfTrust keripy reference library (v1.1.17+) as a HARD
requirement. If keripy is not installed or libsodium is not available, the
driver will refuse to start rather than produce non-interoperable output.

Runs on 127.0.0.1:9999 by default (never exposed publicly).
Spawned by the Go Core in development; runs as a separate service in production.

Endpoints:
    GET  /status    — Driver health and library info
    POST /inception — Create a KERI inception event from Ed25519 key pair
"""

import os
import sys
import time
import ctypes
import ctypes.util
import base64

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
# HTTP routes
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
        return jsonify(result), 201
    except Exception as e:
        return jsonify({"error": f"Inception failed: {str(e)}"}), 500

# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    port = int(os.environ.get("KERI_DRIVER_PORT", "9999"))
    host = os.environ.get("KERI_DRIVER_HOST", "127.0.0.1")

    print(f"[keri-driver] Starting KERI Core Driver on {host}:{port}")
    print(f"[keri-driver] KERI library: keripy (reference)")
    print(f"[keri-driver] Endpoints: /status, /inception")

    app.run(host=host, port=port, debug=False)
