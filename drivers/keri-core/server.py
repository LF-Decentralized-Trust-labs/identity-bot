import os
import sys
import json
import hashlib
import base64
import time
import ctypes
import ctypes.util
import glob

def _ensure_libsodium():
    if ctypes.util.find_library("sodium"):
        return
    found_path = None
    for so_name in ["libsodium.so.26", "libsodium.so.23", "libsodium.so"]:
        try:
            lib = ctypes.CDLL(so_name)
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

from flask import Flask, request, jsonify

KERI_AVAILABLE = False
try:
    from keri.core import coring, eventing
    from keri.core.coring import MtrDex, Matter
    KERI_AVAILABLE = True
except (ImportError, ValueError, OSError) as e:
    print(f"[keri-driver] keripy not available: {e}", file=sys.stderr)

app = Flask(__name__)
start_time = time.time()


def b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def b64url_decode(s: str) -> bytes:
    padding = 4 - len(s) % 4
    if padding != 4:
        s += "=" * padding
    return base64.urlsafe_b64decode(s)


def compute_said(event_dict: dict) -> str:
    placeholder = "#" + "a" * 43
    event_dict["d"] = placeholder
    event_dict["i"] = placeholder

    raw = json.dumps(event_dict, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    size = len(raw)
    event_dict["v"] = f"KERI10JSON{size:06x}_"

    raw = json.dumps(event_dict, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    digest = hashlib.sha256(raw).digest()
    said = "E" + b64url_encode(digest)
    return said


def digest_key(pub_key_bytes: bytes) -> str:
    h = hashlib.sha256(pub_key_bytes).digest()
    return "E" + b64url_encode(h)


def create_inception_event_fallback(public_key: str, next_public_key: str) -> dict:
    if public_key.startswith("B"):
        pub_bytes = b64url_decode(public_key[1:])
    else:
        pub_bytes = b64url_decode(public_key)

    if next_public_key.startswith("B"):
        next_bytes = b64url_decode(next_public_key[1:])
    else:
        next_bytes = b64url_decode(next_public_key)

    next_key_digest = digest_key(next_bytes)

    event = {
        "v": "KERI10JSON000000_",
        "t": "icp",
        "d": "",
        "i": "",
        "s": "0",
        "kt": "1",
        "k": [public_key],
        "nt": "1",
        "n": [next_key_digest],
        "bt": "0",
        "b": [],
        "c": [],
        "a": [],
    }

    said = compute_said(event)
    event["d"] = said
    event["i"] = said

    return {
        "aid": said,
        "inception_event": event,
        "public_key": public_key,
        "next_key_digest": next_key_digest,
    }


def create_inception_event_keri(public_key: str, next_public_key: str) -> dict:
    if public_key.startswith("B"):
        pub_bytes = b64url_decode(public_key[1:])
    else:
        pub_bytes = b64url_decode(public_key)

    if next_public_key.startswith("B"):
        next_bytes = b64url_decode(next_public_key[1:])
    else:
        next_bytes = b64url_decode(next_public_key)

    verfer = coring.Verfer(raw=pub_bytes, code=MtrDex.Ed25519)
    diger = coring.Diger(raw=next_bytes, code=MtrDex.Blake3_256)

    serder = eventing.incept(
        keys=[verfer.qb64],
        ndigs=[diger.qb64],
        code=MtrDex.Blake3_256,
    )

    event_dict = serder.ked

    return {
        "aid": serder.pre,
        "inception_event": event_dict,
        "public_key": verfer.qb64,
        "next_key_digest": diger.qb64,
    }


@app.route("/status", methods=["GET"])
def status():
    uptime = time.time() - start_time
    return jsonify({
        "status": "active",
        "driver": "keri-core",
        "version": "0.1.0",
        "keri_library": "keripy" if KERI_AVAILABLE else "fallback",
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
        if KERI_AVAILABLE:
            result = create_inception_event_keri(public_key, next_public_key)
        else:
            result = create_inception_event_fallback(public_key, next_public_key)

        return jsonify(result), 201
    except Exception as e:
        return jsonify({"error": f"Inception failed: {str(e)}"}), 500


if __name__ == "__main__":
    port = int(os.environ.get("KERI_DRIVER_PORT", "9999"))
    host = os.environ.get("KERI_DRIVER_HOST", "127.0.0.1")

    print(f"[keri-driver] Starting KERI Core Driver on {host}:{port}")
    print(f"[keri-driver] KERI library: {'keripy (reference)' if KERI_AVAILABLE else 'fallback (built-in)'}")
    print(f"[keri-driver] Endpoints: /status, /inception")

    app.run(host=host, port=port, debug=False)
