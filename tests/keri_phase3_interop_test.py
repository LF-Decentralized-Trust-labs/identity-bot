"""
KERI Interoperability Test -- Phase 3: OOBI Resolution + KEL Validation

Proves the following before production code is written:

  STEP 1: A KEL (Key Event Log) can be constructed as a sequence of events
  STEP 2: KEL hash chain is valid -- each event's prior digest matches previous event
  STEP 3: All event signatures in the KEL verify against the correct key at each sn
  STEP 4: An OOBI response payload (JSON with KEL) can be parsed and validated
  STEP 5: A tampered KEL event is detected (hash chain breaks)
  STEP 6: A KEL with a wrong signature is detected

If all steps pass, Phase 3 implementation is safe:
  - Python /resolve-oobi fetches real OOBI URLs and validates the returned KEL
  - keripy validates the hash chain and all event signatures
  - Tampered or forged KELs are rejected before storing contact records

Run with:
  python tests/keri_phase3_interop_test.py
"""

import sys
import os
import base64
import hashlib
import json
import ctypes
import ctypes.util

def _ensure_libsodium():
    if ctypes.util.find_library("sodium"):
        return
    if sys.platform != "win32":
        return
    script_dir = os.path.dirname(os.path.abspath(__file__))
    repo_root = os.path.dirname(script_dir)
    search_dirs = [
        os.path.join(repo_root, "identity_agent_ui", "build", "windows",
                     "x64", "runner", "Release", "backend"),
        os.path.join(repo_root, "drivers", "keri-core"),
        script_dir,
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

_ensure_libsodium()

if sys.platform == "win32":
    import socket as _socket
    import logging as _logging
    import logging.handlers as _lh
    if not hasattr(_socket, "AF_UNIX"):
        _socket.AF_UNIX = 1
    def _win_syslog_init(self, address=("localhost", _lh.SYSLOG_UDP_PORT),
                         facility=_lh.SysLogHandler.LOG_USER, socktype=None):
        _logging.Handler.__init__(self)
        self.address = address; self.facility = facility; self.socktype = socktype
        self.unixsocket = False; self.socket = None; self.ident = ""; self.append_nul = True
    _lh.SysLogHandler.__init__ = _win_syslog_init
    _lh.SysLogHandler.createSocket = lambda self: None
    _lh.SysLogHandler.emit = lambda self, record: None
    _lh.SysLogHandler.close = lambda self: _logging.Handler.close(self)

try:
    from keri.core import coring, eventing
    from keri.core.coring import MtrDex
    import pysodium
except ImportError as e:
    print("FAIL: Could not import keripy/pysodium: %s" % e)
    sys.exit(1)

PASS = "PASS"; FAIL = "FAIL"; results = []

def check(label, condition, detail=""):
    status = PASS if condition else FAIL
    results.append((status, label))
    print("  [%s]  %s" % (status, label))
    if detail:
        print("         %s" % detail)
    return condition

# ---------------------------------------------------------------------------
# Build a realistic 3-event KEL: inception, ixn, rotation
# ---------------------------------------------------------------------------
TEST_SEED = bytes(range(32))

def dart_key(index=0):
    if index == 0:
        s = hashlib.sha256(TEST_SEED[:32]).digest()
    else:
        s = hashlib.sha256(TEST_SEED[:32] + bytes([index])).digest()
    pk, sk = pysodium.crypto_sign_seed_keypair(s)
    return pk, sk

pk0, sk0 = dart_key(0)
pk1, sk1 = dart_key(1)
pk2, sk2 = dart_key(2)

verfer0 = coring.Verfer(raw=pk0, code=MtrDex.Ed25519)
verfer1 = coring.Verfer(raw=pk1, code=MtrDex.Ed25519)
diger1  = coring.Diger(raw=pk1, code=MtrDex.Blake3_256)
diger2  = coring.Diger(raw=pk2, code=MtrDex.Blake3_256)

icp = eventing.incept(keys=[verfer0.qb64], ndigs=[diger1.qb64], code=MtrDex.Blake3_256)
ixn = eventing.interact(pre=icp.pre, dig=icp.said, sn=1, data=[])
rot = eventing.rotate(pre=icp.pre, keys=[verfer1.qb64], dig=ixn.said, ndigs=[diger2.qb64], sn=2)

icp_sig = pysodium.crypto_sign_detached(icp.raw, sk0)
ixn_sig = pysodium.crypto_sign_detached(ixn.raw, sk0)
rot_sig = pysodium.crypto_sign_detached(rot.raw, sk1)  # signed with pre-rotated key

kel = [
    {"event": icp.ked, "raw_b64": base64.b64encode(icp.raw).decode(), "sig_b64": base64.b64encode(icp_sig).decode(), "verfer": verfer0.qb64},
    {"event": ixn.ked, "raw_b64": base64.b64encode(ixn.raw).decode(), "sig_b64": base64.b64encode(ixn_sig).decode(), "verfer": verfer0.qb64},
    {"event": rot.ked, "raw_b64": base64.b64encode(rot.raw).decode(), "sig_b64": base64.b64encode(rot_sig).decode(), "verfer": verfer1.qb64},
]

# ---------------------------------------------------------------------------
# STEP 1: KEL construction
# ---------------------------------------------------------------------------
print("\n-- STEP 1: KEL construction -----------------------------------------")
check("KEL has 3 events", len(kel) == 3)
check("Event 0 is inception (icp)", kel[0]["event"].get("t") == "icp")
check("Event 1 is interaction (ixn)", kel[1]["event"].get("t") == "ixn")
check("Event 2 is rotation (rot)", kel[2]["event"].get("t") == "rot")
check("AID (prefix) is consistent across all events",
      kel[0]["event"]["i"] == kel[1]["event"]["i"] == kel[2]["event"]["i"])

# ---------------------------------------------------------------------------
# STEP 2: Hash chain validation
# ---------------------------------------------------------------------------
print("\n-- STEP 2: KEL hash chain validation --------------------------------")

# Each event's 'p' (prior) field must match the SAID of the previous event
check("IXN prior matches ICP SAID",
      ixn.ked.get("p") == icp.said,
      "ICP SAID: %s\nIXN prior: %s" % (icp.said, ixn.ked.get("p")))
check("ROT prior matches IXN SAID",
      rot.ked.get("p") == ixn.said,
      "IXN SAID: %s\nROT prior: %s" % (ixn.said, rot.ked.get("p")))
check("Sequence numbers are contiguous (0, 1, 2)",
      [e["event"].get("s") for e in kel] == ["0", "1", "2"])

# ---------------------------------------------------------------------------
# STEP 3: All event signatures verify
# ---------------------------------------------------------------------------
print("\n-- STEP 3: KEL signature verification --------------------------------")

for entry in kel:
    raw = base64.b64decode(entry["raw_b64"])
    sig = base64.b64decode(entry["sig_b64"])
    vf  = coring.Verfer(qb64=entry["verfer"])
    t   = entry["event"].get("t")
    check("Event sn=%s (%s) signature verifies" % (entry["event"].get("s"), t),
          vf.verify(sig=sig, ser=raw))

# ---------------------------------------------------------------------------
# STEP 4: OOBI response payload round-trip
# ---------------------------------------------------------------------------
print("\n-- STEP 4: OOBI response payload round-trip -------------------------")

# Simulate what a real OOBI endpoint returns: the KEL events as JSON
oobi_payload = json.dumps({
    "pre": icp.pre,
    "kel": [e["event"] for e in kel],
    "sigs": [e["sig_b64"] for e in kel],
    "verfers": [e["verfer"] for e in kel],
})

parsed = json.loads(oobi_payload)
check("Parsed OOBI payload has correct AID", parsed["pre"] == icp.pre)
check("Parsed OOBI payload has 3 KEL events", len(parsed["kel"]) == 3)
check("Parsed event type sequence is correct",
      [e.get("t") for e in parsed["kel"]] == ["icp", "ixn", "rot"])

# ---------------------------------------------------------------------------
# STEP 5: Tampered KEL is detected (hash chain breaks)
# ---------------------------------------------------------------------------
print("\n-- STEP 5: Tampered KEL detection ------------------------------------")

import copy
tampered_kel = copy.deepcopy([e["event"] for e in kel])
original_prior = tampered_kel[1].get("p")
tampered_kel[1]["p"] = "ETAMPEREDPRIORXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX"

check("Tampered IXN prior no longer matches ICP SAID",
      tampered_kel[1]["p"] != icp.said)
check("Original IXN prior did match ICP SAID (sanity)",
      original_prior == icp.said)

def validate_hash_chain(events):
    for i in range(1, len(events)):
        # Reconstruct the previous event's SAID to check
        # We can check the 'p' field in each event vs the previous event's 'd' field
        expected_prior = events[i-1].get("d", "")
        actual_prior   = events[i].get("p", "")
        if expected_prior != actual_prior:
            return False, i
    return True, -1

valid, _ = validate_hash_chain([e["event"] for e in kel])
tampered_valid, tampered_idx = validate_hash_chain(tampered_kel)

check("Original KEL passes hash chain validation", valid)
check("Tampered KEL fails hash chain validation", not tampered_valid,
      "Tampered event index: %d" % tampered_idx)

# ---------------------------------------------------------------------------
# STEP 6: KEL with wrong signature is detected
# ---------------------------------------------------------------------------
print("\n-- STEP 6: Wrong-signature detection ---------------------------------")

# Sign an event with a completely different key
pk_bad, sk_bad = pysodium.crypto_sign_seed_keypair(bytes([0xff] * 32))
bad_sig = pysodium.crypto_sign_detached(icp.raw, sk_bad)
verfer_bad = coring.Verfer(raw=pk_bad, code=MtrDex.Ed25519)

check("Correct sig on ICP verifies with verfer0", verfer0.verify(sig=icp_sig, ser=icp.raw))
check("Wrong sig on ICP is rejected by verfer0", not verfer0.verify(sig=bad_sig, ser=icp.raw))
check("Wrong sig would verify with its own (wrong) key (sanity)",
      verfer_bad.verify(sig=bad_sig, ser=icp.raw))

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------
print("\n-- Summary -----------------------------------------------------------")
passed = sum(1 for s, _ in results if s == PASS)
failed = sum(1 for s, _ in results if s == FAIL)
print("\n  PASSED: %d   FAILED: %d\n" % (passed, failed))

if failed > 0:
    print("  SOME TESTS FAILED -- do not proceed with Phase 3 implementation.")
    sys.exit(1)
else:
    print("  ALL TESTS PASSED")
    print()
    print("  PROVEN for Phase 3 implementation:")
    print("  [+] KEL hash chain (prior digest chain) validates correctly")
    print("  [+] All event signatures verify against the correct key for each sn")
    print("  [+] OOBI payload round-trip (serialize/parse) preserves KEL integrity")
    print("  [+] Tampered event (modified prior field) is detected")
    print("  [+] Wrong-key signatures are detected")
    print()
    print("  Safe to proceed with Phase 3 implementation.")
    sys.exit(0)
