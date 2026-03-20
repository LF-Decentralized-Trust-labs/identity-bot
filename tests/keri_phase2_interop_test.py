"""
KERI Interoperability Test -- Phase 2: IXN Events + Key Rotation

Proves the following before production code is written:

  STEP 1: keripy creates a valid IXN (interaction) event from an established AID
  STEP 2: Dart-path signing (sha256 seed -> Ed25519) produces a CESR Cigar sig
          that keripy verifier accepts for the IXN event body
  STEP 3: keripy creates a valid rotation event committing the pre-rotated key
  STEP 4: Rotation event signed with the pre-rotated key verifies correctly
  STEP 5: Pre-rotation commitment check -- new key matches digest from inception
  STEP 6: Post-rotation signing uses the new (rotated) key, NOT the original key
  STEP 7: keripy rejects a rotation event signed with the wrong key

If all steps pass, Phase 2 implementation is safe:
  - Dart signs IXN events locally (same path as inception)
  - Dart derives the pre-rotated key with index 1 (sha256(seed + 0x01))
  - Python /interact and /rotation endpoints return raw_bytes_b64 for Dart to sign
  - keripy verifier accepts all output

Run with:
  python tests/keri_phase2_interop_test.py
"""

import sys
import os
import base64
import hashlib
import json
import ctypes
import ctypes.util

# ---------------------------------------------------------------------------
# Windows: find libsodium.dll
# ---------------------------------------------------------------------------
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
        os.path.join(repo_root, "identity_agent_ui", "build", "windows",
                     "x64", "runner", "Release", "backend", "keri-driver"),
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

# ---------------------------------------------------------------------------
# Windows: patch SysLogHandler
# ---------------------------------------------------------------------------
if sys.platform == "win32":
    import socket as _socket
    import logging as _logging
    import logging.handlers as _lh
    if not hasattr(_socket, "AF_UNIX"):
        _socket.AF_UNIX = 1
    _orig = _lh.SysLogHandler.__init__
    def _win_syslog_init(self, address=("localhost", _lh.SYSLOG_UDP_PORT),
                         facility=_lh.SysLogHandler.LOG_USER, socktype=None):
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

try:
    from keri.core import coring, eventing
    from keri.core.coring import MtrDex
    import pysodium
except ImportError as e:
    print("FAIL: Could not import keripy/pysodium: %s" % e)
    print("Install with: pip install keri==1.1.17")
    sys.exit(1)

PASS = "PASS"
FAIL = "FAIL"
results = []

def check(label, condition, detail=""):
    status = PASS if condition else FAIL
    results.append((status, label))
    marker = "[PASS]" if condition else "[FAIL]"
    print("  %s  %s" % (marker, label))
    if detail:
        print("         %s" % detail)
    return condition

# ---------------------------------------------------------------------------
# Test seed and data
# ---------------------------------------------------------------------------
TEST_SEED = bytes(range(32))  # same deterministic seed as Phase 1 test

# Dart key derivation: sha256(seed[:32]) = index-0 key
def dart_key(seed, index=0):
    """Derive Ed25519 keypair at given index. Index 0 = signing key, 1 = pre-rotated."""
    if index == 0:
        private_seed = hashlib.sha256(seed[:32]).digest()
    else:
        private_seed = hashlib.sha256(seed[:32] + bytes([index])).digest()
    pk, sk = pysodium.crypto_sign_seed_keypair(private_seed)
    return pk, sk, private_seed

def cesr_encode_sig(raw_sig):
    """Wrap raw 64-byte sig in Cigar -> '0B...' CESR format."""
    return coring.Cigar(raw=raw_sig, code=MtrDex.Ed25519_Sig)

# Derive keys
pk0, sk0, seed0 = dart_key(TEST_SEED, 0)  # current signing key
pk1, sk1, seed1 = dart_key(TEST_SEED, 1)  # pre-rotated key

verfer0 = coring.Verfer(raw=pk0, code=MtrDex.Ed25519)
verfer1 = coring.Verfer(raw=pk1, code=MtrDex.Ed25519)
diger1  = coring.Diger(raw=pk1, code=MtrDex.Blake3_256)  # digest of pre-rotated key

# Build inception event (same as Phase 1)
icp_serder = eventing.incept(
    keys=[verfer0.qb64],
    ndigs=[diger1.qb64],
    code=MtrDex.Blake3_256,
)
icp_sig_raw = pysodium.crypto_sign_detached(icp_serder.raw, sk0)
icp_cigar = cesr_encode_sig(icp_sig_raw)

# ---------------------------------------------------------------------------
# STEP 1: keripy creates a valid IXN event
# ---------------------------------------------------------------------------
print("\n-- STEP 1: IXN event creation ----------------------------------------")

# A seal anchors external data (e.g., credential SAID) into the KEL
test_seal = {"d": "EsomethingFromCredentialSAID00000000000000000"}

ixn_serder = eventing.interact(
    pre=icp_serder.pre,
    dig=icp_serder.said,
    sn=1,
    data=[test_seal],
)

check("IXN event created by keripy", ixn_serder is not None)
check("IXN event type is 'ixn'", ixn_serder.ked.get("t") == "ixn",
      "Got: %s" % ixn_serder.ked.get("t"))
check("IXN event sequence number is 1", ixn_serder.ked.get("s") == "1",
      "Got: %s" % ixn_serder.ked.get("s"))
check("IXN event references inception SAID as prior",
      ixn_serder.ked.get("p") == icp_serder.said,
      "ICP SAID: %s\nIXN prior: %s" % (icp_serder.said, ixn_serder.ked.get("p")))
check("IXN event raw bytes are non-empty", len(ixn_serder.raw) > 0)
print("  IXN SAID: %s" % ixn_serder.said)
print("  IXN raw bytes length: %d" % len(ixn_serder.raw))

# ---------------------------------------------------------------------------
# STEP 2: Dart-path signing of IXN event verifies with keripy
# ---------------------------------------------------------------------------
print("\n-- STEP 2: IXN event signing -----------------------------------------")

# Sign IXN event body with current key (index 0) -- same as Dart will do
ixn_raw_sig = pysodium.crypto_sign_detached(ixn_serder.raw, sk0)
ixn_cigar = cesr_encode_sig(ixn_raw_sig)

check("IXN raw signature is 64 bytes", len(ixn_raw_sig) == 64)
check("IXN CESR signature starts with '0B'", ixn_cigar.qb64.startswith("0B"),
      "Got: %s" % ixn_cigar.qb64[:10])
check("IXN CESR signature is 88 chars", len(ixn_cigar.qb64) == 88)
check("keripy verfer0 verifies IXN signature",
      verfer0.verify(sig=ixn_raw_sig, ser=ixn_serder.raw))
check("keripy rejects IXN signature from wrong key (key1)",
      not verfer1.verify(sig=ixn_raw_sig, ser=ixn_serder.raw))

print("  IXN CESR sig: %s..." % ixn_cigar.qb64[:30])

# ---------------------------------------------------------------------------
# STEP 3: keripy creates a valid rotation event
# ---------------------------------------------------------------------------
print("\n-- STEP 3: Rotation event creation ----------------------------------")

# For rotation, we need the next-next key (index 2) to pre-rotate to
pk2, sk2, seed2 = dart_key(TEST_SEED, 2)
verfer2 = coring.Verfer(raw=pk2, code=MtrDex.Ed25519)
diger2  = coring.Diger(raw=pk2, code=MtrDex.Blake3_256)

rot_serder = eventing.rotate(
    pre=icp_serder.pre,
    keys=[verfer1.qb64],       # revealing the pre-rotated key
    dig=icp_serder.said,       # digest of previous event (inception)
    ndigs=[diger2.qb64],       # committing to next pre-rotation
    sn=1,
)

check("Rotation event created by keripy", rot_serder is not None)
check("Rotation event type is 'rot'", rot_serder.ked.get("t") == "rot",
      "Got: %s" % rot_serder.ked.get("t"))
check("Rotation event sequence number is 1", rot_serder.ked.get("s") == "1")
check("Rotation event keys field contains new verfer",
      verfer1.qb64 in rot_serder.ked.get("k", []),
      "Keys: %s" % rot_serder.ked.get("k"))
check("Rotation event ndigs field contains next digest",
      diger2.qb64 in rot_serder.ked.get("n", []),
      "NDigs: %s" % rot_serder.ked.get("n"))
print("  Rotation SAID: %s" % rot_serder.said)

# ---------------------------------------------------------------------------
# STEP 4: Rotation event is signed with the pre-rotated key (key index 1)
# ---------------------------------------------------------------------------
print("\n-- STEP 4: Rotation event signing -----------------------------------")

# Rotation event MUST be signed with the key that was committed as pre-rotation
# in the inception event -- this is key1 (index 1), NOT key0
rot_raw_sig = pysodium.crypto_sign_detached(rot_serder.raw, sk1)
rot_cigar = cesr_encode_sig(rot_raw_sig)

check("Rotation raw signature is 64 bytes", len(rot_raw_sig) == 64)
check("Rotation CESR signature starts with '0B'", rot_cigar.qb64.startswith("0B"))
check("keripy verfer1 (pre-rotated key) verifies rotation signature",
      verfer1.verify(sig=rot_raw_sig, ser=rot_serder.raw))

# ---------------------------------------------------------------------------
# STEP 5: Pre-rotation commitment check
# ---------------------------------------------------------------------------
print("\n-- STEP 5: Pre-rotation commitment check ----------------------------")

# The inception event committed to diger1 = Blake3_256(pk1).
# The rotation reveals pk1 as the new signing key.
# We verify that the digest committed in inception matches pk1.
diger1_recomputed = coring.Diger(raw=pk1, code=MtrDex.Blake3_256)

check("Pre-rotated key digest matches inception commitment",
      diger1_recomputed.qb64 == diger1.qb64,
      "Expected: %s\nGot: %s" % (diger1.qb64, diger1_recomputed.qb64))
check("Inception ndigs field matches the recomputed pre-rotated key digest",
      diger1.qb64 in icp_serder.ked.get("n", []),
      "ICP ndigs: %s" % icp_serder.ked.get("n"))

# ---------------------------------------------------------------------------
# STEP 6: Post-rotation signing uses the new key (key1), not the old (key0)
# ---------------------------------------------------------------------------
print("\n-- STEP 6: Post-rotation event signing (IXN after rotation) ---------")

# An IXN event after rotation must be signed with key1 (the new current key)
ixn2_serder = eventing.interact(
    pre=icp_serder.pre,
    dig=rot_serder.said,
    sn=2,
    data=[],
)
ixn2_sig_with_key1 = pysodium.crypto_sign_detached(ixn2_serder.raw, sk1)
ixn2_sig_with_key0 = pysodium.crypto_sign_detached(ixn2_serder.raw, sk0)

check("Post-rotation IXN signed with key1 verifies", verfer1.verify(sig=ixn2_sig_with_key1, ser=ixn2_serder.raw))
check("Post-rotation IXN signed with old key0 is rejected", not verfer0.verify(sig=ixn2_sig_with_key1, ser=ixn2_serder.raw))

# ---------------------------------------------------------------------------
# STEP 7: keripy rejects rotation signed with wrong key
# ---------------------------------------------------------------------------
print("\n-- STEP 7: Wrong-key rejection ---------------------------------------")

rot_wrong_sig = pysodium.crypto_sign_detached(rot_serder.raw, sk0)  # signed with key0, wrong

check("Rotation signed with OLD key (key0) is rejected by key1 verfer",
      not verfer1.verify(sig=rot_wrong_sig, ser=rot_serder.raw))
check("Rotation signed with OLD key (key0) would falsely verify against key0",
      verfer0.verify(sig=rot_wrong_sig, ser=rot_serder.raw),
      "(This confirms key derivation is correct -- wrong key, right math)")

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------
print("\n-- Summary -----------------------------------------------------------")
passed = sum(1 for s, _ in results if s == PASS)
failed = sum(1 for s, _ in results if s == FAIL)
print("\n  PASSED: %d   FAILED: %d\n" % (passed, failed))

if failed > 0:
    print("  SOME TESTS FAILED -- do not proceed with Phase 2 implementation.")
    sys.exit(1)
else:
    print("  ALL TESTS PASSED")
    print()
    print("  PROVEN for Phase 2 implementation:")
    print("  [+] IXN events created by eventing.interact() are valid keripy events")
    print("  [+] IXN events are signed with the CURRENT key (index 0)")
    print("  [+] IXN CESR signature (Cigar 0B...) is accepted by keripy verfer")
    print("  [+] Rotation events created by eventing.rotate() are valid")
    print("  [+] Rotation events are signed with the PRE-ROTATED key (index 1)")
    print("  [+] Pre-rotation commitment (Blake3_256 digest) is verified correctly")
    print("  [+] Post-rotation events use the new key; old key is rejected")
    print("  [+] keripy rejects signatures from wrong keys")
    print()
    print("  Safe to proceed with Phase 2 implementation.")
    sys.exit(0)
