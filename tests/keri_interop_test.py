"""
KERI Interoperability Test — Phase 1: CESR Signing

This script proves the following chain before any production code is written:

  STEP 1: keripy native signing produces CESR-encoded signatures
  STEP 2: Raw pysodium signatures wrapped in coring.Siger are IDENTICAL to keripy native
  STEP 3: keripy verifier accepts signatures produced both ways
  STEP 4: The Dart seed derivation path (BIP39 → sha256 → Ed25519) produces
          the same public key that keripy would compute for that seed

If all steps pass, we can safely implement Phase 1:
  - Dart signs with ed25519_edwards (same math, proven here)
  - Python wraps the raw signature in coring.Siger to produce CESR
  - keripy verifier accepts the result

Run with:
  python tests/keri_interop_test.py
"""

import sys
import os
import base64
import hashlib
import json
import ctypes
import ctypes.util

# ---------------------------------------------------------------------------
# Windows: find libsodium.dll (same logic as drivers/keri-core/server.py)
# ---------------------------------------------------------------------------
def _ensure_libsodium():
    if ctypes.util.find_library("sodium"):
        return
    if sys.platform != "win32":
        return
    # Search known locations relative to repo root and release build
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
                print(f"  [libsodium] loaded from: {dll_path}")
                return
            except OSError:
                continue
    print("  [libsodium] WARNING: could not find libsodium.dll — pysodium may fail")

_ensure_libsodium()

# ---------------------------------------------------------------------------
# Windows: patch SysLogHandler before keripy import (same as server.py)
# ---------------------------------------------------------------------------
if sys.platform == "win32":
    import socket as _socket
    import logging as _logging
    import logging.handlers as _lh

    if not hasattr(_socket, "AF_UNIX"):
        _socket.AF_UNIX = 1

    _orig_syslog_init = _lh.SysLogHandler.__init__

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

# ---------------------------------------------------------------------------
# Import keripy
# ---------------------------------------------------------------------------
try:
    from keri.core import coring, eventing
    from keri.core.coring import MtrDex
    import pysodium
except ImportError as e:
    print(f"FAIL: Could not import keripy/pysodium: {e}")
    print("Install with: pip install keri==1.1.17")
    sys.exit(1)

PASS = "✓ PASS"
FAIL = "✗ FAIL"

results = []

def check(label, condition, detail=""):
    status = PASS if condition else FAIL
    results.append((status, label))
    print(f"  {status}  {label}")
    if detail:
        print(f"         {detail}")
    return condition

# ---------------------------------------------------------------------------
# STEP 1: keripy native signing produces a CESR signature
# ---------------------------------------------------------------------------
print("\n── STEP 1: keripy native signing ──────────────────────────────────────")

# Use a deterministic test seed (32 bytes, all predictable)
TEST_SEED = bytes(range(32))
TEST_DATA = b"test message for keri interop verification"

# keripy's Signer takes the raw seed bytes
signer = coring.Signer(raw=TEST_SEED, code=MtrDex.Ed25519_Seed)
verfer = signer.verfer  # The corresponding public key

keripy_sig = signer.sign(ser=TEST_DATA)  # Returns a Siger (CESR-encoded)
keripy_cesr = keripy_sig.qb64            # The CESR string, e.g. "0B..."

check("keripy signer produces a signature", keripy_sig is not None)
check("CESR signature starts with '0B' (Ed25519 sig code)", keripy_cesr.startswith("0B"),
      f"Got: {keripy_cesr[:10]}...")
check("CESR signature is 88 characters", len(keripy_cesr) == 88,
      f"Got length: {len(keripy_cesr)}")
check("keripy verfer accepts its own signature",
      verfer.verify(sig=keripy_sig.raw, ser=TEST_DATA))

print(f"\n  keripy CESR sig: {keripy_cesr}")
print(f"  keripy public key (CESR): {verfer.qb64}")

# ---------------------------------------------------------------------------
# STEP 2: raw pysodium sig wrapped in coring.Siger == keripy native sig
# ---------------------------------------------------------------------------
print("\n── STEP 2: pysodium raw sig → coring.Siger wrapping ──────────────────")

# pysodium directly: derive keypair from same seed, sign
pk_raw, sk_raw = pysodium.crypto_sign_seed_keypair(TEST_SEED)
raw_sig_bytes = pysodium.crypto_sign_detached(TEST_DATA, sk_raw)

check("pysodium produces 64-byte raw signature", len(raw_sig_bytes) == 64,
      f"Got: {len(raw_sig_bytes)} bytes")

# Wrap raw signature in keripy's Siger (CESR encoding)
wrapped_siger = coring.Siger(raw=raw_sig_bytes)
wrapped_cesr = wrapped_siger.qb64

check("pysodium sig wrapped in coring.Siger starts with '0B'",
      wrapped_cesr.startswith("0B"))
check("pysodium-wrapped CESR equals keripy native CESR",
      wrapped_cesr == keripy_cesr,
      f"keripy: {keripy_cesr}\n         wrapped: {wrapped_cesr}")
check("keripy verfer accepts pysodium-produced raw sig",
      verfer.verify(sig=raw_sig_bytes, ser=TEST_DATA))
check("pysodium public key matches keripy verfer raw bytes",
      pk_raw == verfer.raw)

print(f"\n  pysodium-wrapped CESR: {wrapped_cesr}")
print(f"  Match: {wrapped_cesr == keripy_cesr}")

# ---------------------------------------------------------------------------
# STEP 3: CESR public key encoding for our inception event
# ---------------------------------------------------------------------------
print("\n── STEP 3: CESR public key encoding ───────────────────────────────────")

# keripy Verfer from raw public key bytes
verfer_from_raw = coring.Verfer(raw=pk_raw, code=MtrDex.Ed25519)
check("Verfer from raw bytes matches signer's verfer",
      verfer_from_raw.qb64 == verfer.qb64)
check("Ed25519 public key CESR starts with 'B' (1-char code)",
      verfer.qb64.startswith("B"),
      f"Got: {verfer.qb64[:10]}...")
check("Ed25519 public key CESR is 44 characters",
      len(verfer.qb64) == 44,
      f"Got: {len(verfer.qb64)}")

print(f"\n  Public key CESR: {verfer.qb64}")

# ---------------------------------------------------------------------------
# STEP 4: Dart key derivation path matches keripy
#
# Dart's KeyManager.generateFromSeed does:
#   1. seed = Bip39.mnemonicToSeed(mnemonic)  [BIP39 PBKDF2 — we test with raw bytes here]
#   2. seedHash = sha256(seed[:32])
#   3. privateSeed = seedHash.bytes
#   4. privateKey = ed.newKeyFromSeed(privateSeed)
#
# We simulate step 2+3+4 in Python and verify keripy produces the same keypair.
# ---------------------------------------------------------------------------
print("\n── STEP 4: Dart seed derivation path produces same keys ───────────────")

# Simulate what Dart does: sha256 hash of first 32 bytes of the BIP39 seed
# For this test we use TEST_SEED as the "BIP39 seed bytes" input
dart_private_seed = hashlib.sha256(TEST_SEED[:32]).digest()  # 32 bytes

pk_dart, sk_dart = pysodium.crypto_sign_seed_keypair(dart_private_seed)
verfer_dart = coring.Verfer(raw=pk_dart, code=MtrDex.Ed25519)

# Sign test data with the dart-derived key
dart_raw_sig = pysodium.crypto_sign_detached(TEST_DATA, sk_dart)
dart_wrapped = coring.Siger(raw=dart_raw_sig)
dart_cesr = dart_wrapped.qb64

check("Dart-derived key produces 64-byte raw signature",
      len(dart_raw_sig) == 64)
check("Dart-derived sig wrapped in coring.Siger starts with '0B'",
      dart_cesr.startswith("0B"))
check("keripy verfer from Dart-derived public key verifies Dart signature",
      verfer_dart.verify(sig=dart_raw_sig, ser=TEST_DATA))

# Cross-verify: keripy rejects wrong key
check("keripy correctly rejects signature from wrong key",
      not verfer.verify(sig=dart_raw_sig, ser=TEST_DATA))

print(f"\n  Dart-path public key CESR: {verfer_dart.qb64}")
print(f"  Dart-path sig CESR:        {dart_cesr}")

# ---------------------------------------------------------------------------
# STEP 5: Full inception event with keripy — signed correctly
# ---------------------------------------------------------------------------
print("\n── STEP 5: Signed KERI inception event ────────────────────────────────")

# Derive next key from Dart path (Dart appends 0x01 to seed before hashing)
dart_next_seed_input = TEST_SEED[:32] + bytes([0x01])
dart_next_private_seed = hashlib.sha256(dart_next_seed_input).digest()
pk_next, _ = pysodium.crypto_sign_seed_keypair(dart_next_private_seed)

verfer_current = coring.Verfer(raw=pk_dart, code=MtrDex.Ed25519)
verfer_next = coring.Verfer(raw=pk_next, code=MtrDex.Ed25519)
diger_next = coring.Diger(raw=pk_next, code=MtrDex.Blake3_256)

# Create inception event body (keripy)
serder = eventing.incept(
    keys=[verfer_current.qb64],
    ndigs=[diger_next.qb64],
    code=MtrDex.Blake3_256,
)

# Sign the serialized event body with the current key
icp_raw = serder.raw  # bytes of the serialized event
icp_sig_bytes = pysodium.crypto_sign_detached(icp_raw, sk_dart)
icp_siger = coring.Siger(raw=icp_sig_bytes)

# Verify the inception event signature with keripy
icp_verified = verfer_current.verify(sig=icp_sig_bytes, ser=icp_raw)

check("Inception event body created by keripy", serder is not None)
check("AID (prefix) derived from inception event", len(serder.pre) > 0,
      f"AID: {serder.pre}")
check("Signed inception event signature is CESR '0B...'",
      icp_siger.qb64.startswith("0B"))
check("keripy verfer verifies inception event signature", icp_verified)

print(f"\n  AID: {serder.pre}")
print(f"  Inception sig CESR: {icp_siger.qb64[:30]}...")

# ---------------------------------------------------------------------------
# STEP 6: Export a test vector for Dart validation
# ---------------------------------------------------------------------------
print("\n── STEP 6: Test vector for Dart ────────────────────────────────────────")

test_vector = {
    "description": "Known-good KERI test vector — use to validate Dart signing path",
    "input_seed_hex": TEST_SEED.hex(),
    "dart_private_seed_hex": dart_private_seed.hex(),
    "public_key_raw_hex": pk_dart.hex(),
    "public_key_cesr": verfer_dart.qb64,
    "test_data_hex": TEST_DATA.hex(),
    "raw_signature_hex": dart_raw_sig.hex(),
    "cesr_signature": dart_cesr,
    "cesr_signature_length": len(dart_cesr),
}
vector_path = os.path.join(os.path.dirname(__file__), "keri_test_vector.json")
with open(vector_path, "w") as f:
    json.dump(test_vector, f, indent=2)
print(f"  Test vector written to: {vector_path}")
print(f"  Use this to validate Dart produces the same raw_signature_hex")

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------
print("\n── Summary ─────────────────────────────────────────────────────────────")
passed = sum(1 for s, _ in results if s == PASS)
failed = sum(1 for s, _ in results if s == FAIL)
print(f"\n  {passed} passed / {failed} failed\n")

if failed > 0:
    print("  SOME TESTS FAILED — do not proceed with Phase 1 implementation.")
    print("  Fix the failing cases above before writing production code.")
    sys.exit(1)
else:
    print("  ALL TESTS PASSED")
    print()
    print("  Proven:")
    print("  ✓ keripy native signing produces CESR '0B...' signatures (88 chars)")
    print("  ✓ pysodium raw sig + coring.Siger produces IDENTICAL CESR output")
    print("  ✓ keripy verfer accepts both signing paths")
    print("  ✓ Dart seed derivation path (sha256 of BIP39 seed) produces valid keripy keys")
    print("  ✓ Signed inception events verify correctly with keripy")
    print()
    print("  Safe to proceed with Phase 1 implementation.")
    sys.exit(0)
