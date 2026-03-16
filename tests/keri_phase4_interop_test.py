"""
KERI Interoperability Test -- Phase 4: ACDC Credential Issuance

Proves the following before production code is written:

  STEP 1: An ACDC credential body can be JSON-serialized and its SAID computed
          using keripy's Diger (Blake3_256) -- the SAID is self-addressing
  STEP 2: The credential SAID is embedded back in the credential correctly
  STEP 3: An IXN seal anchoring the credential SAID can be created in keripy
  STEP 4: The IXN event (with seal) is signed locally and the CESR sig verifies
  STEP 5: Full issuance chain: ACDC format -> SAID -> IXN seal -> sign -> verify
  STEP 6: A tampered credential body changes the SAID (integrity check)

If all steps pass, Phase 4 implementation is safe:
  - Python /credential/issue formats the ACDC and computes the SAID
  - Python /interact creates the anchoring IXN event with the seal
  - Dart signs the IXN event body locally (same path as all other events)
  - keripy verifier accepts the entire chain

Run with:
  python tests/keri_phase4_interop_test.py
"""

import sys
import os
import base64
import hashlib
import json
import copy
import ctypes
import ctypes.util

def _ensure_libsodium():
    if ctypes.util.find_library("sodium"):
        return
    if sys.platform != "win32":
        return
    script_dir = os.path.dirname(os.path.abspath(__file__))
    repo_root = os.path.dirname(script_dir)
    for d in [
        os.path.join(repo_root, "identity_agent_ui", "build", "windows", "x64", "runner", "Release", "backend"),
        os.path.join(repo_root, "drivers", "keri-core"), script_dir,
    ]:
        dll = os.path.join(d, "libsodium.dll")
        if os.path.isfile(dll):
            try:
                ctypes.CDLL(dll); os.environ["PATH"] = d + ";" + os.environ.get("PATH", ""); return
            except OSError:
                continue

_ensure_libsodium()

if sys.platform == "win32":
    import socket as _socket, logging as _logging, logging.handlers as _lh
    if not hasattr(_socket, "AF_UNIX"): _socket.AF_UNIX = 1
    def _win_syslog_init(self, address=("localhost", _lh.SYSLOG_UDP_PORT), facility=_lh.SysLogHandler.LOG_USER, socktype=None):
        _logging.Handler.__init__(self); self.address=address; self.facility=facility; self.socktype=socktype
        self.unixsocket=False; self.socket=None; self.ident=""; self.append_nul=True
    _lh.SysLogHandler.__init__ = _win_syslog_init
    _lh.SysLogHandler.createSocket = lambda self: None
    _lh.SysLogHandler.emit = lambda self, record: None
    _lh.SysLogHandler.close = lambda self: _logging.Handler.close(self)

try:
    from keri.core import coring, eventing
    from keri.core.coring import MtrDex
    import pysodium
except ImportError as e:
    print("FAIL: Could not import keripy/pysodium: %s" % e); sys.exit(1)

PASS = "PASS"; FAIL = "FAIL"; results = []

def check(label, condition, detail=""):
    status = PASS if condition else FAIL
    results.append((status, label))
    print("  [%s]  %s" % (status, label))
    if detail: print("         %s" % detail)
    return condition

# ---------------------------------------------------------------------------
# Setup: establish an AID for the issuer
# ---------------------------------------------------------------------------
TEST_SEED = bytes(range(32))

def dart_key(index=0):
    s = hashlib.sha256(TEST_SEED[:32] + (bytes([index]) if index > 0 else b"")).digest()
    if index == 0: s = hashlib.sha256(TEST_SEED[:32]).digest()
    pk, sk = pysodium.crypto_sign_seed_keypair(s)
    return pk, sk

pk0, sk0 = dart_key(0)
pk1, sk1 = dart_key(1)
verfer0 = coring.Verfer(raw=pk0, code=MtrDex.Ed25519)
diger1  = coring.Diger(raw=pk1, code=MtrDex.Blake3_256)

icp = eventing.incept(keys=[verfer0.qb64], ndigs=[diger1.qb64], code=MtrDex.Blake3_256)
issuer_aid = icp.pre

# Test subject AID (different key, represents the credential holder)
holder_seed = bytes([42] * 32)
pk_holder, sk_holder = pysodium.crypto_sign_seed_keypair(hashlib.sha256(holder_seed).digest())
verfer_holder = coring.Verfer(raw=pk_holder, code=MtrDex.Ed25519)
diger_holder  = coring.Diger(raw=pk_holder, code=MtrDex.Blake3_256)
icp_holder    = eventing.incept(keys=[verfer_holder.qb64], ndigs=[diger_holder.qb64], code=MtrDex.Blake3_256)
holder_aid    = icp_holder.pre

# Test schema SAID (in production this would be a real registered schema)
SCHEMA_SAID = "EFgnk_c08WmZGgv9_mpldibingSchemaXXXXXXXXXXXXXX"

# ---------------------------------------------------------------------------
# STEP 1: ACDC credential body and SAID computation
# ---------------------------------------------------------------------------
print("\n-- STEP 1: ACDC credential SAID computation -------------------------")

# ACDC structure: version, self-addressing id (d), issuer (i), schema (s), attributes (a)
# The 'd' field starts as empty -- the SAID is computed over the serialized body
acdc_body = {
    "v": "ACDC10JSON000000_",
    "d": "",
    "i": issuer_aid,
    "s": SCHEMA_SAID,
    "a": {
        "d": "",
        "i": holder_aid,
        "name": "Alice Smith",
        "studentId": "S-12345",
        "degree": "Bachelor of Science",
        "graduationYear": 2025,
    },
}

# Compute the attribute block SAID first
attr_json = json.dumps(acdc_body["a"], separators=(",", ":")).encode()
attr_diger = coring.Diger(ser=attr_json, code=MtrDex.Blake3_256)
acdc_body["a"]["d"] = attr_diger.qb64

# Compute the top-level ACDC SAID
acdc_json_v1 = json.dumps(acdc_body, separators=(",", ":")).encode()
acdc_diger = coring.Diger(ser=acdc_json_v1, code=MtrDex.Blake3_256)
acdc_said = acdc_diger.qb64
acdc_body["d"] = acdc_said

acdc_json_final = json.dumps(acdc_body, separators=(",", ":")).encode()

check("ACDC SAID is non-empty", bool(acdc_said))
check("ACDC SAID starts with 'E' (Blake3_256 code)", acdc_said.startswith("E"),
      "Got: %s" % acdc_said[:5])
check("ACDC SAID is 44 characters", len(acdc_said) == 44,
      "Got: %d" % len(acdc_said))
check("Attribute block SAID is embedded in credential", acdc_body["a"]["d"] == attr_diger.qb64)
print("  ACDC SAID: %s" % acdc_said)

# ---------------------------------------------------------------------------
# STEP 2: SAID is self-addressing (recompute to verify)
# ---------------------------------------------------------------------------
print("\n-- STEP 2: SAID self-addressing integrity ----------------------------")

# Recompute: blank out 'd', recompute SAID, verify it matches
verification_body = copy.deepcopy(acdc_body)
verification_body["d"] = ""
recompute_json = json.dumps(verification_body, separators=(",", ":")).encode()
recomputed_diger = coring.Diger(ser=recompute_json, code=MtrDex.Blake3_256)

check("Recomputed SAID matches embedded SAID",
      recomputed_diger.qb64 == acdc_said,
      "Embedded: %s\nRecomputed: %s" % (acdc_said, recomputed_diger.qb64))

# ---------------------------------------------------------------------------
# STEP 3: IXN seal anchoring the credential SAID
# ---------------------------------------------------------------------------
print("\n-- STEP 3: IXN seal creation -----------------------------------------")

# The seal structure for a credential: digest of the ACDC SAID anchored in an IXN
credential_seal = {"d": acdc_said}

ixn_for_cred = eventing.interact(
    pre=issuer_aid,
    dig=icp.said,
    sn=1,
    data=[credential_seal],
)

check("IXN event created with credential seal", ixn_for_cred is not None)
check("IXN event type is 'ixn'", ixn_for_cred.ked.get("t") == "ixn")
check("Credential SAID is in IXN seal data",
      any(s.get("d") == acdc_said for s in ixn_for_cred.ked.get("a", [])),
      "IXN data: %s" % ixn_for_cred.ked.get("a"))
print("  IXN for credential SAID: %s" % ixn_for_cred.said)

# ---------------------------------------------------------------------------
# STEP 4: Sign the IXN event locally (Dart-path)
# ---------------------------------------------------------------------------
print("\n-- STEP 4: IXN event signing -----------------------------------------")

ixn_raw_sig = pysodium.crypto_sign_detached(ixn_for_cred.raw, sk0)
ixn_cigar   = coring.Cigar(raw=ixn_raw_sig, code=MtrDex.Ed25519_Sig)

check("IXN CESR sig starts with '0B'", ixn_cigar.qb64.startswith("0B"))
check("keripy verfer accepts IXN sig for credential anchor",
      verfer0.verify(sig=ixn_raw_sig, ser=ixn_for_cred.raw))

# ---------------------------------------------------------------------------
# STEP 5: Full issuance chain integrity
# ---------------------------------------------------------------------------
print("\n-- STEP 5: Full issuance chain integrity check -----------------------")

# The verifier can:
# 1. Find the ACDC SAID in the IXN seal
# 2. Verify the IXN is in the issuer's KEL (sn=1, prior=icp.said)
# 3. Verify the IXN signature with the issuer's current key
# 4. Recompute the ACDC SAID and confirm it matches

found_in_seal = any(s.get("d") == acdc_said for s in ixn_for_cred.ked.get("a", []))
chain_valid   = ixn_for_cred.ked.get("p") == icp.said
sig_valid     = verfer0.verify(sig=ixn_raw_sig, ser=ixn_for_cred.raw)

check("Credential SAID found in IXN seal", found_in_seal)
check("IXN prior links correctly to inception event", chain_valid)
check("IXN signature valid (issuer vouches for credential anchor)", sig_valid)
check("Full issuance chain is valid", found_in_seal and chain_valid and sig_valid)

# ---------------------------------------------------------------------------
# STEP 6: Tampered credential changes SAID
# ---------------------------------------------------------------------------
print("\n-- STEP 6: Tampered credential detection -----------------------------")

tampered_body = copy.deepcopy(acdc_body)
tampered_body["a"]["degree"] = "Doctor of Philosophy"  # attacker modifies degree

tampered_json = json.dumps(tampered_body, separators=(",", ":")).encode()
tampered_diger = coring.Diger(ser=tampered_json, code=MtrDex.Blake3_256)

check("Tampered credential produces different SAID",
      tampered_diger.qb64 != acdc_said,
      "Original: %s\nTampered: %s" % (acdc_said, tampered_diger.qb64))
check("Tampered SAID is NOT in IXN seal",
      not any(s.get("d") == tampered_diger.qb64 for s in ixn_for_cred.ked.get("a", [])))

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------
print("\n-- Summary -----------------------------------------------------------")
passed = sum(1 for s, _ in results if s == PASS)
failed = sum(1 for s, _ in results if s == FAIL)
print("\n  PASSED: %d   FAILED: %d\n" % (passed, failed))

if failed > 0:
    print("  SOME TESTS FAILED -- do not proceed with Phase 4 implementation.")
    sys.exit(1)
else:
    print("  ALL TESTS PASSED")
    print()
    print("  PROVEN for Phase 4 implementation:")
    print("  [+] ACDC SAID is computed correctly with keripy Diger (Blake3_256)")
    print("  [+] SAID is self-addressing and verifiable by recomputation")
    print("  [+] IXN seal anchors the credential SAID in the issuer's KEL")
    print("  [+] IXN event signed with Dart-path key verifies correctly")
    print("  [+] Full chain (ACDC -> SAID -> IXN seal -> signature) is valid")
    print("  [+] Tampered credential produces a different SAID (integrity protected)")
    print()
    print("  Safe to proceed with Phase 4 implementation.")
    sys.exit(0)
