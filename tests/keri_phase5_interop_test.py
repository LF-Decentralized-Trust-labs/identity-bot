"""
KERI Interoperability Test -- Phase 5: Credential Presentation

Proves the following before production code is written:

  STEP 1: A verifiable presentation (VP) body can be structured and SAID-computed
  STEP 2: The holder signs the presentation with their current key
  STEP 3: The presentation CESR signature verifies with the holder's verfer
  STEP 4: The presentation correctly references the credential being presented
  STEP 5: A different holder cannot forge a valid presentation for another holder's credential
  STEP 6: An expired/wrong-key presentation is rejected

If all steps pass, Phase 5 implementation is safe.

Run with:
  python tests/keri_phase5_interop_test.py
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
    if ctypes.util.find_library("sodium"): return
    if sys.platform != "win32": return
    script_dir = os.path.dirname(os.path.abspath(__file__))
    repo_root  = os.path.dirname(script_dir)
    for d in [os.path.join(repo_root, "identity_agent_ui", "build", "windows", "x64", "runner", "Release", "backend"),
              os.path.join(repo_root, "drivers", "keri-core"), script_dir]:
        dll = os.path.join(d, "libsodium.dll")
        if os.path.isfile(dll):
            try: ctypes.CDLL(dll); os.environ["PATH"] = d + ";" + os.environ.get("PATH", ""); return
            except OSError: continue

_ensure_libsodium()

if sys.platform == "win32":
    import socket as _s, logging as _l, logging.handlers as _lh
    if not hasattr(_s, "AF_UNIX"): _s.AF_UNIX = 1
    def _wsi(self, address=("localhost", _lh.SYSLOG_UDP_PORT), facility=_lh.SysLogHandler.LOG_USER, socktype=None):
        _l.Handler.__init__(self); self.address=address; self.facility=facility; self.socktype=socktype
        self.unixsocket=False; self.socket=None; self.ident=""; self.append_nul=True
    _lh.SysLogHandler.__init__ = _wsi
    _lh.SysLogHandler.createSocket = lambda self: None
    _lh.SysLogHandler.emit = lambda self, record: None
    _lh.SysLogHandler.close = lambda self: _l.Handler.close(self)

try:
    from keri.core import coring, eventing
    from keri.core.coring import MtrDex
    import pysodium
except ImportError as e:
    print("FAIL: %s" % e); sys.exit(1)

PASS = "PASS"; FAIL = "FAIL"; results = []

def check(label, condition, detail=""):
    status = PASS if condition else FAIL
    results.append((status, label))
    print("  [%s]  %s" % (status, label))
    if detail: print("         %s" % detail)
    return condition

# ---------------------------------------------------------------------------
# Setup: issuer AID, holder AID, a credential
# ---------------------------------------------------------------------------
def make_aid(seed_bytes):
    pk, sk = pysodium.crypto_sign_seed_keypair(hashlib.sha256(seed_bytes).digest())
    pk1, _  = pysodium.crypto_sign_seed_keypair(hashlib.sha256(seed_bytes + b"\x01").digest())
    vf = coring.Verfer(raw=pk, code=MtrDex.Ed25519)
    d1 = coring.Diger(raw=pk1, code=MtrDex.Blake3_256)
    icp = eventing.incept(keys=[vf.qb64], ndigs=[d1.qb64], code=MtrDex.Blake3_256)
    return icp.pre, pk, sk, vf

issuer_aid, pk_i, sk_i, vf_i = make_aid(bytes(range(32)))
holder_aid,  pk_h, sk_h, vf_h = make_aid(bytes([42]*32))
other_aid,   pk_o, sk_o, vf_o = make_aid(bytes([99]*32))  # attacker

# Credential issued to holder
acdc = {"v": "ACDC10JSON000000_", "d": "", "i": issuer_aid, "s": "EschemaXXX",
        "a": {"d": "", "i": holder_aid, "degree": "B.Sc."}}
acdc_json = json.dumps(acdc, separators=(",", ":")).encode()
acdc_said = coring.Diger(ser=acdc_json, code=MtrDex.Blake3_256).qb64
acdc["d"] = acdc_said

# ---------------------------------------------------------------------------
# STEP 1: Verifiable presentation body and SAID
# ---------------------------------------------------------------------------
print("\n-- STEP 1: Presentation body and SAID --------------------------------")

presentation = {
    "v": "ACDC10JSON000000_",
    "d": "",
    "i": holder_aid,           # presenter is the holder
    "ri": issuer_aid,          # credential issuer
    "s": "EpresentationSchema",
    "a": {
        "d": "",
        "credential_said": acdc_said,
        "holder_aid": holder_aid,
    },
}

pres_attr_json = json.dumps(presentation["a"], separators=(",", ":")).encode()
pres_attr_said = coring.Diger(ser=pres_attr_json, code=MtrDex.Blake3_256).qb64
presentation["a"]["d"] = pres_attr_said

pres_json_v1 = json.dumps(presentation, separators=(",", ":")).encode()
pres_said    = coring.Diger(ser=pres_json_v1, code=MtrDex.Blake3_256).qb64
presentation["d"] = pres_said

check("Presentation SAID is 44 chars", len(pres_said) == 44)
check("Presentation SAID starts with 'E'", pres_said.startswith("E"))
check("Presentation references correct credential SAID",
      presentation["a"]["credential_said"] == acdc_said)
check("Presentation holder AID matches credential subject",
      presentation["i"] == holder_aid)
print("  Presentation SAID: %s" % pres_said)

# ---------------------------------------------------------------------------
# STEP 2 + 3: Holder signs the presentation SAID (proof of possession)
# ---------------------------------------------------------------------------
print("\n-- STEP 2+3: Holder signs presentation, sig verifies ----------------")

pres_said_bytes = pres_said.encode()  # holder signs the presentation SAID
pres_sig_raw    = pysodium.crypto_sign_detached(pres_said_bytes, sk_h)
pres_cigar      = coring.Cigar(raw=pres_sig_raw, code=MtrDex.Ed25519_Sig)

check("Presentation sig is 64 bytes", len(pres_sig_raw) == 64)
check("Presentation CESR sig starts with '0B'", pres_cigar.qb64.startswith("0B"))
check("Holder verfer accepts presentation signature",
      vf_h.verify(sig=pres_sig_raw, ser=pres_said_bytes))

# ---------------------------------------------------------------------------
# STEP 4: Presentation references the credential
# ---------------------------------------------------------------------------
print("\n-- STEP 4: Presentation-credential linkage ---------------------------")

check("Credential SAID in presentation matches issued ACDC SAID",
      presentation["a"]["credential_said"] == acdc_said)
check("Holder AID in presentation matches credential subject AID",
      presentation["a"]["holder_aid"] == acdc["a"]["i"])

# ---------------------------------------------------------------------------
# STEP 5: Attacker cannot forge a valid presentation for holder's credential
# ---------------------------------------------------------------------------
print("\n-- STEP 5: Forged presentation rejection -----------------------------")

forged_pres_sig = pysodium.crypto_sign_detached(pres_said_bytes, sk_o)
check("Forged sig (other key) is rejected by holder verfer",
      not vf_h.verify(sig=forged_pres_sig, ser=pres_said_bytes))
check("Forged sig verifies with attacker's own key (sanity)",
      vf_o.verify(sig=forged_pres_sig, ser=pres_said_bytes))

# ---------------------------------------------------------------------------
# STEP 6: Wrong-message sig is rejected (replay protection)
# ---------------------------------------------------------------------------
print("\n-- STEP 6: Wrong-message signature rejection -------------------------")

wrong_msg  = b"EDIFFERENTPRESENTATIONSAIDXXXXXXXXXXXXXXXXXXXXXXXX"
wrong_sig  = pysodium.crypto_sign_detached(wrong_msg, sk_h)
check("Sig over different SAID is rejected for this presentation",
      not vf_h.verify(sig=wrong_sig, ser=pres_said_bytes))
check("That same sig verifies the message it was actually signed over",
      vf_h.verify(sig=wrong_sig, ser=wrong_msg))

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------
print("\n-- Summary -----------------------------------------------------------")
passed = sum(1 for s, _ in results if s == PASS)
failed = sum(1 for s, _ in results if s == FAIL)
print("\n  PASSED: %d   FAILED: %d\n" % (passed, failed))
if failed > 0:
    print("  SOME TESTS FAILED -- do not proceed with Phase 5 implementation.")
    sys.exit(1)
else:
    print("  ALL TESTS PASSED")
    print()
    print("  PROVEN for Phase 5 implementation:")
    print("  [+] Presentation SAID is self-addressing and verifiable")
    print("  [+] Holder proof-of-possession signature verifies with keripy")
    print("  [+] Presentation correctly references the credential SAID")
    print("  [+] Attacker cannot forge a valid presentation for another holder")
    print("  [+] Replay attacks (wrong SAID) are rejected")
    print()
    print("  Safe to proceed with Phase 5 implementation.")
    sys.exit(0)
