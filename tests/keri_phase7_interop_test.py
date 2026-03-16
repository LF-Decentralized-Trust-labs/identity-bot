"""
KERI Interoperability Test -- Phase 7: KERL + Witness Receipts

Proves the following before production code is written:

  STEP 1: A witness receipt is structured as a CESR-encoded signature over an event SAID
  STEP 2: Multiple witness receipts can be accumulated for a single event
  STEP 3: A threshold check (n-of-m witnesses) is correct
  STEP 4: A receipt from a non-witness (untrusted AID) is excluded from threshold count
  STEP 5: A KERL (Key Event Receipt Log) entry combines the event + all valid receipts
  STEP 6: A tampered receipt (wrong event SAID) is detected

If all steps pass, Phase 7 implementation is safe.

Run with:
  python tests/keri_phase7_interop_test.py
"""

import sys
import os
import base64
import hashlib
import json
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
# Setup: controller + 5 witnesses
# ---------------------------------------------------------------------------
def make_witness(seed_bytes):
    pk, sk = pysodium.crypto_sign_seed_keypair(hashlib.sha256(seed_bytes).digest())
    pk1, _ = pysodium.crypto_sign_seed_keypair(hashlib.sha256(seed_bytes + b"\x01").digest())
    vf  = coring.Verfer(raw=pk, code=MtrDex.Ed25519)
    d1  = coring.Diger(raw=pk1, code=MtrDex.Blake3_256)
    icp = eventing.incept(keys=[vf.qb64], ndigs=[d1.qb64], code=MtrDex.Blake3_256)
    return icp.pre, pk, sk, vf

controller_aid, pk_c, sk_c, vf_c = make_witness(bytes(range(32)))
w1_aid, pk_w1, sk_w1, vf_w1 = make_witness(bytes([10]*32))
w2_aid, pk_w2, sk_w2, vf_w2 = make_witness(bytes([20]*32))
w3_aid, pk_w3, sk_w3, vf_w3 = make_witness(bytes([30]*32))
w4_aid, pk_w4, sk_w4, vf_w4 = make_witness(bytes([40]*32))
untrusted_aid, _, sk_u, vf_u = make_witness(bytes([99]*32))  # not in witness list

WITNESS_THRESHOLD = 3  # require 3-of-4 witnesses
TRUSTED_WITNESSES = {w1_aid, w2_aid, w3_aid, w4_aid}

# Build inception event for the controller
icp_c = eventing.incept(
    keys=[vf_c.qb64],
    ndigs=[coring.Diger(raw=pk_c, code=MtrDex.Blake3_256).qb64],
    code=MtrDex.Blake3_256,
)
event_said = icp_c.said

# ---------------------------------------------------------------------------
# STEP 1: Witness receipt structure
# ---------------------------------------------------------------------------
print("\n-- STEP 1: Witness receipt structure --------------------------------")

# A witness receipt: the witness signs the event SAID with their key
# CESR format: Cigar(raw=sig, code=MtrDex.Ed25519_Sig).qb64
def make_receipt(witness_sk, event_said_str):
    sig = pysodium.crypto_sign_detached(event_said_str.encode(), witness_sk)
    cigar = coring.Cigar(raw=sig, code=MtrDex.Ed25519_Sig)
    return sig, cigar.qb64

w1_sig, w1_cesr = make_receipt(sk_w1, event_said)
check("Witness receipt CESR starts with '0B'", w1_cesr.startswith("0B"))
check("Witness receipt CESR is 88 chars", len(w1_cesr) == 88)
check("Witness1 verfer accepts its own receipt sig",
      vf_w1.verify(sig=w1_sig, ser=event_said.encode()))
print("  Event SAID: %s" % event_said)
print("  W1 receipt: %s..." % w1_cesr[:30])

# ---------------------------------------------------------------------------
# STEP 2: Multiple witness receipts accumulate
# ---------------------------------------------------------------------------
print("\n-- STEP 2: Multiple witness receipt accumulation --------------------")

w2_sig, w2_cesr = make_receipt(sk_w2, event_said)
w3_sig, w3_cesr = make_receipt(sk_w3, event_said)
w4_sig, w4_cesr = make_receipt(sk_w4, event_said)
wu_sig, wu_cesr = make_receipt(sk_u, event_said)  # untrusted

receipts = [
    {"witness_aid": w1_aid, "cesr_sig": w1_cesr, "raw_sig": w1_sig, "verfer": vf_w1},
    {"witness_aid": w2_aid, "cesr_sig": w2_cesr, "raw_sig": w2_sig, "verfer": vf_w2},
    {"witness_aid": w3_aid, "cesr_sig": w3_cesr, "raw_sig": w3_sig, "verfer": vf_w3},
    {"witness_aid": w4_aid, "cesr_sig": w4_cesr, "raw_sig": w4_sig, "verfer": vf_w4},
    {"witness_aid": untrusted_aid, "cesr_sig": wu_cesr, "raw_sig": wu_sig, "verfer": vf_u},
]

check("4 trusted + 1 untrusted receipts accumulated", len(receipts) == 5)
for r in receipts[:4]:
    check("Receipt from %s...verifies" % r["witness_aid"][:12],
          r["verfer"].verify(sig=r["raw_sig"], ser=event_said.encode()))

# ---------------------------------------------------------------------------
# STEP 3: Threshold check (3-of-4 trusted witnesses)
# ---------------------------------------------------------------------------
print("\n-- STEP 3: Witness threshold check ----------------------------------")

def count_valid_receipts(receipts, trusted_set, event_said_str, threshold):
    valid_count = 0
    for r in receipts:
        if r["witness_aid"] not in trusted_set:
            continue  # ignore untrusted witnesses
        if r["verfer"].verify(sig=r["raw_sig"], ser=event_said_str.encode()):
            valid_count += 1
    return valid_count, valid_count >= threshold

valid_count, threshold_met = count_valid_receipts(receipts, TRUSTED_WITNESSES, event_said, WITNESS_THRESHOLD)
check("Valid receipt count is 4 (all trusted witnesses)", valid_count == 4,
      "Got: %d" % valid_count)
check("Threshold (3-of-4) is met with 4 valid receipts", threshold_met)

# Check that untrusted receipt is excluded from count
untrusted_count = sum(1 for r in receipts if r["witness_aid"] == untrusted_aid)
check("Untrusted receipt exists but is excluded from threshold count",
      untrusted_count == 1 and valid_count == 4)

# ---------------------------------------------------------------------------
# STEP 4: Threshold fails when too few receipts
# ---------------------------------------------------------------------------
print("\n-- STEP 4: Insufficient receipts fail threshold ---------------------")
only_2_receipts = receipts[:2]  # only 2 trusted receipts
count_2, threshold_2 = count_valid_receipts(only_2_receipts, TRUSTED_WITNESSES, event_said, WITNESS_THRESHOLD)
check("2 valid receipts do NOT meet threshold of 3", not threshold_2,
      "Valid: %d, Threshold: %d" % (count_2, WITNESS_THRESHOLD))

# ---------------------------------------------------------------------------
# STEP 5: KERL entry = event + receipts
# ---------------------------------------------------------------------------
print("\n-- STEP 5: KERL entry construction ----------------------------------")

kerl_entry = {
    "event_said": event_said,
    "event_type": icp_c.ked.get("t"),
    "sn": icp_c.ked.get("s"),
    "receipts": [
        {"witness_aid": r["witness_aid"], "cesr_sig": r["cesr_sig"]}
        for r in receipts if r["witness_aid"] in TRUSTED_WITNESSES
    ],
    "threshold_met": threshold_met,
}

check("KERL entry has event SAID", bool(kerl_entry["event_said"]))
check("KERL entry has 4 trusted receipts", len(kerl_entry["receipts"]) == 4)
check("KERL entry records threshold_met = True", kerl_entry["threshold_met"])

# ---------------------------------------------------------------------------
# STEP 6: Tampered receipt detection
# ---------------------------------------------------------------------------
print("\n-- STEP 6: Tampered receipt detection --------------------------------")

wrong_said = "EDIFFERENTEVENTXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX"[:44]
tampered_sig, _ = make_receipt(sk_w1, wrong_said)
check("Receipt over wrong event SAID is rejected by w1 verfer",
      not vf_w1.verify(sig=tampered_sig, ser=event_said.encode()))
check("That receipt verifies the wrong SAID it was actually signed over",
      vf_w1.verify(sig=tampered_sig, ser=wrong_said.encode()))

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------
print("\n-- Summary -----------------------------------------------------------")
passed = sum(1 for s, _ in results if s == PASS)
failed = sum(1 for s, _ in results if s == FAIL)
print("\n  PASSED: %d   FAILED: %d\n" % (passed, failed))
if failed > 0:
    print("  SOME TESTS FAILED -- do not proceed with Phase 7 implementation.")
    sys.exit(1)
else:
    print("  ALL TESTS PASSED")
    print()
    print("  PROVEN for Phase 7 implementation:")
    print("  [+] Witness receipts are CESR '0B...' sigs over the event SAID")
    print("  [+] Multiple receipts accumulate correctly")
    print("  [+] Threshold (n-of-m) correctly counts only trusted witnesses")
    print("  [+] Untrusted witness receipts are excluded from threshold")
    print("  [+] Insufficient receipts correctly fail threshold check")
    print("  [+] KERL entry structure combines event + receipts + threshold status")
    print("  [+] Tampered receipts (wrong event SAID) are detected")
    print()
    print("  Safe to proceed with Phase 7 implementation.")
    sys.exit(0)
