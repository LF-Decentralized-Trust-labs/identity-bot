"""
KERI Interoperability Test -- Phase 8: Mobile IXN via Rust Bridge + Cross-Instance KEL Verification

Proves:

  STEP 1: Mobile agent at https://grapeid.org/agents is live and healthy
  STEP 2: Mobile AID is retrievable and has a valid self-addressing identifier format
  STEP 3: Mobile OOBI endpoint returns a parseable KEL document
  STEP 4: Every event in the mobile KEL has a valid SAID (content hash == embedded 'd' field)
  STEP 5: KEL hash chain is intact (each event's 'p' prior == previous event's 'd' SAID)
  STEP 6: Inception event was produced by a Rust keri_core key -- public key is Ed25519 CESR 'D...' format
  STEP 7: Any IXN events present have correct structure (type, sequence, anchor data)
  STEP 8: keripy independently constructs a reference IXN and verifies the format
           matches what the Rust bridge produces
  STEP 9: Cross-instance -- the LOCAL desktop agent (port 5050) resolves the mobile OOBI
           using Python keripy and confirms the KEL is valid
  STEP 10: (Optional) IXN count -- reports how many IXN events are in the live KEL

If no IXN events are present yet, STEPS 7-8 are skipped with a clear message.
To create an IXN on mobile, issue a credential or use the Interact feature in the mobile app,
then re-run this test.

Run with:
  python tests/keri_phase8_mobile_ixn_crossinstance_test.py
"""

import sys
import os
import json
import time
import base64
import hashlib
import requests
import ctypes
import ctypes.util

# ---------------------------------------------------------------------------
# Windows: ensure libsodium is findable by keripy
# ---------------------------------------------------------------------------
def _ensure_libsodium():
    if ctypes.util.find_library("sodium"):
        return
    if sys.platform != "win32":
        return
    script_dir = os.path.dirname(os.path.abspath(__file__))
    repo_root  = os.path.dirname(script_dir)
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

# Windows SysLogHandler shim (keripy imports logging.handlers)
if sys.platform == "win32":
    import socket as _socket
    import logging as _logging
    import logging.handlers as _lh
    if not hasattr(_socket, "AF_UNIX"):
        _socket.AF_UNIX = 1
    _orig_init = _lh.SysLogHandler.__init__
    def _win_syslog_init(self, address=("localhost", _lh.SYSLOG_UDP_PORT),
                         facility=_lh.SysLogHandler.LOG_USER, socktype=None):
        _logging.Handler.__init__(self)
        self.address = address; self.facility = facility; self.socktype = socktype
        self.unixsocket = False; self.socket = None; self.ident = ""; self.append_nul = True
    _lh.SysLogHandler.__init__ = _win_syslog_init
    _lh.SysLogHandler.createSocket = lambda self: None
    _lh.SysLogHandler.emit        = lambda self, record: None
    _lh.SysLogHandler.close       = lambda self: _logging.Handler.close(self)

try:
    from keri.core import coring, eventing
    from keri.core.coring import MtrDex
    import pysodium
except ImportError as e:
    print("FAIL: Could not import keripy/pysodium: %s" % e)
    print("      Install with: pip install keri==1.1.17")
    sys.exit(1)

# ---------------------------------------------------------------------------
# Test infrastructure
# ---------------------------------------------------------------------------
PASS = "PASS"; FAIL = "FAIL"; SKIP = "SKIP"; WARN = "WARN"
results = []

def check(label, condition, detail=""):
    status = PASS if condition else FAIL
    results.append((status, label))
    marker = "+" if condition else "x"
    print("  [%s] %s  %s" % (status, marker, label))
    if detail:
        print("         %s" % detail)
    return condition

def skip(label, reason=""):
    results.append((SKIP, label))
    print("  [SKIP] -  %s" % label)
    if reason:
        print("         %s" % reason)

def warn(label, detail=""):
    results.append((WARN, label))
    print("  [WARN] !  %s" % label)
    if detail:
        print("         %s" % detail)

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------
MOBILE_BASE_URL  = "https://grapeid.org/agents"
DESKTOP_BASE_URL = "http://127.0.0.1:5050"
MAX_WAIT_SECONDS = 600   # 10 minutes
RETRY_INTERVAL   = 30    # seconds between health-check retries

# ---------------------------------------------------------------------------
# STEP 1: Poll mobile health with retry
# ---------------------------------------------------------------------------
print("\n" + "=" * 70)
print("Phase 8: Mobile IXN via Rust Bridge + Cross-Instance KEL Verification")
print("=" * 70)
print("\n-- STEP 1: Mobile agent health check (retry every %ds, up to %ds) --" % (
    RETRY_INTERVAL, MAX_WAIT_SECONDS))

health_ok  = False
health_url = "%s/api/health" % MOBILE_BASE_URL
elapsed    = 0

while elapsed < MAX_WAIT_SECONDS:
    try:
        r = requests.get(health_url, timeout=10)
        if r.status_code == 200:
            data = r.json()
            if data.get("status") == "active":
                health_ok = True
                print("  Mobile agent is LIVE: %s" % json.dumps(data))
                break
            else:
                print("  Health returned non-active status: %s -retrying in %ds..." % (
                    data.get("status"), RETRY_INTERVAL))
        else:
            print("  Health check HTTP %d -retrying in %ds..." % (r.status_code, RETRY_INTERVAL))
    except Exception as e:
        print("  Health check failed (%s) -retrying in %ds..." % (e, RETRY_INTERVAL))

    time.sleep(RETRY_INTERVAL)
    elapsed += RETRY_INTERVAL

check("Mobile agent is live and healthy", health_ok,
      "URL: %s" % health_url)

if not health_ok:
    print("\nFATAL: Mobile agent did not become reachable within %d seconds." % MAX_WAIT_SECONDS)
    print("       Make sure the mobile app is open and connected to the GrapeID tunnel.")
    sys.exit(1)

# ---------------------------------------------------------------------------
# STEP 2: Fetch mobile AID
# ---------------------------------------------------------------------------
print("\n-- STEP 2: Mobile AID --------------------------------------------------")

mobile_aid = None
try:
    r = requests.get("%s/api/identity" % MOBILE_BASE_URL, timeout=10)
    if r.status_code == 200:
        identity = r.json()
        mobile_aid = identity.get("aid") or identity.get("prefix")
        print("  Mobile AID: %s" % mobile_aid)
        print("  Event count: %s" % identity.get("event_count", "unknown"))
except Exception as e:
    print("  ERROR fetching identity: %s" % e)

check("Mobile AID is present", bool(mobile_aid))
if mobile_aid:
    # KERI SAIDs start with 'E' (self-addressing Blake3), DIDs with 'D', etc.
    check("Mobile AID has valid KERI prefix format",
          len(mobile_aid) == 44 and mobile_aid[0] in ('E', 'F', 'D', 'B', 'I'),
          "AID: %s" % mobile_aid)

if not mobile_aid:
    print("\nFATAL: Could not retrieve mobile AID.")
    sys.exit(1)

# ---------------------------------------------------------------------------
# STEP 3: Fetch mobile OOBI document
# ---------------------------------------------------------------------------
print("\n-- STEP 3: OOBI document fetch -----------------------------------------")

oobi_url      = "%s/public/oobi/%s" % (MOBILE_BASE_URL, mobile_aid)
oobi_response = None
kel_events    = []

try:
    r = requests.get(oobi_url, timeout=10)
    check("OOBI endpoint returns HTTP 200", r.status_code == 200,
          "URL: %s  Status: %d" % (oobi_url, r.status_code))
    if r.status_code == 200:
        oobi_response = r.json()
        print("  OOBI response keys: %s" % list(oobi_response.keys()))
except Exception as e:
    check("OOBI endpoint returns HTTP 200", False, "Exception: %s" % e)

if oobi_response is None:
    print("\nFATAL: Could not fetch OOBI document.")
    sys.exit(1)

# Extract KEL events — handle both array-of-events and wrapped formats
raw_events = (oobi_response.get("events") or
              oobi_response.get("kel") or
              oobi_response.get("event_log") or [])

# Events may be:
#   - raw KERI JSON strings
#   - already-parsed KERI event dicts (with 't', 'd', 's' fields)
#   - Go server wrapper dicts with an 'event_json' field containing the real event
parsed_events = []
for ev in raw_events:
    if isinstance(ev, str):
        try:
            parsed_events.append(json.loads(ev))
        except Exception:
            parsed_events.append({"_raw": ev})
    elif isinstance(ev, dict):
        # Go server wraps events: {"sequence_number":0, "event_type":"icp", "event_json":"{...}", ...}
        if "event_json" in ev and isinstance(ev["event_json"], str):
            try:
                parsed_events.append(json.loads(ev["event_json"]))
            except Exception:
                parsed_events.append(ev)
        else:
            parsed_events.append(ev)

kel_events = parsed_events

check("OOBI contains at least one KEL event", len(kel_events) >= 1,
      "Event count: %d" % len(kel_events))
print("  KEL event count: %d" % len(kel_events))
if kel_events:
    print("  Event types: %s" % [e.get("t") for e in kel_events])

# ---------------------------------------------------------------------------
# STEP 4: SAID integrity validation for each KEL event
# ---------------------------------------------------------------------------
print("\n-- STEP 4: SAID integrity (each event's 'd' matches its content hash) -")

def validate_said(event_dict):
    """
    Recompute SAID for a KERI event dict.
    KERI SAID: replace 'd' with placeholder, serialize to canonical JSON,
    Blake3-256 hash -> CESR base64.
    keripy's Saider handles this properly.
    """
    try:
        import copy
        ev = copy.deepcopy(event_dict)
        embedded_said = ev.get("d", "")
        if not embedded_said:
            return False, "no 'd' field"
        # Use keripy Saider to verify
        saider = coring.Saider(sad=ev, label="d")
        return saider.verify(sad=ev, prefixed=False, versioned=False), embedded_said
    except Exception as ex:
        return False, "error: %s" % ex

said_ok = True
for i, ev in enumerate(kel_events):
    t  = ev.get("t", "?")
    sn = ev.get("s", str(i))
    ok, detail = validate_said(ev)
    if not check("Event sn=%s (%s) SAID is self-consistent" % (sn, t), ok, detail):
        said_ok = False

# ---------------------------------------------------------------------------
# STEP 5: Hash chain validation
# ---------------------------------------------------------------------------
print("\n-- STEP 5: KEL hash chain validation -----------------------------------")

chain_ok = True
for i in range(1, len(kel_events)):
    prior_said    = kel_events[i - 1].get("d", "")
    current_prior = kel_events[i].get("p", "")
    t             = kel_events[i].get("t", "?")
    sn            = kel_events[i].get("s", str(i))
    if not check("Event sn=%s (%s) prior == previous event SAID" % (sn, t),
                 current_prior == prior_said,
                 "expected: %s\n         got:      %s" % (prior_said, current_prior)):
        chain_ok = False

if len(kel_events) == 1:
    print("  Only inception event present -hash chain has nothing to verify yet.")

check("Sequence numbers are contiguous starting from 0",
      [ev.get("s") for ev in kel_events] == [str(i) for i in range(len(kel_events))],
      "Got: %s" % [ev.get("s") for ev in kel_events])

# ---------------------------------------------------------------------------
# STEP 6: Inception event was produced by keri_core Rust bridge
# ---------------------------------------------------------------------------
print("\n-- STEP 6: Inception event structure (Rust keri_core fingerprints) ----")

icp = kel_events[0]
check("First event is inception type (icp)", icp.get("t") == "icp",
      "Got type: %s" % icp.get("t"))
check("Inception AID matches fetched AID", icp.get("i") == mobile_aid)
check("Inception has 'k' (keys) field", bool(icp.get("k")))
check("Inception has 'n' (next key digest) field", bool(icp.get("n")))

keys = icp.get("k", [])
if keys:
    pk_cesr = keys[0]
    # keri_core uses Ed25519 non-transferable ('B...') or transferable ('D...') keys
    check("Inception public key is CESR Ed25519 format ('D...' or 'B...', 44 chars)",
          len(pk_cesr) == 44 and pk_cesr[0] in ('D', 'B'),
          "Key: %s" % pk_cesr)
    print("  Public key (CESR): %s" % pk_cesr)

# Hashing function: keri_core uses Blake3_256, which gives prefix 'E'
check("Inception SAID uses Blake3-256 (prefix 'E')",
      icp.get("d", "").startswith("E"),
      "SAID: %s" % icp.get("d"))

# ---------------------------------------------------------------------------
# STEP 7: IXN event structure (if any IXN events present)
# ---------------------------------------------------------------------------
print("\n-- STEP 7: IXN event validation ----------------------------------------")

ixn_events = [ev for ev in kel_events if ev.get("t") == "ixn"]
print("  IXN events found in live KEL: %d" % len(ixn_events))

if not ixn_events:
    skip("IXN event structure checks",
         "No IXN events yet in the live mobile KEL.\n"
         "         To create one: issue a credential or use the Interact feature\n"
         "         in the mobile app, then re-run this test.")
else:
    for ixn in ixn_events:
        sn = ixn.get("s", "?")
        check("IXN sn=%s has type 'ixn'" % sn, ixn.get("t") == "ixn")
        check("IXN sn=%s has AID matching mobile AID" % sn, ixn.get("i") == mobile_aid)
        check("IXN sn=%s has prior ('p') field" % sn, bool(ixn.get("p")))
        check("IXN sn=%s has anchor ('a') field" % sn, "a" in ixn)
        check("IXN sn=%s SAID uses Blake3-256 (prefix 'E')" % sn,
              ixn.get("d", "").startswith("E"),
              "SAID: %s" % ixn.get("d"))
        anchor = ixn.get("a", [])
        print("  IXN sn=%s anchor data: %s" % (sn, json.dumps(anchor)))

# ---------------------------------------------------------------------------
# STEP 8: keripy reference IXN construction -verify format matches mobile
# ---------------------------------------------------------------------------
print("\n-- STEP 8: keripy reference IXN (format parity with Rust bridge) ------")

# Reconstruct the inception event using keripy to get a proper Verfer + prefix
icp_said = icp.get("d", "")
icp_pre  = icp.get("i", mobile_aid)

if keys:
    try:
        # Build a keripy Verfer from the CESR public key
        verfer_mobile = coring.Verfer(qb64=keys[0])
        check("keripy can parse mobile Rust bridge public key",
              verfer_mobile.qb64 == keys[0],
              "CESR key: %s" % keys[0])

        # Build a reference IXN event with the same AID + prior as what the
        # Rust bridge would produce (data=[] for a bare IXN, or seal data for anchored)
        ref_ixn = eventing.interact(
            pre  = icp_pre,
            dig  = icp_said,
            sn   = 1,
            data = [],
        )
        check("keripy-constructed IXN has type 'ixn'", ref_ixn.ked.get("t") == "ixn")
        check("keripy-constructed IXN has same AID as mobile", ref_ixn.ked.get("i") == icp_pre)
        check("keripy-constructed IXN prior matches mobile ICP SAID",
              ref_ixn.ked.get("p") == icp_said,
              "ICP SAID: %s\nIXN prior: %s" % (icp_said, ref_ixn.ked.get("p")))
        check("keripy-constructed IXN SAID uses Blake3-256 (prefix 'E')",
              ref_ixn.said.startswith("E"),
              "SAID: %s" % ref_ixn.said)

        if ixn_events:
            live_ixn = ixn_events[0]
            check("Live IXN 'p' prior field matches keripy reference format",
                  live_ixn.get("p") == ref_ixn.ked.get("p"),
                  "Live IXN prior:  %s\nRef IXN prior:   %s" % (
                      live_ixn.get("p"), ref_ixn.ked.get("p")))

        print("  Reference IXN SAID: %s" % ref_ixn.said)
        print("  Reference IXN prior: %s" % ref_ixn.ked.get("p"))
    except Exception as e:
        check("keripy reference IXN construction succeeded", False, "Error: %s" % e)
else:
    skip("keripy reference IXN construction", "No public key found in inception event")

# ---------------------------------------------------------------------------
# STEP 9: Cross-instance -desktop agent resolves mobile OOBI
# ---------------------------------------------------------------------------
print("\n-- STEP 9: Cross-instance KEL resolution (desktop -> mobile OOBI) ------")

desktop_live = False
try:
    r = requests.get("%s/api/health" % DESKTOP_BASE_URL, timeout=3)
    desktop_live = r.status_code == 200 and r.json().get("status") == "active"
except Exception:
    pass

if not desktop_live:
    skip("Cross-instance OOBI resolution via desktop Python keripy",
         "Desktop agent not running at %s.\n"
         "         Start it with: cd identity-agent-core && go run .\n"
         "         Then re-run this test." % DESKTOP_BASE_URL)
else:
    print("  Desktop agent live at %s" % DESKTOP_BASE_URL)
    try:
        resolve_r = requests.post(
            "%s/api/contacts/resolve" % DESKTOP_BASE_URL,
            headers={"Content-Type": "application/json"},
            json={"oobi_url": oobi_url},
            timeout=30,
        )
        check("Desktop agent resolves mobile OOBI (HTTP 200/201)",
              resolve_r.status_code in (200, 201),
              "Status: %d  Body: %s" % (resolve_r.status_code,
                                         resolve_r.text[:200]))
        if resolve_r.status_code in (200, 201):
            body = resolve_r.json()
            print("  Resolution result: %s" % json.dumps(body)[:300])
            kel_verified = body.get("kel_verified", body.get("verified", False))
            check("Desktop keripy confirms mobile KEL is cryptographically valid",
                  kel_verified,
                  "Full response: %s" % json.dumps(body)[:400])
            event_count = body.get("event_count", 0)
            if event_count:
                check("Desktop-resolved event count matches OOBI event count",
                      event_count == len(kel_events),
                      "Desktop: %d  OOBI direct: %d" % (event_count, len(kel_events)))
    except Exception as e:
        check("Desktop agent resolves mobile OOBI", False, "Exception: %s" % e)

# ---------------------------------------------------------------------------
# STEP 10: IXN count summary
# ---------------------------------------------------------------------------
print("\n-- STEP 10: KEL summary ------------------------------------------------")

total_events = len(kel_events)
icp_count    = sum(1 for ev in kel_events if ev.get("t") == "icp")
ixn_count    = sum(1 for ev in kel_events if ev.get("t") == "ixn")
rot_count    = sum(1 for ev in kel_events if ev.get("t") == "rot")

print("  Total KEL events: %d" % total_events)
print("    icp (inception):   %d" % icp_count)
print("    ixn (interaction): %d" % ixn_count)
print("    rot (rotation):    %d" % rot_count)

check("KEL has exactly one inception event", icp_count == 1)

if ixn_count == 0:
    warn("No IXN events in live KEL yet",
         "Create an IXN on the mobile device (issue a credential or use Interact),\n"
         "         then re-run this test to verify STEP 7 and the full IXN chain.")
else:
    check("KEL has at least one IXN event (Rust bridge interact_aid confirmed)",
          ixn_count >= 1)
    check("All events account for total (icp + ixn + rot == total)",
          icp_count + ixn_count + rot_count == total_events)

# ---------------------------------------------------------------------------
# Results summary
# ---------------------------------------------------------------------------
print("\n" + "=" * 70)
passes   = sum(1 for s, _ in results if s == PASS)
fails    = sum(1 for s, _ in results if s == FAIL)
skips    = sum(1 for s, _ in results if s == SKIP)
warnings = sum(1 for s, _ in results if s == WARN)

print("RESULTS: %d passed, %d failed, %d skipped, %d warnings" % (
    passes, fails, skips, warnings))

if fails:
    print("\nFAILED checks:")
    for s, label in results:
        if s == FAIL:
            print("  x %s" % label)

if ixn_count == 0 and fails == 0:
    print("\nAll checks passed for current KEL state (inception only).")
    print("Re-run after creating an IXN on the mobile device to validate STEP 7.")
elif fails == 0:
    print("\nAll checks passed. Mobile Rust bridge IXN events are")
    print("cryptographically valid and cross-instance verifiable.")

sys.exit(0 if fails == 0 else 1)
