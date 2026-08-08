"""Run genuine and forged key logs through the driver's validator.

The two forgeries are the ones that mattered: an unsigned rotation, and a signed
rotation revealing a key the previous event never committed to. Both were
accepted before this was checked, and either one takes over an identity.

Needs keripy:  python3 -m venv v && v/bin/pip install keri==1.1.17
Then:          v/bin/python3 tests/make_kel_cases.py > tests/kel_cases.json
               v/bin/python3 tests/check_kel_validation.py
"""
import os
import json, sys, re, types
src = open(os.path.join(os.path.dirname(__file__), "..", "server.py")).read()
# Pull just the validator and its helpers out of the Flask app so we can call it.
mod = types.ModuleType("drv")
mod.__dict__["json"] = json
import base64 as _b64; mod.__dict__["base64"] = _b64
exec("from keri.core import coring, serdering, eventing\nfrom keri.core.coring import MtrDex\n", mod.__dict__)
for fn in ("_b64url_decode", "_extract_raw_key", "_derive_aid_from_inception", "_check_aid_binding", "_wits_of_event", "_validate_kel_events"):
    m = re.search(r"^def %s\(.*?(?=^@app\.|^def |\Z)" % fn, src, re.S | re.M)
    if m: exec(m.group(0), mod.__dict__)

failures = []
data = json.load(open(os.path.join(os.path.dirname(__file__), "kel_cases.json")))
for name, events in data["cases"].items():
    r = mod._validate_kel_events(events, data["aid"])
    verdict = "ACCEPTED" if r["kel_verified"] else "REFUSED"
    print("%-52s %s  (validated %d)" % (name[:52], verdict, r["events_validated"]))
    for e in r["validation_errors"][:2]:
        print("      %s" % e)
    expect_ok = name.startswith("genuine")
    if r["kel_verified"] != expect_ok:
        failures.append(name)

if failures:
    raise SystemExit("KEL validation is wrong for: %s" % ", ".join(failures))
print("\nAll cases behaved as required.")
