#!/usr/bin/env python3
"""An independent check of app-request-vectors.json, written without Go.

Everything is rebuilt from app-request/app-request.md: the string an app's back
end signs, the order the Identity Agent reads a request in, and the Ed25519
signature on each vector. The digest encoding and the Ed25519 verifier are the
ones check_ai_agent_vectors.py already holds, imported rather than copied.

Run: python3 -I check_app_request_vectors.py <app-request-vectors.json>
Needs the blake3 module (pip install blake3).
"""
import datetime
import importlib.util
import json
import os
import re
import sys

here = os.path.dirname(os.path.abspath(__file__))
spec = importlib.util.spec_from_file_location("agent_vectors", os.path.join(here, "check_ai_agent_vectors.py"))
base = importlib.util.module_from_spec(spec)
spec.loader.exec_module(base)

failures = []


def fail(what):
    failures.append(what)
    print("MISMATCH " + what)


WINDOW = 120  # seconds either side of the Identity Agent's clock
MIN_NONCE = 16

RFC3339 = re.compile(r"([0-9]{4})-([0-9]{2})-([0-9]{2})T([0-9]{2}):([0-9]{2}):([0-9]{2})(?:[.,][0-9]+)?(Z|[+-][0-9]{2}:[0-9]{2})", re.ASCII)


def when(text):
    """RFC 3339 as a UTC datetime, or None."""
    m = RFC3339.fullmatch(text)
    if not m:
        return None
    try:
        t = datetime.datetime.fromisoformat(text.replace(",", ".").replace("Z", "+00:00"))
    except ValueError:
        return None
    return t.astimezone(datetime.timezone.utc)


def signed_string(r):
    """IA-BODY-REQ-V3: eleven lines, the body's digest on the eighth."""
    return "\n".join(["IA-BODY-REQ-V3", r["for"], r["host"], r["method"].upper(), r["target"], r["timestamp"], r["nonce"],
                      base.digest(bytes.fromhex(r["body_hex"])), r["work_item"], r["reason"], r["session"]])


def lapsed(until, now):
    if until == "":
        return False
    t = when(until)
    return t is None or now >= t


def check(v, set_):
    """Admitted, with the string signed, or the first reason it is refused."""
    r, a = v["request"], v["admission"]
    now = when(set_["now"])
    if r["for"] == "":
        return None, "names_no_identity_agent"
    if r["for"] != set_["identity_agent"]:
        return None, "other_identity_agent"
    t = when(r["timestamp"])
    if t is None:
        return None, "unreadable_time"
    if abs((now - t).total_seconds()) > WINDOW:
        return None, "outside_window"
    if len(r["nonce"].encode()) < MIN_NONCE:
        return None, "bad_nonce"
    if r["host"] != a["body_host"]:
        return None, "key_is_not_the_app_bodys"
    msg = signed_string(r).encode()
    try:
        pub = base.qb64_raw("D", a["body_verkey"], 32)
        if base.qb64_raw("B", r["host"], 32) != pub:
            raise ValueError("the identifier and the key are not one key")
        sig = base.qb64_raw("0B", r["signature"], 64)
        ok = base.ed25519_verify(pub, sig, msg)
    except ValueError:
        ok = False
    if not ok:
        return None, "bad_signature"
    if lapsed(a["body_valid_until"], now):
        return None, "app_body_lapsed"
    if lapsed(a["grant_valid_until"], now):
        return None, "app_grant_lapsed"
    if a["capability_the_route_needs"] not in a["grant_capabilities"]:
        return None, "capability_not_held"
    limits, given = a.get("grant_constraints", {}), a.get("route_arguments", {})
    for arg in sorted(limits):
        if arg not in given:
            return None, "limit_the_route_cannot_check"
        if given[arg] not in limits[arg]:
            return None, "outside_the_grants_limit"
    return msg.decode(), None


def main():
    set_ = json.load(open(sys.argv[1]))
    for v in set_["vectors"]:
        signed, why = check(v, set_)
        if why is None:
            if v.get("signed") != signed:
                fail("%s: python admits it with %r, the file says signed %r, refused %r" % (v["name"], signed, v.get("signed"), v.get("refused")))
        elif v.get("refused") != why or v.get("signed"):
            fail("%s: python refuses it for %s, the file says signed %r, refused %r" % (v["name"], why, v.get("signed"), v.get("refused")))
    if failures:
        sys.exit(1)
    print("app-request-vectors.json: %d vectors agree" % len(set_["vectors"]))


main()
