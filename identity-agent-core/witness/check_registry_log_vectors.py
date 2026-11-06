#!/usr/bin/env python3
"""An independent check of registry-log-vectors.json, written without Go.

Built from SEAM-13 §2 as the vectors' own 'about' states it, not from the Go
checker. A conforming answer to GET /witness/tel/{aid} is an object with exactly
aid, registry_prefix, events, anchored_sn, latest_kel_sn, and registries only
when the issuer has two or more registries (registry_prefix is the first). Each
event is a KERI event: vcp (names itself in i, one of the answer's registries),
iss or rev (ri names one of them, dt present, a rev carries p). anchored_sn never
exceeds latest_kel_sn. A head is exactly anchored_sn, latest_kel_sn, event_digest.

Run: python3 check_registry_log_vectors.py [file]   (exit 1 on any disagreement)
"""
import json
import os
import sys


def is_int(x):
    return isinstance(x, int) and not isinstance(x, bool)


def answer_problem(a):
    if not isinstance(a, dict):
        return "not an object"
    required = {"aid", "registry_prefix", "events", "anchored_sn", "latest_kel_sn"}
    missing = required - set(a)
    if missing:
        return "missing " + ", ".join(sorted(missing))
    extra = set(a) - required - {"registries"}
    if extra:
        return "extra " + ", ".join(sorted(extra))
    if not (isinstance(a["aid"], str) and a["aid"] and isinstance(a["registry_prefix"], str) and a["registry_prefix"]):
        return "aid and registry_prefix are non-empty strings"
    if not (is_int(a["anchored_sn"]) and is_int(a["latest_kel_sn"]) and a["anchored_sn"] >= -1 and a["latest_kel_sn"] >= 0):
        return "sequence numbers are whole numbers"
    if a["anchored_sn"] > a["latest_kel_sn"]:
        return "anchored_sn above latest_kel_sn"
    names = {a["registry_prefix"]}
    if "registries" in a:
        r = a["registries"]
        if not isinstance(r, list) or len(r) < 2 or not all(isinstance(x, str) for x in r):
            return "registries only with two or more"
        if r[0] != a["registry_prefix"]:
            return "registry_prefix is not the first registry"
        names |= set(r)
    if not isinstance(a["events"], list):
        return "events is not an array"
    for i, e in enumerate(a["events"]):
        if not isinstance(e, dict) or not e.get("d") or not e.get("i"):
            return "event %d is not a KERI event" % i
        t = e.get("t")
        if t == "vcp":
            if e["i"] != e["d"] or e["i"] not in names:
                return "event %d: vcp must name itself and a registry of the answer" % i
        elif t in ("iss", "rev"):
            if e.get("ri") not in names:
                return "event %d: ri is not a registry of the answer" % i
            if "dt" not in e:
                return "event %d: no dt" % i
            if t == "rev" and "p" not in e:
                return "event %d: a rev carries p" % i
        else:
            return "event %d: t is %r" % (i, t)
    return None


def head_problem(h):
    if not isinstance(h, dict) or set(h) != {"anchored_sn", "latest_kel_sn", "event_digest"}:
        return "wrong fields"
    if not (is_int(h["anchored_sn"]) and is_int(h["latest_kel_sn"]) and isinstance(h["event_digest"], str) and h["event_digest"]):
        return "wrong types"
    return None


def main():
    path = sys.argv[1] if len(sys.argv) > 1 else os.path.join(os.path.dirname(os.path.abspath(__file__)), "registry-log-vectors.json")
    with open(path) as f:
        v = json.load(f)
    bad = 0
    for a in v["answers"]:
        problem = answer_problem(a["answer"])
        if (problem is None) != a["conforms"]:
            bad += 1
            print("DISAGREE %s: conforms=%s, I find %s" % (a["name"], a["conforms"], problem))
    for h in v["heads"]:
        problem = head_problem(h["head"])
        if (problem is None) != h["conforms"]:
            bad += 1
            print("DISAGREE %s: conforms=%s, I find %s" % (h["name"], h["conforms"], problem))
    if v["no_tel"] != {"status": 404, "body": {"error": "no_tel"}}:
        bad += 1
        print("DISAGREE no_tel")
    print("%d answers, %d heads: %s" % (len(v["answers"]), len(v["heads"]), "all agree" if not bad else "%d disagree" % bad))
    sys.exit(1 if bad else 0)


main()
