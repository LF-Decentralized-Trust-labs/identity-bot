#!/usr/bin/env python3
"""An independent check of schemas/controller-grant-vectors.json, written
without Go and from the published schema files alone.

For each version of the Controller Grant it checks that the file in
contracts/asset-grants digests to the identifier the vectors give (Blake3-256 of
the document with "$id" replaced by 44 '#', as the CESR code "E" and the URL-safe
base64 of the digest behind a zero byte), then holds every case's attribute block
to the schema's own attribute definition: no attribute the schema does not
declare, every required attribute present, each value of its declared type, and
the const and enum it states. Whether a case is admitted must be what the file
says.

Run: python3 check_controller_grant_vectors.py controller-grant-vectors.json
Needs the blake3 module (pip install blake3).
"""
import base64
import json
import os
import sys

import blake3

HERE = os.path.dirname(os.path.abspath(__file__))
GRANTS = os.path.join(HERE, "asset-grants")
failures = []


def fail(what):
    failures.append(what)
    print("MISMATCH " + what)


def said_of(raw):
    doc = json.loads(raw, object_pairs_hook=lambda pairs: dict(pairs))
    doc["$id"] = "#" * 44
    compact = json.dumps(doc, separators=(",", ":"), ensure_ascii=False).encode()
    return "E" + base64.urlsafe_b64encode(b"\x00" + blake3.blake3(compact).digest()).decode()[1:]


def why_refused(block, attrs):
    declared = attrs["properties"]
    for k in block:
        if k not in declared:
            return "%s is not declared" % k
    for r in attrs["required"]:
        if r not in block:
            return "%s is required" % r
    for k, v in block.items():
        d = declared[k]
        if d.get("type") == "string" and not isinstance(v, str):
            return "%s is not a string" % k
        if "const" in d and v != d["const"]:
            return "%s is not %r" % (k, d["const"])
        if "enum" in d and v not in d["enum"]:
            return "%s is not one of %s" % (k, d["enum"])
    return None


def main():
    if len(sys.argv) != 2:
        sys.exit(__doc__)
    with open(sys.argv[1]) as f:
        v = json.load(f)
    attrs = {}
    for version, s in v["schemas"].items():
        with open(os.path.join(GRANTS, s["file"]), "rb") as f:
            raw = f.read()
        doc = json.loads(raw)
        if doc["$id"] != s["said"] or said_of(raw) != s["said"]:
            fail("%s carries %s and digests to %s, not %s" % (s["file"], doc["$id"], said_of(raw), s["said"]))
        if doc["version"] != version:
            fail("%s says it is version %s, not %s" % (s["file"], doc["version"], version))
        attrs[version] = doc["properties"]["a"]["oneOf"][1]
    for c in v["cases"]:
        why = why_refused(c["attributes"], attrs[c["version"]])
        if (why is None) != c["accepted"]:
            fail("%s: the file says accepted=%s, the schema says %s" % (c["name"], c["accepted"], why or "admitted"))
        elif why and c.get("because") and c["because"] not in why:
            fail("%s: refused because %s, not for %s" % (c["name"], why, c["because"]))
    if failures:
        sys.exit(1)
    print("ok: %d cases, %d schemas" % (len(v["cases"]), len(v["schemas"])))


main()
