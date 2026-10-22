#!/usr/bin/env python3
"""An independent check of signing-vectors.json, written without Go.

ADR-049's form, rebuilt from its text: every field (keys included) a string of
printable ASCII, the "signature" field left out, keys sorted by byte value, no
whitespace. Python's json.dumps with ensure_ascii and these separators then
writes exactly the bytes Go writes: for printable ASCII the only escapes are \\"
and \\\\, and "/" is not escaped. If this script and relayproto ever disagree,
the form is not what the ADR says it is.

Run: python3 check_signing_vectors.py [path-to-signing-vectors.json]
"""
import json
import os
import sys


def printable_ascii(s):
    return isinstance(s, str) and all(0x20 <= ord(c) <= 0x7E for c in s)


def canonical_body(fields):
    out = {}
    for k, v in fields.items():
        if k == "signature":
            continue
        if not printable_ascii(k) or not printable_ascii(v):
            raise ValueError("every signed field is a string of printable ASCII; %r is not" % k)
        out[k] = v
    return json.dumps(out, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def main():
    path = sys.argv[1] if len(sys.argv) > 1 else os.path.join(os.path.dirname(__file__), "signing-vectors.json")
    with open(path) as f:
        data = json.load(f)
    failures = 0
    for v in data["vectors"]:
        got = canonical_body(v["fields"])
        if got != v["canonical"]:
            print("MISMATCH %s:\n  python %s\n  file   %s" % (v["name"], got, v["canonical"]))
            failures += 1
    for r in data["refused"]:
        try:
            canonical_body(r["fields"])
        except ValueError:
            continue
        print("NOT REFUSED %s" % r["name"])
        failures += 1
    if failures:
        sys.exit(1)
    print("ok: %d vectors, %d refused" % (len(data["vectors"]), len(data["refused"])))


if __name__ == "__main__":
    main()
