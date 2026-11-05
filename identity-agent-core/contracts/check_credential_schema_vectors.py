"""Independent check of the credential schema vectors.

Written from the rule in schemas/credential-schema-vectors.json, not from the Go
code: a schema's identifier is the Blake3-256 digest of the schema document with
its "$id" replaced by 44 '#' characters, written as the CESR code "E" followed
by the URL-safe base64 of the digest (the digest is prefixed with one zero byte
so the 33 bytes encode to 44 characters, of which the first is dropped for the
code). The document is serialised compactly, keys in the order written, with no
HTML escaping.

Accepted vectors: the published file must carry exactly the identifier given,
must digest to it, and the retired placeholder must not be it.
Refused vectors: the document must not digest to the identifier claimed.

Needs the blake3 module (pip install blake3).
Usage: check_credential_schema_vectors.py credential-schema-vectors.json
"""
import base64
import json
import os
import sys

import blake3

failures = []


def fail(what):
    failures.append(what)
    print("FAIL:", what, file=sys.stderr)


def said_of(raw):
    doc = json.loads(raw, object_pairs_hook=lambda pairs: dict(pairs))
    if "$id" not in doc:
        return None
    doc["$id"] = "#" * 44
    compact = json.dumps(doc, separators=(",", ":"), ensure_ascii=False).encode()
    digest = blake3.blake3(compact).digest()
    return "E" + base64.urlsafe_b64encode(b"\x00" + digest).decode()[1:]


def carried_id(raw):
    return json.loads(raw).get("$id")


def main():
    if len(sys.argv) != 2:
        sys.exit(__doc__)
    vectors = sys.argv[1]
    with open(vectors) as f:
        v = json.load(f)
    contracts = os.path.join(os.path.dirname(os.path.abspath(__file__)), "credential-schemas")
    n = 0
    for a in v["accepted"]:
        n += 1
        with open(os.path.join(contracts, a["file"]), "rb") as f:
            raw = f.read()
        if carried_id(raw) != a["said"]:
            fail("%s carries %s, not %s" % (a["name"], carried_id(raw), a["said"]))
        if said_of(raw) != a["said"]:
            fail("%s digests to %s, not %s" % (a["name"], said_of(raw), a["said"]))
        if a["said"] == a["retired_placeholder"] or "placeholder" in a["said"]:
            fail("%s is identified by a placeholder" % a["name"])
    for r in v["refused"]:
        n += 1
        raw = r["document"].encode()
        if said_of(raw) == r["claimed_said"]:
            fail("%s: the document digests to the identifier it claims" % r["name"])
        elif carried_id(raw) == r["claimed_said"] and said_of(raw) == r["claimed_said"]:
            fail("%s: accepted" % r["name"])
    if failures:
        sys.exit(1)
    print("ok: %d vectors" % n)


if __name__ == "__main__":
    main()
