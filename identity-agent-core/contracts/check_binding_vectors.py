#!/usr/bin/env python3
"""An independent check of binding-vectors.json, written without Go.

A binding joins two identifiers to one record by ONE statement signed with BOTH keys
over the same bytes (ADR-080). Everything is rebuilt from the ADR: the string both keys
sign (the statement's fields in the order the ADR gives, as JSON with no spaces), the
rules that refuse a link, and the Ed25519 signature of each key. The Ed25519 verifier and
the qb64 reader are the ones check_ai_agent_vectors.py already holds, imported rather
than copied.

Run: python3 -I check_binding_vectors.py <binding-vectors.json>
Needs the blake3 module (pip install blake3), which that file imports.
"""
import importlib.util
import json
import os
import sys

here = os.path.dirname(os.path.abspath(__file__))
spec = importlib.util.spec_from_file_location("agent_vectors", os.path.join(here, "check_ai_agent_vectors.py"))
base = importlib.util.module_from_spec(spec)
spec.loader.exec_module(base)

ORDER = ("v", "org", "site", "record", "new", "invite", "role")


def signed_bytes(st):
    # Go writes < > & as < > &; none of them is in a vector, and a statement
    # holding one is not rebuilt here.
    return json.dumps({k: st[k] for k in ORDER}, separators=(",", ":"), ensure_ascii=False).encode()


def sig_ok(key, sig, msg):
    try:
        return base.ed25519_verify(base.qb64_raw("D", key, 32), base.qb64_raw("0B", sig, 64), msg)
    except ValueError:
        return False


def refusal(link, expect, keys):
    """The reason a link is refused, or None when it is accepted."""
    st = link["statement"]
    if st.get("v") != "BIND1":
        return "version"
    if st.get("role") not in ("person", "owner"):
        return "role"
    if not all(st.get(k) for k in ("org", "site", "record", "new", "invite")):
        return "incomplete"
    if st["record"] == st["new"]:
        return "same-identifier"
    if not (expect["Org"] and expect["Site"] and expect["Invite"]):
        return "not-told"
    if st["org"] != expect["Org"]:
        return "organisation"
    if st["site"] != expect["Site"]:
        return "site"
    if st["invite"] != expect["Invite"]:
        return "invite"
    msg = signed_bytes(st)
    for who, ident, key, sig in (("record-signature", st["record"], link["record_key"], link["record_sig"]),
                                 ("new-signature", st["new"], link["new_key"], link["new_sig"])):
        if not key or not sig:
            return "missing-signature"
        if key.strip() != key:
            return "key-form"
        try:
            base.qb64_raw("D", key, 32)
        except ValueError:
            return "key-form"
        if keys.get(ident) != key:
            return "key-not-of-identifier"
        if not sig_ok(key, sig, msg):
            return who
    return None


def main():
    doc = json.load(open(sys.argv[1]))
    bad = 0
    for v in doc["vectors"]:
        got = refusal(v["link"], v["expect"], v["keys"])
        if v["signed"] != signed_bytes(v["link"]["statement"]).decode():
            print("MISMATCH %s: the signed string\n  python %r\n  file   %r" % (v["name"], signed_bytes(v["link"]["statement"]).decode(), v["signed"]))
            bad += 1
        if (got is None) != v["valid"]:
            print("MISMATCH %s: python says %r, the file says valid=%s" % (v["name"], got, v["valid"]))
            bad += 1
        elif got is not None and v["rule"] != got:
            print("MISMATCH %s: python refuses by rule %r, the file says %r" % (v["name"], got, v["rule"]))
            bad += 1
    if bad:
        sys.exit(1)
    print("%d binding vectors agree" % len(doc["vectors"]))


main()
