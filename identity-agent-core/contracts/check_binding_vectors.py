#!/usr/bin/env python3
"""An independent check of binding-vectors.json, written without Go.

A binding joins two identifiers to one record by ONE statement signed with BOTH keys
over the same bytes (ADR-082). Everything is rebuilt from the ADR: the string both keys
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
import re
import sys

here = os.path.dirname(os.path.abspath(__file__))
spec = importlib.util.spec_from_file_location("agent_vectors", os.path.join(here, "check_ai_agent_vectors.py"))
base = importlib.util.module_from_spec(spec)
spec.loader.exec_module(base)

ORDER = ("v", "org", "site", "record", "new", "invite", "role")


IDENT = re.compile(r"^[A-Za-z0-9_-]{1,128}$")


def signed_bytes(st):
    # Every field of an accepted statement is plain ASCII (IDENT, or a fixed literal), so no writer escapes
    # anything and these bytes are the ones any implementation writes. A statement with some other character
    # is refused before it is signed over, so its bytes are not compared.
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
    if not all(IDENT.match(st[k]) for k in ("org", "site", "record", "new", "invite")):
        return "identifier-form"
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
    raws = []
    for key, sig in ((link["record_key"], link["record_sig"]), (link["new_key"], link["new_sig"])):
        if not key or not sig:
            return "missing-signature"
        try:
            raws.append(base.qb64_raw("D", key, 32))  # the one spelling of a key: qb64, code D, canonical
        except ValueError:
            return "key-form"
    if raws[0] == raws[1]:
        return "same-key"
    msg = signed_bytes(st)
    for who, ident, key, sig in (("record-signature", st["record"], link["record_key"], link["record_sig"]),
                                 ("new-signature", st["new"], link["new_key"], link["new_sig"])):
        if keys.get(ident) != key:
            return "key-not-of-identifier"
        if not sig_ok(key, sig, msg):
            return who
    return None


INVITE_ORDER = ("v", "org", "site", "record_site", "role", "invite", "redeem_url", "org_name_sha256", "site_name_sha256")
URL = re.compile(r"^https?://[A-Za-z0-9._~:/%-]{1,500}$")
HEX = re.compile(r"^[0-9a-f]{64}$")


def invite_form(i):
    """The form an organization signs, built from its inputs: the two names go in as the SHA-256 of their UTF-8 bytes."""
    import hashlib
    return {"v": "ORGASK1", "org": i["org"], "site": i["site"], "record_site": i["record_site"], "role": i["role"],
            "invite": i["invite"], "redeem_url": i["redeem_url"],
            "org_name_sha256": hashlib.sha256(i["org_name"].encode("utf-8")).hexdigest(),
            "site_name_sha256": hashlib.sha256(i["site_name"].encode("utf-8")).hexdigest()}


def invite_refusal(v):
    f = invite_form(v["inputs"])
    if f["role"] not in ("person", "owner") or not all(IDENT.match(f[k]) for k in ("org", "site", "record_site", "invite")) \
            or not URL.match(f["redeem_url"]) or not (HEX.match(f["org_name_sha256"]) and HEX.match(f["site_name_sha256"])):
        return "form"
    # ASCII only, so no writer escapes anything.
    signed = json.dumps({k: f[k] for k in INVITE_ORDER}, separators=(",", ":")).encode()
    if v["signed"] != signed.decode():
        return "signed-string"
    if not sig_ok(v["key"], v["signature"], signed):
        return "signature"
    return None


def main():
    doc = json.load(open(sys.argv[1]))
    bad = 0
    for v in doc["vectors"]:
        got = refusal(v["link"], v["expect"], v["keys"])
        if v.get("rule") != "identifier-form" and v["signed"] != signed_bytes(v["link"]["statement"]).decode():
            print("MISMATCH %s: the signed string\n  python %r\n  file   %r" % (v["name"], signed_bytes(v["link"]["statement"]).decode(), v["signed"]))
            bad += 1
        if (got is None) != v["valid"]:
            print("MISMATCH %s: python says %r, the file says valid=%s" % (v["name"], got, v["valid"]))
            bad += 1
        elif got is not None and v["rule"] != got:
            print("MISMATCH %s: python refuses by rule %r, the file says %r" % (v["name"], got, v["rule"]))
            bad += 1
    for v in doc.get("invites", []):
        got = invite_refusal(v)
        if (got is None) != v["valid"] or (got is not None and got != v["rule"]):
            print("MISMATCH invite %s: python says %r, the file says valid=%s rule=%r" % (v["name"], got, v["valid"], v.get("rule")))
            bad += 1
    if bad:
        sys.exit(1)
    print("%d binding vectors and %d invites agree" % (len(doc["vectors"]), len(doc.get("invites", []))))


main()
