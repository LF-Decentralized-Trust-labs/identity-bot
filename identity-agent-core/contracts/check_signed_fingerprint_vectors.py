#!/usr/bin/env python3
"""An independent check of signed-fingerprint-vectors.json, written without Go.

Everything is rebuilt from agent-message/signed-fingerprint.md: the salted
fingerprint, the string a person signs, the rules that refuse a statement, and
the Ed25519 signature on each. The digest encoding and the Ed25519 verifier are
the ones check_ai_agent_vectors.py already holds, imported rather than copied.

Run: python3 -I check_signed_fingerprint_vectors.py <signed-fingerprint-vectors.json>
Needs the blake3 module (pip install blake3).
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

failures = []


def fail(what):
    failures.append(what)
    print("MISMATCH " + what)


def same(what, got, want):
    if got != want:
        fail("%s:\n  python %r\n  file   %r" % (what, got, want))


def fingerprint(salt, words):
    if not 16 <= len(salt) <= 1024:
        raise ValueError("salt size")
    return base.digest(b"IA-FINGERPRINT-V1" + len(salt).to_bytes(2, "big") + salt + words)


KINDS = ("message", "ask", "split", "hand-off", "close", "reopen", "limit")

FIELDS = ("agent", "conversation", "message_id", "kind", "from", "signer", "to", "in_reply_to",
          "range_first", "range_last", "nonce", "time", "fingerprint_version", "fingerprint")

# RFC 3339 as Go's time.Parse reads it (an hour may be one digit): ASCII digits only, a capital T, a zone
# that is Z or a signed hh:mm, and a fraction of one or more digits after a "."
# or ",". Nothing else: no date alone, no basic form, no space, no spaces around.
RFC3339 = re.compile(
    r"([0-9]{4})-([0-9]{2})-([0-9]{2})T([0-9]{1,2}):([0-9]{2}):([0-9]{2})([.,][0-9]+)?(Z|[+-]([0-9]{2}):([0-9]{2}))",
    re.ASCII)


def rfc3339(t):
    m = RFC3339.fullmatch(t)
    if not m:
        return False
    y, mo, d, h, mi, sec = (int(m.group(i)) for i in range(1, 7))
    leap = y % 4 == 0 and (y % 100 != 0 or y % 400 == 0)
    days = [31, 29 if leap else 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31]
    if not (1 <= mo <= 12 and 1 <= d <= days[mo - 1] and h <= 23 and mi <= 59 and sec <= 59):
        return False
    if m.group(9) is not None and (int(m.group(9)) > 24 or int(m.group(10)) > 60):
        return False
    return True


def statement_bytes(s):
    """IA-PERSON-MSG-V1 and then the fields in FIELDS order, one per line."""
    return "\n".join(["IA-PERSON-MSG-V1"] + [str(s.get(f, 0)) if f == "fingerprint_version" else s.get(f, "")
                                              for f in FIELDS]).encode()


def no_repeats(pairs):
    """Go's strict reader (PersonStatement.UnmarshalJSON) refuses a key named twice, where json.loads keeps the last."""
    keys = [k for k, _ in pairs]
    if len(set(keys)) != len(keys):
        raise ValueError("a key twice")
    return dict(pairs)


def refused(s):
    """The reason a statement is refused, or None. Go decodes a statement into
    a struct, so an unknown field or a field of the wrong JSON type is refused
    before any rule is applied; a missing field is its zero value."""
    if not isinstance(s, dict):
        return "not an object"
    for k, v in s.items():
        if k not in FIELDS:
            return "unknown field " + k
        if k == "fingerprint_version":
            if type(v) is not int:  # not true, not 1.0, not "1"
                return "fingerprint_version is not a JSON integer"
        elif not isinstance(v, str):
            return k + " is not a string"
    for f in ("agent", "conversation", "message_id", "kind", "from", "signer", "nonce", "time", "fingerprint"):
        if not s.get(f):
            return "no " + f
    for v in s.values():
        if isinstance(v, str) and ("\r" in v or "\n" in v):
            return "line break"
    k, to = s["kind"], s.get("to", "")
    first, last = s.get("range_first", ""), s.get("range_last", "")
    if k not in KINDS:
        return "kind"
    if k in ("message", "ask", "hand-off", "split") and not to:
        return "no recipient"
    if k in ("close", "reopen", "limit") and to:
        return "recipient on a close"
    if k == "split" and not (first and last):
        return "split range"
    if k != "split" and (first or last):
        return "range on a " + k
    if s.get("fingerprint_version", 0) != 1:
        return "fingerprint version"
    if len(s["nonce"].encode("utf-8")) < 16:  # bytes, as Go counts them
        return "nonce"
    if not rfc3339(s["time"]):
        return "time"
    return None


def main():
    v = json.load(open(sys.argv[1]))
    for f in v["fingerprints"]:
        same(f["name"], fingerprint(bytes.fromhex(f["salt_hex"]), bytes.fromhex(f["words_hex"])), f["fingerprint"])
    prints = [f["fingerprint"] for f in v["fingerprints"]]
    if len(set(prints)) != len(prints):
        fail("two different (salt, words) pairs gave one fingerprint")
    for r in v["refused_fingerprints"]:
        try:
            fingerprint(bytes.fromhex(r["salt_hex"]), b"")
            fail(r["name"] + " was accepted")
        except ValueError:
            pass
    same("version 0", base.digest(bytes.fromhex(v["version_zero"]["words_hex"])), v["version_zero"]["fingerprint"])
    pub = base.qb64_raw("D", v["verkey"], 32)
    for s in v["statements"]:
        st = s["statement"]
        if refused(st):
            fail("%s is refused: %s" % (s["name"], refused(st)))
        same(s["name"] + " fingerprint", fingerprint(bytes.fromhex(s["salt_hex"]), bytes.fromhex(s["words_hex"])), st["fingerprint"])
        same(s["name"] + " signed", statement_bytes(st).decode(), s["signed"])
        sig = base.qb64_raw("0B", s["signature"], 64)
        if not base.ed25519_verify(pub, sig, statement_bytes(st)):
            fail(s["name"] + ": the signature does not verify")
    for r in v["refused_statements"]:
        if refused(r["statement"]) is None:
            fail(r["name"] + " was accepted")
    for r in v["refused_raw_statements"]:
        try:
            st = json.loads(r["json"], object_pairs_hook=no_repeats)
        except ValueError:
            continue  # not even JSON: refused
        if refused(st) is None:
            fail(r["name"] + " was accepted")
    if failures:
        sys.exit(1)
    print("ok: %d fingerprints, %d statements, %d refused, %d refused as raw JSON" % (
        len(v["fingerprints"]), len(v["statements"]), len(v["refused_statements"]), len(v["refused_raw_statements"])))


if __name__ == "__main__":
    main()
