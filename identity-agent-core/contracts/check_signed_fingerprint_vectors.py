#!/usr/bin/env python3
"""An independent check of signed-fingerprint-vectors.json, written without Go.

Everything is rebuilt from agent-message/signed-fingerprint.md: the salted
fingerprint, the string a person signs, the rules that refuse a statement, and
the Ed25519 signature on each. The digest encoding and the Ed25519 verifier are
the ones check_ai_agent_vectors.py already holds, imported rather than copied.

Run: python3 -I check_signed_fingerprint_vectors.py <signed-fingerprint-vectors.json>
Needs the blake3 module (pip install blake3).
"""
import datetime
import importlib.util
import json
import os
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


KINDS = ("message", "ask", "split", "hand-off", "close", "reopen")


def statement_bytes(s):
    return "\n".join(["IA-PERSON-MSG-V1", s["conversation"], s["message_id"], s["kind"], s["from"],
                      s["signer"], s.get("to", ""), s.get("in_reply_to", ""), s.get("range_first", ""),
                      s.get("range_last", ""), s["nonce"], s["time"], str(s["fingerprint_version"]),
                      s["fingerprint"]]).encode()


def refused(s):
    """The reason a statement is refused, or None."""
    for f in ("conversation", "message_id", "kind", "from", "signer", "nonce", "time", "fingerprint"):
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
    if k in ("close", "reopen") and to:
        return "recipient on a close"
    if k == "split" and not (first and last):
        return "split range"
    if k != "split" and (first or last):
        return "range on a " + k
    if s["fingerprint_version"] != 1:
        return "fingerprint version"
    if len(s["nonce"]) < 16:
        return "nonce"
    try:
        datetime.datetime.fromisoformat(s["time"].replace("Z", "+00:00"))
    except ValueError:
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
    if failures:
        sys.exit(1)
    print("ok: %d fingerprints, %d statements, %d refused" % (
        len(v["fingerprints"]), len(v["statements"]), len(v["refused_statements"])))


if __name__ == "__main__":
    main()
