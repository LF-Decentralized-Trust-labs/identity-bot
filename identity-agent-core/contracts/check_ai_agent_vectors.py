#!/usr/bin/env python3
"""An independent check of the AI-agent vector files, written without Go.

Everything here is rebuilt from the prose in agent-body.schema.json and
agent-message.schema.json, not from the Go code: the strings a body signs, the
keys digest, the six words, the nonce and key-size rules, the grades, the
countersigned message's fields and the hash that chains entries. If this script
and the vector files ever disagree, the prose no longer says what the code does.

It checks bytes and digests, not signatures: those the Go tests verify.

Run: python3 check_ai_agent_vectors.py <body-vectors.json | message-vectors.json>
Needs the blake3 module (pip install blake3).
"""
import base64
import datetime
import json
import os
import sys

import blake3

HERE = os.path.dirname(os.path.abspath(__file__))
P256_N = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551
failures = []


def fail(what):
    failures.append(what)
    print("MISMATCH " + what)


def same(what, got, want):
    if got != want:
        fail("%s:\n  python %r\n  file   %r" % (what, got, want))


def b64url(raw):
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


def unb64url(s):
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def digest(data):
    """Blake3-256 as CESR qb64 with code E: one zero lead byte, then the code
    replaces the first base64 character."""
    return "E" + b64url(b"\x00" + blake3.blake3(data).digest())[1:]


def lines(*fields):
    return "\n".join(fields)


# ── agent-body.schema.json ────────────────────────────────────────────────


def check_body(v):
    words = open(os.path.join(HERE, "..", "agentbody", "bip39_english.txt")).read().split()
    k = v["keys"]
    same("keys host", k["host"], v["host"])
    same("keys verkey", k["verkey"], v["verkey"])
    same("host and verkey are the same key", v["host"][1:], v["verkey"][1:])
    sizes = (("x25519", 32), ("mlkem768", 1184), ("ed25519", 32), ("mldsa65", 1952))
    for name, size in sizes:
        same("%s size" % name, len(unb64url(k[name])), size)
    refused_keys = v["refused_keys"]
    same("refused key count", len(refused_keys), len(sizes))
    for r in refused_keys:
        wrong = [name for name, size in sizes if len(unb64url(r["keys"][name])) != size]
        if len(wrong) != 1:
            fail("%s has %d keys of the wrong size, not one" % (r["name"], len(wrong)))
    keys_digest = digest(lines("IA-BODY-KEYS-V1", k["host"], k["verkey"], k["x25519"], k["mlkem768"],
                               k["ed25519"], k["mldsa65"]).encode())
    same("keys_digest", keys_digest, v["keys_digest"])

    required = ("url", "ia", "d", "agent", "secret")
    for e in v["enrolments"]:
        same(e["name"] + " prefix", e["encoded"][:8], "iabody1.")
        same(e["name"] + " fields", json.loads(unb64url(e["encoded"][8:])), e["fields"])
    for r in v["refused_enrolments"]:
        refused = False
        try:
            if not r["encoded"].startswith("iabody1."):
                raise ValueError
            f = json.loads(unb64url(r["encoded"][8:]))
            refused = f.get("v") != 1 or any(not f.get(x) for x in required)
        except Exception:
            refused = True
        if not refused:
            fail("%s is not refused by the prose's rules" % r["name"])

    first = v["enrolments"][0]["fields"]
    for r in v["enrol_requests"]:
        signed = lines("IA-BODY-ENROL-V1", first["ia"], first["agent"], first["secret"], r["nonce"], k["host"],
                       k["verkey"], keys_digest, r["claimed_grade"], r["platform"], r["placement"])
        same(r["name"] + " signed", signed, r["signed"])
        q = r["request"]
        for field, want in (("secret", first["secret"]), ("agent", first["agent"]), ("keys", k), ("nonce", r["nonce"]),
                            ("claimed_grade", r["claimed_grade"]), ("platform", r["platform"]),
                            ("placement", r["placement"])):
            same("%s request %s" % (r["name"], field), q[field], want)
        if len(q["nonce"]) < 16:
            fail(r["name"] + " carries a nonce under 16 characters")
    same("sealed enrolment sender", v["sealed_enrolment"]["sender"], k)

    for r in v["signed_requests"]:
        h = r["headers"]
        signed = lines("IA-BODY-REQ-V3", h.get("X-IA-Body-For", ""), h.get("X-IA-Body-Host", ""), r["method"].upper(),
                       r["target"], h.get("X-IA-Body-Timestamp", ""), h.get("X-IA-Body-Nonce", ""),
                       digest(r["body"].encode()), h.get("X-Work-Item", ""), h.get("X-Reason", ""),
                       h.get("X-IA-Session", ""))
        same(r["name"] + " signed", signed, r["signed"])
        if len(h.get("X-IA-Body-Nonce", "")) < 16:
            fail(r["name"] + " carries a nonce under 16 characters")
    for n in v["refused_nonces"]:
        if len(n) >= 16:
            fail("refused nonce %r is 16 characters or more" % n)

    for w in v["words"]:
        bits = int.from_bytes(blake3.blake3(("IA-BODY-WORDS-V1\n" + w["host"]).encode()).digest()[:9], "big")
        got = [words[(bits >> (72 - 11 * (i + 1))) & 0x7FF] for i in range(6)]
        same("words for " + w["host"], got, w["words"])

    order = ["software", "hardware-asserted", "hardware-attested", "attested-runtime"]
    for g in v["grades"]:
        c = g["claimed"]
        if c in ("software", "hardware-asserted"):
            want = (c, False)
        elif c in order:
            want = ("hardware-asserted", True)
        else:
            want = ("software", c != "")
        same("grade for %r" % c, (g["grade"], g["clamped"]), want)

    p = v["p256"]
    for name, sig, low in (("signature", p["signature"], True), ("refused_signature", p["refused_signature"], False)):
        same("p256 %s code" % name, sig[:2], "0I")
        raw = unb64url("AA" + sig[2:])[2:]
        s = int.from_bytes(raw[32:], "big")
        if (s <= P256_N // 2) != low:
            fail("p256 %s is %s-s" % (name, "high" if low else "low"))
    return len(v["enrol_requests"]) + len(v["signed_requests"]) + len(v["words"])


# ── agent-message.schema.json ─────────────────────────────────────────────


def statement_bytes(s):
    b = s.get("brain", {})
    return lines("IA-AGENT-MSG-V1", s["conversation"], s["kind"], s["from"], s["to"], s.get("in_reply_to", ""),
                 s["body_hash"], b.get("provider", ""), b.get("model", ""), b.get("session", ""),
                 b.get("run_hash", ""), s["host"], s["host_nonce"], s["host_time"], s["body_credential"])


def statement_refused(s):

    req = ("conversation", "kind", "from", "to", "body_hash", "host", "host_nonce", "host_time", "body_credential")
    if any(not s.get(x) for x in req):
        return True
    vals = [s.get(x, "") for x in req + ("in_reply_to",)] + list(s.get("brain", {}).values())
    if any("\n" in x or "\r" in x for x in vals):
        return True
    if s["kind"] not in ("ask", "reply", "receipt", "failure") or not s.get("in_reply_to"):
        return True
    if len(s["host_nonce"]) < 16:
        return True
    try:
        datetime.datetime.fromisoformat(s["host_time"].replace("Z", "+00:00"))
    except ValueError:
        return True
    return False


def jwm_of(env):
    return json.loads(unb64url(env["plaintext"]), object_pairs_hook=lambda kv: kv)


def check_message(v):
    for s in v["statements"]:
        st = s["statement"]
        same(s["name"] + " body_hash", digest(s["body"].encode()), st["body_hash"])
        same(s["name"] + " host", st["host"], v["host"])
        same(s["name"] + " signed", statement_bytes(st), s["signed"])
        if statement_refused(st):
            fail(s["name"] + " breaks a rule in the prose")
    for r in v["refused_statements"]:
        if not statement_refused(r["statement"]):
            fail(r["name"] + " is not refused by the prose's rules")

    me = v["countersigner"]["aid"]
    prev = ""
    for i, e in enumerate(v["conversation"]):
        rec, env = e["record"], e["envelope"]
        where = "entry %d" % i
        same(where + " mode", env["mode"], "signed")
        pairs = jwm_of(env)
        same(where + " field order", [k for k, _ in pairs],
             ["id", "type", "from", "to", "created_time", "expires_time", "body"])
        jwm = dict(pairs)
        to = rec["to"][len("person:"):] if rec["to"].startswith("person:") else rec["to"]
        same(where + " id", jwm["id"], rec["message_id"])
        same(where + " type", jwm["type"], "agent-message")
        same(where + " from", jwm["from"], "did:keri:" + me)
        same(where + " to", jwm["to"], ["did:keri:" + to])
        same(where + " created_time", jwm["created_time"], rec["ia_time"])
        same(where + " expires_time", jwm["expires_time"], "")
        same(where + " body", json.loads(json.dumps(dict_deep(jwm["body"]))), rec)
        same(where + " prev_hash", rec["prev_hash"], prev)
        same(where + " body_hash", digest(e["body"].encode()), rec["body_hash"])
        st = rec["statement"]
        for f in ("conversation", "kind", "from", "to", "in_reply_to", "body_hash", "body_credential"):
            same("%s statement %s" % (where, f), st.get(f, ""), rec.get(f, ""))
        h = digest(lines(env["plaintext"], env["ed_sig"], env["mldsa_sig"]).encode())
        same(where + " hash", h, e["hash"])
        prev = h
    for r in v["refused_entries"]:
        jwm = dict(jwm_of(r["envelope"]))
        if jwm["id"] == dict_deep(jwm["body"])["message_id"]:
            fail(r["name"] + " is not refused by the prose's rules")
    return len(v["statements"]) + len(v["conversation"])


def dict_deep(x):
    if isinstance(x, list) and all(isinstance(p, tuple) and len(p) == 2 for p in x) and x:
        return {k: dict_deep(val) for k, val in x}
    if isinstance(x, list):
        return [dict_deep(i) for i in x]
    return x


def main():
    if len(sys.argv) != 2:
        sys.exit(__doc__)
    with open(sys.argv[1]) as f:
        v = json.load(f)
    if "enrolments" in v:
        n = check_body(v)
    elif "statements" in v:
        n = check_message(v)
    else:
        sys.exit("%s is not a body or message vector file" % sys.argv[1])
    if failures:
        sys.exit(1)
    print("ok: %d vectors" % n)


if __name__ == "__main__":
    main()
