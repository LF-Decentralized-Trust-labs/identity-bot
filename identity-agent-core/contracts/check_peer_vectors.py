#!/usr/bin/env python3
"""An independent check of agentpeer/peer-vectors.json, written without Go.

Everything is rebuilt from agent-peer/agent-peer.md: the KERI exchange message
an Identity Agent signs for a message between AI agents two Identity Agents hold (its
bytes, its self-addressing identifier, its Ed25519 signature checked against the
sender's own key), the salted fingerprint of the words, every rule that refuses
a message, and the rules that refuse a contact's directory of AI agents or an AI
agent's grant. A refusal is matched by its stable code, never by its text. The
digest encoding, the strict base64url reading and Ed25519 verification are the
ones check_ai_agent_vectors.py already holds, imported rather than copied.

Optional, and used when installed:
  dilithium_py  (pip install dilithium-py)  checks the ML-DSA-65 half too;
                without it the refusals that turn on that signature are matched
                only as far as the rest of the message allows, and a note says so.
  keri          (pip install keri==1.3.6)   gives every signed message to a keripy
                Exchanger, which must take it.

Run: python3 -I check_peer_vectors.py <peer-vectors.json>
Needs the blake3 module (pip install blake3).
"""
import importlib.util
import json
import os
import sys
import unicodedata

here = os.path.dirname(os.path.abspath(__file__))
spec = importlib.util.spec_from_file_location("agent_vectors", os.path.join(here, "check_ai_agent_vectors.py"))
base = importlib.util.module_from_spec(spec)
spec.loader.exec_module(base)

try:
    from dilithium_py.ml_dsa import ML_DSA_65
except ImportError:  # optional
    ML_DSA_65 = None

failures = []
notes = []


def fail(what):
    failures.append(what)
    print("MISMATCH " + what)


def same(what, got, want):
    if got != want:
        fail("%s:\n  python %r\n  file   %r" % (what, got, want))


ROUTE_PREFIX = "/ia/agent/peer/"
KINDS = ("ask", "reply", "failure", "progress")
MAX_FIELD = 128
MAX_WORDS = 64 << 10
MIN_SALT, MAX_SALT = 16, 1024
FINGERPRINT_VERSION = 1
MAX_AGE_SECONDS = 3600
PQ_DOMAIN = b"IA-AGENT-PEER-PQ-V1\n"
MLDSA65_SIG_BYTES = 3309
ID_ALPHABET = set("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_.:-")


def plain(s):
    """An identifier: one to 128 of the letters, digits, '_', '.', ':' and '-'."""
    return bool(s) and len(s) <= MAX_FIELD and all(c in ID_ALPHABET for c in s)


def place_id_shaped(s):
    """"e" and a positive number: an entry's place in a conversation, never a
    message's own name."""
    return len(s) >= 2 and s[0] == "e" and s[1] != "0" and s[1:].isdigit()


def is_digest(s):
    try:
        base.qb64_raw("E", s, 32)
        return True
    except ValueError:
        return False


# ── the fingerprint (ADR-067, version 1) ─────────────────────────────────


def fingerprint(salt, words):
    pre = b"IA-FINGERPRINT-V1" + len(salt).to_bytes(2, "big") + salt + words
    return base.digest(pre)


# ── dates: ISO 8601, microseconds, UTC written +00:00 ────────────────────

import datetime


def parse_sent_at(s):
    """None unless s is in the one spelling YYYY-MM-DDTHH:MM:SS.ffffff+00:00."""
    if len(s) != 32 or s[-6:] != "+00:00":
        return None
    try:
        t = datetime.datetime.strptime(s[:-6], "%Y-%m-%dT%H:%M:%S.%f").replace(tzinfo=datetime.timezone.utc)
    except ValueError:
        return None
    return t if t.strftime("%Y-%m-%dT%H:%M:%S.%f") + "+00:00" == s else None


# ── the exchange message ─────────────────────────────────────────────────

FIELD_ORDER = ("v", "t", "d", "i", "rp", "p", "dt", "r", "q", "a", "e")


def compact(obj):
    return json.dumps(obj, separators=(",", ":"), ensure_ascii=False)


def split_stream(stream):
    """The exchange message at the front of a stream and what is attached to it."""
    try:
        obj, end = json.JSONDecoder().raw_decode(stream)
    except ValueError:
        return None, None, None
    return stream[:end], stream[end:], obj


def keri_message_problem(message, obj):
    """Why message is not a KERI exchange message in its one form, or None. Its
    identifier is the Blake3-256 digest of the message with the identifier
    blanked (44 '#'), the version string declares the message's size, and the
    message is the fields v t d i rp p dt r q a e in that order with no white
    space and nothing else."""
    if not isinstance(obj, dict) or list(obj.keys()) != list(FIELD_ORDER) or obj["t"] != "exn":
        return "fields"
    if compact(obj) != message:
        return "spelling"
    v = obj["v"]
    if len(v) != 17 or v[:10] != "KERI10JSON" or v[16] != "_" or v[10:16] != "%06x" % len(message.encode()):
        return "version"
    blanked = dict(obj)
    blanked["d"] = "#" * 44
    if base.digest(compact(blanked).encode()) != obj["d"]:
        return "identifier"
    if obj["p"] != "" and not is_digest(obj["p"]):
        return "fields"
    return None


def read_signed_exchange(stream):
    """What a keripy Exchanger reads of a signed exchange message from a
    non-transferable sender: (obj, message, signer, signature) or an error. The
    attachment is exactly one -CAB group: the sender's identifier (code B) and
    its Ed25519 signature (code 0B) over the message bytes."""
    message, attached, obj = split_stream(stream)
    if message is None:
        return None, "unreadable"
    if keri_message_problem(message, obj):
        return None, "unreadable"
    if len(attached) != 4 + 44 + 88 or attached[:4] != "-CAB":
        return None, "unreadable"
    sender, sig = attached[4:48], attached[48:]
    if obj["i"][0] != "B" or sender != obj["i"]:
        return None, "unreadable"
    try:
        pub = base.qb64_raw("B", sender, 32)
        raw_sig = base.qb64_raw("0B", sig, 64)
    except ValueError:
        return None, "unreadable"
    if not base.ed25519_verify(pub, raw_sig, message.encode()):
        return None, "unreadable"
    return (obj, message, pub), None


def attributes_of(st):
    """`a` after the recipient, in order; in_reply_to is absent for an ask."""
    a = {"from_aid": st["from_aid"], "from_agent": st["from_agent"], "to_agent": st["to_agent"], "message_id": st["message_id"]}
    if st.get("in_reply_to"):
        a["in_reply_to"] = st["in_reply_to"]
    a["fingerprint_version"] = FINGERPRINT_VERSION
    a["fingerprint"] = st["fingerprint"]
    return a


def rebuild(st, sender):
    """The exchange message this statement is, from its sender, as the prose says."""
    a = {"i": st["to_aid"]}
    a.update(attributes_of(st))
    blanked = {"v": "KERI10JSON000000_", "t": "exn", "d": "#" * 44, "i": sender, "rp": st["to_aid"], "p": "",
               "dt": st["sent_at"], "r": ROUTE_PREFIX + st["kind"], "q": {}, "a": a, "e": {}}
    # The size is that of the message with the real identifier, which is as long
    # as the blanked one.
    size = len(compact(blanked).encode())
    blanked["v"] = "KERI10JSON%06x_" % size
    blanked["d"] = base.digest(compact(blanked).encode())
    return compact(blanked)


# ── the rules ────────────────────────────────────────────────────────────


def check_statement_fields(st):
    """The refusal code for a statement that is not well formed by itself, or None."""
    for f in ("from_aid", "to_aid", "from_agent", "to_agent", "message_id"):
        if not plain(st.get(f, "")):
            return "field"
    kind = st.get("kind")
    if kind == "ask":
        if st.get("in_reply_to"):
            return "reply_to"
    elif kind in ("reply", "failure", "progress"):
        if not plain(st.get("in_reply_to", "")):
            return "reply_to"
    else:
        return "kind"
    if place_id_shaped(st["message_id"]) or (st.get("in_reply_to") and place_id_shaped(st["in_reply_to"])):
        return "place_id"
    if not is_digest(st.get("fingerprint", "")):
        return "fingerprint"
    if parse_sent_at(st.get("sent_at", "")) is None:
        return "time"
    return None


def pq_ok(pk, message, sig):
    if ML_DSA_65 is None:
        return None
    return ML_DSA_65.verify(pk, PQ_DOMAIN + message.encode(), sig)


def verify_message(m, signer, sent_by, self_aid, now):
    """The refusal code Verify gives a message, or '' when it is taken. signer
    is the sending Identity Agent's entry of keys."""
    if not m.get("exn"):
        return "no_message"
    read, err = read_signed_exchange(m["exn"])
    if err:
        return "unreadable"
    obj, message, pub = read
    # The sender must be the Identity Agent's Ed25519 messaging key as an identifier.
    if obj["i"] != signer["sender_identifier"]:
        return "not_signed"
    try:
        pq = base.unb64url(m.get("pq_sig", ""))
        pk = base.unb64url(signer["mldsa65_public_b64url"])
    except ValueError:
        return "not_signed"
    if len(pq) != MLDSA65_SIG_BYTES:
        return "not_signed"
    verdict = pq_ok(pk, message, pq)
    if verdict is False:
        return "not_signed"
    if verdict is None and not notes:
        notes.append("dilithium_py is not installed: the ML-DSA-65 signatures were not checked")
    route = obj["r"]
    kind = route[len(ROUTE_PREFIX):] if route.startswith(ROUTE_PREFIX) else ""
    if kind not in KINDS:
        return "kind"
    a = obj["a"]
    allowed = {"i", "from_aid", "from_agent", "to_agent", "message_id", "in_reply_to", "fingerprint_version", "fingerprint"}
    if not isinstance(a, dict) or set(a) - allowed or {"i", "from_aid", "from_agent", "to_agent", "message_id", "fingerprint_version", "fingerprint"} - set(a):
        return "unreadable"
    if a["fingerprint_version"] != FINGERPRINT_VERSION or isinstance(a["fingerprint_version"], bool):
        return "fingerprint_version"
    if obj["p"] != "" or a["i"] != obj["rp"]:
        return "not_one_form"
    st = {"kind": kind, "from_aid": a["from_aid"], "to_aid": obj["rp"], "from_agent": a["from_agent"], "to_agent": a["to_agent"],
          "message_id": a["message_id"], "in_reply_to": a.get("in_reply_to", ""), "fingerprint": a["fingerprint"], "sent_at": obj["dt"]}
    if st["from_aid"] != signer["aid"]:
        return "wrong_sender"
    code = check_statement_fields(st)
    if code:
        return code
    if rebuild(st, obj["i"]) != message:
        return "not_one_form"
    # Verify
    if st["from_aid"] != sent_by:
        return "wrong_sender"
    if st["to_aid"] != self_aid:
        return "wrong_recipient"
    words = m.get("words", "")
    if not words or len(words.encode()) > MAX_WORDS:
        return "words"
    try:
        salt = base.unb64url(m.get("salt", ""))
    except ValueError:
        return "salt"
    if not (MIN_SALT <= len(salt) <= MAX_SALT):
        return "salt"
    if fingerprint(salt, words.encode()) != st["fingerprint"]:
        return "fingerprint"
    at = parse_sent_at(st["sent_at"])
    nowt = datetime.datetime.strptime(now, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=datetime.timezone.utc)
    if abs((nowt - at).total_seconds()) > MAX_AGE_SECONDS:
        return "time"
    return ""


# ── directories ──────────────────────────────────────────────────────────

MAX_DIRECTORY = 200
MAX_NAME = 64


def shown(s):
    """Only what can be read as itself: no control, format, private-use or
    unassigned, and nothing Python would call unprintable."""
    for ch in s:
        cat = unicodedata.category(ch)
        if cat in ("Cc", "Cf", "Co", "Cn") or (not ch.isprintable() and ch != " "):
            return False
    return True


ERR_FIELD_TEXT = "an identifier in the message is missing, too long, or uses a character an identifier may not"
DIR_TOO_MANY = "a directory lists at most 200 AI agents"
DIR_NAME = "an AI agent's name is one to sixty-four characters, with no @ and no line break"
DIR_ROLE = "an AI agent's role is one short line"
DIR_ONCE = "a directory names each AI agent once, under a name of its own"


def check_directory(d):
    agents = d.get("agents") or []
    if len(agents) > MAX_DIRECTORY:
        return DIR_TOO_MANY
    names, aids = set(), set()
    for a in agents:
        aid, name, role = a.get("aid", ""), a.get("name", ""), a.get("role", "")
        n = name.strip()
        if not plain(aid):
            return ERR_FIELD_TEXT
        if n == "" or n != name or len(n) > MAX_NAME or "@" in n or not shown(n):
            return DIR_NAME
        if len(role) > 200 or not shown(role):
            return DIR_ROLE
        if name.lower() in names or aid in aids:
            return DIR_ONCE
        names.add(name.lower())
        aids.add(aid)
    return None


# ── grants ───────────────────────────────────────────────────────────────


def text_list(v):
    return isinstance(v, list) and len(v) > 0 and all(isinstance(x, str) and x != "" for x in v)


def grant_allows(limits, contact, agent):
    """agent.message.peer: an object whose contact is a list of the contacts it
    may reach, whose `agent` constraint (when given at all) is a non-empty list of the AI
    agents, and which has no other key. A grant not shaped so allows nothing."""
    if "agent.message.peer" not in limits:
        return False
    c = limits["agent.message.peer"]
    if not isinstance(c, dict) or set(c) - {"contact", "agent"}:
        return False
    if not text_list(c.get("contact")):
        return False
    if "agent" in c and not text_list(c["agent"]):
        return False
    if contact not in c["contact"]:
        return False
    return "agent" not in c or agent in c["agent"]


# ── keripy ───────────────────────────────────────────────────────────────


def keripy_takes(stream):
    """Whether a keripy Exchanger fed by keripy's parser takes the stream; None
    when keripy is not installed."""
    try:
        from keri.core import eventing, parsing  # noqa: F401  (eventing first: keripy has an import cycle)
        from keri.db import basing
        from keri.peer import exchanging
    except ImportError:
        return None
    from types import SimpleNamespace

    class Taker:
        resource = None

        def __init__(self, route):
            self.resource = route
            self.taken = []

        def verify(self, serder, **kw):
            return True

        def handle(self, serder, **kw):
            self.taken.append(serder.said)

    message, _, obj = split_stream(stream)
    taker = Taker(obj["r"])
    with basing.openDB(name="peer-vectors", temp=True) as db:
        exc = exchanging.Exchanger(hby=SimpleNamespace(db=db), handlers=[taker])
        steps = parsing.Parser().allParsator(ims=bytearray(stream.encode()), framed=True, exc=exc)
        for _ in range(200):
            try:
                next(steps)
            except StopIteration:
                break
            except Exception:
                break
    return bool(taker.taken)


def main(path):
    v = json.load(open(path))
    keys = v["keys"]
    for name, k in keys.items():
        same("%s: the sender identifier is the Ed25519 key as code B" % name, k["sender_identifier"],
             "B" + base.b64url(b"\x00" + base.unb64url(k["ed25519_public_b64url"]))[1:])
        same("%s: the Identity Agent's identifier is a digest" % name, is_digest(k["aid"]), True)
    keripy_seen = False
    for c in v["signed"]:
        st, frm, to = c["statement"], keys[c["from"]], keys[c["to"]]
        read, err = read_signed_exchange(c["exn"])
        if err:
            fail("%s: the signed message is not one: %s" % (c["name"], err))
            continue
        obj, message, pub = read
        same("%s: exchange_message" % c["name"], message, c["exchange_message"])
        same("%s: the stream is the message and its one signature" % c["name"], c["exn"].startswith(message), True)
        same("%s: said" % c["name"], obj["d"], c["said"])
        same("%s: rebuilt from the statement" % c["name"], rebuild(st, frm["sender_identifier"]), message)
        same("%s: sender" % c["name"], obj["i"], frm["sender_identifier"])
        same("%s: recipient" % c["name"], obj["rp"], to["aid"])
        same("%s: from_aid" % c["name"], st["from_aid"], frm["aid"])
        same("%s: to_aid" % c["name"], st["to_aid"], to["aid"])
        same("%s: route" % c["name"], obj["r"], ROUTE_PREFIX + st["kind"])
        salt = base.unb64url(c["salt"])
        if not (MIN_SALT <= len(salt) <= MAX_SALT):
            fail("%s: salt size" % c["name"])
        same("%s: fingerprint" % c["name"], fingerprint(salt, c["words"].encode()), st["fingerprint"])
        if not (c["words"] and len(c["words"].encode()) <= MAX_WORDS):
            fail("%s: words size" % c["name"])
        if check_statement_fields(st) is not None:
            fail("%s: a signed statement was refused: %s" % (c["name"], check_statement_fields(st)))
        same("%s: taken" % c["name"], verify_message({"exn": c["exn"], "pq_sig": c["pq_sig"], "words": c["words"], "salt": c["salt"]},
                                                      frm, frm["aid"], to["aid"], c["now"]), "")
        took = keripy_takes(c["exn"])
        if took is not None:
            keripy_seen = True
            same("%s: keripy takes it" % c["name"], took, True)
    for c in v["refused"]:
        got = verify_message(c["message"], keys[c["signer"]], c["sent_by"], c["self"], c["now"])
        same("%s: refusal code" % c["name"], got, c["code"])
    for c in v.get("directories", []):
        got = check_directory(c["directory"]) or ""
        same("%s: directory" % c["name"], got, c.get("refuse", ""))
    for c in v.get("grants", []):
        same("%s: grant" % c["name"], grant_allows(c["limits"], c["contact"], c["agent"]), c["allow"])
    for n in notes:
        print("note: " + n)
    if not keripy_seen:
        print("note: keripy is not installed: no signed message was given to a keripy Exchanger")
    if failures:
        print("\n%d mismatch(es)" % len(failures))
        sys.exit(1)
    print("OK: %d signed, %d refused, %d directories, %d grants" % (
        len(v["signed"]), len(v["refused"]), len(v.get("directories", [])), len(v.get("grants", []))))


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print(__doc__)
        sys.exit(2)
    main(sys.argv[1])
