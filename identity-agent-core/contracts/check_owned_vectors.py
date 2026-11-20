#!/usr/bin/env python3
"""An independent check of owned-vectors.json, written without Go.

Whether an owner identity owns an Identity Agent is decided from their two key
logs (ADR-087). Everything here is rebuilt from contracts/owned/owned.md: how a
key log verifies (the SAID of each event, the chain, the signature of the key
in force, the commitment a rotation opens), the owner set in force, the anchor,
how two copies of one log are judged, the witness receipts, the steps and the
grade and reason each case must give.

The Ed25519 arithmetic, the qb64 reader and the Blake3 digest are the ones
check_ai_agent_vectors.py already holds, imported rather than copied.

This reads the logs the vectors hold and no others: version 1 JSON events, one
Ed25519 key with a threshold of one, one signature attached at index 0. A log
of any other shape is reported as not readable by this script, which is not a
verdict on the log.

Run: python3 -I check_owned_vectors.py <owned-vectors.json>
Needs the blake3 module (pip install blake3), which that file imports.
"""
import hashlib
import importlib.util
import json
import os
import re
import sys

here = os.path.dirname(os.path.abspath(__file__))
spec = importlib.util.spec_from_file_location("agent_vectors", os.path.join(here, "check_ai_agent_vectors.py"))
base = importlib.util.module_from_spec(spec)
spec.loader.exec_module(base)

HEX = re.compile(r"^(0|[1-9a-f][0-9a-f]*)$")
VERSION = re.compile(r'^\{"v":"KERI10JSON([0-9a-f]{6})_"')
ESTABLISHMENT = ("icp", "rot", "dip", "drt")
MAX_EVENTS = 2048  # a longer log is not judged


class Unreadable(Exception):
    """A log this script cannot read. Not a verdict on the log."""


class Invalid(Exception):
    """A log that does not verify."""


# ── one key log ──────────────────────────────────────────────────────────


def split(message):
    """An event's exact bytes and the one signature attached to it."""
    m = VERSION.match(message)
    if not m:
        raise Invalid("a message does not begin with a version 1 JSON event")
    size = int(m.group(1), 16)
    raw, attached = message[:size], message[size:]
    if not (attached.startswith("-AAB") and len(attached) == 4 + 88):
        # Several well-formed signatures are a log this script does not read.
        # Anything else attached is not a signature group at all.
        if re.match(r"^-AA[C-Z]([A-Za-z0-9_-]{88}){2,}$", attached):
            raise Unreadable("this script reads one attached signature per event")
        raise Invalid("what is attached to an event is not its one signature")
    try:
        sig = base.qb64_raw("AA", attached[4:], 64)  # code A, index 0
    except ValueError:
        raise Invalid("an attached signature is not an indexed Ed25519 signature at index 0")
    return raw, sig


def said_of(raw, ev):
    """The digest an event must carry: Blake3-256 of its bytes with the digest,
    and for an inception the identifier (a copy of it) too, replaced by 44 '#'
    characters. `d` is the first place the digest is written and `i` the
    second, whatever the spacing."""
    if not isinstance(ev["d"], str) or len(ev["d"]) != 44:
        raise Invalid("an event's digest is not 44 characters")
    return base.digest(raw.replace(ev["d"], "#" * 44, 2 if ev["t"] in ("icp", "dip") else 1).encode())


def number(s):
    if not isinstance(s, str) or not HEX.match(s):
        raise Invalid("a sequence number or threshold is not lowercase hex")
    return int(s, 16)


# ── reading JSON as it was written ───────────────────────────────────────
#
# json.loads keeps the last of two values written under one key and says
# nothing, and it cannot say how a key was written. The check has to know
# both, so objects and lists are also walked as text.

DECODER = json.JSONDecoder()


def _skip(text, pos):
    while pos < len(text) and text[pos] in " \t\n\r":
        pos += 1
    return pos


def members(text):
    """The own members of an object, as written: (key text, key, value text)."""
    pos = _skip(text, 0)
    if text[pos:pos + 1] != "{":
        raise ValueError("not an object")
    pos = _skip(text, pos + 1)
    out = []
    if text[pos:pos + 1] == "}":
        return out
    while True:
        key, end = DECODER.raw_decode(text, pos)
        if not isinstance(key, str):
            raise ValueError("a key is not a string")
        written, pos = text[pos:end], _skip(text, end)
        if text[pos:pos + 1] != ":":
            raise ValueError("no value")
        pos = _skip(text, pos + 1)
        _, end = DECODER.raw_decode(text, pos)
        out.append((written, key, text[pos:end]))
        pos = _skip(text, end)
        if text[pos:pos + 1] == "}":
            return out
        if text[pos:pos + 1] != ",":
            raise ValueError("not an object")
        pos = _skip(text, pos + 1)


def entries(text):
    """The elements of a list, as written."""
    pos = _skip(text, 0)
    if text[pos:pos + 1] != "[":
        raise ValueError("not a list")
    pos = _skip(text, pos + 1)
    out = []
    if text[pos:pos + 1] == "]":
        return out
    while True:
        _, end = DECODER.raw_decode(text, pos)
        out.append(text[pos:end])
        pos = _skip(text, end)
        if text[pos:pos + 1] == "]":
            return out
        if text[pos:pos + 1] != ",":
            raise ValueError("not a list")
        pos = _skip(text, pos + 1)


def odd_keys(text):
    """Whether an object names one of its own keys twice, or writes one with
    an escape (owned.md, 'Reading an `a` list')."""
    own = members(text)
    keys = [key for _, key, _ in own]
    return len(set(keys)) != len(keys) or any("\\" in written for written, _, _ in own)


# The fields of each kind of event, in the order KERI writes them.
FIELDS = {
    "icp": ["v", "t", "d", "i", "s", "kt", "k", "nt", "n", "bt", "b", "c", "a"],
    "dip": ["v", "t", "d", "i", "s", "kt", "k", "nt", "n", "bt", "b", "c", "a", "di"],
    "rot": ["v", "t", "d", "i", "s", "p", "kt", "k", "nt", "n", "bt", "br", "ba", "a"],
    "drt": ["v", "t", "d", "i", "s", "p", "kt", "k", "nt", "n", "bt", "br", "ba", "a"],
    "ixn": ["v", "t", "d", "i", "s", "p", "a"],
}


class Log:
    """A key log that verified."""

    def __init__(self, messages):
        if not messages:
            raise Invalid("a log with no events")
        self.messages = list(messages)
        self.raws, self.events = [], []
        self.witnesses, self.thresholds = [], []  # in force at each event
        key = commitment = None
        witnesses, threshold = [], 0
        for place, message in enumerate(messages):
            try:
                raw, sig, ev, key, commitment, witnesses, threshold = self.one(
                    place, message, key, commitment, witnesses, threshold)
            except (KeyError, TypeError, AttributeError, IndexError, ValueError):
                raise Invalid("event %d lacks a field, or holds one of the wrong kind" % place)
            self.raws.append(raw)
            self.events.append(ev)
            self.witnesses.append(list(witnesses))
            self.thresholds.append(threshold)
        self.forked = False
        self.retired = []

    def one(self, place, message, key, commitment, witnesses, threshold):
        """Verify the event at place against the state before it."""
        raw, sig = split(message)
        try:
            ev = json.loads(raw)
        except ValueError:
            raise Invalid("an event is not JSON")
        if not isinstance(ev, dict):
            raise Invalid("an event is not a JSON object")
        t = ev.get("t")
        if t not in ESTABLISHMENT + ("ixn",):
            raise Invalid("an event of an unknown kind")
        # An event has exactly its kind's fields, each once, in order. (Spacing
        # and escapes inside it are the writer's business: KERI signs the
        # bytes whatever they are.)
        if [key for _, key, _ in members(raw)] != FIELDS[t]:
            raise Invalid("event %d does not have its kind's fields, each once and in order" % place)
        if said_of(raw, ev) != ev["d"]:
            raise Invalid("event %d does not carry its own digest" % place)
        if number(ev["s"]) != place:
            raise Invalid("event %d is out of sequence" % place)
        if place == 0:
            if t not in ("icp", "dip") or ev["i"] != ev["d"]:
                raise Invalid("the log does not begin with an inception that derives its identifier")
            self.id = ev["i"]
        else:
            if t in ("icp", "dip") or ev["i"] != self.id or ev["p"] != self.events[-1]["d"]:
                raise Invalid("event %d does not follow the one before" % place)
            # A log rotates the way it was founded: a delegated rotation in a
            # log that began with an icp, or a plain one in a log that began
            # with a dip, does not verify.
            if (t == "drt") != (self.events[0]["t"] == "dip") and t in ("rot", "drt"):
                raise Invalid("event %d is a %s in a log founded by %s" % (place, t, self.events[0]["t"]))
        if t in ESTABLISHMENT:
            if len(ev["k"]) != 1 or ev["kt"] != "1" or len(ev["n"]) > 1:
                raise Unreadable("this script reads logs with one signing key")
            if place > 0 and base.digest(ev["k"][0].encode()) != commitment:
                raise Invalid("the rotation at %d does not open the commitment before it" % place)
            key = ev["k"][0]
            commitment = ev["n"][0] if ev["n"] else None
            if t in ("icp", "dip"):
                witnesses = list(ev["b"])
            else:
                witnesses = [w for w in witnesses if w not in ev["br"]] + list(ev["ba"])
            threshold = number(ev["bt"])
        try:
            pub = base.qb64_raw("D", key, 32)
        except ValueError:
            raise Invalid("a signing key is not a qb64 Ed25519 key")
        if not base.ed25519_verify(pub, sig, raw.encode()):
            raise Invalid("event %d is not signed by the key in force" % place)
        return raw, sig, ev, key, commitment, witnesses, threshold

    def establishment(self, place):
        return self.events[place]["t"] in ESTABLISHMENT

    def judge_against(self, other):
        """Judge this copy against another copy of the same log (owned.md,
        'Two copies of one log'). Returns a reason code when this copy is
        refused."""
        if other.id != self.id:
            return "log_unchecked"
        mine, theirs = self.events, other.events
        both = min(len(mine), len(theirs))
        for p in range(both):
            if mine[p]["d"] == theirs[p]["d"]:
                continue
            only_interactions = lambda evs: all(e["t"] == "ixn" for e in evs[p:])
            if mine[p]["t"] == "rot" and only_interactions(theirs):
                self.retired.extend(other.raws[p:])
                return None
            if theirs[p]["t"] == "rot" and only_interactions(mine):
                return "stale_copy"
            self.forked = True
            return None
        return "stale_copy" if len(theirs) > len(mine) else None

    def witnessed(self, said, receipts):
        """Whether the event carries valid receipts to its log's threshold."""
        place = next((i for i, e in enumerate(self.events) if e["d"] == said), None)
        if place is None:
            return False
        designated, threshold = self.witnesses[place], self.thresholds[place]
        counted = set()
        for r in receipts.get(said, []):
            witness, sig = r["witness"], r["signature"]
            if witness not in designated or len(sig) != 88 or sig[0] != "A":
                continue
            if base.B64URL.index(sig[1]) != designated.index(witness):
                continue
            try:
                raw_sig = base.unb64url("AA" + sig[2:])[2:]
                pub = base.qb64_raw("B", witness, 32)
            except ValueError:
                continue
            if base.ed25519_verify(pub, raw_sig, self.raws[place].encode()):
                counted.add(witness)
        return bool(designated) and threshold > 0 and len(counted) >= threshold


def read(v):
    """A log of the file, verified and judged against the copies kept.
    Returns (log, reason)."""
    if len(v["messages"]) > MAX_EVENTS:
        return None, "log_unchecked"
    try:
        log = Log(v["messages"])
    except Invalid:
        return None, "log_invalid"
    for kept in v.get("kept") or []:
        if not kept:
            continue
        if len(kept) > MAX_EVENTS:
            return None, "log_unchecked"
        try:
            other = Log(kept)
        except Invalid:
            return None, "log_unchecked"
        why = log.judge_against(other)
        if why:
            return None, why
    return log, None


# ── owner seals and anchors ──────────────────────────────────────────────


def owners_named(ev):
    """The owners an event names, or None when it carries no owner seal."""
    if ev["t"] not in ESTABLISHMENT:
        return None
    named = []
    a = ev.get("a")
    for seal in a if isinstance(a, list) else []:
        if not isinstance(seal, dict) or set(seal) != {"i", "s", "d"}:
            continue
        i, s, d = (seal[k] if isinstance(seal[k], str) else "" for k in ("i", "s", "d"))
        if not i or not d:
            raise Invalid("an owner seal with nothing in it")
        if s == "0" and d == i and i not in named:
            named.append(i)
    return named or None


def owner_sets(log):
    """The owner set in force at each event."""
    first = owners_named(log.events[0])
    if first is None:
        return [[] for _ in log.events]
    sets, current = [], first
    for ev in log.events:
        current = owners_named(ev) or current
        sets.append(current)
    return sets


UNREADABLE = object()
ODD = object()  # unreadable because a key is written twice or with an escape
OTHER = object()


def elements(raw):
    """The `a` list of an event, read from its text element by element: an
    event seal as (identifier, place, digest), OTHER for a seal shown not to
    be an event seal, ODD or UNREADABLE for anything else (owned.md, 'Reading
    an `a` list')."""
    if odd_keys(raw):
        return [ODD]
    top = {key: value for _, key, value in members(raw)}
    if "a" not in top or top["a"] == "null":
        return []
    try:
        listed = entries(top["a"])
    except ValueError:
        return [UNREADABLE]
    out = []
    for text in listed:
        if not text.startswith("{"):
            out.append(UNREADABLE)
            continue
        if odd_keys(text):
            out.append(ODD)
            continue
        el = json.loads(text)
        if not {"i", "s", "d"} <= set(el):
            out.append(OTHER)
        elif (len(el) == 3 and all(isinstance(el[k], str) for k in ("i", "s", "d"))
              and el["i"] and el["d"] and HEX.match(el["s"]) and len(el["s"]) <= 16):
            out.append((el["i"], int(el["s"], 16), el["d"]))
        else:
            out.append(UNREADABLE)
    return out


def owner_seals_unreadable(log, place):
    """Whether an establishment event carries a seal with a key written twice
    or with an escape, so whom it names depends on who reads it."""
    return log.establishment(place) and ODD in elements(log.raws[place])


def is_anchor(log, seal, owner):
    """Whether a seal is an anchor of this log for owner: (is, known).
    Raises Invalid when the sealed event's owner seals cannot be read."""
    _, place, said = seal
    if place >= len(log.events) or log.events[place]["d"] != said:
        return False, False
    if not log.establishment(place):
        return False, True
    if owner_seals_unreadable(log, place):
        raise Invalid("a seal in the sealed event has a key written twice or with an escape")
    return owner in (owners_named(log.events[place]) or []), True


# ── the check ────────────────────────────────────────────────────────────


def check(case):
    r = {"grade": "refused", "reason": ""}

    def end(grade, reason):
        r["grade"], r["reason"] = grade, reason
        return r

    # 1. M's log verifies, and carries on from the copies kept.
    m, why = read(case["machine"])
    if why:
        return end("refused", why)
    r["machine"] = m.id
    # Who the owner is claimed to be is the `i` of the first event of its log,
    # as written. Nothing rests on it until step 4 has verified that log.
    try:
        owner = json.JSONDecoder().raw_decode(case["owner"]["messages"][0])[0]["i"]
    except (IndexError, ValueError, KeyError, TypeError):
        return end("refused", "log_invalid")
    if not isinstance(owner, str) or not owner:
        return end("refused", "log_invalid")
    r["owner"] = owner
    if owner == m.id:
        return end("refused", "same_identifier")
    if any(owner_seals_unreadable(m, i) for i in range(len(m.events))):
        return end("refused", "log_invalid")
    try:
        sets = owner_sets(m)
    except Invalid:
        return end("refused", "log_invalid")
    est = [i for i in range(len(m.events)) if m.establishment(i)]
    named = owner in sets[est[-1]]
    if any(e["t"] in ("dip", "drt") or e.get("di") for e in m.events):
        return end("named_not_owned" if named else "refused", "delegated")

    # 2. X is named, and E is where it entered.
    if not named:
        return end("refused", "not_named")
    e = est[-1]
    for i in reversed(est):
        if owner not in sets[i]:
            break
        e = i
    sealed = m.events[e]
    r["event"], r["event_sn"] = sealed["d"], e

    # 4. X's log verifies.
    x, why = read(case["owner"])
    if why:
        return end("refused", why)

    # Step 7 of the record, reported here.
    if m.forked or x.forked:
        return end("refused", "duplicity")

    # Step 5 of the record: an interaction of X seals E exactly. X's
    # interactions are read in order until that seal is found.
    exact = (m.id, e, sealed["d"])
    before, anchor = [], None
    for i, ev in enumerate(x.events):
        if ev["t"] != "ixn" or anchor is not None:
            continue
        for el in elements(x.raws[i]):
            if el is UNREADABLE or el is ODD:
                return end("refused", "log_unchecked")
            if el is OTHER:
                continue
            if el == exact:
                anchor = i
                break
            before.append(el)
    if anchor is None:
        removed = any(el == exact for gone in x.retired for el in elements(gone))
        return end("named_not_owned", "anchor_removed" if removed else "named_not_anchored")

    # Step 6 of the record: the first anchor in X's log names M.
    others = {}
    for v in case.get("other_logs") or []:
        o, why = read(v)
        if o is not None and not o.forked and o.id not in (m.id, x.id):
            others[o.id] = o
    for s in before:
        own = s[0] in (m.id, x.id)
        of = m if s[0] == m.id else x if s[0] == x.id else others.get(s[0])
        if of is None:
            r["needs"] = s[0]
            return end("refused", "log_unchecked")
        try:
            is_one, known = is_anchor(of, s, x.id)
        except Invalid:
            return end("refused", "log_unchecked")
        if not known and not own:
            r["needs"] = s[0]
            return end("refused", "log_unchecked")
        if is_one and of is m:
            break
        if is_one:
            return end("named_not_owned", "second_machine")

    r["anchored_by"] = x.events[anchor]["d"]

    # 8. Confirmed needs both copies from their witnesses, and the receipts.
    if case["machine"]["source"] != "its_witnesses" or case["owner"]["source"] != "its_witnesses":
        return end("owned_anchored", "not_from_witnesses")
    if not (m.witnessed(sealed["d"], case["machine"].get("receipts") or {})
            and x.witnessed(r["anchored_by"], case["owner"].get("receipts") or {})):
        return end("owned_anchored", "receipts_short")
    return end("owned_confirmed", "")


# ── the keys come from the published seeds ───────────────────────────────


def public_key(seed):
    """The Ed25519 public key of a 32-byte seed (RFC 8032, section 5.1.5)."""
    h = hashlib.sha512(seed).digest()
    a = int.from_bytes(h[:32], "little")
    a &= (1 << 254) - 8
    a |= 1 << 254
    y = 4 * pow(5, -1, base._P) % base._P
    x, y = base._mul(a, (base._recover_x(y, 0), y))
    return (y | ((x & 1) << 255)).to_bytes(32, "little")


def qb64(code, raw):
    """A 32-byte value under a one-character code."""
    return code + base.b64url(b"\x00" + raw)[1:]


def main(path):
    with open(path, encoding="utf-8") as f:
        vectors = json.load(f)

    made = {qb64("D", public_key(bytes.fromhex(seed))) for seed in vectors["seeds"].values()}
    for name, w in vectors["witnesses"].items():
        base.same("witness %s: its identifier is its seed's key" % name,
                  qb64("B", public_key(bytes.fromhex(w["seed"]))), w["identifier"])

    seen = set()
    for case in vectors["cases"]:
        label = case["label"]
        if label in seen:
            base.fail("%s: the label is used twice" % label)
        seen.add(label)
        logs = [case["machine"], case["owner"]] + (case.get("other_logs") or [])
        for v in logs:
            for copy in [v["messages"]] + (v.get("kept") or []):
                for message in copy:
                    try:
                        keys = DECODER.raw_decode(message)[0].get("k", [])
                    except (ValueError, AttributeError):
                        base.fail("%s: a message does not begin with an event, so its keys cannot be traced to a seed" % label)
                        continue
                    for key in keys if isinstance(keys, list) else []:
                        if key not in made:
                            base.fail("%s: the key %s comes from no published seed" % (label, key))
        try:
            got = check(case)
        except Invalid:
            got = {"grade": "refused", "reason": "log_invalid"}
        except Exception as exc:  # noqa: BLE001 - report the case, never a traceback
            base.fail("%s: this script could not judge it: %s: %s" % (label, type(exc).__name__, exc))
            continue
        want = dict(case["expect"])
        for field in ("machine", "owner", "event", "anchored_by", "needs"):
            got.setdefault(field, "")
            want.setdefault(field, "")
        got.setdefault("event_sn", None)
        want.setdefault("event_sn", None)
        base.same(label, got, want)

    if not vectors["cases"]:
        base.fail("no cases are published")
    if base.failures:
        print("%d mismatches" % len(base.failures))
        return 1
    print("ok: %d cases" % len(vectors["cases"]))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1]))
