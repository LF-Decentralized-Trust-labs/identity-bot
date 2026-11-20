#!/usr/bin/env python3
"""An independent check of set-up-file-vectors.json, written without Go.

A set-up file (ADR-088) is read here from docs/set-up-file.md alone: the strict
reading, what refuses a file and what blocks an item, the canonical contents and
their digest, the seal (the statement signature envelope of
docs/statement-signature.md), and the chosen list an approval signs. The
Ed25519 verifier, the qb64 reader and the digest are the ones
check_ai_agent_vectors.py already holds, imported rather than copied.

Text is judged by the Unicode facts published beside the vectors
(unicode-15.0.json), never by this language's own tables, so that no verdict
depends on a library's version. Where this Python's tables cover that version,
the normal forms made here from the published facts are swept against this
Python's own normaliser, and the published case folds against its own.

Run: python3 -I check_set_up_file_vectors.py <set-up-file-vectors.json>
Needs the blake3 module (pip install blake3), which that file imports.
"""
import bisect
import datetime
import hashlib
import importlib.util
import ipaddress
import json
import os
import random
import re
import sys
import unicodedata

here = os.path.dirname(os.path.abspath(__file__))
spec = importlib.util.spec_from_file_location("agent_vectors", os.path.join(here, "check_ai_agent_vectors.py"))
base = importlib.util.module_from_spec(spec)
spec.loader.exec_module(base)

MAX_FILE, MAX_ITEMS, MAX_NAME, MAX_KIND, MAX_MEMBER, MAX_ABOUT, MAX_TEXT = 4 << 20, 500, 64, 64, 128, 2048, 64 << 10
MAX_PERMISSIONS, MAX_ARGUMENTS, MAX_VALUES, MAX_VALUE, MAX_CREDENTIALS, MAX_DEPTH, MAX_ORIGIN = 200, 32, 256, 256, 200, 64, 300
COMMON = ("kind", "name", "permissions", "limits", "grant_end")
TOP = ("format", "made_at", "about", "items", "credentials_needed", "seal")
REST_LABEL = b"identity-agent-set-up-rest/1\n"


class Refused(Exception):
    """A file, a choice or a chosen list refused whole, by its code."""


class Num:
    """A number as the file wrote it."""

    def __init__(self, s):
        self.s = s


# -- The Unicode facts, pinned ------------------------------------------------

ZWNJ, ZWJ, VS15, VS16 = 0x200C, 0x200D, 0xFE0E, 0xFE0F
# What changes at most how the characters beside it are drawn.
DRAWN_ONLY = (VS15, VS16, ZWJ, ZWNJ)
HANGUL_S, HANGUL_L, HANGUL_V, HANGUL_T = 0xAC00, 0x1100, 0x1161, 0x11A7


class Ranges:
    """Ranges [first, last] or [first, last, word], looked up by character."""

    def __init__(self, rows):
        self.first = [r[0] for r in rows]
        self.rows = rows

    def find(self, cp):
        i = bisect.bisect_right(self.first, cp) - 1
        return self.rows[i] if i >= 0 and cp <= self.rows[i][1] else None

    def __contains__(self, cp):
        return self.find(cp) is not None

    def word(self, cp):
        r = self.find(cp)
        return r[2] if r else ""


class Unicode:
    def __init__(self, path):
        with open(path, "rb") as f:
            d = json.loads(f.read().decode("utf-8"))
        self.version = d["unicode"]
        self.seen, self.letters, self.marks, self.emoji = (Ranges(d[k]) for k in ("seen", "letters", "marks", "emoji"))
        self.script, self.joining, self.classes = Ranges(d["script"]), Ranges(d["joining"]), Ranges(d["ccc"])
        self.nfd = {r[0]: r[1:] for r in d["nfd"]}
        self.nfkd = {r[0]: r[1:] for r in d["nfkd"]}
        self.compose = {(a, b): c for a, b, c in d["compose"]}
        self.fold = {a: b for a, b in d["fold"]}

    def ccc(self, cp):
        r = self.classes.find(cp)
        return r[2] if r else 0

    def decomposed(self, s, compat):
        out = []
        for ch in s:
            cp = ord(ch)
            if HANGUL_S <= cp < HANGUL_S + 19 * 21 * 28:
                n = cp - HANGUL_S
                out += [HANGUL_L + n // (21 * 28), HANGUL_V + n % (21 * 28) // 28]
                if n % 28:
                    out.append(HANGUL_T + n % 28)
            elif compat and cp in self.nfkd:
                out += self.nfkd[cp]
            elif cp in self.nfd:
                out += self.nfd[cp]
            else:
                out.append(cp)
        for i in range(1, len(out)):  # canonical ordering
            j = i
            while j > 0 and self.ccc(out[j]) != 0 and self.ccc(out[j - 1]) > self.ccc(out[j]):
                out[j - 1], out[j] = out[j], out[j - 1]
                j -= 1
        return out

    def normalized(self, s, compat):
        """Normalization Form C, or KC, from the published facts."""
        out, starter, last = [], -1, -1
        for cp in self.decomposed(s, compat):
            cl = self.ccc(cp)
            if starter >= 0:
                st = out[starter]
                blocked = starter != len(out) - 1 and (last == 0 or last >= cl)
                if blocked:
                    pass
                elif (st, cp) in self.compose:
                    out[starter] = self.compose[(st, cp)]
                    continue
                elif HANGUL_L <= st < HANGUL_L + 19 and HANGUL_V <= cp < HANGUL_V + 21:
                    out[starter] = HANGUL_S + ((st - HANGUL_L) * 21 + (cp - HANGUL_V)) * 28
                    continue
                elif HANGUL_S <= st < HANGUL_S + 19 * 21 * 28 and (st - HANGUL_S) % 28 == 0 and HANGUL_T < cp < HANGUL_T + 28:
                    out[starter] = st + (cp - HANGUL_T)
                    continue
            if cl == 0:
                starter = len(out)
            out.append(cp)
            last = cl
        return "".join(chr(c) for c in out)

    def nfc(self, s):
        return self.normalized(s, False)

    def nfkc(self, s):
        return self.normalized(s, True)

    def after_a_virama(self, before):
        """UAX #31, rules A2 and B: a letter, any marks, a virama, then only
        marks of a class other than 0."""
        i = len(before) - 1
        while i >= 0 and self.ccc(before[i]) not in (0, 9):
            i -= 1
        if i < 0 or self.ccc(before[i]) != 9:
            return False
        i -= 1
        while i >= 0 and before[i] in self.marks:
            i -= 1
        return i >= 0 and before[i] in self.letters

    def joiner_allowed(self, cps, i):
        before, after = cps[:i], cps[i + 1:]
        if self.after_a_virama(before):
            return cps[i] == ZWJ or (len(after) > 0 and after[0] in self.letters)
        if cps[i] != ZWNJ:
            return False
        j = len(before) - 1
        while j >= 0 and self.joining.word(before[j]) == "T":
            j -= 1
        k = 0
        while k < len(after) and self.joining.word(after[k]) == "T":
            k += 1
        if j < 0 or k == len(after):
            return False
        return self.joining.word(before[j]) in ("L", "D") and self.joining.word(after[k]) in ("R", "D")

    def joiner_in_text(self, cps, i):
        """Where text of several lines also takes a joiner: between two emoji,
        neither of them ASCII (a variation selector may stand before the
        joiner), between a letter and a virama in either order; and a
        non-joiner after an Arabic letter."""
        if i == 0:
            return False
        before = cps[i - 1]
        if cps[i] == ZWNJ:
            return before in self.letters and self.script.word(before) == "ARABIC"
        if i + 1 == len(cps):
            return False
        after = cps[i + 1]
        if before in (VS15, VS16) and i >= 2:
            before = cps[i - 2]
        # The digits, "#" and "*" have the Emoji property too: no ASCII neighbour counts.
        return ((before >= 0x80 and before in self.emoji and after >= 0x80 and after in self.emoji) or (before in self.letters and self.ccc(after) == 9)
                or (self.ccc(before) == 9 and after in self.letters))

    def shown(self, s, lines):
        cps = [ord(c) for c in s]
        for i, cp in enumerate(cps):
            if cp in self.seen:
                continue
            if cp in (ZWJ, ZWNJ):
                if not self.joiner_allowed(cps, i) and not (lines and self.joiner_in_text(cps, i)):
                    return False
            elif cp in (VS15, VS16):
                if i == 0 or cps[i - 1] not in self.emoji:
                    return False
            elif lines and cp in (0x0A, 0x09, 0xA0, 0x202F, 0xAD):
                continue
            elif lines and cp == 0x0D and i + 1 < len(cps) and cps[i + 1] == 0x0A:
                continue
            else:
                return False
        return True

    def fold_name(self, s):
        """The form two names share exactly when they are one name."""
        plain = self.nfkc(s.strip(" "))
        folded = "".join(chr(self.fold.get(ord(c), ord(c))) for c in plain if ord(c) not in DRAWN_ONLY)
        return self.nfkc(folded)

    def mixes_scripts(self, name):
        """One word of the name holds letters of more than one of Latin, Greek
        and Cyrillic. A word is a run of letters and marks."""
        found = set()
        for ch in self.nfkc(name) + " ":
            cp = ord(ch)
            if cp in self.letters:
                if self.script.word(cp) in ("LATIN", "GREEK", "CYRILLIC"):
                    found.add(self.script.word(cp))
            elif cp in self.marks or cp in (ZWJ, ZWNJ):
                pass
            else:
                if len(found) > 1:
                    return True
                found = set()
        return False

    def problems(self):
        """Where this Python's own tables cover the pinned version, the normal
        forms made here are what this Python's own normaliser makes, for every
        seen character alone and for many strings of them, and the published
        case folds are what this Python folds. (Normalization and case folding
        of an assigned character never change between versions.)"""
        mine = tuple(int(x) for x in unicodedata.unidata_version.split("."))
        if mine < tuple(int(x) for x in self.version.split(".")):
            return []
        out, all_seen = [], [c for a, b in self.seen.rows for c in range(a, b + 1)]
        for c in all_seen:
            ch = chr(c)
            for form, compat in (("NFC", False), ("NFKC", True)):
                if self.normalized(ch, compat) != unicodedata.normalize(form, ch):
                    out.append("unicode data: %s of U+%04X is not what this Python makes" % (form, c))
            f = ch.casefold()
            simple = f if len(f) == 1 else (ch.lower() if len(ch.lower()) == 1 else ch)
            if chr(self.fold.get(c, c)) != simple:
                out.append("unicode data: the fold of U+%04X is not what this Python folds" % c)
            if len(out) > 20:
                return out
        rnd = random.Random(15)
        busy = sorted({c for c in all_seen if self.ccc(c) or c in self.nfd or c in self.nfkd} | {a for a, _ in self.compose} | {b for _, b in self.compose}
                      | set(range(0x1100, 0x1113)) | set(range(0x1161, 0x1176)) | set(range(0x11A8, 0x11C3)) | {0xAC00, 0xAC01, 0xAC1C} | set(range(0x41, 0x7B)))
        for _ in range(40000):
            s = "".join(chr(rnd.choice(busy)) for _ in range(rnd.randint(2, 6)))
            for form, compat in (("NFC", False), ("NFKC", True)):
                if self.normalized(s, compat) != unicodedata.normalize(form, s):
                    out.append("unicode data: %s of %r is not what this Python makes" % (form, [hex(ord(c)) for c in s]))
                    return out
        return out


U = None  # set in main


def line(s):
    """Every character reads as it is written, on one line."""
    return U.shown(s, False)


def shown(s):
    """line(), for text of several lines."""
    return U.shown(s, True)


# -- Reading JSON the one way every reader reads it ---------------------------

def strict(text_bytes):
    """One JSON value: valid UTF-8, no byte order mark, no member named twice, no
    half of a surrogate pair, no number too large for a 64-bit float, nothing
    after it, nested at most 64 deep."""
    try:
        s = text_bytes.decode("utf-8")
    except UnicodeDecodeError:
        raise Refused("not_json")

    def pairs(ps):
        seen = set()
        for k, _ in ps:
            if k in seen:
                raise Refused("not_json")
            seen.add(k)
        return dict(ps)

    def constant(_):
        raise Refused("not_json")

    def number(text):
        if float(text) in (float("inf"), float("-inf")):
            raise Refused("not_json")
        return Num(text)

    try:
        v = json.loads(s, object_pairs_hook=pairs, parse_int=number, parse_float=number, parse_constant=constant)
    except (ValueError, RecursionError):
        raise Refused("not_json")

    def walk(x, depth):
        if isinstance(x, str):
            if any(0xD800 <= ord(c) <= 0xDFFF for c in x):
                raise Refused("not_json")
        elif isinstance(x, (list, dict)):
            if depth >= MAX_DEPTH:
                raise Refused("not_json")
            if isinstance(x, dict):
                for k, e in x.items():
                    walk(k, depth + 1)
                    walk(e, depth + 1)
            else:
                for e in x:
                    walk(e, depth + 1)

    walk(v, 0)
    return v


def whole(n):
    """A whole number written plainly, exact in a 64-bit float."""
    return (isinstance(n, Num) and re.fullmatch(r"-?(0|[1-9][0-9]*)", n.s, re.ASCII) is not None and n.s != "-0"
            and abs(int(n.s)) <= 2 ** 53 - 1)


def text(v):
    """A member's value is text only when it is a JSON string."""
    return isinstance(v, str)


def canonical(v):
    """RFC 8785: members sorted by UTF-16 code units, no spaces, the shortest
    string escapes, whole numbers as they are."""
    if v is None:
        return "null"
    if v is True:
        return "true"
    if v is False:
        return "false"
    if isinstance(v, Num):
        return str(int(v.s))
    if isinstance(v, int):
        return str(v)
    if isinstance(v, str):
        return json.dumps(v, ensure_ascii=False)
    if isinstance(v, list):
        return "[" + ",".join(canonical(e) for e in v) + "]"
    keys = sorted(v, key=lambda k: k.encode("utf-16-be"))
    return "{" + ",".join(canonical(k) + ":" + canonical(v[k]) for k in keys) + "}"


def digest_of(v):
    return base.digest(canonical(v).encode("utf-8"))


def rest_of(own):
    return base.digest(REST_LABEL + canonical(own).encode("utf-8"))


# -- What text is shaped like -------------------------------------------------

KNOWN_SECRETS = re.compile("|".join([
    r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY( BLOCK)?-----",
    r"\bgh[pousr]_[A-Za-z0-9]{20,}",
    r"\bgithub_pat_[A-Za-z0-9_]{20,}",
    r"\bglpat-[A-Za-z0-9_-]{20,}",
    r"\bnpm_[A-Za-z0-9]{36}",
    r"\b[sr]k_live_[A-Za-z0-9]{10,}",
    r"\bxox[abprs]-[A-Za-z0-9-]{10,}",
    r"\bAKIA[0-9A-Z]{16}\b",
    r"\bAIza[0-9A-Za-z_-]{35}",
    r"\bAGE-SECRET-KEY-1[A-Z0-9]{20,}",
    r"\bSG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}",
    r"\beyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.",
]), re.ASCII)
SK_TOKEN = re.compile(r"\bsk-[A-Za-z0-9_-]+", re.ASCII)
PASSWORD_IN_ADDRESS = re.compile(r"[A-Za-z][A-Za-z0-9+.-]*://[^\t\n\f\r /?#@:]+:([^\t\n\f\r /?#@]+)@", re.ASCII)
PLACEHOLDER = re.compile(r"(?i:password|pass|passwd|pwd|secret|token|changeme|redacted|example|your[-_]password|[x*]+)"
                         r"|\$[A-Z0-9_]+|\$\{[A-Z0-9_]+\}|<[^<>]+>|\{[^{}]+\}|\{\{[^{}]+\}\}|\[[^\[\]]+\]|%s", re.ASCII)
SHAPES = ("", "identifier", "likely", "secret")


def canonical_44(run):
    """44 characters of qb64 under a one-character code, with zero lead bits."""
    try:
        base.qb64_raw("E", "E" + run[1:], 32)
        return True
    except ValueError:
        return False


def a_salt(run):
    """The whole run is a salt in CESR: 24 characters under the code 0A, 16
    bytes in canonical qb64."""
    try:
        base.qb64_raw("0A", run, 16)
        return True
    except ValueError:
        return False


def mixed(run):
    return bool(re.search("[A-Z]", run) and re.search("[a-z]", run) and re.search("[0-9]", run))


# Characters not seen as themselves that stand between words or lines, and so
# end a token: a tab, a line feed, a carriage return, a no-break space and a
# narrow no-break space. (A space is seen.)
ENDS_A_WORD = (0x09, 0x0A, 0x0D, 0xA0, 0x202F)


def without_unseen(s):
    """Text as a reader sees it: without every character that is not seen as
    itself, but those that end a word."""
    return "".join(c for c in s if ord(c) in U.seen or ord(c) in ENDS_A_WORD)


def shape(s):
    """'secret', 'likely' (what may be a secret), 'identifier' or '': the
    greatest found (the section "Text shaped like a secret or an identifier"),
    judged as a reader sees the text. It is a secret also when its
    compatibility form (NFKC) is one."""
    found = shape_seen(without_unseen(s))
    if found != "secret" and shape_seen(without_unseen(U.nfkc(s))) == "secret":
        return "secret"
    return found


def shape_seen(s):
    """The shape of text a reader sees all of."""
    if KNOWN_SECRETS.search(s):
        return "secret"
    for token in SK_TOKEN.findall(s):
        last = re.split("[-_]", token)[-1]  # after the last "-" or "_"
        if re.fullmatch("[A-Za-z0-9]{20,}", last) and re.search("[0-9]", last):
            return "secret"
    for password in PASSWORD_IN_ADDRESS.findall(s):
        if not PLACEHOLDER.fullmatch(password):
            return "secret"
    found = 0
    for run in re.findall(r"[A-Za-z0-9_-]+", s, re.ASCII):
        hexadecimal = re.fullmatch(r"[0-9a-fA-F]+", run) and re.search("[0-9]", run) and re.search("[A-Za-z]", run)
        if (len(run) == 44 and run[0] == "A" and mixed(run) and canonical_44(run)) or a_salt(run):
            return "secret"
        if (len(run) == 44 and run[0] in "EDB" and canonical_44(run)) or (len(run) == 48 and run.startswith("1AAI")):
            found = max(found, 1)
        elif hexadecimal and len(run) >= 64:
            found = max(found, 2)
        elif hexadecimal and len(run) >= 32:
            found = max(found, 1)
        elif (len(run) >= 40 and re.search("[A-Z]", run) and re.search("[a-z]", run)
              and len(re.findall("[0-9]+", run)) >= 3):
            found = max(found, 2)
    return SHAPES[found]


def is_digest(s):
    try:
        base.qb64_raw("E", s, 32)
        return True
    except (ValueError, TypeError, AttributeError):
        return False


def is_identifier(s):
    """An identifier by its CESR code: E, D or B (32 bytes; a D or B value is
    also a point of the curve) or 1AAI (33 bytes)."""
    if not isinstance(s, str):
        return False
    try:
        if s[:1] == "E":
            base.qb64_raw("E", s, 32)
        elif s[:1] in ("D", "B"):
            base._point(base.qb64_raw(s[0], s, 32))
        elif s.startswith("1AAI"):
            base.qb64_raw("1AAI", s, 33)
        else:
            return False
        return True
    except ValueError:
        return False


def name_code(s):
    """Why s is not a name, or ''."""
    if not isinstance(s, str) or s == "" or len(s.encode()) > MAX_NAME:
        return "bad_name"
    if not line(s) or s != s.strip(" ") or "  " in s or "@" in s:
        return "bad_name"
    if U.nfc(s) != s or U.mixes_scripts(s):
        return "bad_name"
    return "name_identifier_shaped" if shape(s) else ""


def fold(s):
    """Names are one name when this is equal."""
    return U.fold_name(s)


def a_time(s):
    if not isinstance(s, str) or not re.fullmatch(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z", s, re.ASCII):
        return None
    y, mo, d, h, mi, sec = (int(x) for x in re.findall(r"[0-9]+", s))
    try:
        return datetime.datetime(y, mo, d, h, mi, sec)  # a year from 0001
    except ValueError:
        return None


KIND = re.compile(r"[a-z][a-z0-9_]*(\.[a-z][a-z0-9_]*)*")
CAPABILITY = re.compile(r"[a-z][a-z0-9_]*(\.[a-z][a-z0-9_]*)+")
WORD = re.compile(r"[a-z][a-z0-9_]{0,63}")


def a_kind(s):
    return isinstance(s, str) and len(s) <= MAX_KIND and KIND.fullmatch(s) is not None


# -- A website's origin, in its one spelling ----------------------------------

def host_ok(h):
    if h == "" or len(h) > 253:
        return False
    last = h.rsplit(".", 1)[-1]
    if re.fullmatch(r"(?i)0x[0-9a-f]*|[0-9]+", last, re.ASCII):
        try:
            if str(ipaddress.IPv4Address(h)) != h:
                return False
        except ValueError:
            return False
    return all(lab and len(lab) <= 63 and lab[0] != "-" and lab[-1] != "-" and re.fullmatch(r"[a-z0-9-]+", lab)
               for lab in h.split("."))


def origin_ok(o):
    if not isinstance(o, str) or len(o.encode()) > MAX_ORIGIN or "://" not in o:
        return False
    scheme, rest = o.split("://", 1)
    own = {"https": "443", "http": "80"}.get(scheme)
    if own is None:
        return False
    if rest.rfind(":") > rest.rfind("]"):
        host, port = rest.rsplit(":", 1)
        if port == own:
            return False
    else:
        host, port = rest, own
    if not (re.fullmatch("[0-9]+", port) and str(int(port)) == port and 1 <= int(port) <= 65535):
        return False
    if host.startswith("["):
        if not host.endswith("]"):
            return False
        try:
            ip = ipaddress.IPv6Address(host[1:-1])
        except ValueError:
            return False
        return ip.ipv4_mapped is None and "%" not in host and str(ip) == host[1:-1]
    return host_ok(host)


# -- The kinds this reader knows ----------------------------------------------

class Reading:
    def __init__(self):
        self.blocks, self.flags, self.credentials, self.identifiers, self.prose, self.utility_apps = [], [], [], [], [], []
        self.read = True  # False when the kind's own fields could not be read
        self.same = ""    # what makes two items of the kind one thing


def website(own, common, r):
    if set(own) - {"origin", "policy"}:
        r.read = False
        return r.blocks.append("unknown_field")
    policy = own.get("policy")
    if not text(own.get("origin")) or own["origin"] == "" or not isinstance(policy, dict):
        r.read = False
        return r.blocks.append("bad_field")
    members = ("mode", "membership_source", "required_cred_schema", "required_cred_issuer")
    if set(policy) - set(members):
        r.read = False
        return r.blocks.append("unknown_field")
    if any(not text(policy[m]) for m in policy):
        r.read = False
        return r.blocks.append("bad_field")
    mode, source, schema, issuer = (policy.get(m, "") for m in members)
    if common["permissions"] or common["limits"] or common["grant_end"]:
        r.blocks.append("bad_field")
    if not origin_ok(own["origin"]):
        r.blocks.append("bad_field")
    if mode not in ("open", "request", "invite"):
        r.blocks.append("bad_field")
    if source not in ("", "asset"):
        if re.fullmatch(r"[a-z][a-z0-9_-]{0,63}", source):
            r.flags.append("needs_set_up_here")
        else:
            r.blocks.append("bad_field")
    if schema != "" and not is_digest(schema):
        r.blocks.append("bad_field")
    if issuer != "" and schema == "":
        r.blocks.append("bad_field")
    if issuer not in ("", "self") and not is_identifier(issuer):
        r.blocks.append("bad_field")
    r.identifiers += ["policy.required_cred_schema", "policy.required_cred_issuer"]
    r.same = own["origin"]


def example_worker(own, common, r, allowed=("note", "title", "credential", "reports_to")):
    if set(own) - set(allowed):
        r.read = False
        return r.blocks.append("unknown_field")
    if any(not text(own[m]) for m in own):
        r.read = False
        return r.blocks.append("bad_field")
    note, title, credential, reports_to = (own.get(m, "") for m in ("note", "title", "credential", "reports_to"))
    if len(note.encode()) > 200 or len(title.encode()) > 200:
        r.blocks.append("bad_field")
    if reports_to != "":
        if name_code(reports_to):
            r.blocks.append("bad_field")
        else:
            r.utility_apps.append(reports_to)  # a field of the kind names a utility app
    if credential != "":
        if name_code(credential):
            r.blocks.append("bad_field")
        r.credentials.append(credential)
    r.prose.append("note")


def example_utility_app(own, common, r):
    example_worker(own, common, r, allowed=("note",))


def example_labels(value, r):
    if not isinstance(value, dict):
        return r.blocks.append("bad_field")
    if set(value) - {"label"}:
        return r.blocks.append("unknown_field")
    if not text(value.get("label")) or not WORD.fullmatch(value["label"]):
        r.blocks.append("bad_field")


KINDS = {"website": website, "example.worker": example_worker, "example.utility_app": example_utility_app}
UTILITY_APP_KINDS = {"example.utility_app"}
EXTENSIONS = {"example.labels": example_labels}


# -- What every item carries --------------------------------------------------

def on_app(p):
    return isinstance(p, dict)


def permission_ok(p):
    return text(p) or (isinstance(p, dict) and set(p) == {"utility_app", "permission"}
                       and all(text(x) and x for x in p.values()))


def permission_key(p):
    """What two permissions share exactly when they are one permission."""
    return ("on", fold(p["utility_app"]), p["permission"]) if on_app(p) else ("may", p)


def read_common(item, knows, now):
    """(common, blocks, flags): the members every item may carry."""
    common, blocks, flags = {"permissions": [], "limits": {}, "grant_end": ""}, [], []
    if "permissions" in item:
        ps = item["permissions"]
        if not (isinstance(ps, list) and len(ps) <= MAX_PERMISSIONS and all(permission_ok(p) for p in ps)):
            blocks.append("bad_field")
        else:
            seen = set()
            for p in ps:
                if not on_app(p) and (len(p.encode()) > 128 or not CAPABILITY.fullmatch(p) or shape(p)):
                    blocks.append("bad_field")
                elif on_app(p) and not WORD.fullmatch(p["permission"]):
                    blocks.append("bad_field")
                elif on_app(p) and name_code(p["utility_app"]):
                    blocks.append("bad_field")
                elif permission_key(p) in seen:
                    blocks.append("bad_field")
                elif knows is not None and not (text(p) and p in knows):
                    blocks.append("unknown_permission")
                seen.add(permission_key(p))
            common["permissions"] = ps
    if "limits" in item:
        ls = item["limits"]
        ok = isinstance(ls, dict) and all(
            isinstance(args, dict) and all(isinstance(vs, list) and all(text(v) for v in vs) for vs in args.values())
            for args in ls.values())
        if not ok:
            blocks.append("bad_field")
        else:
            common["limits"] = ls
            # A limit is on a capability: a permission on a utility app holds
            # no place here.
            held = {p for p in common["permissions"] if not on_app(p)}
            for capability in sorted(ls):
                args = ls[capability]
                if capability not in held:
                    blocks.append("limit_without_permission")
                    continue
                if not 1 <= len(args) <= MAX_ARGUMENTS:
                    blocks.append("bad_field")
                    continue
                for argument, values in args.items():
                    if (not WORD.fullmatch(argument) or not 1 <= len(values) <= MAX_VALUES or len(set(values)) != len(values)
                            or any(v == "" or len(v.encode()) > MAX_VALUE or not line(v) for v in values)):
                        blocks.append("bad_field")
                flags.append("needs_access_here")
    if "grant_end" in item:
        end = a_time(item["grant_end"])
        if end is None:
            blocks.append("bad_field")
        else:
            common["grant_end"] = item["grant_end"]
            if now is not None and end <= now:
                blocks.append("grant_ended")
    return common, blocks, flags


def item_text(v, where, r, blocks, flags):
    """Text too long, not seen as itself, what may be a secret, or shaped like
    an identifier outside a member declared to hold one or declared prose."""
    if isinstance(v, str):
        member = re.sub(r"\[[0-9]+\]", "", where)
        if r.read and where in r.identifiers:
            if v in ("", "self"):
                pass
            elif is_identifier(v):
                flags.append("needs_access_here")
            else:
                blocks.append("bad_field")
        elif where in ("name", "kind") or where.startswith("permissions["):
            pass
        elif len(v.encode()) > MAX_TEXT:
            blocks.append("text_too_long")
        elif not shown(v):
            blocks.append("hidden_character")
        elif shape(v) == "likely":
            blocks.append("looks_like_a_secret")
        elif shape(v) == "identifier":
            if not r.read or where.startswith("limits."):
                pass
            elif member in r.prose:
                flags.append("identifier_in_text")
            else:
                blocks.append("identifier_shaped")
    elif isinstance(v, list):
        for i, e in enumerate(v):
            item_text(e, "%s[%d]" % (where, i), r, blocks, flags)
    elif isinstance(v, dict):
        for k in sorted(v):
            if len(k.encode()) > MAX_MEMBER or not line(k) or shape(k):
                blocks.append("bad_field")
            item_text(v[k], (where + "." + k) if where else k, r, blocks, flags)


def read_item(item, knows, now, needed):
    out = {"kind": "", "name": "", "state": "ready", "blocks": [], "flags": [], "rest": "", "utility_apps": [], "named_by_fields": [],
           "credentials": [], "same": "", "is_utility_app": False, "permissions": [], "limits": {}, "grant_end": ""}
    if not isinstance(item, dict):
        out["state"], out["blocks"] = "blocked", ["not_an_object"]
        return out
    blocks, flags = [], []
    if a_kind(item.get("kind")):
        out["kind"] = item["kind"]
    else:
        blocks.append("bad_field")
    # A name that is not a name is not kept: an item is listed by a name only
    # when it has one.
    if not text(item.get("name")):
        blocks.append("bad_name")
    elif name_code(item["name"]):
        blocks.append(name_code(item["name"]))
    else:
        out["name"] = item["name"]
    own = {k: v for k, v in item.items() if k not in COMMON}
    out["rest"] = rest_of(own)
    if out["kind"] and out["kind"] not in KINDS:
        out["state"], out["blocks"] = "not_understood", sorted(set(blocks) | {"unknown_kind"})
        return out
    common, b, f = read_common(item, knows, now)
    out.update(common)
    blocks += b
    flags += f
    if out["kind"]:
        out["is_utility_app"] = out["kind"] in UTILITY_APP_KINDS
        r = Reading()
        has_extensions = "extensions" in own
        extensions = own.pop("extensions", None)
        KINDS[out["kind"]](own, common, r)
        if not r.read:
            r.identifiers, r.prose, r.same, r.credentials, r.utility_apps = [], [], "", [], []
        out["same"] = r.same
        if has_extensions:
            if not isinstance(extensions, dict):
                r.blocks.append("bad_field")
            else:
                for ns in sorted(extensions):
                    if ns not in EXTENSIONS:
                        r.blocks.append("unknown_extension")
                    else:
                        EXTENSIONS[ns](extensions[ns], r)
        seen = set()
        for n in r.utility_apps:
            if fold(n) not in seen:
                seen.add(fold(n))
                out["named_by_fields"].append(n)
        seen = set()
        for n in [p["utility_app"] for p in common["permissions"] if on_app(p)] + r.utility_apps:
            if fold(n) not in seen:
                seen.add(fold(n))
                out["utility_apps"].append(n)
        out["credentials"] = r.credentials
        for c in r.credentials:
            if fold(c) not in needed:
                r.blocks.append("unknown_credential")
        blocks += r.blocks
        flags += r.flags
        item_text(item, "", r, blocks, flags)
    out["blocks"], out["flags"] = sorted(set(blocks)), sorted(set(flags))
    if out["blocks"]:
        out["state"] = "blocked"
    return out


# -- A file -------------------------------------------------------------------

def refused_whole(v):
    """Three passes, so the reason does not depend on the order of the file's
    members: a spelling only a secret has, in a value or a member's name; then
    a null; then a number that is not whole."""
    def walk(x, what):
        if what == 0 and isinstance(x, str) and shape(x) == "secret":
            raise Refused("secret_shaped")
        if what == 1 and x is None:
            raise Refused("null_value")
        if what == 2 and isinstance(x, Num) and not whole(x):
            raise Refused("bad_number")
        if isinstance(x, list):
            for e in x:
                walk(e, what)
        elif isinstance(x, dict):
            for k in x:
                if what == 0 and shape(k) == "secret":
                    raise Refused("secret_shaped")
                walk(x[k], what)

    for what in range(3):
        walk(v, what)


def read_seal(seal):
    if not isinstance(seal, dict) or set(seal) != {"by", "kel_sn", "contents", "signature"}:
        raise Refused("bad_seal")
    by, sn, contents, sig = seal["by"], seal["kel_sn"], seal["contents"], seal["signature"]
    if not (whole(sn) and int(sn.s) >= 0 and is_identifier(by) and is_digest(contents) and text(sig)):
        raise Refused("bad_seal")
    try:
        raw = base.qb64_raw("AA", sig, 64)  # code A, index 0
    except ValueError:
        raise Refused("bad_seal")
    return {"by": by, "kel_sn": int(sn.s), "contents": contents, "raw": raw}


def seal_input(by, contents, kel_sn):
    return ("statement-signature/1\nasker: %s\n\nset-up-seal/1\ncontents=%s\nkel-sn=%d" % (by, contents, kel_sn)).encode()


def note_flags(s, flags):
    if shape(s) == "likely":
        flags.append("looks_like_a_secret")
    elif shape(s) == "identifier":
        flags.append("identifier_in_text")


def read_file(text_bytes, v, keys):
    """A file as a reader that knows what the vector v says it knows."""
    knows = v.get("knows")
    now = a_time(v["now"]) if v.get("now") else None
    if len(text_bytes) > MAX_FILE:
        raise Refused("too_large")
    top = strict(text_bytes)
    if not isinstance(top, dict):
        raise Refused("not_json")
    m = re.fullmatch(r"identity-agent-set-up/([1-9][0-9]{0,3})", top["format"], re.ASCII) if text(top.get("format")) else None
    if m is None:
        raise Refused("not_a_set_up_file")
    if int(m.group(1)) > 1:
        raise Refused("newer_version")
    contents = {k: x for k, x in top.items() if k != "seal"}
    refused_whole(contents)
    if set(top) - set(TOP):
        raise Refused("unknown_field")
    flags = []
    if "made_at" in top and a_time(top["made_at"]) is None:
        raise Refused("bad_field")
    if "about" in top:
        if not (text(top["about"]) and len(top["about"].encode()) <= MAX_ABOUT and shown(top["about"])):
            raise Refused("bad_field")
        note_flags(top["about"], flags)
    needed, needs = set(), []
    if "credentials_needed" in top:
        cs = top["credentials_needed"]
        if not isinstance(cs, list) or len(cs) > MAX_CREDENTIALS:
            raise Refused("bad_field")
        for c in cs:
            if not isinstance(c, dict) or set(c) - {"name", "about"}:
                raise Refused("bad_field")
            if not text(c.get("name")):
                raise Refused("bad_name")
            if name_code(c["name"]):
                raise Refused(name_code(c["name"]))
            if fold(c["name"]) in needed:
                raise Refused("duplicate_name")
            needed.add(fold(c["name"]))
            needs.append(c["name"])
            if "about" in c:
                if not text(c["about"]) or len(c["about"].encode()) > MAX_ABOUT or not shown(c["about"]):
                    raise Refused("bad_field")
                note_flags(c["about"], flags)
    seal = read_seal(top["seal"]) if "seal" in top else None
    result = {"contents": digest_of(contents), "flags": sorted(set(flags)), "items": [], "needs": needs,
              "seal": "unsealed", "sealed_by": "", "seal_input": "", "the_seal": seal}
    items = top.get("items")
    if not isinstance(items, list):
        raise Refused("bad_field")
    if len(items) > MAX_ITEMS:
        raise Refused("too_many_items")
    names, same = {}, {}
    for i, raw in enumerate(items):
        it = read_item(raw, knows, now, needed)

        def block(code):
            if it["state"] != "not_understood":
                it["state"] = "blocked"
            it["blocks"] = sorted(set(it["blocks"]) | {code})

        if it["name"] and "bad_name" not in it["blocks"] and "name_identifier_shaped" not in it["blocks"]:
            if fold(it["name"]) in names:
                block("duplicate_name")
            else:
                names[fold(it["name"])] = i
        if it["same"]:
            key = (it["kind"], it["same"])
            if key in same:
                block("duplicate_item")
            else:
                same[key] = i
        result["items"].append(it)
    for i, it in enumerate(result["items"]):
        it["depends_on"] = []
        for n in it["utility_apps"]:
            j = names.get(fold(n))
            if j is not None and j != i and result["items"][j]["is_utility_app"]:
                it["depends_on"].append(result["items"][j]["name"])
            elif it["state"] != "not_understood":
                it["flags"] = sorted(set(it["flags"]) | {"needs_set_up_here"})
    if seal is not None:
        signed = seal_input(seal["by"], seal["contents"], seal["kel_sn"])
        result["seal_input"] = signed.decode()
        # The reader holds, for each identity in keys, a key log of one event,
        # at 0; the signature is checked before the contents are compared.
        name = next((n for n, k in keys.items() if k["identifier"] == seal["by"]), None)
        if v.get("no_key_log") or name is None or seal["kel_sn"] != 0:
            result["seal"] = "unchecked"
        elif not base.ed25519_verify(base.qb64_raw("D", keys[name]["key"], 32), seal["raw"], signed):
            result["seal"] = "broken"
        elif seal["contents"] != result["contents"]:
            result["seal"] = "changed"  # a seal made for other contents names nobody
        else:
            result["sealed_by"] = seal["by"]
            result["seal"] = "sealed_by_an_earlier_key" if name in v.get("earlier_keys", []) else "sealed"
    return result


# -- A chosen list ------------------------------------------------------------

VERIFIED = ("sealed", "sealed_by_an_earlier_key")  # the states that name a sealer


def check_list(a, needs):
    """Why a chosen list is refused: raises Refused, or returns."""
    def bad():
        raise Refused("bad_approval")

    if not isinstance(a, dict) or set(a) != {"format", "identity_agent", "proposal", "nonce", "source", "items", "utility_apps", "credentials"}:
        bad()
    src = a["source"]
    if not isinstance(src, dict) or set(src) != {"contents", "seal", "sealed_by"}:
        bad()
    if a["format"] != "identity-agent-set-up-approval/1" or not is_identifier(a["identity_agent"]):
        bad()
    if not (text(a["proposal"]) and re.fullmatch(r"[A-Za-z0-9_-]{16,128}", a["proposal"], re.ASCII)):
        bad()
    if not (text(a["nonce"]) and re.fullmatch(r"[A-Za-z0-9_-]{22,128}", a["nonce"], re.ASCII)):
        bad()
    if not is_digest(src["contents"]) or src["seal"] not in VERIFIED + ("unsealed", "changed", "broken", "unchecked") or not text(src["sealed_by"]):
        bad()
    verified = src["seal"] in VERIFIED
    if verified != (src["sealed_by"] != "") or (verified and not is_identifier(src["sealed_by"])):
        bad()
    items = a["items"]
    if not isinstance(items, list) or not 1 <= len(items) <= MAX_ITEMS:
        bad()
    if not isinstance(a["utility_apps"], list) or not isinstance(a["credentials"], list):
        bad()
    names, named, previous = set(), [], -1
    for c in items:
        if not isinstance(c, dict) or set(c) != {"item", "operation", "kind", "name", "permissions", "limits", "grant_end", "rest", "acknowledged", "utility_apps"}:
            bad()
        if c["operation"] in ("change", "remove"):
            raise Refused("not_built")
        if c["operation"] != "create":
            bad()
        if not whole(c["item"]) or int(c["item"].s) <= previous:
            bad()
        previous = int(c["item"].s)
        if not isinstance(c["permissions"], list) or not isinstance(c["limits"], dict) or not isinstance(c["acknowledged"], list):
            bad()
        if not all(permission_ok(p) for p in c["permissions"] + c["acknowledged"]) or not text(c["grant_end"]):
            bad()
        fields_name = c["utility_apps"]
        if not isinstance(fields_name, list) or any(name_code(n) for n in fields_name) or len({fold(n) for n in fields_name}) != len(fields_name):
            bad()
        probe = {"permissions": c["permissions"], "limits": c["limits"]}
        if c["grant_end"] != "":
            probe["grant_end"] = c["grant_end"]
        _, blocks, _ = read_common(probe, None, None)
        if not a_kind(c["kind"]) or name_code(c["name"]) or blocks or fold(c["name"]) in names or not is_digest(c["rest"]):
            bad()
        names.add(fold(c["name"]))
        held = [permission_key(p) for p in c["permissions"]]
        at = 0
        for p in c["acknowledged"]:  # some of the permissions, in their order
            while at < len(held) and held[at] != permission_key(p):
                at += 1
            if at == len(held):
                bad()
            at += 1
        acknowledged = {permission_key(p) for p in c["acknowledged"]}
        for p in c["permissions"]:
            if text(p) and p in needs and permission_key(p) not in acknowledged:
                raise Refused("not_acknowledged")
        for n in [p["utility_app"] for p in c["permissions"] if on_app(p)] + fields_name:
            if fold(n) not in [fold(x) for x in named]:
                named.append(n)
    if len(named) != len(a["utility_apps"]):
        bad()
    for want, u in zip(named, a["utility_apps"]):
        if not isinstance(u, dict) or set(u) != {"name", "is", "identifier"} or u["name"] != want or not text(u["identifier"]):
            bad()
        if u["is"] == "item":
            if u["identifier"] != "" or fold(u["name"]) not in names:
                bad()
        elif u["is"] == "existing":
            if not is_identifier(u["identifier"]) or fold(u["name"]) in names:
                bad()
        else:
            bad()
    seen = set()
    for c in a["credentials"]:
        if not isinstance(c, dict) or set(c) != {"name", "use"} or not text(c["use"]):
            bad()
        if name_code(c["name"]) or (c["use"] != "" and name_code(c["use"])) or fold(c["name"]) in seen:
            bad()
        seen.add(fold(c["name"]))


def approve(r, choice, needs):
    """The chosen list a choice from a read file gives, as canonical bytes."""
    def bad():
        raise Refused("bad_approval")

    verified = r["seal"] in VERIFIED
    a = {"format": "identity-agent-set-up-approval/1", "identity_agent": choice["identity_agent"], "proposal": choice["proposal"],
         "nonce": choice["nonce"],
         "source": {"contents": r["contents"], "seal": r["seal"], "sealed_by": r["sealed_by"] if verified else ""},
         "items": [], "utility_apps": [], "credentials": []}
    picks = sorted(choice["items"], key=lambda p: p["index"])  # the file's order
    needed = set()
    for n, p in enumerate(picks):
        if not 0 <= p["index"] < len(r["items"]) or (n and picks[n - 1]["index"] == p["index"]):
            bad()
        it = r["items"][p["index"]]
        if it["state"] != "ready":
            bad()
        wanted = [permission_key(x) for x in p["acknowledged"]]
        held = [permission_key(x) for x in it["permissions"]]
        if set(wanted) - set(held) or len(set(wanted)) != len(wanted):
            bad()
        needed.update(fold(c) for c in it["credentials"])
        a["items"].append({"item": p["index"], "operation": "create", "kind": it["kind"], "name": it["name"],
                           "permissions": it["permissions"], "limits": it["limits"], "grant_end": it["grant_end"], "rest": it["rest"],
                           "acknowledged": [x for x in it["permissions"] if permission_key(x) in wanted],
                           "utility_apps": it["named_by_fields"]})
    # Two keys that are one name give no list.
    mapped = {fold(k): x for k, x in choice["utility_apps"].items()}
    uses = {fold(k): x for k, x in choice["credentials"].items()}
    if len(mapped) != len(choice["utility_apps"]) or len(uses) != len(choice["credentials"]):
        bad()
    named = []
    for c in a["items"]:
        for n in [p["utility_app"] for p in c["permissions"] if on_app(p)] + c["utility_apps"]:
            if fold(n) not in [fold(x) for x in named]:
                named.append(n)
    for name in named:
        chosen = any(r["items"][p["index"]]["is_utility_app"] and fold(r["items"][p["index"]]["name"]) == fold(name) for p in picks)
        existing = fold(name) in mapped
        if chosen == existing:
            bad()
        a["utility_apps"].append({"name": name, "is": "item" if chosen else "existing", "identifier": "" if chosen else mapped.pop(fold(name))})
    if mapped:
        bad()
    for name in r["needs"]:
        if fold(name) in needed:
            a["credentials"].append({"name": name, "use": uses.get(fold(name), "")})
        uses.pop(fold(name), None)
    if uses:
        bad()
    wire = json.loads(canonical(a), parse_int=Num)
    check_list(wire, needs)
    return canonical(a).encode("utf-8")


def read_list(raw, needs):
    """The bytes of a chosen list as a device is handed them."""
    try:
        a = strict(raw)
    except Refused:
        raise Refused("bad_approval")

    def no_null(x):
        if x is None:
            raise Refused("bad_approval")
        for e in (x.values() if isinstance(x, dict) else x if isinstance(x, list) else ()):
            no_null(e)

    no_null(a)
    check_list(a, needs)
    if canonical(a).encode("utf-8") != raw:
        raise Refused("bad_approval")


# -- The vectors --------------------------------------------------------------

def main():
    global U
    with open(sys.argv[1], "rb") as f:
        vectors = json.loads(f.read().decode("utf-8"))
    U = Unicode(os.path.join(os.path.dirname(os.path.abspath(sys.argv[1])), "unicode-15.0.json"))
    problems = U.problems()

    def same(what, got, want):
        if got != want:
            problems.append("%s: this check makes %r, the file says %r" % (what, got, want))

    for name, k in vectors["keys"].items():
        same("the seed of " + name, hashlib.sha256(k["seed_of"].encode()).hexdigest(), k["seed"])
    files = {}
    for v in vectors["files"]:
        data = bytes.fromhex(v["file_hex"]) if v.get("file_hex") else v["file"].encode("utf-8", "surrogatepass")
        try:
            got = read_file(data, v, vectors["keys"])
        except Refused as r:
            same(v["name"] + ": refused", str(r), v["refused"])
            continue
        files[v["name"]] = got
        same(v["name"] + ": refused", "", v["refused"])
        same(v["name"] + ": contents", got["contents"], v.get("contents"))
        same(v["name"] + ": flags", got["flags"], v.get("flags", []))
        same(v["name"] + ": seal", got["seal"], v.get("seal"))
        same(v["name"] + ": sealed by", got["sealed_by"], v.get("sealed_by", ""))
        same(v["name"] + ": seal input", got["seal_input"], v.get("seal_input", ""))
        want = v.get("items") or []
        same(v["name"] + ": how many items", len(got["items"]), len(want))
        for g, w in zip(got["items"], want):
            for member in ("kind", "name", "state", "blocks", "flags", "rest", "utility_apps", "depends_on", "credentials"):
                same("%s: %s of %r" % (v["name"], member, w["name"]), g[member], w[member])
    for v in vectors["approvals"]:
        try:
            got = approve(files[v["from"]], v["choice"], set(v["needs_acknowledging"]))
        except Refused as r:
            same(v["name"] + ": refused", str(r), v["refused"])
            continue
        same(v["name"] + ": refused", "", v["refused"])
        same(v["name"] + ": bytes", got.decode(), v.get("bytes"))
        same(v["name"] + ": digest", base.digest(got), v.get("digest"))
    for v in vectors["lists"]:
        try:
            read_list(v["list"].encode("utf-8"), set(v["needs_acknowledging"]))
            same(v["name"] + ": refused", "", v["refused"])
        except Refused as r:
            same(v["name"] + ": refused", str(r), v["refused"])
    if problems:
        print("\n".join(problems[:60]))
        sys.exit(1)
    print("%d files, %d choices and %d lists agree" % (len(vectors["files"]), len(vectors["approvals"]), len(vectors["lists"])))


if __name__ == "__main__":
    main()
