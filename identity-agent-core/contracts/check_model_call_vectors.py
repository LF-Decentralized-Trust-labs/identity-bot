#!/usr/bin/env python3
"""An independent check of the model-call vector file, written without Go.

Everything here is rebuilt from the prose in model-call/model-call.schema.json,
not from the Go code: which calls a body may start and how each refused one is
answered, the query and headers that travel on, the collection paths and how a
collection's query is read, the refusal statuses, and the answers' offsets. The
provider's routes, headers, query parameters and answer-length names come from
the vector file's example profile, as an Identity Agent's come from its own
profile for each provider. If this script and the vector file ever disagree,
the prose no longer says what the code does.

Run: python3 check_model_call_vectors.py model-call-vectors.json
Needs nothing beyond the Python standard library.
"""
import base64
import binascii
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
failures = []

REQUEST_LARGEST = 3 * 1024 * 1024
START_LARGEST = 6 * 1024 * 1024
PART_LARGEST = 2 * 1024 * 1024
PATH_LONGEST = 256
ANSWER_LONGEST = 32768
DEPTH_DEEPEST = 1000
PLAIN = set("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789.-_:/~")
FORM_SAFE = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_.~"
PATH_SAFE = FORM_SAFE + b"$&+:=@"
# The headers that never travel, whatever a profile lists, as the request
# definition's prose and the answer's header prose name them.
NEVER_ON = ["Authorization", "Authentication", "Proxy-Authorization", "Cookie", "Cookie2", "Set-Cookie", "Set-Cookie2",
            "X-Api-Key", "Api-Key", "X-Auth-Token", "Host", "Content-Length", "Transfer-Encoding", "Connection", "Keep-Alive",
            "Proxy-Connection", "TE", "Trailer", "Upgrade", "Expect"]
NEVER_BACK = list(NEVER_ON)
# The characters of an HTTP header name (RFC 9110 token).
TOKEN = set("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!#$%&'*+-.^_`|~")

# The refusal statuses, by reason, as the refusal definition's prose lists them:
# (status, says refused, says no_call).
REASONS = {
    "no_lease": (400, False, False),
    "too_large": (413, False, False),
    "not_allowed": (403, True, False),
    "allowance": (403, True, False),
    "collected_already": (409, False, False),
    "gone": (410, False, True),
    "too_many_held": (429, False, False),
    "one_at_a_time": (429, True, False),
    "unreadable": (503, True, False),
    "not_kept": (503, False, False),
    "unreachable": (503, False, False),
}


def fold(s):
    """ASCII letters in lower case; nothing outside ASCII folds."""
    return "".join(chr(ord(c) + 32) if "A" <= c <= "Z" else c for c in s)


def upper(s):
    return "".join(chr(ord(c) - 32) if "a" <= c <= "z" else c for c in s)


def fail(what):
    failures.append(what)
    print("MISMATCH " + what)


def same(what, got, want):
    if got != want:
        fail("%s:\n  python %r\n  file   %r" % (what, got, want))


class Refused(Exception):
    def __init__(self, reason):
        Exception.__init__(self, reason)
        self.reason = reason


# ── the path and the route ───────────────────────────────────────────────


def plain_chars(s):
    return all(c in PLAIN for c in s)


def plain_path(p):
    if len(p.encode()) > PATH_LONGEST or not p.startswith("/") or not plain_chars(p):
        return False
    if p == "/":
        return True
    return all(seg not in ("", ".", "..") for seg in p[1:].split("/"))


def route_of(profile, method, p):
    if method not in ("GET", "POST") or not plain_path(p):
        return None
    models = profile.get("models_path", "")
    for r in profile["routes"]:
        if r["method"] != method:
            continue
        if p == r["path"]:
            return r
        if method == "GET" and models and r["path"] == models and p.startswith(models + "/"):
            return r
    return None


# ── the query ────────────────────────────────────────────────────────────


def form_decode(s):
    """+ as a space, %XX as a byte; None for a broken escape."""
    out = bytearray()
    raw = s.encode()
    i = 0
    while i < len(raw):
        c = raw[i]
        if c == ord("%"):
            h = raw[i + 1:i + 3]
            if len(h) != 2 or any(x not in b"0123456789abcdefABCDEF" for x in h):
                return None
            out.append(int(h, 16))
            i += 3
            continue
        out.append(ord(" ") if c == ord("+") else c)
        i += 1
    return out.decode("utf-8", errors="replace")


def form_pieces(raw, skip=False):
    """The query's names and values in order. A piece that is unreadable makes
    the whole query unreadable (None), or, with skip, is skipped."""
    pairs = []
    for piece in raw.split("&"):
        if piece == "":
            continue
        name, _, value = piece.partition("=")
        name, value = form_decode(name), form_decode(value)
        if ";" in piece or name is None or value is None:
            if skip:
                continue
            return None
        pairs.append((name, value))
    return pairs


def form_encode(s, safe):
    out = []
    for b in s.encode():
        if b in safe:
            out.append(chr(b))
        elif b == ord(" ") and safe is FORM_SAFE:
            out.append("+")
        else:
            out.append("%%%02X" % b)
    return "".join(out)


def parameter_allows(p, v):
    if p.get("value"):
        return v == p["value"]
    if p.get("digits"):
        return len(v.encode()) <= p["digits"] and all(c in "0123456789" for c in v)
    if p.get("plain"):
        return len(v.encode()) <= p["plain"] and plain_chars(v)
    return False


def query(profile, raw):
    if raw == "":
        return ""
    pairs = form_pieces(raw)
    if pairs is None:
        raise Refused("not_allowed")
    names = [n for n, _ in pairs]
    by = {}
    for n, v in pairs:
        p = next((q for q in profile["query"] if q["name"] == n), None)
        if p is None or names.count(n) != 1 or not parameter_allows(p, v):
            raise Refused("not_allowed")
        by[n] = v
    return "&".join(form_encode(n, FORM_SAFE) + "=" + form_encode(by[n], FORM_SAFE) for n in sorted(by))


# ── the headers ──────────────────────────────────────────────────────────


def pick(names, sent, never):
    out = {}
    never = {fold(n).replace("_", "-") for n in never}
    for name in names:
        if fold(name).replace("_", "-") in never:
            continue
        for k in sorted(sent):
            if fold(k) == fold(name) and sent[k] != "":
                out[name] = sent[k]
                break
    return out


# ── the body ─────────────────────────────────────────────────────────────


def no_constants(c):
    raise ValueError("not JSON: " + c)


def depth(text):
    n = most = 0
    in_string = escaped = False
    for c in text:
        if in_string:
            if escaped:
                escaped = False
            elif c == "\\":
                escaped = True
            elif c == '"':
                in_string = False
        elif c == '"':
            in_string = True
        elif c in "[{":
            n += 1
            most = max(most, n)
        elif c in "]}":
            n -= 1
    return most


def one_object(body):
    """The object's own fields in order, keys exactly as written, or None where
    the body is anything but one UTF-8 JSON object nested no deeper than
    DEPTH_DEEPEST."""
    try:
        text = body.decode("utf-8")
    except UnicodeDecodeError:
        return None
    if depth(text) > DEPTH_DEEPEST:
        return None
    try:
        top = json.loads(text, object_pairs_hook=lambda pairs: pairs, parse_constant=no_constants)
    except (ValueError, RecursionError):
        return None
    if not isinstance(top, list) or (top and not all(isinstance(p, tuple) for p in top)):
        return None
    # An empty object and an empty array both read as []: tell them apart.
    if top == [] and not text.strip().startswith("{"):
        return None
    return top


def is_number(v):
    return isinstance(v, (int, float)) and not isinstance(v, bool)


def check_model(chosen, method, body):
    chosen = chosen.strip()
    if chosen == "" or method == "GET":
        return
    fields = one_object(body)
    if fields is None:
        raise Refused("not_allowed")
    named, seen = "", False
    for k, v in fields:
        if fold(k) == "models":
            raise Refused("not_allowed")
        if fold(k) != "model":
            continue
        if k != "model" or seen:
            raise Refused("not_allowed")
        seen = True
        if v is None:
            named = ""
        elif isinstance(v, str):
            named = v
        else:
            raise Refused("not_allowed")
    if named != chosen:
        raise Refused("not_allowed")


def answer_bound(profile, body):
    fields = one_object(body)
    if fields is None:
        raise Refused("allowance")
    seen, most = set(), 0
    for k, v in fields:
        for m in profile["answer_count_names"]:
            if fold(k) == fold(m) and not (is_number(v) and v == 1):
                raise Refused("allowance")
        name = next((n for n in profile["answer_bound_names"] if fold(k) == fold(n)), None)
        if name is None:
            continue
        if k != name or name in seen:
            raise Refused("allowance")
        seen.add(name)
        if not is_number(v) or v != v or v in (float("inf"), float("-inf")) or v != int(v) or not 1 <= v <= ANSWER_LONGEST:
            raise Refused("allowance")
        most = max(most, int(v))
    if most == 0:
        raise Refused("allowance")
    return most


def decode_body(b64):
    try:
        body = base64.b64decode(b64, validate=True)
    except (binascii.Error, ValueError):
        raise Refused("too_large")
    if len(body) > REQUEST_LARGEST:
        raise Refused("too_large")
    return body


def lone_surrogate(v):
    """Whether any string in v, a key included, holds a surrogate code point:
    JSON joins an escaped pair into one character, so any left is lone."""
    todo = [v]
    while todo:
        x = todo.pop()
        if isinstance(x, str):
            if any(0xD800 <= ord(c) <= 0xDFFF for c in x):
                return True
        elif isinstance(x, list):
            todo.extend(x)
        elif isinstance(x, dict):
            todo.extend(x.keys())
            todo.extend(x.values())
    return False


def parse_start(raw):
    """A start as it arrives: too long is too_large; anything but one UTF-8
    JSON object whose named fields have the right types is unreadable."""
    if len(raw) > START_LARGEST:
        raise Refused("too_large")
    try:
        text = raw.decode("utf-8")
        if depth(text) > DEPTH_DEEPEST:
            raise Refused("no_lease")
        v = json.loads(text, parse_constant=no_constants)
    except (UnicodeDecodeError, ValueError, RecursionError):
        raise Refused("no_lease")
    if lone_surrogate(v):
        raise Refused("no_lease")
    if not isinstance(v, dict):
        raise Refused("no_lease")
    q = {}
    for name in ("lease_id", "method", "path", "query", "body_b64"):
        x = v.get(name)
        if x is not None and not isinstance(x, str):
            raise Refused("no_lease")
        q[name] = x or ""
    h = v.get("header")
    if h is not None:
        if not isinstance(h, dict) or any(x is not None and not isinstance(x, str) for x in h.values()):
            raise Refused("no_lease")
        q["header"] = {k: (x or "") for k, x in h.items()}
    return q


def profile_valid(profile):
    """The profile definition's rules: upper-case route methods, names distinct
    in each list ignoring ASCII case, and exactly one rule per query parameter."""
    for r in profile["routes"]:
        if r["method"] == "" or r["method"] != upper(r["method"]):
            return False
    for h in profile["headers"] + profile["answer_headers"]:
        if h == "" or any(c not in TOKEN for c in h):
            return False
    for q in profile["query"]:
        given = [q.get("value", "") != "", q.get("digits", 0) != 0, q.get("plain", 0) != 0]
        if sum(given) != 1 or q.get("digits", 0) < 0 or q.get("plain", 0) < 0:
            return False
    lists = [profile["headers"], profile["answer_headers"], [q["name"] for q in profile["query"]],
             profile["answer_bound_names"], profile["answer_count_names"]]
    for names in lists:
        folded = [fold(n) for n in names]
        if len(set(folded)) != len(folded):
            return False
    return True


def check_start(profile, s, request):
    if request.get("lease_id", "") == "":
        raise Refused("no_lease")
    body = decode_body(request.get("body_b64", ""))
    if not profile_valid(profile):
        raise Refused("not_allowed")
    method = upper(request.get("method", ""))
    route = route_of(profile, method, request.get("path", ""))
    if route is None:
        raise Refused("not_allowed")
    q = query(profile, request.get("query", ""))
    check_model(s.get("model", ""), method, body)
    call = {"method": method, "path": request["path"]}
    if q:
        call["query"] = q
    h = pick(profile["headers"], request.get("header") or {}, NEVER_ON)
    if h:
        call["header"] = h
    reads = method == "GET"
    counts = bool(route.get("counts")) and not reads
    if reads:
        call["reads"] = True
    if counts:
        call["counts"] = True
    if s.get("allowance") and not reads and not counts:
        call["bound"] = answer_bound(profile, body)
    return call


def start_body(s):
    if s.get("nest"):
        n = s["nest"] - 1
        return ('{"model":"m","max_answer_tokens":5,"x":' + "[" * n + "]" * n + "}").encode()
    b = s.get("body", "").encode()
    pad = s.get("pad_to", 0)
    if pad > len(b):
        b += b" " * (pad - len(b))
    return b


def check_starts(v):
    for s in v["starts"]:
        request = dict(s["request"])
        if s.get("body") or s.get("nest"):
            b64 = base64.b64encode(start_body(s)).decode()
            if s.get("pad_to") or s.get("nest"):
                same(s["name"] + " leaves body_b64 out", request.get("body_b64", ""), "")
            else:
                same(s["name"] + " body_b64", request.get("body_b64", ""), b64)
            request["body_b64"] = b64
        raw = s["raw"].encode() if s.get("raw") else json.dumps(request).encode()
        if s.get("raw_pad_to", 0) > len(raw):
            raw += b" " * (s["raw_pad_to"] - len(raw))
        profile = s.get("profile") or v["example_profile"]
        try:
            call = check_start(profile, s, parse_start(raw))
            got = {"allowed": True, "call": call}
        except Refused as r:
            status, refused, _ = REASONS[r.reason]
            got = {"allowed": False, "reason": r.reason, "status": status}
            if refused:
                got["refused"] = True
        same(s["name"], got, s["outcome"])
    return len(v["starts"])


# ── collections ──────────────────────────────────────────────────────────


def read_from(raw):
    sign = raw[:1] if raw[:1] in ("+", "-") else ""
    digits = raw[len(sign):]
    if digits == "" or any(c not in "0123456789" for c in digits):
        return 0
    n = int(raw)
    if n < 0 or n > 2 ** 63 - 1:
        return 0
    return n


def check_collections(v):
    for c in v["collections"]:
        p = "/api/agent-host/model-calls/" + form_encode(c["call_id"], PATH_SAFE)
        p += "?from=%d&lease=%s" % (c["from"], form_encode(c["lease"], FORM_SAFE))
        if c["head"]:
            p += "&head=1"
        same(c["name"], p, c["path"])
    for c in v["collection_queries"]:
        first = {}
        for n, val in form_pieces(c["query"], skip=True):
            first.setdefault(n, val)
        got = {"from": read_from(first.get("from", "")), "lease": first.get("lease", ""), "head": first.get("head") == "1"}
        same(c["name"], got, {"from": c["from"], "lease": c["lease"], "head": c["head"]})
    return len(v["collections"]) + len(v["collection_queries"])


# ── refusals and answers ─────────────────────────────────────────────────


def check_refusals(v):
    got = {r["reason"]: (r["status"], r["refused"], r["no_call"]) for r in v["refusals"]}
    same("refusals", got, REASONS)
    return len(v["refusals"])


def check_answers(v):
    schema = json.load(open(os.path.join(HERE, "model-call", "model-call.schema.json")))
    d = schema["$defs"]["answer"]
    back = v["example_profile"]["answer_headers"]
    for a in v["answers"]:
        ans = a["answer"]
        for f in d["required"]:
            if f not in ans:
                fail("%s lacks %s" % (a["name"], f))
        for f in ans:
            if f not in d["properties"]:
                fail("%s carries %s, which the schema does not declare" % (a["name"], f))
        for k in ans.get("header", {}):
            if k not in back:
                fail("%s carries the header %s, which does not travel back" % (a["name"], k))
        data = a["data"].encode()
        if data:
            same(a["name"] + " data_b64", ans.get("data_b64"), base64.b64encode(data).decode())
        elif "data_b64" in ans:
            fail(a["name"] + " carries data_b64 with no data")
        if len(data) > PART_LARGEST:
            fail(a["name"] + " carries more than one answer may")
        same(a["name"] + " next", ans["next"], a["from"] + len(data))
    return len(v["answers"])


def check_limits(v):
    same("limits", v["limits"], {"request_largest": REQUEST_LARGEST, "start_largest": START_LARGEST,
                                 "part_largest": PART_LARGEST, "path_longest": PATH_LONGEST,
                                 "answer_longest": ANSWER_LONGEST, "depth_deepest": DEPTH_DEEPEST,
                                 "collection_wait_seconds": 20})




def check_headers(v):
    for h in v["headers"]:
        profile = h.get("profile") or v["example_profile"]
        same(h["name"], pick(profile["headers"], h["sent"], NEVER_ON), h.get("passed", {}))
    for h in v["answer_headers"]:
        profile = h.get("profile") or v["example_profile"]
        same("answer: " + h["name"], pick(profile["answer_headers"], h["sent"], NEVER_BACK), h.get("passed", {}))
    return len(v["headers"]) + len(v["answer_headers"])


def check_borrow(v):
    """Each borrow vector has what its definition requires, of the right kind,
    and the constants it names; a renewal keeps the lease it renews."""
    defs = json.load(open(os.path.join(HERE, "model-call", "model-call.schema.json")))["$defs"]
    b = v["borrow"]
    kinds = {"string": str, "integer": int, "boolean": bool}
    for name, d in [("request", "borrowing"), ("answer", "borrowed"), ("renew", "lease_request"), ("renewed", "renewed"),
                    ("return", "lease_request"), ("returned", "returned"), ("lease_gone", "borrow_refusal"),
                    ("update_agent_host", "borrow_refusal")]:
        x, sd = b[name], defs[d]
        for f in sd.get("required", []):
            if f not in x:
                fail("borrow %s lacks %s" % (name, f))
        for f, val in x.items():
            prop = sd["properties"].get(f)
            if prop is None:
                fail("borrow %s carries %s, which %s does not declare" % (name, f, d))
            elif "const" in prop:
                same("borrow %s %s" % (name, f), val, prop["const"])
            elif not isinstance(val, kinds[prop["type"]]):
                fail("borrow %s %s is not a %s" % (name, f, prop["type"]))
    same("borrow request", b["request"], {"model_calls": "through_identity_agent"})
    same("borrow answer's model_calls", b["answer"].get("model_calls"), "through_identity_agent")
    same("renewal keeps the lease", b["renewed"]["lease_id"], b["answer"]["lease_id"])
    same("renew names the lease", b["renew"], {"lease_id": b["answer"]["lease_id"]})
    same("return names the lease", b["return"], {"lease_id": b["answer"]["lease_id"]})
    same("lease gone", b["lease_gone"].get("no_lease"), True)
    same("update", b["update_agent_host"].get("update_agent_host"), True)
    return 8


def main():
    if len(sys.argv) != 2:
        sys.exit(__doc__)
    with open(sys.argv[1]) as f:
        v = json.load(f)
    if "starts" not in v:
        sys.exit("%s is not a model-call vector file" % sys.argv[1])
    check_limits(v)
    n = check_starts(v) + check_headers(v) + check_collections(v) + check_refusals(v) + check_answers(v) + check_borrow(v)
    if failures:
        sys.exit(1)
    print("ok: %d vectors" % n)


if __name__ == "__main__":
    main()
