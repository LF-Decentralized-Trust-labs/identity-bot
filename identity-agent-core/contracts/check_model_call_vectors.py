#!/usr/bin/env python3
"""An independent check of the model-call vector file, written without Go.

Everything here is rebuilt from the prose in model-call/model-call.schema.json,
not from the Go code: which calls a body may start and how each refused one is
answered, the query and headers that travel on, the collection paths and how a
collection's query is read, the refusal statuses, and the answers' offsets. If
this script and the vector file ever disagree, the prose no longer says what
the code does.

Run: python3 check_model_call_vectors.py model-call-vectors.json
Needs nothing beyond the Python standard library.
"""
import base64
import binascii
import json
import os
import sys
import unicodedata

HERE = os.path.dirname(os.path.abspath(__file__))
failures = []

REQUEST_LARGEST = 3 * 1024 * 1024
PART_LARGEST = 2 * 1024 * 1024
PATH_LONGEST = 256
ANSWER_LONGEST = 32768
HEADER_NAMES = ["Content-Type", "Accept", "Anthropic-Version", "Anthropic-Beta", "Openai-Beta"]
ANSWER_HEADER_NAMES = ["Content-Type", "Retry-After", "Request-Id", "X-Request-Id"]
BOUND_NAMES = ["max_tokens", "max_completion_tokens", "max_output_tokens"]
COUNT_NAMES = ["n", "best_of"]
QUERY_NAMES = ["after_id", "before_id", "beta", "limit"]
FORM_SAFE = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_.~"
PATH_SAFE = FORM_SAFE + b"$&+:=@"

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


# ── the path ─────────────────────────────────────────────────────────────


def plain_chars(s):
    for c in s:
        cat = unicodedata.category(c)
        if not (cat.startswith("L") or cat == "Nd" or c in ".-_:/~"):
            return False
    return True


def plain_path(p):
    if len(p.encode()) > PATH_LONGEST or not p.startswith("/") or not plain_chars(p):
        return False
    if p == "/":
        return True
    segments = p[1:].split("/")
    return all(seg not in ("", ".", "..") for seg in segments)


def route_allowed(routes, method, p):
    if not plain_path(p):
        return False
    for r in routes:
        if r["method"] != method:
            continue
        if p == r["path"]:
            return True
        if method == "GET" and r["path"] == "/v1/models" and p.startswith("/v1/models/"):
            return True
    return False


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


def query_value_ok(name, v):
    n = len(v.encode())
    if name == "beta":
        return v == "true"
    if name == "limit":
        return n <= 4 and all(c in "0123456789" for c in v)
    if name in ("after_id", "before_id"):
        return n <= 128 and plain_chars(v)
    return False


def query(raw):
    if raw == "":
        return ""
    pairs = form_pieces(raw)
    if pairs is None:
        raise Refused("not_allowed")
    names = [n for n, _ in pairs]
    by = {}
    for n, v in pairs:
        if n not in QUERY_NAMES or names.count(n) != 1 or not query_value_ok(n, v):
            raise Refused("not_allowed")
        by[n] = v
    return "&".join(form_encode(n, FORM_SAFE) + "=" + form_encode(by[n], FORM_SAFE) for n in sorted(by))


# ── the headers ──────────────────────────────────────────────────────────


def headers(sent):
    out = {}
    for name in HEADER_NAMES:
        for k in sorted(sent):
            if fold(k) == fold(name) and sent[k] != "":
                out[name] = sent[k]
                break
    return out


# ── the body ─────────────────────────────────────────────────────────────


def no_constants(c):
    raise ValueError("not JSON: " + c)


def one_object(body):
    """The object's own fields in order, keys exactly as written, or None where
    the body is anything but one JSON object."""
    try:
        text = body.decode("utf-8")
    except UnicodeDecodeError:
        return None
    try:
        top = json.loads(text, object_pairs_hook=lambda pairs: pairs, parse_constant=no_constants)
    except ValueError:
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
    if chosen == "" or method != "POST":
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


def answer_bound(body):
    fields = one_object(body)
    if fields is None:
        raise Refused("allowance")
    seen, most = set(), 0
    for k, v in fields:
        for m in COUNT_NAMES:
            if fold(k) == m and not (is_number(v) and v == 1):
                raise Refused("allowance")
        name = next((n for n in BOUND_NAMES if fold(k) == n), None)
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


def check_start(routes, s, request):
    if request.get("lease_id", "") == "":
        raise Refused("no_lease")
    body = decode_body(request.get("body_b64", ""))
    method = upper(request.get("method", ""))
    if not route_allowed(routes, method, request.get("path", "")):
        raise Refused("not_allowed")
    q = query(request.get("query", ""))
    check_model(s.get("model", ""), method, body)
    call = {"method": method, "path": request["path"]}
    if q:
        call["query"] = q
    h = headers(request.get("header", {}))
    if h:
        call["header"] = h
    reads = method != "POST"
    if reads:
        call["reads"] = True
    if s.get("allowance") and not reads:
        call["bound"] = answer_bound(body)
    return call


def start_body(s):
    b = s.get("body", "").encode()
    pad = s.get("pad_to", 0)
    if pad > len(b):
        b += b" " * (pad - len(b))
    return b


def check_starts(v):
    routes = v["routes"]
    for s in v["starts"]:
        request = dict(s["request"])
        if s.get("body"):
            b64 = base64.b64encode(start_body(s)).decode()
            if s.get("pad_to"):
                same(s["name"] + " leaves body_b64 out", request.get("body_b64", ""), "")
            else:
                same(s["name"] + " body_b64", request.get("body_b64", ""), b64)
            request["body_b64"] = b64
        try:
            call = check_start(routes, s, request)
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
        pairs = form_pieces(c["query"], skip=True)
        first = {}
        for n, val in pairs:
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
    for a in v["answers"]:
        ans = a["answer"]
        for f in d["required"]:
            if f not in ans:
                fail("%s lacks %s" % (a["name"], f))
        for f in ans:
            if f not in d["properties"]:
                fail("%s carries %s, which the schema does not declare" % (a["name"], f))
        for k in ans.get("header", {}):
            if k not in ANSWER_HEADER_NAMES:
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
    same("limits", v["limits"], {"request_largest": REQUEST_LARGEST, "start_largest": 2 * REQUEST_LARGEST, "part_largest": PART_LARGEST,
                                 "path_longest": PATH_LONGEST, "answer_longest": ANSWER_LONGEST,
                                 "collection_wait_seconds": 20})
    same("header_names", v["header_names"], HEADER_NAMES)
    same("answer_header_names", v["answer_header_names"], ANSWER_HEADER_NAMES)
    same("query_parameters", v["query_parameters"], QUERY_NAMES)
    same("answer_bound_names", v["answer_bound_names"], BOUND_NAMES)
    same("answer_count_names", v["answer_count_names"], COUNT_NAMES)
    schema = json.load(open(os.path.join(HERE, "model-call", "model-call.schema.json")))
    same("borrowing", v["borrowing"], {"model_calls": schema["$defs"]["borrowing"]["properties"]["model_calls"]["const"]})


def check_headers(v):
    for h in v["headers"]:
        same(h["name"], headers(h["sent"]), h.get("passed", {}))
    return len(v["headers"])


def main():
    if len(sys.argv) != 2:
        sys.exit(__doc__)
    with open(sys.argv[1]) as f:
        v = json.load(f)
    if "starts" not in v:
        sys.exit("%s is not a model-call vector file" % sys.argv[1])
    check_limits(v)
    n = check_starts(v) + check_headers(v) + check_collections(v) + check_refusals(v) + check_answers(v)
    if failures:
        sys.exit(1)
    print("ok: %d vectors" % n)


if __name__ == "__main__":
    main()
