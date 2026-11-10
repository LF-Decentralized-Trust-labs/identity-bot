#!/usr/bin/env python3
"""An independent check of authorisation/ai-agent-body-request-vectors.json,
written without Go.

Everything here is rebuilt from the prose of ADR-045, Amendment 3 (a grant for
an AI agent that another AI agent created rests on a request the creator's body
signed), not from the Go code. For each case it decides whether the grant is
authorised, by its own reading of the rules, and compares that with the file.

It does more than compare accepted with refused: a refusing case must break
exactly the one rule the case is about, so a case cannot pass by being refused
for some other reason. The rules, as the ADR states them:

  1. every credential and every registry event is the digest of what it says
     (its `d`), and the nested attribute block likewise;
  2. the request is a body's: eleven lines, the first IA-BODY-REQ-V3, naming the
     Identity Agent that issued the grant, the signing body, the method, the
     target, the time, a nonce, the digest of the request's body, then the work
     item, reason and session; and it is POST /api/agent-host/agents (create an
     AI agent) or PUT /api/agent-host/agents/{id}/github (set its repositories);
  3. the grant is of the version that admits a body's request (1.2.0) and rests,
     by its authorised_by edge, on the creator's AI Agent Grant, which holds
     agent.create, was issued by the same Identity Agent, and is not the new
     AI agent's own;
  4. the creator's body credential is for the same creator and Identity Agent,
     and the key it names signed the request, over the string kept;
  5. both of the creator's credentials were in force when the request was made
     and neither was revoked before the new grant was issued, and the request
     was made no more than five minutes before or after that issue;
  6. the body given is the body signed, and what the grant says was asked for
     (name, capabilities, limits) is what that body asked for, and what it
     grants;
  7. the new AI agent is no more powerful than its creator: it holds only
     capabilities the creator's grant holds, and for every argument the
     creator's grant limits to some values, its own limit is some of those; and
     where the creator's grant has a valid_until, its own exists and is no
     later, so it does not outlive its creator. A limit is never an empty list.

What it does not check, as the ADR says: any count or resource limit on how
many AI agents a creator may create, which the party that issues the creator's
grant enforces.

Run: python3 check_ai_agent_body_request_vectors.py ai-agent-body-request-vectors.json
Needs the blake3 module (pip install blake3).
"""
import datetime
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

# The digest, base64 and Ed25519 helpers of the other independent check, which
# are not what is under test here.
from check_ai_agent_vectors import digest, ed25519_verify, qb64_raw  # noqa: E402

SKEW = datetime.timedelta(minutes=5)
CREATE_PATH = "/api/agent-host/agents"
GRANT_DIR = os.path.join(HERE, "asset-grants")
failures = []


def fail(what):
    failures.append(what)
    print("MISMATCH " + what)


def schema_id(name):
    with open(os.path.join(GRANT_DIR, name)) as f:
        return json.load(f)["$id"]


def when(s):
    return datetime.datetime.fromisoformat(s.replace("Z", "+00:00"))


def ordered(raw):
    return json.loads(raw, object_pairs_hook=lambda kv: dict(kv))


def compact(x):
    return json.dumps(x, separators=(",", ":"), ensure_ascii=False)


def said_of(doc, size_field=True):
    """The digest of doc with its `d` replaced by 44 filler characters and, for
    a document with a version string, that string's size field set to the
    document's length. Returns the said and the document in its final form."""
    filled = dict(doc)
    filled["d"] = "#" * 44
    text = compact(filled)
    if size_field and "v" in doc:
        proto = doc["v"][:10]
        size = len(text.encode())
        filled["v"] = "%s%06x_" % (proto, size)
        text = compact(filled)
    return digest(text.encode())


def credential_ok(raw, rules):
    """The credential is exactly its own digest, and so is its attribute block."""
    c = ordered(raw)
    if compact(c) != raw:
        rules.add("credential-not-compact")
    a = c.get("a", {})
    if "d" in a and said_of(a, size_field=False) != a["d"]:
        rules.add("attributes-digest")
    if said_of(c) != c["d"]:
        rules.add("credential-digest")
    return c


def log_events(log, subject, rules):
    """The registry events of a credential, each its own digest, as (kind, time)."""
    out = []
    for raw in log:
        e = ordered(raw)
        if said_of(e) != e["d"]:
            rules.add("log-digest")
        if e["i"] != subject:
            rules.add("log-subject")
        out.append((e["t"], when(e["dt"])))
    return out


def signed_fields(signed):
    lines = signed.split("\n")
    if len(lines) != 11 or lines[0] != "IA-BODY-REQ-V3":
        return None
    return {"ia": lines[1], "host": lines[2], "method": lines[3], "target": lines[4], "stamp": lines[5],
            "digest": lines[7]}


def route_ok(method, target):
    """The request is one of the two a body signs that grant an AI agent
    something: POST to the create route, or PUT to /agents/{id}/github. Returns
    the id the PUT is about, "" for a create, None if it is neither."""
    if method == "POST" and target == CREATE_PATH:
        return ""
    parts = target.strip("/").split("/")
    if method == "PUT" and len(parts) == 5 and parts[:3] == ["api", "agent-host", "agents"] and parts[4] == "github":
        return parts[3]
    return None


def repositories_grant(sent):
    """The capabilities and limits a list of repositories asks for: read on
    each repository asked for, write on those asked for write, each limit
    naming the repositories (lower case) in a list of its own."""
    read, write = [], []
    for item in sent.get("repositories", []):
        name = item["repository"].strip().lower()
        if name not in read:
            read.append(name)
        if item["access"].strip().lower() in ("write", "read and write", "read-write") and name not in write:
            write.append(name)
    caps, limits = [], {}
    for cap, names in (("code.repository.read", read), ("code.repository.write", write)):
        if names:
            caps.append(cap)
            limits[cap] = {"repository": sorted(names)}
    return caps, limits


def judge(v, case, ids):
    """The rules that case breaks, by this reading of the ADR. Empty if none."""
    rules = set()
    cred = credential_ok(case["credential"], rules)
    grant = credential_ok(case["creator_grant"], rules)
    body = credential_ok(case["creator_body"], rules)
    attrs = cred["a"]
    request = attrs.get("request", {})
    if request.get("kind") != v["request_kind"]:
        rules.add("kind")

    s = signed_fields(request.get("signed", ""))
    if s is None:
        rules.add("signed-form")
        return rules
    if s["ia"] != cred["i"]:
        rules.add("other-identity-agent")
    if s["host"] != request["signer"]:
        rules.add("signer-named")
    about = route_ok(s["method"], s["target"])
    if about is None:
        rules.add("route")
    if digest(case["request_body"].encode()) != s["digest"]:
        rules.add("body-digest")

    # The grant is of the version that admits the request, and rests on the
    # creator's grant.
    if cred["s"] != v["grant_schema"] or cred["s"] != ids["grant-1.2.0"]:
        rules.add("version")
    edge = cred.get("e", {}).get("authorised_by", {})
    if edge.get("n") != grant["d"] or edge.get("s") != grant["s"]:
        rules.add("edge")
    if grant["s"] not in (ids["grant-1.0.0"], ids["grant-1.1.0"], ids["grant-1.2.0"]):
        rules.add("edge")
    if grant["i"] != cred["i"] or body["i"] != cred["i"]:
        rules.add("creator-issuer")
    creator = grant["a"]["i"]
    if creator == attrs["i"]:
        rules.add("own-request")
    if body["a"]["i"] != creator:
        rules.add("body-creator")
    if body["s"] not in (ids["body-1.0.0"], ids["body-1.1.0"]):
        rules.add("body-schema")
    if "agent.create" not in grant["a"]["capabilities"]:
        rules.add("no-create")

    # The creator's body signed the request.
    if body["a"]["host"] != s["host"]:
        rules.add("signer")
    try:
        sig = qb64_raw("0B", request["signature"], 64)
        key = qb64_raw("D", body["a"]["verkey"], 32)
        if not ed25519_verify(key, sig, request["signed"].encode()):
            rules.add("signature")
    except ValueError:
        rules.add("signature")

    # In force when the request was made, not revoked before the issue, and the
    # request close to the issue.
    stamp, issued = when(s["stamp"]), when(attrs["dt"])
    if stamp > issued + SKEW:
        rules.add("after-issue")
    if stamp < issued - SKEW:
        rules.add("long-before")
    for name, c, log in (("grant", grant, case["creator_grant_log"]), ("body", body, case["creator_body_log"])):
        events = log_events(log, c["d"], rules)
        if not any(k == "iss" for k, _ in events):
            rules.add("not-issued")
        if stamp + SKEW < when(c["a"]["dt"]):
            rules.add("before-granted")
        ends_at = c["a"].get("valid_until")
        if ends_at is not None and not stamp < when(ends_at):
            rules.add("lapsed")
        for kind, at in events:
            if kind == "rev" and not at > issued:
                rules.add("revoked-before")

    # What was asked for is what the body asked, and what the grant gives.
    # Judged only against the body that was signed: a body that is not it says
    # nothing about what was asked.
    sent = json.loads(case["request_body"])
    if "body-digest" not in rules:
        if request["asked"] != sent:
            rules.add("asked")
        if about == "":
            if attrs["name"] != sent.get("name") or sorted(attrs["capabilities"]) != sorted(sent.get("capabilities", [])):
                rules.add("asked")
            if sent.get("resource_constraints", {}) != attrs.get("resource_constraints", {}):
                rules.add("asked")
        elif about:
            # A request for repositories: the grant is about the AI agent named
            # in the route and gives exactly the repositories asked for.
            if attrs.get("about") != about:
                rules.add("asked")
            caps, limits = repositories_grant(sent)
            if not set(caps) <= set(attrs["capabilities"]):
                rules.add("asked")
            for cap, lim in limits.items():
                got = attrs.get("resource_constraints", {}).get(cap, {}).get("repository")
                if sorted(got or []) != lim["repository"]:
                    rules.add("asked")

    # No more powerful than its creator.
    held = set(grant["a"]["capabilities"])
    limits = grant["a"].get("resource_constraints", {})
    own = attrs.get("resource_constraints", {})
    for lim in (limits, own):
        for args in lim.values():
            if any(len(values) == 0 for values in args.values()):
                rules.add("empty-limit")
    ends = grant["a"].get("valid_until")
    if ends is not None:
        mine = attrs.get("valid_until")
        if mine is None or when(mine) > when(ends):
            rules.add("outlives-creator")
    for cap in attrs["capabilities"]:
        if cap not in held:
            rules.add("wider-capability")
        for arg, allowed in limits.get(cap, {}).items():
            mine = own.get(cap, {}).get(arg)
            if mine is None:
                rules.add("unlimited")
            elif not set(mine) <= set(allowed):
                rules.add("wider-limit")
    return rules


# The one rule each refusing case is about, by its name in the file. A case
# the file adds without a line here fails, so none is accepted unread.
REFUSED_FOR = {
    "the creator's grant does not hold agent.create": "no-create",
    "the request is signed by a key that is not the creator's body": "signature",
    "the request was for another Identity Agent": "other-identity-agent",
    "the body given is not the body signed": "body-digest",
    "the credential asks for what the signed body did not": "asked",
    "the request is to a route that is not the creator's channel": "route",
    "the request is to a route that grants nothing": "route",
    "the creator's grant was revoked before the new grant was issued": "revoked-before",
    "the request was made long before the grant it authorised": "long-before",
    "the grant is the creator's own": "own-request",
    "the creator's body credential belongs to another AI agent than the creator's grant": "body-creator",
    "the creator's body credential was revoked before the new grant was issued": "revoked-before",
    "the creator's grant had lapsed when its body made the request": "lapsed",
    "the grant is of a version that does not admit the kind": "version",
    "the new AI agent would hold a capability its creator's grant does not": "wider-capability",
    "the creator's grant lapses and the new AI agent's grant has no end": "outlives-creator",
    "the new AI agent's grant lapses after its creator's": "outlives-creator",
    "the creator limits an argument that the new AI agent's grant leaves unlimited": "unlimited",
    "the new AI agent may use a value its creator's limit does not allow": "wider-limit",
}


def main():
    if len(sys.argv) != 2:
        sys.exit(__doc__)
    with open(sys.argv[1]) as f:
        v = json.load(f)
    ids = {
        "grant-1.0.0": schema_id("ai-agent-grant-1.0.0.schema.json"),
        "grant-1.1.0": schema_id("ai-agent-grant-1.1.0.schema.json"),
        "grant-1.2.0": schema_id("ai-agent-grant-1.2.0.schema.json"),
        "body-1.0.0": schema_id("ai-agent-body-1.0.0.schema.json"),
        "body-1.1.0": schema_id("ai-agent-body-1.1.0.schema.json"),
    }
    accepted = 0
    for case in v["cases"]:
        broken = judge(v, case, ids)
        name = case["name"]
        if case["accepted"]:
            accepted += 1
            if broken:
                fail("%s: the file accepts it, and it breaks %s" % (name, sorted(broken)))
        else:
            want = REFUSED_FOR.get(name)
            if want is None:
                fail("%s: no rule is named for this refusal" % name)
            elif broken != {want}:
                fail("%s: refused by the file for %s; broken here: %s" % (name, want, sorted(broken)))
    if not accepted or accepted == len(v["cases"]):
        fail("the file needs both accepted and refused cases")
    if failures:
        sys.exit(1)
    print("ok: %d vectors" % len(v["cases"]))


if __name__ == "__main__":
    main()
