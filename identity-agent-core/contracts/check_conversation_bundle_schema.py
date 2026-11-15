#!/usr/bin/env python3
"""An independent check that conversation-bundle.schema.json refuses what a bundle's head must not carry.

Written without Go: it reads the published schema and the published vectors and asks a
JSON Schema validator, not the Go verifier, whether each is accepted. The genuine
vectors' signed envelopes must be accepted, and every patch of head-tamper-vectors.json
must be refused by the schema unless the vector says the schema cannot (schema_refuses), with
the control accepted.

Run: python3 -I check_conversation_bundle_schema.py <contracts dir>
Needs the jsonschema module (pip install jsonschema), version 4 or later.
"""
import copy
import json
import os
import sys

import jsonschema
from jsonschema import Draft202012Validator, RefResolver

failures = []


def fail(what):
    failures.append(what)
    print("MISMATCH " + what)


def load(path):
    with open(path, "rb") as f:
        return json.loads(f.read())


def patch(doc, ops):
    """RFC 6902 add, replace and remove over object members, as the vectors use them."""
    doc = copy.deepcopy(doc)
    for op in ops:
        parts = [p.replace("~1", "/").replace("~0", "~") for p in op["path"].lstrip("/").split("/")]
        node = doc
        for p in parts[:-1]:
            node = node[int(p)] if isinstance(node, list) else node[p]
        key = parts[-1]
        if op["op"] == "add":
            node[key] = op["value"]
        elif op["op"] == "replace":
            if key not in node:
                raise ValueError("replace of what is not there: " + op["path"])
            node[key] = op["value"]
        elif op["op"] == "remove":
            if key not in node:
                raise ValueError("remove of what is not there: " + op["path"])
            del node[key]
        else:
            raise ValueError("operation " + op["op"])
    return doc


def main(contracts):
    bundle_dir = os.path.join(contracts, "conversation-bundle")
    schema = load(os.path.join(bundle_dir, "conversation-bundle.schema.json"))
    message = load(os.path.join(contracts, "agent-message", "agent-message.schema.json"))
    # The schemas name themselves by a relative $id; give them one base, so the
    # reference from one to the other resolves the way it does from a checkout.
    root = "https://contracts.invalid/"
    schema["$id"] = root + "conversation-bundle/conversation-bundle.schema.json"
    message["$id"] = root + "agent-message/agent-message.schema.json"
    store = {schema["$id"]: schema, message["$id"]: message}
    resolver = RefResolver(schema["$id"], schema, store=store)

    def refused_as_a_head(envelope):
        v = Draft202012Validator({"$ref": "#/$defs/signed_envelope"}, resolver=resolver)
        return list(v.iter_errors(envelope))

    genuine = load(os.path.join(bundle_dir, "genuine-bundle-with-head.json"))
    if refused_as_a_head(genuine["head"]):
        fail("the genuine head is refused: " + refused_as_a_head(genuine["head"])[0].message[:100])
    for i, e in enumerate(genuine["entries"], 1):
        if refused_as_a_head(e["envelope"]):
            fail("entry %d's genuine envelope is refused" % i)
    # The whole genuine file is a bundle.
    bundle = Draft202012Validator(schema, resolver=resolver)
    errs = list(bundle.iter_errors(genuine))
    if errs:
        fail("the genuine head-bearing bundle is refused by its own schema: " + errs[0].message[:100])

    vs = load(os.path.join(bundle_dir, "head-tamper-vectors.json"))
    if patch(genuine, vs["control"]["patch"]) != genuine:
        fail("the control changes the file")
    for v in vs["vectors"]:
        changed = patch(genuine, v["patch"])
        refused = bool(list(bundle.iter_errors(changed)))
        if refused != v["schema_refuses"]:
            fail(v["name"] + (" is refused by the schema, which says it is not" if refused else " is accepted by the schema, and " + v["because"]))
    print("checked %d tampers" % len(vs["vectors"]))


if __name__ == "__main__":
    if len(sys.argv) != 2:
        sys.exit("usage: check_conversation_bundle_schema.py <contracts dir>")
    main(sys.argv[1])
    if failures:
        sys.exit(1)
    print("ok")
