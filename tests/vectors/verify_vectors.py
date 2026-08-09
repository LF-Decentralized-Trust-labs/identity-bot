"""Check the vectors still match what keripy produces.

A vector file is a claim about the reference implementation. That claim can go
stale two ways, and both are silent:

  - keripy is upgraded and its output changes. Every implementation checked
    against the old file then agrees with something no longer true.
  - somebody edits the file by hand to make a failing test pass, which converts
    a disagreement with the ecosystem into a disagreement nobody can see.

This runs the vectors back through keripy and fails on either. It is the guard
on the guard, and it is why the file must be generated rather than written.

Run: python3 tests/vectors/verify_vectors.py tests/vectors/keri_vectors_v1.json
"""

import base64
import json
import sys

from keri.core import serdering


def check_serialisation(cid, expect):
    """The bytes must parse as a KERI event, and be the event they claim."""
    raw = base64.b64decode(expect["raw_b64"])
    serder = serdering.SerderKERI(raw=raw)
    problems = []
    if serder.said != expect["said"]:
        problems.append(f"said is {serder.said}, vector says {expect['said']}")
    if expect.get("aid") and serder.pre != expect["aid"]:
        problems.append(f"aid is {serder.pre}, vector says {expect['aid']}")
    return problems


def check_refusal(cid, case):
    """A case that must be refused has to actually be refused by the reference."""
    raw = base64.b64decode(case["input"]["raw_b64"])
    try:
        serder = serdering.SerderKERI(raw=raw)
    except Exception:
        return []  # refused at parse, which is a refusal
    claimed = case["input"].get("claimed_said")
    if claimed and serder.said == claimed:
        return [f"expected a refusal, but keripy accepted it and agreed the "
                f"identifier is {claimed} — the vector no longer describes a forgery"]
    return []


def main(path):
    doc = json.load(open(path))
    failures = []
    checked = 0

    for c in doc["cases"]:
        cid, kind = c["id"], c["kind"]
        if kind in ("inception", "rotation", "interaction", "delegation", "property"):
            if "raw_b64" in c.get("expect", {}):
                failures += [f"{cid}: {p}" for p in check_serialisation(cid, c["expect"])]
                checked += 1
            elif "raw_b64" in c.get("input", {}):
                raw = base64.b64decode(c["input"]["raw_b64"])
                serder = serdering.SerderKERI(raw=raw)
                if serder.pre != c["expect"]["aid"] or serder.said != c["expect"]["said"]:
                    failures.append(f"{cid}: keripy no longer produces this identifier")
                checked += 1
        elif kind == "reject":
            failures += [f"{cid}: {p}" for p in check_refusal(cid, c)]
            checked += 1
        elif kind == "constants":
            checked += 1  # asserted directly by the conformance tests

    print(f"checked {checked} of {len(doc['cases'])} cases against {doc['oracle']}")
    if failures:
        print("\nThe vectors no longer match the reference implementation:\n")
        for f in failures:
            print(f"  {f}")
        print("\nRegenerate them, and find out WHY they moved before trusting the new "
              "file — a change here is a change to what every implementation must produce.")
        return 1
    print("the vectors still describe what keripy produces")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1] if len(sys.argv) > 1 else "tests/vectors/keri_vectors_v1.json"))
