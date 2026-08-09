"""Generate KERI conformance vectors from keripy.

WHAT THIS IS FOR

KERI identifiers are derived from the bytes of an event. Change one byte and you
have a different identity. So two implementations only interoperate if they
produce byte-for-byte identical output, and the only way to know that is to fix
the answers in advance and check every implementation against them.

keripy is the reference: Apache-2.0, and the implementations table lists it at
100% spec compliance for KERI, ACDC and CESR. So it is the oracle here. These
vectors are what IT produces, captured exactly, so that any other
implementation — our Go core, a Rust one, anything later — can be held to the
same answers.

WHY GENERATED RATHER THAN WRITTEN

A hand-written expectation is somebody's belief about what the answer should be.
A generated one is what the reference implementation actually does. Only the
second is worth checking against, and only the second can be regenerated when
the reference moves, which is how we would find out that it moved.

Run:  python3 tests/vectors/generate_vectors.py > tests/vectors/keri_vectors_v1.json
"""

import base64
import json
import sys

from keri.core import coring, eventing, serdering
from keri.core.coring import MtrDex

VECTOR_VERSION = 1


def signer(tag: str, transferable: bool = True) -> coring.Signer:
    """A deterministic key, so the vectors are reproducible.

    Fixed seeds rather than random ones: a vector whose inputs change on every
    run cannot be a fixed expectation.
    """
    raw = ((tag * 32)[:32]).encode()
    return coring.Signer(raw=raw, code=MtrDex.Ed25519_Seed, transferable=transferable)


def digest_of(verkey_qb64: str) -> str:
    """The pre-rotation commitment: a digest of the NEXT key, never the key."""
    return coring.Diger(ser=verkey_qb64.encode()).qb64


def case(cid, kind, why, inputs, serder):
    """One expectation: given these inputs, exactly these bytes and this identifier."""
    return {
        "id": cid,
        "kind": kind,
        "why": why,
        "input": inputs,
        "expect": {
            # The canonical serialisation, which is what a signature covers and
            # what the identifier is a digest of. Base64 so it survives JSON
            # without any encoder touching it.
            "raw_b64": base64.b64encode(serder.raw).decode(),
            "said": serder.said,
            "aid": serder.pre,
            # Carried for readability only. The bytes above are authoritative:
            # this field has been through a JSON encoder and its key order is
            # not the order that was signed.
            "event_readable": serder.ked,
        },
    }


def inception_cases():
    out = []

    cur, nxt = signer("a"), signer("b")
    srdr = eventing.incept(keys=[cur.verfer.qb64], ndigs=[digest_of(nxt.verfer.qb64)])
    out.append(case(
        "icp/single-key/no-witnesses",
        "inception",
        "The simplest identity there is. If this one disagrees, nothing else can agree.",
        {"keys": [cur.verfer.qb64], "next_digests": [digest_of(nxt.verfer.qb64)]},
        srdr,
    ))

    # Witnesses are designated in the inception and are therefore part of what
    # the identifier commits to — a different witness set is a different identity.
    wits = [signer(t, transferable=False).verfer.qb64 for t in ("w", "x", "y")]
    srdr = eventing.incept(
        keys=[cur.verfer.qb64], ndigs=[digest_of(nxt.verfer.qb64)], wits=wits, toad=2,
    )
    out.append(case(
        "icp/three-witnesses/toad-2",
        "inception",
        "Witnesses and the threshold are part of the identifier, so an implementation "
        "that formats them differently produces a different identity.",
        {"keys": [cur.verfer.qb64], "next_digests": [digest_of(nxt.verfer.qb64)],
         "witnesses": wits, "toad": 2},
        srdr,
    ))

    # Multiple signing keys with a threshold — the shape an organisation uses.
    k1, k2, k3 = signer("m"), signer("n"), signer("o")
    n1, n2, n3 = signer("p"), signer("q"), signer("r")
    srdr = eventing.incept(
        keys=[k1.verfer.qb64, k2.verfer.qb64, k3.verfer.qb64],
        ndigs=[digest_of(n.verfer.qb64) for n in (n1, n2, n3)],
        isith="2", nsith="2",
    )
    out.append(case(
        "icp/three-keys/2-of-3",
        "inception",
        "Thresholds are serialised in the event, and 2 is not the same as '2' — this "
        "catches an implementation that guesses the encoding.",
        {"keys": [k1.verfer.qb64, k2.verfer.qb64, k3.verfer.qb64],
         "next_digests": [digest_of(n.verfer.qb64) for n in (n1, n2, n3)],
         "isith": "2", "nsith": "2"},
        srdr,
    ))

    # An anchor in the inception. This is how an identifier commits to something
    # beyond its keys, and it is the mechanism this product uses to commit to
    # the keys people encrypt to it with.
    seal = [{"i": "EOwner0000000000000000000000000000000000000x", "r": "owner"}]
    srdr = eventing.incept(
        keys=[cur.verfer.qb64], ndigs=[digest_of(nxt.verfer.qb64)], data=seal,
    )
    out.append(case(
        "icp/with-anchor-seal",
        "inception",
        "An anchored seal changes the identifier, which is the whole point of anchoring. "
        "An implementation that drops or reorders seals produces a different identity.",
        {"keys": [cur.verfer.qb64], "next_digests": [digest_of(nxt.verfer.qb64)],
         "data": seal},
        srdr,
    ))
    return out


def rotation_cases():
    out = []
    cur, nxt, nxt2 = signer("a"), signer("b"), signer("c")
    icp = eventing.incept(keys=[cur.verfer.qb64], ndigs=[digest_of(nxt.verfer.qb64)])

    rot = eventing.rotate(
        pre=icp.pre, keys=[nxt.verfer.qb64], dig=icp.said, sn=1,
        ndigs=[digest_of(nxt2.verfer.qb64)],
    )
    out.append(case(
        "rot/simple/sn-1",
        "rotation",
        "A rotation must carry the key the previous event committed to, and must chain "
        "to that event by digest. Both are places an implementation can quietly differ.",
        {"prefix": icp.pre, "keys": [nxt.verfer.qb64], "prior_said": icp.said,
         "sn": 1, "next_digests": [digest_of(nxt2.verfer.qb64)]},
        rot,
    ))
    return out


def interaction_cases():
    out = []
    cur, nxt = signer("a"), signer("b")
    icp = eventing.incept(keys=[cur.verfer.qb64], ndigs=[digest_of(nxt.verfer.qb64)])

    seal = [{"i": "ECredential000000000000000000000000000000x", "s": "0",
             "d": "EDigest000000000000000000000000000000000000x"}]
    ixn = eventing.interact(pre=icp.pre, dig=icp.said, sn=1, data=seal)
    out.append(case(
        "ixn/one-seal",
        "interaction",
        "Interaction events are how a credential is anchored into a key history, so "
        "their serialisation decides whether an issuance can be verified elsewhere.",
        {"prefix": icp.pre, "prior_said": icp.said, "sn": 1, "data": seal},
        ixn,
    ))
    return out


def identifier_property_cases():
    """Properties that hold for every conformant implementation, stated as data."""
    cur, nxt = signer("a"), signer("b")
    icp = eventing.incept(keys=[cur.verfer.qb64], ndigs=[digest_of(nxt.verfer.qb64)])
    return [
        {
            "id": "property/aid-is-said-of-inception",
            "kind": "property",
            "why": "A self-certifying identifier IS the digest of the event that created "
                   "it. An implementation where these differ has not made an identity.",
            "assert": "aid_equals_said",
            "input": {"raw_b64": base64.b64encode(icp.raw).decode()},
            "expect": {"aid": icp.pre, "said": icp.said},
        },
        {
            "id": "property/tampered-event-is-refused",
            "kind": "reject",
            "why": "An event whose contents do not digest to the identifier it claims "
                   "must be refused. Accepting it would let a forged event borrow a real "
                   "identity, which is what the digest exists to prevent.",
            "input": {
                "raw_b64": base64.b64encode(
                    icp.raw.replace(b'"kt":"1"', b'"kt":"2"', 1)
                ).decode(),
                "claimed_said": icp.said,
            },
            "expect": {"refused": True,
                       "because": "the contents do not digest to the claimed identifier"},
        },
    ]


def cesr_code_cases():
    """The code table is normative in the spec: these characters are fixed."""
    return [{
        "id": "cesr/codes",
        "kind": "constants",
        "why": "CESR codes are normative. An implementation that emits a different "
               "prefix is producing values no other implementation can read.",
        "input": {},
        "expect": {
            "blake3_256": MtrDex.Blake3_256,
            "ed25519_pubkey": MtrDex.Ed25519,
            "ed25519_pubkey_nontransferable": MtrDex.Ed25519N,
            "ed25519_seed": MtrDex.Ed25519_Seed,
            "ed25519_sig": MtrDex.Ed25519_Sig,
        },
    }]


def main():
    cases = []
    cases += cesr_code_cases()
    cases += inception_cases()
    cases += rotation_cases()
    cases += interaction_cases()
    cases += identifier_property_cases()

    doc = {
        "vector_version": VECTOR_VERSION,
        "oracle": f"keripy {getattr(__import__('keri'), '__version__', 'unknown')}",
        "what_this_is":
            "Fixed answers every conformant KERI implementation must reproduce "
            "byte for byte. Generated from keripy, which the KERI implementations "
            "table lists at 100% spec compliance. Regenerate rather than edit: a "
            "hand-edited expectation is a belief, not a reference.",
        "how_to_use":
            "Run every implementation against every case. raw_b64 is the "
            "authoritative serialisation — the readable event is for humans and its "
            "key order is not the order that was signed.",
        "cases": cases,
    }
    json.dump(doc, sys.stdout, indent=2, sort_keys=False)
    sys.stdout.write("\n")


if __name__ == "__main__":
    main()
