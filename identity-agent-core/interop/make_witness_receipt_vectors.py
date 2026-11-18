"""Make the witness-receipt test vectors with keripy's own code.

    python3 -I interop/make_witness_receipt_vectors.py > witnessproto/testdata/keripy_witness_receipts.json   # needs keri==1.3.6

A controller incepts with two witnesses; each witness, a keripy Hab, receipts
the inception with Hab.witness (keripy/app/habbing.py). What it prints is what
keripy produced and nothing of ours: the event, the receipt message, and the
indexed signature. witnessproto/a_receipt_is_the_one_keripy_makes_test.go checks that our reader
accepts them and that our writer reproduces them byte for byte.
"""
import base64
import importlib.metadata
import json
import sys

from keri.app import habbing
from keri.core import serdering, signing

assert importlib.metadata.version("keri") == "1.3.6", "vectors are made with keri 1.3.6"


def salt(b):
    return signing.Salter(raw=b).qb64


b64 = lambda b: base64.b64encode(b).decode()

with habbing.openHby(name="ctl", temp=True, salt=salt(b"0123456789abcdef")) as hby, \
     habbing.openHby(name="w0", temp=True, salt=salt(b"fedcba9876543210")) as w0, \
     habbing.openHby(name="w1", temp=True, salt=salt(b"abcdef0123456789")) as w1:
    # Fixed seeds, so the signatures can be reproduced: Ed25519 is deterministic.
    seeds = [bytes([7] * 32), bytes([9] * 32)]
    h0 = w0.makeHab(name="w", transferable=False, secrecies=[[signing.Signer(raw=seeds[0], transferable=False).qb64]])
    h1 = w1.makeHab(name="w", transferable=False, secrecies=[[signing.Signer(raw=seeds[1], transferable=False).qb64]])
    ctl = hby.makeHab(name="c", wits=[h0.pre, h1.pre], toad=2)
    msg = ctl.makeOwnEvent(sn=0)
    serder = serdering.SerderKERI(raw=bytes(msg))
    receipts = []
    inception_wits = list(ctl.kever.wits)
    for hab, seed in zip((h0, h1), seeds):
        hab.psr.parse(ims=bytearray(msg))
        rct = bytes(hab.witness(serder))
        cut = rct.index(b"-VA")
        receipts.append({
            "witness": hab.pre,
            "seed_b64": b64(seed),
            "index": ctl.kever.wits.index(hab.pre),
            "receipt_b64": b64(rct[:cut]),
            "attachment": rct[cut:].decode(),
            "message_b64": b64(rct),
        })

    def receipted(sn):
        """Every witness in the list in force after event sn receipts it."""
        m = ctl.makeOwnEvent(sn=sn)
        ser = serdering.SerderKERI(raw=bytes(m))
        out = []
        for hab, seed in zip((h0, h1), seeds):
            if hab.pre not in ctl.kever.wits:
                continue
            hab.psr.parse(ims=bytearray(m))
            rct = bytes(hab.witness(ser))
            cut = rct.index(b"-VA")
            out.append({
                "witness": hab.pre,
                "seed_b64": b64(seed),
                "index": ctl.kever.wits.index(hab.pre),
                "receipt_b64": b64(rct[:cut]),
                "attachment": rct[cut:].decode(),
            })
        return {
            "sn": sn,
            "event_said": ser.said,
            "event_b64": b64(ser.raw),
            "witnesses": list(ctl.kever.wits),
            "receipts": out,
        }

    # Later events, to exercise a sequence number that is not zero and written
    # in hex, and a witness list a rotation has changed (h0 is cut, so h1
    # moves from index 1 to index 0).
    later = []
    ctl.rotate(cuts=[h0.pre], toad=1)
    later.append(receipted(1))
    while ctl.kever.sn < 26:
        ctl.interact()
    later.append(receipted(26))  # "1a" in hex

    json.dump({
        "keripy": "1.3.6",
        "controller": ctl.pre,
        "event_said": serder.said,
        "event_b64": b64(serder.raw),
        "event_message_b64": b64(bytes(msg)),
        "witnesses": inception_wits,
        "receipts": receipts,
        "later": later,
    }, sys.stdout, indent=1)
