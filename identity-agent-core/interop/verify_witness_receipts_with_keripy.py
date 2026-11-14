"""Judge the witness receipts identity-agent-core writes with keripy's own parser.

    (cd witnessproto && OUR_RECEIPTS_OUT=/tmp/r.json go test . -run TestWriteOurReceiptsForKeripyToJudge)   # witnessproto is its own module
    python3 -I interop/verify_witness_receipts_with_keripy.py /tmp/r.json   # needs keri==1.3.6

The cases are keripy's own inception (made by make_witness_receipt_vectors.py)
and OUR receipts of it, written from the same witness keys. A fresh Kevery is
given the inception, then the receipts, and a receipt passes only if keripy
stores its witness signature against the event: that it parsed, found the
witness in the controller's list, and verified the signature over the event.
Each receipt is then given again with one character of its signature changed,
and that must not be stored, so a run shows the judge can say no.

keripy reads the receipts and the controller's key log, and decides.
"""
import base64
import importlib.metadata
import json
import sys

from keri.core import eventing, parsing
from keri.db import basing, dbing

if importlib.metadata.version("keri") != "1.3.6":
    sys.exit("these checks are made against keri 1.3.6")


def judge(case, tamper):
    with basing.openDB(name="judge", temp=True) as db:
        kvy = eventing.Kevery(db=db, lax=True, local=False)
        psr = parsing.Parser(kvy=kvy)
        # A witnessed inception waits in keripy's escrow for its receipts.
        psr.parse(ims=bytearray(base64.b64decode(case["event_message_b64"])))
        for m in case["receipts"]:
            msg = bytearray(base64.b64decode(m))
            if tamper:
                i = len(msg) - 3
                msg[i] = ord("A") if msg[i] != ord("A") else ord("B")
            psr.parse(ims=msg)
        kvy.processEscrows()
        wigs = db.getWigs(dbing.dgKey(case["controller"], case["event_said"]))
        accepted = case["controller"] in kvy.kevers
        if accepted != (not tamper):
            return -1 if accepted else len(wigs)
        return len(wigs)


case = json.load(open(sys.argv[1]))
good = judge(case, tamper=False)
bad = judge(case, tamper=True)
want = len(case["receipts"])
print(f"keripy stored {good} of {want} witness signatures; with one character changed, {bad}")
if good != want or not isinstance(bad, int) or bad >= want:
    sys.exit(1)
