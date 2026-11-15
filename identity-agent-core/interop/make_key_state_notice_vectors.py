"""Make the key state notice and witness location test vectors with keripy's own code.

    python3 -I interop/make_key_state_notice_vectors.py > witnessproto/testdata/keripy_key_state_notice.json   # needs keri==1.3.6

A controller incepts with two witnesses, rotates (cutting one witness, adding a
third, so br and ba are not empty), then interacts, so the newest event is not
an establishment event. keripy states its key state (Kever.state, the record a
/ksn reply carries), and one witness, a non-transferable keripy Hab, signs:

- the /ksn/{witness} reply carrying that record, as keripy's Kevery makes it
  for a key state query (keri/core/eventing.py, processQuery);
- its own /loc/scheme reply (Hab.makeLocScheme).

What it prints is what keripy produced and nothing of ours. The witness's
signature is the one keripy attaches as a non-transferable couple (-CAB): its
key, then its signature. witnessproto/key_state_notice_keripy_test.go checks
that our reader believes both replies, that our record of the same events is
keripy's record, and that our writer makes keripy's notice byte for byte.
"""
import base64
import importlib.metadata
import json

from keri.app import habbing
from keri.core import eventing, serdering, signing

assert importlib.metadata.version("keri") == "1.3.6", "vectors are made with keri 1.3.6"

STAMP = "2026-11-13T10:00:00.000000+00:00"


def salt(b):
    return signing.Salter(raw=b).qb64


b64 = lambda b: base64.b64encode(bytes(b)).decode()


def couple(msg, serder):
    """The witness key and signature of keripy's non-transferable couple."""
    att = bytes(msg[len(serder.raw):]).decode()
    if att.startswith("-V"):  # the pipelined attachment group around it
        att = att[4:]
    assert att.startswith("-CAB"), att
    return att[4:48], att[48:136]


seeds = [bytes([7] * 32), bytes([9] * 32), bytes([11] * 32)]
with habbing.openHby(name="ctl", temp=True, salt=salt(b"0123456789abcdef")) as hby, \
     habbing.openHby(name="w0", temp=True, salt=salt(b"fedcba9876543210")) as w0, \
     habbing.openHby(name="w1", temp=True, salt=salt(b"abcdef0123456789")) as w1, \
     habbing.openHby(name="w2", temp=True, salt=salt(b"9876543210fedcba")) as w2:
    wits = [hb.makeHab(name="w", transferable=False,
                       secrecies=[[signing.Signer(raw=seed, transferable=False).qb64]])
            for hb, seed in zip((w0, w1, w2), seeds)]
    ctl = hby.makeHab(name="c", wits=[wits[0].pre, wits[1].pre], toad=2)
    ctl.rotate(cuts=[wits[0].pre], adds=[wits[2].pre], toad=2)
    ctl.interact()

    events = []
    for sn in range(ctl.kever.sn + 1):
        ser = serdering.SerderKERI(raw=bytes(ctl.makeOwnEvent(sn=sn)))
        events.append(b64(ser.raw))

    rec = ctl.kever.state()._asdict()
    rec["dt"] = STAMP  # first seen, fixed so the vectors can be reproduced

    signer = wits[1]
    rpy = eventing.reply(route=f"/ksn/{signer.pre}", data=rec, stamp=STAMP)
    msg = signer.endorse(rpy)
    key, sig = couple(msg, rpy)
    assert key == signer.pre

    loc = signer.makeLocScheme(url="https://witness.example:5631/", scheme="https", stamp=STAMP)
    lrpy = eventing.reply(route="/loc/scheme",
                          data=dict(eid=signer.pre, scheme="https", url="https://witness.example:5631/"),
                          stamp=STAMP)
    lmsg = signer.endorse(lrpy)
    assert bytes(lmsg) == bytes(loc), "makeLocScheme is reply + endorse"
    lkey, lsig = couple(lmsg, lrpy)

    print(json.dumps({
        "keripy": "1.3.6",
        "stamp": STAMP,
        "controller": ctl.pre,
        "events_b64": events,
        "key_state_record": rec,
        "witness": signer.pre,
        "witness_seed_b64": b64(seeds[1]),
        "ksn_b64": b64(rpy.raw),
        "ksn_signature": sig,
        "loc_url": "https://witness.example:5631/",
        "loc_b64": b64(lrpy.raw),
        "loc_signature": lsig,
    }, indent=1))
