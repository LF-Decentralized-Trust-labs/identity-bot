"""Genuine keripy events: an inception, then the rotations that matter."""
import json
from keri.core import coring, eventing
from keri.core.coring import MtrDex

def signer(tag):
    return coring.Signer(raw=(tag * 32)[:32].encode(), code=MtrDex.Ed25519_Seed, transferable=True)

cur, nxt, atk = signer("a"), signer("b"), signer("z")
nxt_dig = coring.Diger(ser=nxt.verfer.qb64b).qb64
atk_dig = coring.Diger(ser=atk.verfer.qb64b).qb64

icp = eventing.incept(keys=[cur.verfer.qb64], ndigs=[nxt_dig], code=MtrDex.Blake3_256)
aid = icp.ked["i"]

def rotate(keys, ndigs):
    return eventing.rotate(pre=aid, keys=keys, dig=icp.said, sn=1, ndigs=ndigs)

good = rotate([nxt.verfer.qb64], [atk_dig])   # reveals the key the inception promised
evil = rotate([atk.verfer.qb64], [atk_dig])   # reveals a key nobody ever promised

def rec(serder, sgnr=None):
    r = {"event_json": json.dumps(serder.ked), "event_type": serder.ked["t"]}
    if sgnr:
        r["cesr_signature"] = sgnr.sign(ser=serder.raw, index=None).qb64
    return r

print(json.dumps({"aid": aid, "cases": {
    "genuine — signed, pre-rotation honoured":        [rec(icp, cur), rec(good, nxt)],
    "ATTACK — unsigned rotation to an attacker key":  [rec(icp, cur), rec(evil)],
    "ATTACK — signed, but key was never committed to":[rec(icp, cur), rec(evil, atk)],
}}))
