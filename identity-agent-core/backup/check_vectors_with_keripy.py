"""Check backup/identity-key-vectors.json against stock keripy 1.3.6.

Every post-quantum next-key digest must equal keripy's Diger over the key's qb64
text, each founding must be self-addressing as keripy reads it, and the A, 2A
and B signature forms must read, verify and encode exactly as keripy does.

    python3 -m venv /tmp/kv && /tmp/kv/bin/pip install keri==1.3.6
    /tmp/kv/bin/python -I identity-agent-core/backup/check_vectors_with_keripy.py \
        identity-agent-core/backup/identity-key-vectors.json
"""
import json, sys
from keri.core import coring, indexing, serdering
from keri.core.coring import MtrDex
from keri.core.indexing import IdrDex

v = json.load(open(sys.argv[1]))
fails = 0
for p in v["phrases"]:
    for pq in p["post_quantum"]:
        d = coring.Diger(ser=pq["verkey_qb64"].encode(), code=MtrDex.Blake3_256).qb64
        if d != pq["digest"]:
            print("digest mismatch gen", pq["generation"], d, pq["digest"]); fails += 1
    sf = p["signature_forms"]
    raw = sf["founding_raw"].encode()
    serder = serdering.SerderKERI(raw=raw)  # checks the SAID and the version string
    if serder.pre != serder.said:
        print("founding is not self-addressing"); fails += 1
    k0 = p["keys"][0]["public_key_qb64"]
    verfer = coring.Verfer(qb64=k0)
    for form, want_code, idx, ondex in (("A", IdrDex.Ed25519_Sig, 0, 0), ("2A", IdrDex.Ed25519_Big_Sig, 0, 1), ("B", IdrDex.Ed25519_Crt_Sig, 0, None)):
        s = indexing.Siger(qb64=sf[form])
        if s.code != want_code or s.index != idx or (ondex is not None and s.ondex != ondex):
            print("form", form, "reads as", s.code, s.index, s.ondex); fails += 1
        if not verfer.verify(s.raw, raw):
            print("form", form, "does not verify"); fails += 1
        # keripy encodes the same signature the same way
        mine = indexing.Siger(raw=s.raw, code=want_code, index=idx, ondex=ondex if form == "2A" else (idx if form == "A" else None))
        if mine.qb64 != sf[form]:
            print("form", form, "keripy writes", mine.qb64); fails += 1
print("FAIL" if fails else "OK", fails)
sys.exit(1 if fails else 0)
