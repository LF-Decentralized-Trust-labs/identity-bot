// Every qb64 key and signature has exactly one string. The others that decode
// to the same bytes — lead bits set, a character added, line breaks — are
// refused.
import assert from "node:assert/strict";
import * as ed from "@noble/ed25519";
import { decodeMatterRaw, matterFixedQb64 } from "../dist/canonical.js";

const B64 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

function withLeadBits(qb64, codeLen, k) {
  const leadBits = 2 * (codeLen % 4);
  const v = B64.indexOf(qb64[codeLen]);
  const w = (v & (0x3f >> leadBits)) | (k << (6 - leadBits));
  return qb64.slice(0, codeLen) + B64[w] + qb64.slice(codeLen + 1);
}

// A real key: one that is not a point on the curve is refused in any spelling.
const key = await ed.getPublicKeyAsync(new Uint8Array(32).fill(0x5a));
const verkey = matterFixedQb64("D", key);
assert.deepEqual(decodeMatterRaw(verkey, "D", 32), key, "the canonical key reads back");
for (let k = 1; k < 4; k++) {
  assert.equal(decodeMatterRaw(withLeadBits(verkey, 1, k), "D", 32), null, `key with lead bits ${k}`);
}

const sig = new Uint8Array(64).fill(0xa5);
const sigQb64 = matterFixedQb64("0B", sig);
assert.deepEqual(decodeMatterRaw(sigQb64, "0B", 64), sig, "the canonical signature reads back");
for (let k = 1; k < 16; k++) {
  assert.equal(decodeMatterRaw(withLeadBits(sigQb64, 2, k), "0B", 64), null, `signature with lead bits ${k}`);
}

for (const [name, s] of Object.entries({
  "one long": verkey + "A",
  "four long": verkey + "AAAA",
  "one short": verkey.slice(0, 43),
  "padded": verkey.slice(0, 43) + "=",
  "line break": verkey.slice(0, 20) + "\n" + verkey.slice(20),
  "a character Node skips": verkey.slice(0, 20) + "*" + verkey.slice(20),
})) {
  assert.equal(decodeMatterRaw(s, "D", 32), null, name);
}
console.log("a key has one spelling: ok");
