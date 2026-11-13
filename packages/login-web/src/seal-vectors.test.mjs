// Sealed front-end traffic against the shared cases (test-vectors/seal.json, which
// packages/login-go/seal_vectors_test.go is held to as well), and the file is
// what make-seal-vectors.mjs makes today.
import assert from "node:assert";
import { createECDH } from "node:crypto";
import { readFileSync } from "node:fs";
import { make } from "../test-vectors/make-seal-vectors.mjs";
import { checkSealKey } from "../dist/app.js";
import { openRequest, sealRequest, SealError } from "../dist/seal.js";

const v = JSON.parse(readFileSync(new URL("../test-vectors/seal.json", import.meta.url), "utf8"));
assert.deepEqual(await make(), v, "seal.json is not what make-seal-vectors.mjs makes; run it again");

const enc = new TextEncoder(), dec = new TextDecoder();
const unhex = (h) => Buffer.from(h, "hex");
const spk = Uint8Array.from(Buffer.from(v.seal_key.public_b64u, "base64url"));
const { webcrypto } = await import("node:crypto");
const pair = async (d) => {
  const e = createECDH("prime256v1"); e.setPrivateKey(d);
  const p = e.getPublicKey(null, "uncompressed");
  const jwk = { kty: "EC", crv: "P-256", x: p.subarray(1, 33).toString("base64url"), y: p.subarray(33).toString("base64url") };
  return { privateKey: await webcrypto.subtle.importKey("jwk", { ...jwk, d: d.toString("base64url") }, { name: "ECDH", namedCurve: "P-256" }, true, ["deriveBits"]),
    publicKey: await webcrypto.subtle.importKey("jwk", jwk, { name: "ECDH", namedCurve: "P-256" }, true, []) };
};
const server = await pair(Buffer.from(v.seal_key.private_hex, "hex"));

// the link's sealing key is the relay identifier's and nobody else's
assert.deepEqual(await checkSealKey(v.rid, v.seal_key.statement), spk);
const st = JSON.parse(Buffer.from(v.seal_key.statement, "base64url"));
const re = (o) => Buffer.from(JSON.stringify({ ...st, ...o })).toString("base64url");
const rejects = (p, re_, what) => assert.rejects(p, (e) => re_.test(e.message), what);
await rejects(checkSealKey(v.rid, re({ key: Buffer.from([4, ...new Uint8Array(64).fill(7)]).toString("base64url") })), /did not sign this key/, "a key the identifier did not sign");
await rejects(checkSealKey("E" + v.rid.slice(1).split("").reverse().join(""), v.seal_key.statement), /not the relay identifier the link names/, "a link naming another identifier");
await rejects(checkSealKey(v.rid, re({ extra: 1 })), /fields it should not/, "an extra field");
await rejects(checkSealKey(v.rid, re({ key: Buffer.from([2, ...new Uint8Array(32)]).toString("base64url") })), /uncompressed/, "a compressed point");
await rejects(checkSealKey(v.rid, "!!"), /not readable/, "junk");

for (const c of v.requests) {
  const eph = await pair(unhex(c.eph_d_hex));
  const { outer, reply } = await sealRequest(v.rid, spk, enc.encode(c.content), eph);
  assert.equal(outer, c.outer, c.name + ": the call sealed");
  const opened = await openRequest(v.rid, server, c.outer);
  assert.equal(dec.decode(opened.content), c.content, c.name + ": the call opened");
  assert.equal(await opened.reply.seal(enc.encode(c.answer_content), new Uint8Array(unhex(c.answer_n_hex))), c.answer_outer, c.name + ": the answer sealed");
  assert.equal(dec.decode(await reply.open(c.answer_outer)), c.answer_content, c.name + ": the answer opened");
}
for (const c of v.refusals) await assert.rejects(openRequest(c.rid, server, c.outer), SealError, c.name);
for (const c of v.answer_refusals) {
  const r = v.requests.find((q) => q.name === c.request);
  const { reply } = await sealRequest(v.rid, spk, enc.encode(r.content), await pair(unhex(r.eph_d_hex)));
  await assert.rejects(reply.open(c.answer_outer), SealError, "an answer: " + c.name);
}
// An answer never repeats a key and nonce: two answers to one call differ in n, and so in everything.
{
  const r = v.requests[0];
  const opened = await openRequest(v.rid, server, r.outer);
  const a = JSON.parse(await opened.reply.seal(enc.encode("same")));
  const b = JSON.parse(await opened.reply.seal(enc.encode("same")));
  assert.notEqual(a.n, b.n, "two answers to one call carry the same n");
  assert.notEqual(a.ct, b.ct, "two answers to one call are the same ciphertext");
  assert.equal(Buffer.from(a.n, "base64url").length, 32);
}
for (const s of v.sizes) {
  const { outer } = await sealRequest(v.rid, spk, new Uint8Array(s.content_len));
  assert.equal(Buffer.from(JSON.parse(outer).ct, "base64url").length, s.ct_len, `${s.content_len} bytes seal to ${s.ct_len}`);
}
await assert.rejects(sealRequest(v.rid, spk, new Uint8Array((16 << 20) + 1)), SealError, "more than a message may carry");
await assert.rejects(sealRequest(v.rid, new Uint8Array(65), enc.encode("x")), SealError, "a point that is not on the curve");

console.log("sealed traffic holds the shared cases: bytes equal, refusals refused, sizes in buckets");
