// Sealed front-end traffic against the shared cases (test-vectors/seal.json, which
// packages/login-go/seal_vectors_test.go is held to as well), and the file is
// what make-seal-vectors.mjs makes today.
import assert from "node:assert";
import { createECDH } from "node:crypto";
import { readFileSync } from "node:fs";
import { make } from "../test-vectors/make-seal-vectors.mjs";
import { checkedSealKey, checkSealKey, clockAnswerSkew } from "../dist/app.js";
import { judgeLinkLog, readWitnessedLog } from "../dist/witnessed.js";
import { isSealingKeyAnswer, openRequest, sealRequest, sealPaddedRequestForVectors, SealError, SEAL_STATEMENT_PATH } from "../dist/seal.js";

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

// the link's sealing key is vouched for by the relay identifier's CURRENT key, at its log's last event
assert.deepEqual((await checkSealKey(v.rid, v.seal_key.statement)).key, spk);
assert.equal((await checkSealKey(v.rid, v.seal_key.statement)).log, v.relay_log, "the log to remember is the statement's");
// and the page keeps the longest log it has seen: a statement is read against it, and a longer one is taken
assert.equal((await checkSealKey(v.rid, v.seal_key.statement, v.relay_log)).log, v.relay_log);
// and one that holds the link's latest event is taken, with a page that has seen nothing, or with a corrupt memory
assert.equal((await checkSealKey(v.rid, v.seal_key.statement, null, v.seal_key.min)).log, v.relay_log);
assert.equal((await checkSealKey(v.rid, v.seal_key.statement, "!!", v.seal_key.min)).log, v.relay_log, "an unreadable memory is replaced where the link gives a minimum");
await assert.rejects(checkSealKey(v.rid, v.seal_key.statement, "!!"), /cannot be read/, "an unreadable memory with no minimum is not taken for none");
for (const c of v.statement_refusals) {
  await assert.rejects(checkSealKey(c.rid, c.statement, c.known_log, c.min), (e) => /sealing key is refused/.test(e.message), "a statement: " + c.name);
}

// the log a relay identifier's witnesses vouch for
for (const c of v.witnessed.cases) {
  if (c.refuse) await assert.rejects(readWitnessedLog(c.rid, c.answers), /witnesses' key log is refused/, "witnessed: " + c.name);
  else assert.equal((await readWitnessedLog(c.rid, c.answers)).events, c.events, "witnessed: " + c.name);
}

for (const c of v.witnessed.against_link) {
  const j = await judgeLinkLog(c.rid, c.link_log, c.answers);
  assert.equal(j.verdict, c.verdict, "against the link: " + c.name);
}

for (const c of v.witnessed.page) {
  const held = { "https://w0.example/api": c.held.w0, "https://w1.example/api": c.held.w1 };
  const fetchWit = async (url) => {
    const a = held[String(url).replace(/\/witness\/kel\/.*/, "")];
    if (a === "down") throw new TypeError("network down");
    return a ? new Response(JSON.stringify(a), { status: 200 }) : new Response("not held", { status: 404 });
  };
  const link = { aid: "", kel: "", rid: c.rid, api: "https://tasks.example", seal: c.statement, min: c.min, wit: c.wit };
  const take = checkedSealKey(link, { get: () => null, set: () => {} }, fetchWit);
  if (c.expect === "taken") assert.deepEqual((await take).key, spk, "a page: " + c.name);
  else await assert.rejects(take, /moved on since this link was made/, "a page: " + c.name);
}

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

{
  // an answer's own value is 16 to 32 bytes when it is made, and its version is the one this page reads
  const eph = await pair(Buffer.alloc(32, 7));
  const { outer, reply } = await sealRequest(v.rid, spk, enc.encode("call"), eph);
  const opened = await openRequest(v.rid, server, outer);
  await assert.rejects(opened.reply.seal(enc.encode("a"), new Uint8Array(15)), SealError, "an answer value below the least");
  await assert.rejects(opened.reply.seal(enc.encode("a"), new Uint8Array(33)), SealError, "an answer value above the most");
  const answer = JSON.parse(await opened.reply.seal(enc.encode("a")));
  assert.equal(dec.decode(await reply.open(JSON.stringify(answer))), "a");
  await assert.rejects(reply.open(JSON.stringify({ ...answer, v: 2 })), SealError, "an answer of another version");
  // a message that declares more than the most is refused though its size and zeros are the bucket's
  const n = (16 << 20) + 1;
  let want = 1024; while (want < n + 4) want *= 2;
  const padded = new Uint8Array(want);
  new DataView(padded.buffer).setUint32(0, n);
  const big = await sealPaddedRequestForVectors(v.rid, spk, padded, eph);
  await assert.rejects(openRequest(v.rid, server, big), SealError, "a message declaring more than the most");
}

{
  const ca = v.clock_answer, now = Date.parse(ca.now);
  const ans = (status, body) => ({ status, contentType: "application/json", bytes: enc.encode(body) });
  assert.equal(clockAnswerSkew(ans(ca.status, ca.body), now), ca.skew_ms, "the shared clock answer gives its skew");
  for (const c of ca.not_clock_answers) assert.equal(clockAnswerSkew(ans(c.status, c.body), now), null, "not a clock answer: " + c.name);
}

{
  const sk = v.sealing_key_answer;
  assert.ok(isSealingKeyAnswer(sk.status, sk.body), "the shared sealing key answer is one");
  assert.equal(SEAL_STATEMENT_PATH, sk.statement_path);
  for (const c of sk.not_sealing_key_answers) assert.ok(!isSealingKeyAnswer(c.status, c.body), "not a sealing key answer: " + c.name);
}

{
  // a call sealed before a rotation does not open after it; the statement now in force is the page's to take
  const r = v.rotation, fresh = await pair(unhex(r.new.private_hex));
  await assert.rejects(openRequest(v.rid, fresh, r.old_outer), SealError, "a call sealed to the key before the rotation");
  await assert.rejects(openRequest(v.rid, server, r.new_outer), SealError, "a call sealed to the new key, at the old back end");
  assert.equal(dec.decode((await openRequest(v.rid, fresh, r.new_outer)).content), r.content, "a call sealed to the new key opens");
  const got = await checkSealKey(v.rid, r.new.statement, v.relay_log, r.old.min);
  assert.deepEqual(got.key, Uint8Array.from(Buffer.from(r.new.public_b64u, "base64url")), "the statement now in force gives the new key");
  assert.equal(got.log, r.new.log);
  assert.equal((await checkSealKey(v.rid, r.new.statement, null, r.old.min)).log, r.new.log, "a page with no memory takes it, held to the link's minimum");
  await assert.rejects(checkSealKey(v.rid, r.old.statement, r.new.log, r.old.min), /sealing key is refused/, "the statement made earlier is not taken once the newer log is known");
}

console.log("sealed traffic holds the shared cases: bytes equal, refusals refused, sizes in buckets");
