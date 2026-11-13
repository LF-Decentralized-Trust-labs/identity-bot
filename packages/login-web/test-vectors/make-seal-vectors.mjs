// Makes test-vectors/seal.json: sealed front-end traffic (src/seal.ts, packages/login-go/seal.go), as
// cases both must hold alike, byte for byte. Every key is derived from a fixed seed, ECDH and HKDF
// are deterministic, and the "ephemeral" key of each call is a fixed one, so the file is the same
// every time it is made (the TypeScript test makes it again and compares). Run
// `node test-vectors/make-seal-vectors.mjs` after `npm run build` to rewrite it.
import { createECDH, createHash, hkdfSync, webcrypto } from "node:crypto";
import { writeFileSync } from "node:fs";
import { minimum, relayChain, sealStatement } from "../src/app-test-support.mjs";
import { sealAnswerWithAnyNForVectors, sealPaddedRequestForVectors, sealRequest } from "../dist/seal.js";

const enc = new TextEncoder();
const b64u = (b) => Buffer.from(b).toString("base64url");
const hex = (b) => Buffer.from(b).toString("hex");

// The relay identifier: an inception and one rotation, as a core makes them (the page's
// own key-log test support), so its CURRENT key is its second, and its first key has left.
const chain = relayChain("seal-vectors:relay", 1);
const RID = chain.aid;
const seed = createHash("sha256").update("app-checks:seal-vectors:relay:1").digest(); // the current key's seed
const inception = chain.events[0].text;
const SN = chain.events.length - 1;

// The sealing key from the seed: the first counter whose 32 bytes are a P-256 scalar.
function sealKeyFromSeed(s) {
  for (let ctr = 0; ctr < 8; ctr++) {
    const okm = Buffer.from(hkdfSync("sha256", s, Buffer.alloc(0), "APP-SEAL-KEY-V1" + String.fromCharCode(ctr), 32));
    const e = createECDH("prime256v1");
    try { e.setPrivateKey(okm); return { d: okm, pub: new Uint8Array(e.getPublicKey(null, "uncompressed")) }; } catch { /* not a scalar: next counter */ }
  }
  throw new Error("no sealing key");
}
const jwkPair = async (d, publicKey) => {
  const e = createECDH("prime256v1");
  e.setPrivateKey(d);
  const p = e.getPublicKey(null, "uncompressed");
  const jwk = { kty: "EC", crv: "P-256", x: b64u(p.subarray(1, 33)), y: b64u(p.subarray(33)), d: b64u(d), ext: true };
  const { d: _d, ...pubJwk } = jwk;
  return {
    privateKey: await webcrypto.subtle.importKey("jwk", jwk, { name: "ECDH", namedCurve: "P-256" }, true, ["deriveBits"]),
    publicKey: await webcrypto.subtle.importKey("jwk", pubJwk, { name: "ECDH", namedCurve: "P-256" }, true, []),
  };
};

export async function make() {
  const sk = sealKeyFromSeed(seed);
  const serverPair = await jwkPair(sk.d);
  const statement = sealStatement(chain, sk.pub);
  const ephD = (label) => createHash("sha256").update("seal-vectors:eph:" + label).digest();

  const longBody = JSON.stringify({ words: "héllo ".repeat(300) });
  const calls = [
    { name: "a short call", content: JSON.stringify({ method: "GET", target: "/session/whoami", headers: { authorization: "Bearer tok" }, body: "", ts: "2026-11-12T12:00:00Z" }), answer: JSON.stringify({ status: 200, content_type: "application/json", body: b64u(enc.encode("{}")), inception: null, sig: null }) },
    { name: "an empty call", content: "", answer: "" },
    { name: "a call that just fits its bucket", content: "x".repeat(1020), answer: "y".repeat(1020) },
    { name: "a call one byte over its bucket", content: "x".repeat(1021), answer: "y".repeat(1021) },
    { name: "a call of several buckets", content: longBody, answer: longBody },
  ];
  const requests = [];
  for (const c of calls) {
    const eph = ephD(c.name);
    const { outer, reply } = await sealRequest(RID, sk.pub, enc.encode(c.content), await jwkPair(eph));
    const n = createHash("sha256").update("seal-vectors:n:" + c.name).digest();
    requests.push({ name: c.name, eph_d_hex: hex(eph), content: c.content, outer, answer_n_hex: hex(n), answer_content: c.answer, answer_outer: await reply.seal(enc.encode(c.answer), new Uint8Array(n)) });
  }

  const first = requests[0];
  const tamper = (outer, f) => { const o = JSON.parse(outer); f(o); return JSON.stringify(o); };
  const flip = (s) => (s[0] === "A" ? "B" : "A") + s.slice(1);
  // The last character of a 65-byte point's 87 characters carries 2 unused bits, and a
  // ciphertext of a bucket and a tag (1040 bytes) carries 4: respelling it with only those
  // bits changed decodes to the same bytes, and must not be read.
  const B64 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
  const respell = (t) => { const i = B64.indexOf(t.at(-1)); return t.slice(0, -1) + B64[i ^ 1]; };
  const rename = (outer, from, to) => JSON.stringify(Object.fromEntries(Object.entries(JSON.parse(outer)).map(([k, x]) => [k === from ? to : k, x])));
  const padded = (n, lenField, fill) => { const p = new Uint8Array(n); new DataView(p.buffer).setUint32(0, lenField); p.fill(fill ?? 0, 4 + lenField); return p; };
  const raw = async (label, p) => sealPaddedRequestForVectors(RID, sk.pub, p, await jwkPair(ephD("raw:" + label)));
  const nonZero = padded(1024, 5); nonZero[1023] = 1;
  const refusals = [
    { name: "a changed ciphertext", rid: RID, outer: tamper(first.outer, (o) => { o.ct = flip(o.ct); }) },
    { name: "a changed ephemeral key", rid: RID, outer: tamper(first.outer, (o) => { o.epk = b64u(createECDHPub(ephD("another"))); }) },
    { name: "a call made for another relay identifier", rid: "E" + RID.slice(1).split("").reverse().join(""), outer: first.outer },
    { name: "a version this does not read", rid: RID, outer: tamper(first.outer, (o) => { o.v = 2; }) },
    { name: "a field it does not know", rid: RID, outer: tamper(first.outer, (o) => { o.extra = 1; }) },
    { name: "an answer taken for a call", rid: RID, outer: first.answer_outer },
    { name: "a truncated ciphertext", rid: RID, outer: tamper(first.outer, (o) => { o.ct = o.ct.slice(0, -8); }) },
    { name: "text that is not JSON", rid: RID, outer: "not json" },
    { name: "a true direction swap: an answer's ciphertext in a call's envelope", rid: RID, outer: tamper(first.outer, (o) => { o.ct = JSON.parse(first.answer_outer).ct; }) },
    { name: "an epk respelled in its unused bits", rid: RID, outer: tamper(first.outer, (o) => { o.epk = respell(o.epk); }) },
    { name: "a ciphertext respelled in its unused bits", rid: RID, outer: tamper(first.outer, (o) => { o.ct = respell(o.ct); }) },
    { name: "an epk with padding", rid: RID, outer: tamper(first.outer, (o) => { o.epk += "="; }) },
    { name: "an epk with a line break", rid: RID, outer: tamper(first.outer, (o) => { o.epk += "\n"; }) },
    { name: "an epk with a line break inside it", rid: RID, outer: tamper(first.outer, (o) => { o.epk = o.epk.slice(0, 40) + "\n" + o.epk.slice(40); }) },
    { name: "the field names in upper case", rid: RID, outer: JSON.stringify({ V: 1, EPK: JSON.parse(first.outer).epk, CT: JSON.parse(first.outer).ct }) },
    { name: "one field name in upper case", rid: RID, outer: rename(first.outer, "epk", "Epk") },
    { name: "the version in a different case", rid: RID, outer: rename(first.outer, "v", "V") },
    { name: "a version spelled as text", rid: RID, outer: tamper(first.outer, (o) => { o.v = "1"; }) },
    { name: "padding that is not zeros", rid: RID, outer: await raw("nonzero", nonZero) },
    { name: "a plaintext that is not a bucket's size", rid: RID, outer: await raw("size", padded(1500, 5)) },
    { name: "a bucket twice the size the content needs", rid: RID, outer: await raw("double", padded(2048, 5)) },
    { name: "a length longer than the plaintext", rid: RID, outer: await raw("long", padded(1024, 5000)) },
    { name: "a plaintext too short to hold its length", rid: RID, outer: await raw("short", new Uint8Array(3)) },
  ];
  // Sealed in full under an n of the wrong length: the only thing wrong with each is the length.
  const ANSWERS_WITH_N = {};
  for (const len of [15, 33, 64]) ANSWERS_WITH_N[len] = await sealAnswerWithAnyNForVectors(RID, sk.pub, await jwkPair(ephD(first.name)), new Uint8Array(len).fill(len), enc.encode(first.answer_content));
    const answer_refusals = [
    { name: "a changed ciphertext", request: first.name, answer_outer: tamper(first.answer_outer, (o) => { o.ct = flip(o.ct); }) },
    { name: "another call's answer", request: first.name, answer_outer: requests[2].answer_outer },
    { name: "an answer replayed against a later call", request: requests[1].name, answer_outer: first.answer_outer },
    { name: "a call taken for an answer", request: first.name, answer_outer: first.outer },
    { name: "a true direction swap: a call's ciphertext in an answer's envelope", request: first.name, answer_outer: tamper(first.answer_outer, (o) => { o.ct = JSON.parse(first.outer).ct; }) },
    { name: "a field it does not know", request: first.name, answer_outer: tamper(first.answer_outer, (o) => { o.epk = "x"; }) },
    { name: "no value of the back end's own", request: first.name, answer_outer: tamper(first.answer_outer, (o) => { delete o.n; }) },
    { name: "a changed value of the back end's own", request: first.name, answer_outer: tamper(first.answer_outer, (o) => { o.n = flip(o.n); }) },
    { name: "a value of the back end's own that is too short", request: first.name, answer_outer: tamper(first.answer_outer, (o) => { o.n = o.n.slice(0, 20); }) },
    { name: "a value of the back end's own that is too long", request: first.name, answer_outer: tamper(first.answer_outer, (o) => { o.n = o.n + "AAAAAAAA"; }) },
    ...[15, 33, 64].map((len) => ({ name: `a correctly sealed answer whose own value is ${len} bytes, outside 16 to 32`, request: first.name, answer_outer: ANSWERS_WITH_N[len] })),
    { name: "a ciphertext respelled in its unused bits", request: first.name, answer_outer: tamper(first.answer_outer, (o) => { o.ct = respell(o.ct); }) },
    { name: "the field names in upper case", request: first.name, answer_outer: JSON.stringify({ V: 1, N: JSON.parse(first.answer_outer).n, CT: JSON.parse(first.answer_outer).ct }) },
  ];
  const otherKey = createECDH("prime256v1"); otherKey.generateKeys();
  const stmt = (o) => b64u(JSON.stringify({ ...JSON.parse(Buffer.from(statement, "base64url")), ...o }));
  const without = (k) => { const o = JSON.parse(Buffer.from(statement, "base64url")); delete o[k]; return b64u(JSON.stringify(o)); };
  // The same statement, with only the spelling of its sequence number changed (the value, and so the signature, is the same).
  const respellSn = (spell) => { const t = Buffer.from(statement, "base64url").toString(); return b64u(t.replace(/"sn":(\d+)/, (_, n) => `"sn":${spell(n)}`)); };
  // The same statement written another way that a lax reader would take for it: the sequence number
  // spelled as a float, under an escaped field name, or twice (a reader taking the first and one taking the last differ).
  const text = Buffer.from(statement, "base64url").toString();
  const asText = (t) => b64u(t);
  const shorter = chain.log(1); // the log as it stood before the rotation
  const flipSig = (t) => t.slice(0, 5) + (t[5] === "A" ? "B" : "A") + t.slice(6);
  const otherRid = "E" + RID.slice(1).split("").reverse().join("");
  const MIN = minimum(chain);
  const statement_refusals = [
    { name: "a key the identifier did not sign", rid: RID, statement: stmt({ key: b64u(createECDHPub(ephD("not signed"))) }) },
    { name: "a link naming another identifier", rid: otherRid, statement },
    { name: "a field it does not know", rid: RID, statement: stmt({ extra: 1 }) },
    { name: "no key log", rid: RID, statement: without("log") },
    { name: "no sequence number", rid: RID, statement: without("sn") },
    { name: "an inception alone, as the first version of this carried", rid: RID, statement: b64u(JSON.stringify({ inception: b64u(enc.encode(inception)), key: JSON.parse(Buffer.from(statement, "base64url")).key, sig: JSON.parse(Buffer.from(statement, "base64url")).sig })) },
    { name: "a compressed point", rid: RID, statement: sealStatement(chain, new Uint8Array([2, ...new Uint8Array(32)])) },
    { name: "a signature respelled in its unused bits", rid: RID, statement: stmt({ sig: JSON.parse(Buffer.from(statement, "base64url")).sig.slice(0, -1) + "B" }) },
    { name: "a changed signature", rid: RID, statement: stmt({ sig: flipSig(JSON.parse(Buffer.from(statement, "base64url")).sig) }) },
    { name: "a statement text that is not readable", rid: RID, statement: "!!" },
    { name: "the key the log has left, vouching for the key", rid: RID, statement: sealStatement(chain, sk.pub, { signer: chain.key(0) }) },
    { name: "the key the log has left, vouching at its own, earlier sequence number, in the whole log", rid: RID, statement: sealStatement(chain, sk.pub, { signer: chain.key(0), sn: 0 }) },
    { name: "a statement made at the first event, with the log as it stood then, once a longer log is known", rid: RID, statement: sealStatement(chain, sk.pub, { log: shorter, sn: 0, signer: chain.key(0) }), known_log: chain.log() },
    { name: "a statement whose sequence number is not its log's last", rid: RID, statement: stmt({ sn: 0 }) },
    { name: "a statement the current key signed at an earlier sequence number than its log's last", rid: RID, statement: sealStatement(chain, sk.pub, { sn: 0 }) },
    { name: "a sequence number that is text", rid: RID, statement: stmt({ sn: "1" }) },
    { name: "a sequence number spelled with a fraction", rid: RID, statement: respellSn((n) => `${n}.0`) },
    { name: "a sequence number spelled with an exponent", rid: RID, statement: respellSn((n) => `${n}e0`) },
    { name: "a sequence number spelled as a float under an escaped field name", rid: RID, statement: asText(text.replace(/"sn":(\d+)/, (_, n) => `"\\u0073n":${n}.0`)) },
    { name: "a sequence number given twice, the first whole and the last a float", rid: RID, statement: asText(text.replace(/"sn":(\d+)/, (_, n) => `"sn":${n},"sn":${n}.0`)) },
    { name: "a statement with a space in it", rid: RID, statement: asText(text.replace('"log":', '"log": ')) },
    { name: "a statement with its fields in another order", rid: RID, statement: (() => { const o = JSON.parse(text); return asText(JSON.stringify({ sig: o.sig, sn: o.sn, key: o.key, log: o.log })); })() },
    { name: "a 65-byte key the identifier signed whose first byte is not 4", rid: RID, statement: sealStatement(chain, new Uint8Array([6, ...sk.pub.slice(1)])) },
    { name: "a sequence number spelled with a leading zero", rid: RID, statement: respellSn((n) => `0${n}`) },
    { name: "a true, shorter log that holds the key the removed first machine had, when the link's minimum is the later event", rid: RID, statement: sealStatement(chain, sk.pub, { log: shorter, sn: 0, signer: chain.key(0) }), min: MIN },
    { name: "a log whose event at the minimum's sequence number is another event", rid: RID, statement, min: `${SN}.${chain.events[SN].said.slice(0, -1)}${chain.events[SN].said.endsWith("A") ? "B" : "A"}` },
    { name: "a log that stops short of the minimum's sequence number", rid: RID, statement, min: `${SN + 1}.${chain.events[SN].said}` },
    { name: "a minimum that is not spelled one way", rid: RID, statement, min: `0${SN}.${chain.events[SN].said}` },
    { name: "a key log of another identifier", rid: RID, statement: stmt({ log: relayChain("another", 1).log() }) },
    { name: "a key log whose last event is not signed by the key it names", rid: RID, statement: stmt({ log: (() => { const t = Buffer.from(chain.log(), "base64url").toString(); const i = t.length - 10; return b64u(t.slice(0, i) + (t[i] === "A" ? "B" : "A") + t.slice(i + 1)); })() }) },
  ];

  // What the relay sees of size: the ciphertext's length is its bucket and the tag, nothing finer.
  const sizes = [0, 1, 1019, 1020, 1021, 2043, 2044, 5000].map((n) => ({ content_len: n, ct_len: Math.max(1024, 2 ** Math.ceil(Math.log2(n + 4))) + 16 }));

  // The answer a back end signs to a call dated by a clock it does not share (ADR-072 Amendment 4).
  // `skew_ms` is what a page whose clock reads `now` takes from it (the back end's clock less its own).
  const clock_answer = {
    status: 409,
    now: "2030-01-01T00:00:00Z",
    server_time: "2030-01-01T00:03:00Z",
    body: '{"error":"clock","server_time":"2030-01-01T00:03:00Z"}',
    skew_ms: 180000,
    not_clock_answers: [
      { name: "another status", status: 200, body: '{"error":"clock","server_time":"2030-01-01T00:03:00Z"}' },
      { name: "another error", status: 409, body: '{"error":"other"}' },
      { name: "a time that is not a time", status: 409, body: '{"error":"clock","server_time":"yesterday"}' },
      { name: "not JSON", status: 409, body: "not json" },
    ],
  };

  return {
    about: "Sealed front-end traffic (packages/login-web/src/seal.ts, packages/login-go/seal.go) as cases both must hold alike. Made by make-seal-vectors.mjs; the TypeScript test makes it again and compares. `requests`: sealing `content` to the sealing key with the fixed ephemeral key must give `outer` exactly, opening `outer` gives `content` and a reply that seals `answer_content` to `answer_outer` exactly and opens it again. `refusals`: opening must fail. `answer_refusals`: the reply of the named request must not open it. `sizes`: a ciphertext is its bucket and 16 bytes of tag. `seal_key`: the sealing key is made from the relay identifier's CURRENT key's seed, and its statement is made from the identifier's whole key log, the key, the log's last sequence number and the current key's signature over them. `seal_key.min` is the link's latest key log event the owner's Identity Agent has seen (`<sequence number>.<SAID>`), which the statement's log holds. `statement_refusals`: a statement (read against `known_log`, the longest log the page holds, when there is one, and the link's `min` when there is one) must be refused. `clock_answer`: the answer a back end signs to a call dated by a clock it does not share is `status` with `body` (the back end's UTC time to the second), a page whose clock reads `now` takes `skew_ms` from it, and each of `not_clock_answers` carries no time.",
    rid: RID,
    relay_inception: inception,
    relay_log: chain.log(),
    relay_sn: SN,
    relay_seed_hex: hex(seed),
    seal_key: { private_hex: hex(sk.d), public_b64u: b64u(sk.pub), statement, min: MIN },
    requests, refusals, answer_refusals, statement_refusals, sizes, clock_answer,
  };
}

function createECDHPub(d) { const e = createECDH("prime256v1"); e.setPrivateKey(d); return new Uint8Array(e.getPublicKey(null, "uncompressed")); }

if (import.meta.url === `file://${process.argv[1]}`) {
  writeFileSync(new URL("./seal.json", import.meta.url), JSON.stringify(await make(), null, 2) + "\n");
}
