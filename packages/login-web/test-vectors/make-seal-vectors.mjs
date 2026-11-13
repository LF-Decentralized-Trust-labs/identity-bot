// Makes test-vectors/seal.json: sealed front-end traffic (src/seal.ts, packages/login-go/seal.go), as
// cases both must hold alike, byte for byte. Every key is derived from a fixed seed, ECDH and HKDF
// are deterministic, and the "ephemeral" key of each call is a fixed one, so the file is the same
// every time it is made (the TypeScript test makes it again and compares). Run
// `node test-vectors/make-seal-vectors.mjs` after `npm run build` to rewrite it.
import { createECDH, createHash, createPrivateKey, hkdfSync, sign as edSign, webcrypto } from "node:crypto";
import { writeFileSync } from "node:fs";
import { blake3Qb64, ed25519VerkeyQb64 } from "../../login-verify/dist/browser.js";
import { sealKeyStatementText, sealPaddedRequestForVectors, sealRequest } from "../dist/seal.js";

const enc = new TextEncoder();
const b64u = (b) => Buffer.from(b).toString("base64url");
const hex = (b) => Buffer.from(b).toString("hex");
const PKCS8_ED25519 = Buffer.from("302e020100300506032b657004220420", "hex");

// The relay identifier: one key, one inception, as a core makes it.
const seed = createHash("sha256").update("seal-vectors:relay").digest();
const priv = createPrivateKey({ key: Buffer.concat([PKCS8_ED25519, seed]), format: "der", type: "pkcs8" });
const pub = Buffer.from(priv.export({ format: "jwk" }).x, "base64url");
const key = ed25519VerkeyQb64(new Uint8Array(pub));
const ev = (d) => `{"v":"KERI10JSON000000_","t":"icp","d":"${d}","i":"${d}","s":"0","kt":"1","k":["${key}"],"nt":"1","n":[],"bt":"0","b":[],"c":[],"a":[]}`;
const RID = blake3Qb64(enc.encode(ev("#".repeat(44))));
const inception = ev(RID);
const sign = (bytes) => new Uint8Array(edSign(null, Buffer.from(bytes), priv));

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
  const statement = b64u(JSON.stringify({ inception: b64u(enc.encode(inception)), key: b64u(sk.pub), sig: b64u(sign(sealKeyStatementText(RID, sk.pub))) }));
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
    { name: "a ciphertext respelled in its unused bits", request: first.name, answer_outer: tamper(first.answer_outer, (o) => { o.ct = respell(o.ct); }) },
    { name: "the field names in upper case", request: first.name, answer_outer: JSON.stringify({ V: 1, N: JSON.parse(first.answer_outer).n, CT: JSON.parse(first.answer_outer).ct }) },
  ];
  // What the relay sees of size: the ciphertext's length is its bucket and the tag, nothing finer.
  const sizes = [0, 1, 1019, 1020, 1021, 2043, 2044, 5000].map((n) => ({ content_len: n, ct_len: Math.max(1024, 2 ** Math.ceil(Math.log2(n + 4))) + 16 }));

  return {
    about: "Sealed front-end traffic (packages/login-web/src/seal.ts, packages/login-go/seal.go) as cases both must hold alike. Made by make-seal-vectors.mjs; the TypeScript test makes it again and compares. `requests`: sealing `content` to the sealing key with the fixed ephemeral key must give `outer` exactly, opening `outer` gives `content` and a reply that seals `answer_content` to `answer_outer` exactly and opens it again. `refusals`: opening must fail. `answer_refusals`: the reply of the named request must not open it. `sizes`: a ciphertext is its bucket and 16 bytes of tag. `seal_key`: the sealing key is made from the relay identifier's seed, and its statement is made from the inception, key and signature.",
    rid: RID,
    relay_inception: inception,
    relay_seed_hex: hex(seed),
    seal_key: { private_hex: hex(sk.d), public_b64u: b64u(sk.pub), statement },
    requests, refusals, answer_refusals, sizes,
  };
}

function createECDHPub(d) { const e = createECDH("prime256v1"); e.setPrivateKey(d); return new Uint8Array(e.getPublicKey(null, "uncompressed")); }

if (import.meta.url === `file://${process.argv[1]}`) {
  writeFileSync(new URL("./seal.json", import.meta.url), JSON.stringify(await make(), null, 2) + "\n");
}
