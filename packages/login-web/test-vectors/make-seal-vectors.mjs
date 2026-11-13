// Makes test-vectors/seal.json: sealed front-end traffic (src/seal.ts, packages/login-go/seal.go), as
// cases both must hold alike, byte for byte. Every key is derived from a fixed seed, ECDH and HKDF
// are deterministic, and the "ephemeral" key of each call is a fixed one, so the file is the same
// every time it is made (the TypeScript test makes it again and compares). Run
// `node test-vectors/make-seal-vectors.mjs` after `npm run build` to rewrite it.
import { createECDH, createHash, hkdfSync, webcrypto } from "node:crypto";
import { writeFileSync } from "node:fs";
import { keyFor, logHeader, minimum, relayChain, rotation, sealStatement, witnessAnswer, witnessFor } from "../src/app-test-support.mjs";
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


  // A relay identifier's key log as its witnesses hold it (ADR-072 Amendment 5, src/witnessed.ts): each case is the
  // answers of the witnesses a page asked (GET /witness/kel/{rid}) and what must be made of them: the number of
  // leading events that have their threshold of receipts (`events`), or a refusal. Declared here from how each was
  // built, never by running a reader, so every reader is held to the same expectation.
  const W = [0, 1, 2, 3].map((i) => witnessFor("w" + i));
  const stranger = witnessFor("stranger");
  const chainW = relayChain("witnessed", 1, { b: [W[0].aid, W[1].aid, W[2].aid], bt: "2" });
  const receiptOf = (w, index) => (i, e) => [w.receipt(e.text, index)];
  const ans = (w, index, n = chainW.events.length, chain = chainW) => witnessAnswer(chain, n, receiptOf(w, index));
  // the same inception and the same first key, and a rotation to another next key: a second history from event 1
  const forkChain = (() => {
    const fork = rotation(chainW.aid, 1, chainW.events[0].said, chainW.keys[1], keyFor("witnessed:fork-next"), { bt: "2" });
    return { aid: chainW.aid, events: [chainW.events[0], { ...fork, signer: chainW.keys[1] }] };
  })();
  const case_ = (name, answers, expect, over = {}) => ({ name, rid: over.rid ?? chainW.aid, answers, ...(expect === null ? { refuse: true, ...(over.proven ? { proven: true } : {}) } : { events: expect }) });
  const swapReceipt = (a, i, r) => ({ ...a, kel: a.kel.map((e, j) => (j === i ? { ...e, witness_receipts: [r] } : e)) });
  const rewrite = (a) => ({ ...a, kel: a.kel.map((e, j) => (j === 1 ? { ...e, raw_bytes_b64: Buffer.from(Buffer.from(e.raw_bytes_b64, "base64").toString().replace(/"k":\["D/, '"k":["E')).toString("base64") } : e)) });
  const chainRot = relayChain("witnessed-rot", 1, { b: [W[0].aid, W[1].aid, W[2].aid], bt: "2", over: { 1: { br: [W[2].aid], ba: [W[3].aid], bt: "2" } } });
  const plain = relayChain("witnessed-none", 1);
  // an identifier made without witnesses and given them by its first rotation (the owner's Identity Agent makes that rotation)
  const chainLate = relayChain("witnessed-late", 2, { over: { 1: { ba: [W[0].aid, W[1].aid, W[2].aid], bt: "2" }, 2: { bt: "2" } } });
  // a rotation that cuts a witness the identifier does not have, one that adds a witness it already has, and one that
  // cuts and adds the same: the core does not read such a log, so no reader does
  const badRot = (label, over) => relayChain("witnessed-" + label, 1, { b: [W[0].aid, W[1].aid, W[2].aid], bt: "2", over: { 1: { bt: "2", ...over } } });
  const chainCutStranger = badRot("cut-stranger", { br: [W[3].aid] });
  const chainAddHeld = badRot("add-held", { ba: [W[0].aid] });
  const chainCutAdd = badRot("cut-add", { br: [W[0].aid], ba: [W[0].aid] });
  // a rotation (signed by the owner) that cuts every witness the identifier had
  const chainCutAll = relayChain("witnessed-cut-all", 1, { b: [W[0].aid, W[1].aid, W[2].aid], bt: "2", over: { 1: { br: [W[0].aid, W[1].aid, W[2].aid], bt: "0" } } });
  // the real log's answer with a rotation the controller did not sign, which cuts every witness
  const forgedCutAll = () => { const a = ans(W[2], 2); const forged = JSON.stringify({ ...JSON.parse(Buffer.from(a.kel[1].raw_bytes_b64, "base64").toString()), br: [W[0].aid, W[1].aid, W[2].aid] }); return { ...a, kel: a.kel.map((e, i) => (i === 1 ? { ...e, raw_bytes_b64: Buffer.from(forged).toString("base64") } : e)) }; };
  const threeReceipts = (chain) => [ans(W[0], 0, 2, chain), ans(W[1], 1, 2, chain), ans(W[2], 2, 2, chain)];
  // an answer whose bytes for its first event are not base64 at all
  const unreadable = (a) => ({ ...a, kel: a.kel.map((e, i) => (i === 0 ? { ...e, raw_bytes_b64: "!!!!" } : e)) });
  const newline = (a) => ({ ...a, kel: a.kel.map((e, i) => (i === 0 ? { ...e, raw_bytes_b64: e.raw_bytes_b64.slice(0, 8) + "\n" + e.raw_bytes_b64.slice(8) } : e)) });
  // the older receipts: a `0B` signature over each event's SAID
  const legacy = (w) => witnessAnswer(chainW, 2, (i, e) => [w.legacyReceipt(e.said)]);
  const witnessed = {
    about: "A relay identifier's key log as its witnesses hold it (packages/login-web/src/witnessed.ts, packages/login-dart/lib/witnessed.dart, and in Go identity-agent-core/drivers through witnessed_vectors_test.go). Each case gives `answers` (what each witness the identifier names answered to GET /witness/kel/{rid}: every event with its bytes, the controller's signature and that witness's own receipt) and `rid`. A reader pools the receipts, reads each answer as a key log, counts for each event the distinct witnesses designated at that event whose indexed signature over the event's bytes verifies, and takes the longest log every event of which has its threshold: `events` is how many events that is. `refuse` means no log is taken, and `proven` that the refusal is the witnesses' proof about the identifier (two histories each receipted by a threshold, or a rotation by the owner that cut every witness it had) rather than the want of a log. A log is not read when an event of it names a witness twice or one that is not a witness identifier, a rotation cuts a witness that is not in the list, adds one already in it, or cuts and adds the same: the core refuses it, so every reader does, and only that answer is lost. An answer whose bytes are not base64 (in its one spelling), not UTF-8 or whose signature is not 88 characters is likewise skipped, never an error for the others. A receipt counts only as an indexed signature over the event's bytes at the witness's place; the older unindexed `0B` signature over the SAID is not counted by a page. `page`: a link that names witnesses, taken or refused as `expect` says, by what each address (`w0`, `w1`: the first and second of `wit`) answers. `against_link`: a log a link carried (`link_log`) judged against those answers is `agrees`, `moved_on`, `apart`, `none`, or `refused` (the witnesses prove the identifier unfit: a page then refuses the link rather than going by its minimum).",
    cases: [
      case_("every witness gives the whole log, with its receipt", [ans(W[0], 0), ans(W[1], 1), ans(W[2], 2)], 2),
      case_("exactly a threshold of witnesses answers", [ans(W[0], 0), ans(W[1], 1)], 2),
      case_("one receipt too few", [ans(W[0], 0)], null),
      case_("a witness that is behind does not hold the others back", [ans(W[0], 0), ans(W[1], 1), ans(W[2], 2, 1)], 2),
      case_("the last event has one receipt and the one before it has two", [ans(W[0], 0), { ...ans(W[1], 1), kel: ans(W[1], 1).kel.map((e, i) => (i === 1 ? { raw_bytes_b64: e.raw_bytes_b64, cesr_signature: e.cesr_signature } : e)) }], 1),
      case_("a receipt by a key the identifier did not name", [ans(W[0], 0), ans(stranger, 1)], null),
      case_("a receipt over another event", [ans(W[0], 0), swapReceipt(ans(W[1], 1), 0, W[1].receipt(chainW.events[1].text, 1))], null),
      case_("a receipt at another witness's place in the list", [ans(W[0], 0), ans(W[1], 0)], null),
      case_("one witness's receipt given twice counts once", [ans(W[0], 0), ans(W[0], 0)], null),
      case_("a receipt that is not an indexed signature", [ans(W[0], 0), swapReceipt(ans(W[1], 1), 0, { witness: W[1].aid, cesr_signature: "0B" + W[1].receipt(chainW.events[0].text, 1).cesr_signature.slice(2) })], null),
      case_("a rewritten history: the rotation's bytes changed, the receipt over the original kept", [ans(W[0], 0), rewrite(ans(W[1], 1))], null),
      case_("an answer for another identifier", [ans(W[0], 0), ans(W[1], 1)], null, { rid: chainRot.aid }),
      case_("two histories, each receipted by a threshold, that disagree", [ans(W[0], 0), ans(W[1], 1), ans(W[1], 1, 2, forkChain), ans(W[2], 2, 2, forkChain)], null, { proven: true }),
      case_("a witness list that a rotation changed: the witness it added counts, at its place", [ans(W[0], 0, 2, chainRot), ans(W[1], 1, 1, chainRot), ans(W[3], 2, 2, chainRot)], 2, { rid: chainRot.aid }),
      case_("a witness list that a rotation changed: the witness it cut does not count", [ans(W[0], 0, 2, chainRot), ans(W[1], 1, 1, chainRot), ans(W[2], 2, 2, chainRot)], 1, { rid: chainRot.aid }),
      case_("witnesses named by a rotation: the events before it need no receipt", [witnessAnswer(chainLate, 3, (i, e) => (i === 0 ? [] : [W[0].receipt(e.text, 0)])), witnessAnswer(chainLate, 3, (i, e) => (i === 0 ? [] : [W[1].receipt(e.text, 1)]))], 3, { rid: chainLate.aid }),
      case_("witnesses named by a rotation that has too few receipts", [witnessAnswer(chainLate, 3, (i, e) => (i === 0 ? [] : [W[0].receipt(e.text, 0)]))], 1, { rid: chainLate.aid }),
      case_("a rotation that cuts a witness the identifier does not have", threeReceipts(chainCutStranger), null, { rid: chainCutStranger.aid }),
      case_("a rotation that adds a witness the identifier already has", threeReceipts(chainAddHeld), null, { rid: chainAddHeld.aid }),
      case_("a rotation that cuts and adds the same witness", threeReceipts(chainCutAdd), null, { rid: chainCutAdd.aid }),
      case_("a rotation that cuts every witness, in an answer its controller did not sign, is skipped and not a refusal", [ans(W[0], 0), ans(W[1], 1), forgedCutAll()], 2),
      case_("a rotation that cuts every witness the identifier had", threeReceipts(chainCutAll), null, { rid: chainCutAll.aid, proven: true }),
      case_("receipts in the older form, over the digest, from a threshold of witnesses", [legacy(W[0]), legacy(W[1])], null),
      case_("an answer whose bytes are not base64 does not hold the others back", [ans(W[0], 0), ans(W[1], 1), unreadable(ans(W[2], 2))], 2),
      case_("an answer whose base64 has a newline in it does not hold the others back", [ans(W[0], 0), ans(W[1], 1), newline(ans(W[2], 2))], 2),
      case_("the one answer there is has bytes that are not base64", [unreadable(ans(W[0], 0))], null),
      case_("an identifier whose inception names no witnesses", [witnessAnswer(plain, 2)], null, { rid: plain.aid }),
    ],
    // What a page does with the log a link carried (`link_log`, already read) once it has asked the witnesses (src/witnessed.ts `judgeLinkLog`):
    // the link's log holds what they vouch for (`agrees`), they vouch for more (`moved_on`: the key the link vouched a sealing key for is
    // not current), the two disagree on an event (`apart`), they gave no log to take (`none`), or what they hold proves the identifier unfit (`refused`: two histories each receipted, or a rotation that cut every witness).
    against_link: [
      { name: "the link holds what the witnesses vouch for", link_log: chainW.log(), answers: [ans(W[0], 0), ans(W[1], 1)], verdict: "agrees" },
      { name: "the link is ahead of witnesses that have not been told yet", link_log: chainW.log(), answers: [ans(W[0], 0, 1), ans(W[1], 1, 1)], verdict: "agrees" },
      { name: "the witnesses vouch for a rotation the link's log does not have", link_log: chainW.log(1), answers: [ans(W[0], 0), ans(W[1], 1)], verdict: "moved_on" },
      { name: "the link and the witnesses hold different events at one place", link_log: logHeader(forkChain.events), answers: [ans(W[0], 0), ans(W[1], 1)], verdict: "apart" },
      { name: "the witnesses have receipted nothing", link_log: chainW.log(), answers: [ans(W[0], 0)], verdict: "none" },
      { name: "no witness answered", link_log: chainW.log(), answers: [], verdict: "none" },
      { name: "witnesses that receipted two histories", link_log: chainW.log(), answers: [ans(W[0], 0), ans(W[1], 1), ans(W[1], 1, 2, forkChain), ans(W[2], 2, 2, forkChain)], verdict: "refused" },
      { name: "a rotation that cut every witness", link_log: chainCutAll.log(), answers: threeReceipts(chainCutAll), verdict: "refused", rid: chainCutAll.aid },
    ].map((c) => ({ rid: chainW.aid, ...c })),
    // A page given a link that names witnesses (`wit`, by address) asks each for the log (GET <address>/witness/kel/<rid>) and goes by it:
    // `held` is what each address answers (`down` is a witness that cannot be reached). `taken` gives the sealing key; `moved_on` is refused
    // with "moved on since this link was made". `statement` is the link's sealing key statement, `min` its latest event.
    page: [
      { name: "witnesses that vouch for what the link carries", statement: sealStatement(chainW, sk.pub), min: minimum(chainW), held: { w0: ans(W[0], 0), w1: ans(W[1], 1) }, expect: "taken" },
      { name: "a link made before the rotation the witnesses vouch for", statement: sealStatement(chainW, sk.pub, { log: chainW.log(1), sn: 0, signer: chainW.key(0) }), min: minimum(chainW, 1), held: { w0: ans(W[0], 0), w1: ans(W[1], 1) }, expect: "moved_on" },
      { name: "witnesses that cannot be reached", statement: sealStatement(chainW, sk.pub, { log: chainW.log(1), sn: 0, signer: chainW.key(0) }), min: minimum(chainW, 1), held: { w0: "down", w1: "down" }, expect: "taken" },
      { name: "witnesses that have receipted too little", statement: sealStatement(chainW, sk.pub, { log: chainW.log(1), sn: 0, signer: chainW.key(0) }), min: minimum(chainW, 1), held: { w0: ans(W[0], 0) }, expect: "taken" },
      { name: "witnesses that hold a rotation that cut every witness", rid: chainCutAll.aid, statement: sealStatement(chainCutAll, sk.pub), min: minimum(chainCutAll), held: { w0: ans(W[0], 0, 2, chainCutAll), w1: ans(W[1], 1, 2, chainCutAll) }, expect: "refused" },
    ].map((c) => ({ rid: chainW.aid, ...c, wit: ["https://w0.example/api", "https://w1.example/api"] })),
  };

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

  // The outer answer a back end gives a call it could not open: the sealing key it was sealed to has moved on
  // (a rotation). Unsigned. The front end then GETs `statement_path` and checks the statement as a link's.
  const sealing_key_answer = {
    status: 400,
    body: '{"error":"sealing key"}',
    statement_path: "/sealing-key",
    not_sealing_key_answers: [
      { name: "another status", status: 200, body: '{"error":"sealing key"}' },
      { name: "another error", status: 400, body: '{"error":"not accepted"}' },
      { name: "a space in the body", status: 400, body: '{"error": "sealing key"}' },
      { name: "more in the body", status: 400, body: '{"error":"sealing key","server_time":"2030-01-01T00:00:00Z"}' },
      { name: "not JSON", status: 400, body: "sealing key" },
      { name: "an empty body", status: 400, body: "" },
    ],
  };

  // A routine rotation moves the sealing key. `rotation`: a page whose link carries `old` (the sealing key
  // and statement above, at `old.min`) seals a call to a back end that has since rotated the relay identifier
  // once more (`new`): `old_outer` does not open there and the back end answers `sealing_key_answer`, the
  // statement now in force (`new.statement`, the identifier's log with one more rotation, signed by the key that
  // rotation put in force) is the page's to take, held to `old.min` and to the log it already knows, and a call
  // sealed to its key opens. The statement made earlier is not taken once the newer log is known.
  const after = relayChain("seal-vectors:relay", 2);
  if (after.events[1].said !== chain.events[1].said) throw new Error("the rotated log must carry on from the earlier one");
  const sk2 = sealKeyFromSeed(createHash("sha256").update("seal-vectors:relay:after-rotation").digest());
  const rotationCall = JSON.stringify({ method: "POST", target: "/api/mcp/agents/a/conversations", headers: { authorization: "Bearer tok" }, body: JSON.stringify({ text: "the message being sent" }), ts: "2026-11-12T12:00:00Z" });
  const rotated = {
    old: { public_b64u: b64u(sk.pub), statement, min: MIN },
    new: { private_hex: hex(sk2.d), public_b64u: b64u(sk2.pub), statement: sealStatement(after, sk2.pub), log: after.log(), sn: after.events.length - 1 },
    content: rotationCall,
    old_eph_d_hex: hex(ephD("rotation:old")),
    old_outer: (await sealRequest(RID, sk.pub, enc.encode(rotationCall), await jwkPair(ephD("rotation:old")))).outer,
    new_eph_d_hex: hex(ephD("rotation:new")),
    new_outer: (await sealRequest(RID, sk2.pub, enc.encode(rotationCall), await jwkPair(ephD("rotation:new")))).outer,
  };

  return {
    about: "Sealed front-end traffic (packages/login-web/src/seal.ts, packages/login-go/seal.go) as cases both must hold alike. Made by make-seal-vectors.mjs; the TypeScript test makes it again and compares. `requests`: sealing `content` to the sealing key with the fixed ephemeral key must give `outer` exactly, opening `outer` gives `content` and a reply that seals `answer_content` to `answer_outer` exactly and opens it again. `refusals`: opening must fail. `answer_refusals`: the reply of the named request must not open it. `sizes`: a ciphertext is its bucket and 16 bytes of tag. `seal_key`: the sealing key is made from the relay identifier's CURRENT key's seed, and its statement is made from the identifier's whole key log, the key, the log's last sequence number and the current key's signature over them. `seal_key.min` is the link's latest key log event the owner's Identity Agent has seen (`<sequence number>.<SAID>`), which the statement's log holds. `statement_refusals`: a statement (read against `known_log`, the longest log the page holds, when there is one, and the link's `min` when there is one) must be refused. `clock_answer`: the answer a back end signs to a call dated by a clock it does not share is `status` with `body` (the back end's UTC time to the second), a page whose clock reads `now` takes `skew_ms` from it, and each of `not_clock_answers` carries no time. `sealing_key_answer`: the outer answer a back end gives a call it could not open (the sealing key it was sealed to has moved on) is `status` with exactly `body`, unsigned, and a front end that reads it fetches `statement_path` and checks the statement as it checks a link's; none of `not_sealing_key_answers` is that answer. `rotation`: a call sealed to the `old` sealing key does not open at a back end whose key is `new.private_hex` (`old_outer`), and one sealed to `new` does (`new_outer`, content `content`); the page then takes `new.statement`, checked against `old.min` and the log it already holds (`relay_log`), as the sealing key now in force, and does not take `old.statement` once it holds `new.log`.",
    rid: RID,
    relay_inception: inception,
    relay_log: chain.log(),
    relay_sn: SN,
    relay_seed_hex: hex(seed),
    seal_key: { private_hex: hex(sk.d), public_b64u: b64u(sk.pub), statement, min: MIN },
    requests, refusals, answer_refusals, statement_refusals, sizes, clock_answer, sealing_key_answer, rotation: rotated, witnessed,
  };
}

function createECDHPub(d) { const e = createECDH("prime256v1"); e.setPrivateKey(d); return new Uint8Array(e.getPublicKey(null, "uncompressed")); }

if (import.meta.url === `file://${process.argv[1]}`) {
  writeFileSync(new URL("./seal.json", import.meta.url), JSON.stringify(await make(), null, 2) + "\n");
}
