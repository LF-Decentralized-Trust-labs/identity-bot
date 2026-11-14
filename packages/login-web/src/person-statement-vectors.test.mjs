// What a page signs for a person (ADR-067) is what the core checks: every statement and fingerprint in the core's own
// signed-fingerprint-vectors.json comes out of this code byte for byte, and a statement this makes for a real key
// holds under WebCrypto, in the low-s form the core takes, with every other field the page's own.
import assert from "node:assert";
import { readFileSync } from "node:fs";
import { personFingerprint, personStatementBytes, personSigner, personVerkey, lowSSignature, signPersonStatement } from "../dist/personStatement.js";

const v = JSON.parse(readFileSync(new URL("../../../identity-agent-core/agentmessage/signed-fingerprint-vectors.json", import.meta.url), "utf8"));
const hex = (h) => new Uint8Array(Buffer.from(h, "hex"));

for (const f of v.fingerprints) assert.equal(personFingerprint(hex(f.salt_hex), hex(f.words_hex)), f.fingerprint, f.name);
let lists = 0, asks = 0;
for (const s of v.statements) {
  assert.equal(personStatementBytes(s.statement), s.signed, s.name);
  assert.equal(personFingerprint(hex(s.salt_hex), hex(s.words_hex)), s.statement.fingerprint, s.name);
  if (s.statement.kind === "list") { lists++; assert.match(s.signed, /^IA-PERSON-MSG-V2\n/); assert.ok(s.statement.audience); }
  else { asks++; assert.match(s.signed, /^IA-PERSON-MSG-V1\n/); }
}
assert.ok(lists >= 1 && asks >= 8, "the vectors the core publishes include a list and the other kinds");

const kp = await crypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, false, ["sign", "verify"]);
const jwk = await crypto.subtle.exportKey("jwk", kp.publicKey);
const key = { privateKey: kp.privateKey, jwk, thumbprint: "t" };
const at = new Date("2026-11-14T10:00:00.123Z");
const env = { now: () => at };

// the signer and verkey are the key's own, named as the core names a P-256 key
assert.match(personSigner(jwk), /^1AAI[A-Za-z0-9_-]{44}$/);
assert.equal(personVerkey(jwk).slice(4), personSigner(jwk).slice(4));

const checks = async (signed, want) => {
  const { statement: p } = signed;
  assert.equal(p.statement.signer, personSigner(jwk));
  assert.equal(p.verkey, personVerkey(jwk));
  assert.equal(p.statement.time, "2026-11-14T10:00:00Z");
  assert.equal(p.statement.fingerprint_version, 1);
  assert.match(p.statement.nonce, /^n-[A-Za-z0-9_-]{16}$/);
  assert.match(p.statement.message_id, /^m-[A-Za-z0-9_-]{16}$/);
  assert.equal(p.statement.fingerprint, personFingerprint(Uint8Array.from(Buffer.from(signed.salt, "base64url")), want.words ?? ""));
  // the signature is the key's over exactly the statement's bytes, low-s, a CESR 0I signature
  assert.match(p.signature, /^0I[A-Za-z0-9_-]{86}$/);
  const raw = Buffer.from(p.signature.slice(2).padStart(88, "A"), "base64url").subarray(2); // 2 pad bytes, then r ‖ s
  assert.equal(raw.length, 64);
  assert.ok(await crypto.subtle.verify({ name: "ECDSA", hash: "SHA-256" }, kp.publicKey, raw, new TextEncoder().encode(personStatementBytes(p.statement))), "the signature is not the key's over the bytes");
  const s = BigInt("0x" + raw.subarray(32).toString("hex"));
  assert.ok(s <= 0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551n >> 1n, "not low-s");
};
const ask = await signPersonStatement(key, { agent: "EIA", kind: "ask", from: "p1", conversation: "c_x", to: "Eagent", words: "Ship it" }, env);
await checks(ask, { words: "Ship it" });
assert.equal(ask.statement.statement.to, "Eagent");
assert.equal(ask.statement.statement.audience, undefined);
const list = await signPersonStatement(key, { agent: "EIA", kind: "list", from: "p1", audience: "ASSETCHAT" }, env);
await checks(list, {});
assert.equal(list.statement.statement.conversation, "list");
assert.equal(list.statement.statement.audience, "ASSETCHAT");
assert.match(personStatementBytes(list.statement.statement), /^IA-PERSON-MSG-V2\n/);
for (const kind of ["close", "reopen"]) await checks(await signPersonStatement(key, { agent: "EIA", kind, from: "p1", conversation: "c_x" }, env), {});

// every statement has its own id, nonce and salt
const again = await signPersonStatement(key, { agent: "EIA", kind: "list", from: "p1", audience: "ASSETCHAT" }, env);
assert.notEqual(again.statement.statement.message_id, list.statement.statement.message_id);
assert.notEqual(again.statement.statement.nonce, list.statement.statement.nonce);
assert.notEqual(again.salt, list.salt);

// what the core refuses is refused before a signature is made
const refuse = async (r, why) => assert.rejects(() => signPersonStatement(key, r, env), (e) => e.message.includes(why), JSON.stringify(r));
await refuse({ agent: "EIA", kind: "list", from: "p1" }, "audience");
await refuse({ agent: "EIA", kind: "ask", from: "p1", conversation: "c", to: "E", words: "x", audience: "A" }, "audience");
await refuse({ agent: "EIA", kind: "list", from: "p1", audience: "A", conversation: "c" }, "no conversation");
await refuse({ agent: "EIA", kind: "ask", from: "p1", conversation: "c", words: "x" }, "who it is to");
await refuse({ agent: "EIA", kind: "ask", from: "p1", conversation: "c", to: "E" }, "who it is to");
await refuse({ agent: "EIA", kind: "close", from: "p1", conversation: "c", words: "x" }, "only an ask");
await refuse({ agent: "EIA", kind: "reopen", from: "p1", conversation: "c", to: "E" }, "only an ask");
await refuse({ agent: "EIA", kind: "close", from: "p1" }, "conversation");
await refuse({ agent: "EIA", kind: "limit", from: "p1", conversation: "c" }, "a page signs");
await refuse({ agent: "", kind: "list", from: "p1", audience: "A" }, "Identity Agent");
await refuse({ agent: "EIA", kind: "list", from: "p1", audience: "A\nB" }, "line break");
await refuse({ agent: "EIA", kind: "ask", from: "p1", conversation: "c\nd", to: "E", words: "x" }, "line break");
assert.throws(() => personFingerprint(new Uint8Array(15), "x"), /salt/);
assert.throws(() => lowSSignature(new Uint8Array(63)), /64 bytes/);
console.log("person statements: every vector the core publishes holds in TypeScript, and what a page signs verifies");
