// Every case in test-vectors/app-checks.json holds in TypeScript, and the file is the one the generator makes.
import assert from "node:assert";
import { readFileSync } from "node:fs";
import { make } from "../test-vectors/make-app-checks.mjs";
import { answerText, browserKeyThumbprint, checkAppAnswer, checkAppChallenge, checkAppKeyLog, proofText, readAppLink, serverSkew } from "../dist/app.js";

const path = new URL("../test-vectors/app-checks.json", import.meta.url);
const v = JSON.parse(readFileSync(path, "utf8"));
assert.deepEqual(await make(), v, "app-checks.json is not what make-app-checks.mjs makes: run it");

const hex = (h) => new Uint8Array(Buffer.from(h, "hex"));
const run = async (c, f, check) => {
  if (c.refuse) {
    let err;
    try { await f(); } catch (e) { err = e; }
    assert.ok(err && err.message.includes(c.refuse), `${c.name ?? ""}: want a refusal saying "${c.refuse}", got ${err ? err.message : "none"}`);
  } else check(await f());
};
for (const c of v.links) await run(c, () => readAppLink(c.hash, c.now_ms), (r) => assert.deepEqual(r, c.expect, c.name));
for (const c of v.key_logs) await run(c, () => checkAppKeyLog(c.aid, c.encoded), (r) => assert.deepEqual(Buffer.from(r).toString("hex"), c.expect_key_hex, c.name));
for (const c of v.challenges) await run(c, () => checkAppChallenge({ aid: c.aid, key: hex(c.key_hex), body: c.body, sig: c.sig, rid: c.rid, pointer: c.pointer, ownThumbprint: c.own_thumbprint, now: c.now_ms }), (r) => assert.deepEqual(JSON.parse(JSON.stringify(r)), c.expect, c.name));
for (const c of v.answers) await run(c, () => checkAppAnswer({ rid: c.rid, nonce: c.nonce, status: c.status, contentType: c.content_type, body: new Uint8Array(Buffer.from(c.body_b64, "base64")), log: c.log, known: c.known, sig: c.sig }), (r) => assert.equal(r.log, c.expect_log, c.name));
for (const c of v.proofs) assert.equal(await proofText(c.method, c.target, c.ts, c.nonce, c.binding, c.body), c.expect);
for (const c of v.answer_texts) assert.equal(await answerText(c.rid, c.nonce, c.status, c.content_type, new Uint8Array(Buffer.from(c.body_b64, "base64"))), c.expect);
for (const c of v.thumbprints) assert.equal(browserKeyThumbprint({ x: c.x, y: c.y }), c.expect);
for (const c of v.skews) await run(c, () => serverSkew(c.server_time, c.now_ms), (r) => assert.equal(r, c.expect_ms));
console.log("app checks: every case in test-vectors/app-checks.json holds in TypeScript");
