import assert from "node:assert";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import * as ed from "@noble/ed25519";
import {
  generateDevSiteIdentity, canonicalAssertionBody, assertionDigest, signCanonical,
  nonTransferableAidQb64, inMemoryConsumedNonces, verifyLoginAssertion,
} from "../dist/index.js";
import { fileConsumedNonces } from "../dist/consumed-in-files.js";

// An assertion spent once stays spent: after the full in-memory store is hit,
// after a restart, and on a second instance sharing the same directory.

// 1. A full in-memory store refuses new claims; it does not forget old ones.
const mem = inMemoryConsumedNonces();
mem.claim("first");
for (let i = 0; i < 99_999; i++) mem.claim("k" + i);
assert.throws(() => mem.claim("one-too-many"), /full/);
assert.equal(mem.claim("first"), false, "the oldest entry is still remembered when the store is full");

// 2. Through the verifier, a store that cannot record is a refusal, not an acceptance.
const priv = ed.utils.randomPrivateKey();
const pub = await ed.getPublicKeyAsync(priv);
const aid = nonTransferableAidQb64(pub);
const site = await generateDevSiteIdentity("http://relay.test");
async function assertionFor(nonce) {
  const a = {
    v: "IALOGIN10JSON", t: "login-assertion", i: aid, relationship_aid_oobi: "http://relay.test/oobi/" + aid,
    audience: "https://portal.example", nonce, dt: new Date().toISOString().replace(/\.\d{3}Z$/, "Z"),
    disclosures: {}, presented_acdcs: [], p_kel: "log", site_aid: site.aid,
  };
  a.d = assertionDigest(a);
  a.sig = await signCanonical(canonicalAssertionBody(a), priv);
  return a;
}
const optsFor = (a, consume) => ({ expectedAudience: a.audience, expectedNonce: a.nonce, expectedSiteAid: site.aid, signingPublicKey: pub, consume });
const broken = { claim() { throw new Error("disk full"); } };
const a0 = await assertionFor("n0");
const refused = await verifyLoginAssertion(a0, optsFor(a0, broken));
assert.equal(refused.valid, false);
assert.match(refused.reason, /replay store unavailable: disk full/);

// 3. The file store: two instances over one directory, then a "restart".
const dir = mkdtempSync(join(tmpdir(), "replay-"));
try {
  const a = await assertionFor("n1");
  const one = fileConsumedNonces(dir);
  const two = fileConsumedNonces(dir);
  assert.equal((await verifyLoginAssertion(a, optsFor(a, one))).valid, true);
  const onTwo = await verifyLoginAssertion(a, optsFor(a, two));
  assert.equal(onTwo.valid, false);
  assert.match(onTwo.reason, /already used/);
  const afterRestart = fileConsumedNonces(dir);
  assert.equal((await verifyLoginAssertion(a, optsFor(a, afterRestart))).valid, false, "spent across a restart");

  // Racing claims for one key: exactly one wins.
  const racers = await Promise.all(Array.from({ length: 20 }, (_, i) => (i % 2 ? one : two).claim("race", Date.now() + 60_000)));
  assert.equal(racers.filter(Boolean).length, 1);

  // release lets it be tried again; an entry past its time is forgotten by a sweep.
  one.release("race");
  assert.equal(two.claim("race", Date.now() - 1), true);
  const sweeper = fileConsumedNonces(dir, { sweepEveryMs: 0 });
  assert.equal(sweeper.claim("other", Date.now() + 60_000), true);
  assert.equal(sweeper.claim("race", Date.now() + 60_000), true, "an expired entry is swept and can be claimed again");
} finally {
  rmSync(dir, { recursive: true, force: true });
}
console.log("replay store: full refuses, store failure refuses, file store spends once across instances and restarts");
