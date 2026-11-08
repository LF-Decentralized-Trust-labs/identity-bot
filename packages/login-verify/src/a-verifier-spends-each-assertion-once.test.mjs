import * as ed from "@noble/ed25519";
import {
  IdentityAgentVerifier,
  generateDevSiteIdentity,
  canonicalAssertionBody,
  assertionDigest,
  signCanonical,
  nonTransferableAidQb64,
  inMemoryConsumedNonces,
} from "../dist/index.js";

// Problem 225: login assertions had no replay store on the verifying side.
//
// An assertion that verified once is good for its whole freshness window to
// whoever captured it. IdentityAgentVerifier now spends each one it accepts,
// whether it reaches the verifier through verifyAssertion or the callback.

const priv = ed.utils.randomPrivateKey();
const pub = await ed.getPublicKeyAsync(priv);
const aid = nonTransferableAidQb64(pub);
const site = await generateDevSiteIdentity("http://relay.test");
const resolveKey = async () => pub;

async function assertionFor(nonce) {
  const a = {
    v: "IALOGIN10JSON", t: "login-assertion", i: aid,
    relationship_aid_oobi: "http://relay.test/oobi/" + aid,
    audience: "https://portal.example", nonce,
    dt: new Date().toISOString().replace(/\.\d{3}Z$/, "Z"),
    disclosures: {}, presented_acdcs: [], p_kel: "log", site_aid: site.aid,
  };
  a.d = assertionDigest(a);
  a.sig = await signCanonical(canonicalAssertionBody(a), priv);
  return a;
}
const expect = (a) => ({ expectedAudience: a.audience, expectedNonce: a.nonce, expectedSiteAid: site.aid });
const fail = (m) => { throw new Error(m); };

// 1. Direct verification.
const v = new IdentityAgentVerifier({ siteIdentity: site, resolveKey });
const a1 = await assertionFor("n1");
if (!(await v.verifyAssertion(a1, expect(a1))).valid) fail("a genuine assertion was refused");
const again = await v.verifyAssertion(a1, expect(a1));
if (again.valid || !String(again.reason).includes("already used")) fail(`a replayed assertion was not refused as used: ${JSON.stringify(again)}`);

// 2. Through the callback: a second sign-in session that is still waiting
// cannot be answered with an assertion already spent on the first.
const { session_token, bundle } = await v.createChallenge({
  audience: "https://portal.example", requestedDisclosures: [], callbackUrl: "https://portal.example/cb",
});
const a3 = await assertionFor(bundle.nonce);
if (!(await v.handleCallback(a3, session_token, () => "s")).ok) fail("the callback refused a genuine assertion");
// A second session whose nonce a captured assertion already answered:
const second = await v.createChallenge({ audience: "https://portal.example", requestedDisclosures: [], callbackUrl: "x" });
v.sessionStore.get(second.session_token).challenge.nonce = bundle.nonce;
const replay = await v.handleCallback(a3, second.session_token, () => "s2");
if (replay.ok || !String(replay.reason).includes("already used")) fail(`a replay through the callback was accepted: ${JSON.stringify(replay)}`);

// 3. A refused assertion spends nothing.
const a4 = await assertionFor("n4");
const bad = { ...a4, sig: (a4.sig[0] === "A" ? "B" : "A") + a4.sig.slice(1) };
await v.verifyAssertion(bad, expect(a4));
if (!(await v.verifyAssertion(a4, expect(a4))).valid) fail("a forged copy spent the genuine assertion");

// 4. A store the site supplies is the one used (a shared one across processes).
const shared = inMemoryConsumedNonces();
const p1 = new IdentityAgentVerifier({ siteIdentity: site, resolveKey, consumedAssertions: shared });
const p2 = new IdentityAgentVerifier({ siteIdentity: site, resolveKey, consumedAssertions: shared });
const a5 = await assertionFor("n5");
if (!(await p1.verifyAssertion(a5, expect(a5))).valid) fail("first process refused");
if ((await p2.verifyAssertion(a5, expect(a5))).valid) fail("the second process accepted what the first spent");

// 4b. A site that cannot finish the sign-in gets the assertion back to try again.
const a6 = await assertionFor("n6");
const { session_token: t6 } = await v.createChallenge({ audience: a6.audience, requestedDisclosures: [], callbackUrl: "x" });
v.sessionStore.get(t6).challenge.nonce = "n6";
await v.handleCallback(a6, t6, () => { throw new Error("database down"); }).then(() => fail("the failure was swallowed"), () => {});
if (!(await v.handleCallback(a6, t6, () => "s6")).ok) fail("an assertion was lost to a failure after it was accepted");

// 4c. An assertion dated ahead of now is remembered until it can no longer pass.
const ahead = await assertionFor("n7");
ahead.dt = new Date(Date.now() + 290_000).toISOString().replace(/\.\d{3}Z$/, "Z");
ahead.d = assertionDigest(ahead); delete ahead.sig; ahead.sig = await signCanonical(canonicalAssertionBody(ahead), priv);
const kept = [];
const probe = { claim: (k, until) => (kept.push(until), true) };
const pv = new IdentityAgentVerifier({ siteIdentity: site, resolveKey, consumedAssertions: probe });
if (!(await pv.verifyAssertion(ahead, expect(ahead))).valid) fail("a slightly future assertion was refused");
if (kept[0] < Date.parse(ahead.dt) + 300_000) fail("forgotten while it can still pass the time check");

// 5. The default store forgets what is too old to matter, and holds a bounded number.
const store = inMemoryConsumedNonces();
await store.claim("old", Date.now() - 1);
if (!(await store.claim("old", Date.now() + 60_000))) fail("an expired entry was still held");

console.log("verifier: each accepted assertion is spent once, directly or via the callback; refusals spend nothing");
