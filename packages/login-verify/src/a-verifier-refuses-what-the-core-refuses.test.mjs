import * as ed from "@noble/ed25519";
import express from "express";
import {
  IdentityAgentVerifier,
  assertionDigest,
  canonicalAssertionBody,
  generateDevSiteIdentity,
  mountIdentityAgentLoginRoutes,
  nonTransferableAidQb64,
  signCanonical,
  verifyLoginAssertion,
} from "../dist/index.js";

let failures = 0;
function check(ok, msg) {
  if (!ok) {
    failures++;
    console.error(`FAIL: ${msg}`);
  }
}

const site = await generateDevSiteIdentity("http://relay.example");
const personSeed = ed.utils.randomPrivateKey();
const personPub = await ed.getPublicKeyAsync(personSeed);
const personAid = nonTransferableAidQb64(personPub);
const resolveKey = async () => personPub;

async function signed(fields) {
  const a = {
    v: "IALOGIN10JSON", t: "login-assertion", i: personAid, relationship_aid_oobi: "o",
    dt: new Date().toISOString().replace(/\.\d{3}Z$/, "Z"), disclosures: {}, presented_acdcs: [],
    p_kel: "kel", site_aid: site.aid, ...fields,
  };
  delete a.sig;
  a.d = assertionDigest(a);
  a.sig = await signCanonical(canonicalAssertionBody(a), personSeed);
  return a;
}

// A reference clock that cannot be read refuses, rather than putting every dt
// inside the window: NaN compares false with everything.
{
  const a = await signed({ audience: "https://app.example", nonce: "n", dt: "2026-01-01T00:00:00Z" });
  const opts = { expectedAudience: "https://app.example", expectedNonce: "n", expectedSiteAid: site.aid, signingPublicKey: personPub };
  const r = await verifyLoginAssertion(a, { ...opts, nowMs: NaN });
  check(!r.valid && r.reason === "bad reference time", `an unreadable clock: valid=${r.valid} (${r.reason})`);
  const late = await verifyLoginAssertion(a, { ...opts, nowMs: Date.parse("2030-01-01T00:00:00Z") });
  check(!late.valid, "an assertion from 2026 checked in 2030 was valid");
}

// A freshness window is a whole number of seconds, zero or less meaning the
// default and more than an hour meaning an hour, as in the core. Anything else
// is refused: "abc", NaN and Infinity compared false with everything, so each
// once let an assertion from 2001 through.
{
  const old = await signed({ audience: "https://app.example", nonce: "n", dt: "2001-01-01T00:00:00Z" });
  const opts = { expectedAudience: "https://app.example", expectedNonce: "n", expectedSiteAid: site.aid, signingPublicKey: personPub };
  for (const w of ["abc", "300", NaN, Infinity, -Infinity, 1.5, 1e300, null, true, {}]) {
    const r = await verifyLoginAssertion(old, { ...opts, maxSkewSeconds: w });
    check(!r.valid && /^bad freshness window/.test(r.reason), `a window of ${String(w)}: valid=${r.valid} (${r.reason})`);
  }
  for (const w of [undefined, 0, -1, 999999999]) {
    const r = await verifyLoginAssertion(old, { ...opts, maxSkewSeconds: w });
    check(!r.valid && r.reason === "dt outside freshness window", `a window of ${String(w)}: valid=${r.valid} (${r.reason})`);
  }
  // Two hours old: inside a window of two hours were it honoured, outside the hour it is narrowed to.
  const twoHours = await signed({
    audience: "https://app.example", nonce: "n",
    dt: new Date(Date.now() - 2 * 3600 * 1000).toISOString().replace(/\.\d{3}Z$/, "Z"),
  });
  const narrowed = await verifyLoginAssertion(twoHours, { ...opts, maxSkewSeconds: 3 * 3600 });
  check(!narrowed.valid && narrowed.reason === "dt outside freshness window", `a window wider than an hour was honoured: ${narrowed.reason}`);
  const fiftyMinutes = await signed({
    audience: "https://app.example", nonce: "n",
    dt: new Date(Date.now() - 50 * 60 * 1000).toISOString().replace(/\.\d{3}Z$/, "Z"),
  });
  const hour = await verifyLoginAssertion(fiftyMinutes, { ...opts, maxSkewSeconds: 3600 });
  check(hour.valid, `a window of an hour refused an assertion fifty minutes old: ${hour.reason}`);
  // Only a real true skips the time check.
  for (const skip of ["false", "true", 1, {}]) {
    const r = await verifyLoginAssertion(old, { ...opts, skipDtCheck: skip });
    check(!r.valid && r.reason === "dt outside freshness window", `skipDtCheck ${JSON.stringify(skip)} skipped the time check`);
  }
  // The verifier's own method, which passes the window on.
  const verifier = new IdentityAgentVerifier({ siteIdentity: site, resolveKey });
  const viaVerifier = await verifier.verifyAssertion(old, { expectedAudience: "https://app.example", expectedNonce: "n", expectedSiteAid: site.aid, maxSkewSeconds: "abc" });
  check(!viaVerifier.valid && /^bad freshness window/.test(viaVerifier.reason), `verifyAssertion with a window of "abc": ${viaVerifier.reason}`);
}

// A document that is not an object is a refusal, never a throw.
for (const bad of [null, [], "text", 5]) {
  let r;
  try {
    r = await verifyLoginAssertion(bad, { expectedAudience: "a", expectedNonce: "n", expectedSiteAid: site.aid, resolveKey });
  } catch (e) {
    r = { valid: true, reason: `threw ${e.message}` };
  }
  check(!r.valid && /malformed/.test(r.reason), `${JSON.stringify(bad)}: ${r.reason}`);
}

// Several faults at once are reported in the core's order: dt, nonce,
// audience, site, then the signature.
{
  const a = await signed({ audience: "wrong", nonce: "wrong", dt: "2020-01-01T00:00:00Z", site_aid: "Eother" });
  const opts = { expectedAudience: "https://app.example", expectedNonce: "n", expectedSiteAid: site.aid, resolveKey };
  const order = [];
  order.push((await verifyLoginAssertion(a, opts)).reason);
  order.push((await verifyLoginAssertion({ ...a, dt: new Date().toISOString().replace(/\.\d{3}Z$/, "Z") }, opts)).reason);
  order.push((await verifyLoginAssertion({ ...a, dt: new Date().toISOString().replace(/\.\d{3}Z$/, "Z"), nonce: "n" }, opts)).reason);
  order.push((await verifyLoginAssertion({ ...a, dt: new Date().toISOString().replace(/\.\d{3}Z$/, "Z"), nonce: "n", audience: "https://app.example" }, opts)).reason);
  check(
    order[0] === "dt outside freshness window" && order[1] === "nonce mismatch" && order[2] === "audience mismatch" &&
      order[3].startsWith("site mismatch"),
    `refusals came in the order ${JSON.stringify(order)}`,
  );
  const unsigned = { ...a, dt: new Date().toISOString().replace(/\.\d{3}Z$/, "Z"), nonce: "n", audience: "https://app.example", site_aid: site.aid, sig: "" };
  check((await verifyLoginAssertion(unsigned, opts)).reason === "missing sig", "an unsigned assertion was not refused as unsigned");
}

// verifyAssertion takes the three expected values and the skew, nothing else:
// a caller's key, clock or skip flag is not passed on.
{
  const verifier = new IdentityAgentVerifier({ siteIdentity: site, resolveKey: async () => { throw new Error("no such key log"); } });
  const a = await signed({ audience: "https://app.example", nonce: "n", dt: "2020-01-01T00:00:00Z" });
  const r = await verifier.verifyAssertion(a, {
    expectedAudience: "https://app.example", expectedNonce: "n", expectedSiteAid: site.aid,
    signingPublicKey: personPub, skipDtCheck: true, nowMs: Date.parse("2020-01-01T00:00:00Z"),
  });
  check(!r.valid && r.reason === "dt outside freshness window", `extra options were honoured: ${r.valid} (${r.reason})`);
}

// Only a sign-in still waiting for its answer can be answered.
{
  const verifier = new IdentityAgentVerifier({ siteIdentity: site, resolveKey });
  for (const state of ["expired", "declined", "verified", "created", "scanned", "connected"]) {
    const { session_token, bundle } = await verifier.createChallenge({
      audience: "https://app.example", requestedDisclosures: [], callbackUrl: "https://app.example/cb",
    });
    verifier.sessionStore.updateState(session_token, state);
    const a = await signed({ audience: bundle.audience, nonce: bundle.nonce });
    const out = await verifier.handleCallback(a, session_token, () => "app-token");
    const waiting = ["created", "scanned", "connected"].includes(state);
    check(out.ok === waiting, `a ${state} sign-in answered ok=${out.ok} (${out.reason})`);
    const after = verifier.getSessionState(session_token).state;
    check(waiting ? after === "verified" : after === state, `a ${state} sign-in is now ${after}`);
  }
}

// The callback reads the assertion from its text, so a repeated key is
// refused even though JSON.parse would keep only the last.
{
  const verifier = new IdentityAgentVerifier({ siteIdentity: site, resolveKey });
  const app = express();
  mountIdentityAgentLoginRoutes(app, verifier);
  const server = app.listen(0, "127.0.0.1");
  await new Promise((r) => server.once("listening", r));
  const base = `http://127.0.0.1:${server.address().port}`;
  const { session_token, bundle } = await verifier.createChallenge({
    audience: "https://app.example", requestedDisclosures: [], callbackUrl: `${base}/auth/ia/callback`,
  });
  const a = await signed({ audience: bundle.audience, nonce: bundle.nonce });
  const text = JSON.stringify(a);
  const doubled = text.replace('"nonce":', '"nonce":"another","nonce":');
  const post = (body) => fetch(`${base}/auth/ia/callback?session=${session_token}`, {
    method: "POST", headers: { "Content-Type": "application/json" }, body,
  });
  const refused = await post(doubled);
  check(refused.status === 400, `a repeated key was answered ${refused.status}`);
  const cased = await post(text.replace('"nonce":', '"Nonce":"x","nonce":'));
  check(cased.status === 400, `a field in another case was answered ${cased.status}`);
  const accepted = await post(text);
  check(accepted.status === 200, `the genuine assertion was answered ${accepted.status}`);
  server.close();
}

if (failures) {
  console.error(`${failures} failure(s)`);
  process.exit(1);
}
console.log("the verifier refuses what the core refuses");
