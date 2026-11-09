import * as fs from "node:fs";
import * as path from "node:path";
import { fileURLToPath } from "node:url";
import * as ed from "@noble/ed25519";
import {
  IdentityAgentVerifier,
  generateDevSiteIdentity,
  canonicalAssertionBody,
  assertionDigest,
  signCanonical,
  nonTransferableAidQb64,
} from "../dist/index.js";

// A sign-in is spent only by an ACCEPTED answer. The sequences are data, shared
// with the Go core (identity-agent-core/server, the callback route), so both
// are held to the same rule: a refused answer is recorded and the sign-in stays
// open, and an accepted one spends it.
const PKG = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const V = JSON.parse(fs.readFileSync(path.join(PKG, "test-vectors", "spending-sequences.json"), "utf8"));

const priv = ed.utils.randomPrivateKey();
const pub = await ed.getPublicKeyAsync(priv);
const aid = nonTransferableAidQb64(pub);
const site = await generateDevSiteIdentity("http://relay.test");
const resolveKey = async () => pub;
const fail = (m) => { throw new Error(m); };

async function signed(challenge, { nonce = challenge.nonce, audience = challenge.audience, key = priv, who = aid } = {}) {
  const a = {
    v: "IALOGIN10JSON", t: "login-assertion", i: who,
    relationship_aid_oobi: "http://relay.test/oobi/" + who,
    audience, nonce,
    dt: new Date().toISOString().replace(/\.\d{3}Z$/, "Z"),
    disclosures: {}, presented_acdcs: [], p_kel: "log", site_aid: site.aid,
  };
  a.d = assertionDigest(a);
  a.sig = await signCanonical(canonicalAssertionBody(a), key);
  return a;
}

async function answerOf(kind, challenge) {
  switch (kind) {
    case "genuine": return signed(challenge);
    case "tampered-signature": {
      const a = await signed(challenge);
      return { ...a, sig: (a.sig[0] === "A" ? "B" : "A") + a.sig.slice(1) };
    }
    case "wrong-nonce": return signed(challenge, { nonce: "a-nonce-this-challenge-never-issued" });
    case "wrong-audience": return signed(challenge, { audience: "https://elsewhere.example" });
  }
  return fail(`unknown answer ${kind}`);
}

function outcomeOf(r) {
  if (r.ok) return "accepted";
  return /already been answered|cannot be answered/.test(r.reason ?? "") ? "already-spent" : "refused";
}

let steps = 0;
for (const seq of V.sequences) {
  const v = new IdentityAgentVerifier({ siteIdentity: site, resolveKey });
  const { session_token, bundle } = await v.createChallenge({
    audience: "https://portal.example", requestedDisclosures: [], callbackUrl: "https://portal.example/cb",
  });
  let n = 0;
  for (const step of seq.steps) {
    n++; steps++;
    const r = await v.handleCallback(await answerOf(step.answer, bundle), session_token, () => "app-session");
    const got = outcomeOf(r);
    if (got !== step.outcome) fail(`"${seq.name}" step ${n} (${step.answer}): ${got} (${r.reason}), want ${step.outcome}`);
    const state = v.getSessionState(session_token).state;
    if ((step.after === "spent") !== (state === "verified")) fail(`"${seq.name}" step ${n}: the sign-in is ${state}, want it ${step.after}`);
  }
}

// Two different people's accepted answers arriving together: one spends the
// sign-in, the other is told it is spent and keeps its assertion.
{
  const privB = ed.utils.randomPrivateKey();
  const pubB = await ed.getPublicKeyAsync(privB);
  const aidB = nonTransferableAidQb64(pubB);
  const both = new IdentityAgentVerifier({
    siteIdentity: site,
    resolveKey: async (who) => (who === aidB ? pubB : pub),
  });
  const { session_token, bundle } = await both.createChallenge({
    audience: "https://portal.example", requestedDisclosures: [], callbackUrl: "x",
  });
  const mine = await signed(bundle);
  const theirs = await signed(bundle, { key: privB, who: aidB });
  const issued = [];
  const results = await Promise.all([mine, theirs].map((a) =>
    both.handleCallback(a, session_token, (p) => { issued.push(p); return "s"; })));
  if (results.filter((r) => r.ok).length !== 1 || issued.length !== 1) {
    fail(`two accepted answers at once: ${JSON.stringify(results)}, ${issued.length} sessions issued`);
  }
}

console.log(`spending: ${V.sequences.length} sequences, ${steps} steps; only an accepted answer spends a sign-in`);
