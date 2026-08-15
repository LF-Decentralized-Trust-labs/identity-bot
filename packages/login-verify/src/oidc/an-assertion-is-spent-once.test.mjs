import * as ed from "@noble/ed25519";
import {
  verifyLoginAssertion,
  inMemoryConsumedNonces,
  canonicalAssertionBody,
  assertionDigest,
  signCanonical,
} from "../../dist/index.js";

// An assertion is spent once.
//
// The nonce makes a captured assertion useless against a DIFFERENT sign-in. It
// does nothing about the same one: the standalone verifier compares the nonce
// it is handed and remembers nothing, so a relying party calling it accepts the
// same message as many times as it arrives. That is a replay inside the
// freshness window, needing no key and no forgery — only a copy of a message
// that was already sent.
async function run() {
  const priv = ed.utils.randomPrivateKey();
  const pub = await ed.getPublicKeyAsync(priv);
  const aid = "E" + Buffer.from(pub).toString("base64url").slice(0, 43);

  const assertion = {
    v: "IALOGIN10JSON", t: "login-assertion", i: aid,
    relationship_aid_oobi: "http://relay.test/oobi/" + aid,
    audience: "https://portal.example", nonce: "one-question",
    dt: new Date().toISOString().replace(/\.\d{3}Z$/, "Z"),
    disclosures: {}, presented_acdcs: [],
  };
  assertion.d = assertionDigest(assertion);
  assertion.sig = await signCanonical(canonicalAssertionBody(assertion), priv);

  const opts = {
    expectedAudience: assertion.audience,
    expectedNonce: assertion.nonce,
    signingPublicKey: pub,
  };

  // Without a store, the same assertion verifies twice. That is the behaviour
  // this exists to make optional rather than inevitable.
  const a = await verifyLoginAssertion(assertion, opts);
  const b = await verifyLoginAssertion(assertion, opts);
  if (!a.valid || !b.valid) throw new Error("the assertion does not verify at all");

  // With one, the second presentation is refused.
  const consume = inMemoryConsumedNonces();
  const first = await verifyLoginAssertion(assertion, { ...opts, consume });
  if (!first.valid) throw new Error(`the first presentation was refused: ${first.reason}`);
  const second = await verifyLoginAssertion(assertion, { ...opts, consume });
  if (second.valid) throw new Error("the same assertion was accepted twice");
  if (!String(second.reason).includes("already used")) {
    throw new Error(`refused for the wrong reason: ${second.reason}`);
  }

  // A bad signature must not spend the nonce the real assertion still needs.
  const forged = { ...assertion, nonce: "another-question", sig: assertion.sig };
  const consume2 = inMemoryConsumedNonces();
  await verifyLoginAssertion(forged, { ...opts, expectedNonce: "another-question", consume: consume2 });
  const genuine = { ...assertion, nonce: "another-question" };
  genuine.d = assertionDigest(genuine);
  genuine.sig = await signCanonical(canonicalAssertionBody(genuine), priv);
  const after = await verifyLoginAssertion(genuine, { ...opts, expectedNonce: "another-question", consume: consume2 });
  if (!after.valid) {
    throw new Error("a forged assertion burnt the nonce its genuine counterpart needed");
  }

  console.log("assertion spend: second presentation refused; a bad one spends nothing");
}
run().catch((e) => { console.error(String(e.message || e)); process.exit(1); });
