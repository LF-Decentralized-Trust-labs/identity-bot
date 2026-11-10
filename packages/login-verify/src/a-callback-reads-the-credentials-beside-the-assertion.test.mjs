// ADR-071: a callback is posted either the bare assertion (nothing presented,
// or an Identity Agent that has not updated) or {assertion, credentials}, the
// credentials being for the website owner's Identity Agent alone. Both are read
// as the core reads them, and the assertion names its credentials by digest.
import assert from "node:assert/strict";
import { readSignInPost } from "../dist/canonical.js";

const assertion = (presented) => ({
  v: "IALOGIN10JSON", t: "login-assertion", i: "EAid",
  relationship_aid_oobi: "https://r.example/oobi/EAid", audience: "https://app.example.com",
  nonce: "n1", dt: "2026-06-17T12:00:00Z", disclosures: { email: "a@example.com" },
  presented_acdcs: presented, site_aid: "ESite",
});
const credential = { said: "ECred", schema_said: "ESchema", acdc_json_b64: "e30=" };

// With a credential: the assertion holds its digest, the credential comes beside it.
const wrapped = readSignInPost(JSON.stringify({ assertion: assertion(["ECred"]), credentials: [credential] }));
assert.deepEqual(wrapped.assertion.presented_acdcs, ["ECred"]);
assert.deepEqual(wrapped.credentials, [credential]);

// Bare, as before: no credentials.
const bare = readSignInPost(JSON.stringify(assertion([])));
assert.deepEqual(bare.credentials, []);
assert.deepEqual(bare.assertion.presented_acdcs, []);

// The form before ADR-071 is still read for its window.
const old = readSignInPost(JSON.stringify(assertion([credential])));
assert.deepEqual(old.assertion.presented_acdcs, [credential]);
assert.deepEqual(old.credentials, []);

// Read as strictly as an assertion alone.
assert.throws(() => readSignInPost(JSON.stringify({ assertion: assertion([]), credentials: [], extra: 1 })));
assert.throws(() => readSignInPost(JSON.stringify({ assertion: assertion([]), credentials: "x" })));
assert.throws(() => readSignInPost(JSON.stringify({ assertion: { ...assertion([]), nonce: 1 }, credentials: [] })));
assert.throws(() => readSignInPost('{"assertion":{},"assertion":{}}'));
console.log("a callback reads the credentials beside the assertion: ok");
