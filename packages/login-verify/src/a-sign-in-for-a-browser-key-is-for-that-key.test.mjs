// ADR-066: the browser-key thumbprint vectors the core pins
// (identity-agent-core/login), read and checked here by this package's own code.
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import {
  assertionDigest,
  canonicalAssertionBody,
  canonicalChallengeBody,
  decodeVerkeyQb64,
  isBrowserKeyThumbprint,
  readAssertion,
  readChallenge,
  thumbprintP256,
  verifyCanonical,
  verifyLoginAssertion,
} from "../dist/index.js";

const v = JSON.parse(readFileSync(new URL("../test-vectors/browser-key-thumbprint.json", import.meta.url), "utf8"));
const key = decodeVerkeyQb64(v.signing_verkey_qb64);

assert.equal(v.thumbprint_jwk_input, `{"crv":"P-256","kty":"EC","x":"${v.jwk.x}","y":"${v.jwk.y}"}`);
assert.equal(thumbprintP256(v.jwk.x, v.jwk.y), v.thumbprint, "the thumbprint is RFC 7638's");
assert.equal(thumbprintP256(v.jwk.x + "A", v.jwk.y), null, "a coordinate of another length is refused");
assert.ok(isBrowserKeyThumbprint(v.thumbprint));
for (const bad of ["", v.thumbprint + "=", v.thumbprint.slice(1), "A".repeat(42) + "B", "+".repeat(43), 7]) {
  assert.equal(isBrowserKeyThumbprint(bad), false, `${bad} is not a thumbprint`);
}

assert.equal(canonicalAssertionBody(v.assertion), v.assertion_canonical_body, "assertion body is the core's");
assert.equal(canonicalChallengeBody(v.challenge), v.challenge_canonical_body, "challenge body is the core's");
assert.equal(assertionDigest({ ...v.assertion, d: undefined, sig: undefined }), v.assertion.d, "the SAID is the core's");
assert.ok(await verifyCanonical(v.assertion_canonical_body, v.assertion.sig, key), "assertion signature");
assert.ok(await verifyCanonical(v.challenge_canonical_body, v.challenge.sig, key), "challenge signature");
assert.equal(readChallenge(JSON.stringify(v.challenge)).browser_key, v.thumbprint);
assert.equal(readAssertion(JSON.stringify(v.assertion)).browser_key, v.thumbprint);

const base = {
  expectedAudience: v.assertion.audience,
  expectedNonce: v.assertion.nonce,
  expectedSiteAid: v.expected_verify.site_aid,
  signingPublicKey: key,
  skipDtCheck: true,
};
const ok = await verifyLoginAssertion(v.assertion, { ...base, expectedBrowserKey: v.thumbprint });
assert.ok(ok.valid, ok.reason);
for (const [name, opts, assertion] of [
  ["another thumbprint expected", { expectedBrowserKey: v.negative_vectors.other_browser_key }, v.assertion],
  ["none expected", {}, v.assertion],
  ["the assertion names none", { expectedBrowserKey: v.thumbprint }, (({ browser_key, ...r }) => r)(v.assertion)],
  ["a thumbprint rewritten after signing", { expectedBrowserKey: v.negative_vectors.other_browser_key },
    { ...v.assertion, browser_key: v.negative_vectors.other_browser_key }],
]) {
  const r = await verifyLoginAssertion(assertion, { ...base, ...opts });
  assert.equal(r.valid, false, name);
}
const r = await verifyLoginAssertion(v.assertion, { ...base, expectedBrowserKey: v.negative_vectors.other_browser_key });
assert.match(r.reason, /browser key mismatch/);
console.log("✅ browser key vectors agree with the core");
