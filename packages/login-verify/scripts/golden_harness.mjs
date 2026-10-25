#!/usr/bin/env node
/** Conformance harness — byte-pin + verify golden assertion. */
import * as fs from "node:fs";
import * as path from "node:path";
import { fileURLToPath } from "node:url";
import {
  assertionDigest,
  canonicalAssertionBody,
  decodeVerkeyQb64,
} from "../dist/canonical.js";
import { verifyLoginAssertion } from "../dist/standalone-verify.js";

const PKG = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const GOLDEN = JSON.parse(
  fs.readFileSync(path.join(PKG, "golden_vectors.json"), "utf8"),
);
const v = GOLDEN.login_assertion;

function fail(msg) {
  console.error(`FAIL: ${msg}`);
  process.exit(1);
}

async function main() {
  const pub = decodeVerkeyQb64(v.signing_verkey_qb64);
  if (!pub) fail("decode signing_verkey_qb64");

  const recomputedD = assertionDigest({
    v: v.version,
    t: "login-assertion",
    i: v.pairwise_aid,
    relationship_aid_oobi: v.relationship_aid_oobi,
    audience: v.audience,
    nonce: v.nonce,
    dt: v.dt,
    disclosures: v.disclosures,
    presented_acdcs: v.presented_acdcs,
    p_kel: v.p_kel,
    site_aid: v.site_aid,
  });
  if (recomputedD !== v.said) fail(`SAID mismatch: ${recomputedD} !== ${v.said}`);

  const body = canonicalAssertionBody(v.assertion);
  if (body !== v.canonical_body) {
    fail("canonical_body byte mismatch");
  }
  if (body.length !== v.canonical_body_len) {
    fail(`canonical_body_len ${body.length} !== ${v.canonical_body_len}`);
  }

  const result = await verifyLoginAssertion(v.assertion, {
    expectedAudience: v.expected_verify.audience,
    expectedNonce: v.expected_verify.nonce,
    expectedSiteAid: v.expected_verify.site_aid,
    signingPublicKey: pub,
    skipDtCheck: true,
  });
  if (!result.valid) fail(`verify golden: ${result.reason}`);

  const otherSite = await verifyLoginAssertion(v.assertion, {
    expectedAudience: v.expected_verify.audience,
    expectedNonce: v.expected_verify.nonce,
    expectedSiteAid: v.negative_vectors.wrong_site_aid,
    signingPublicKey: pub,
    skipDtCheck: true,
  });
  if (otherSite.valid) fail("an assertion for another site should reject");

  const badSig = { ...v.assertion, sig: v.negative_vectors.corrupt_sig_last_char };
  const bad = await verifyLoginAssertion(badSig, {
    expectedAudience: v.expected_verify.audience,
    expectedNonce: v.expected_verify.nonce,
    expectedSiteAid: v.expected_verify.site_aid,
    signingPublicKey: pub,
    skipDtCheck: true,
  });
  if (bad.valid) fail("corrupt sig should reject");

  console.log("✅ login golden harness passed");
  console.log(`   canonical_body_len=${v.canonical_body_len}`);
  console.log(`   said=${v.said}`);
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});