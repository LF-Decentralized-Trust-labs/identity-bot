import * as fs from "node:fs";
import * as path from "node:path";
import { fileURLToPath } from "node:url";
import {
  assertionDigest,
  canonicalAssertionBody,
  decodeVerkeyQb64,
  verifyLoginAssertion,
  type LoginAssertion,
} from "@identity-agent/login-verify";

export interface GoldenVectorFile {
  login_assertion: {
    assertion: LoginAssertion;
    canonical_body: string;
    canonical_body_len: number;
    said: string;
    signing_verkey_qb64: string;
    expected_verify: {
      audience: string;
      nonce: string;
      site_aid: string;
      max_skew_seconds: number;
      reference_now_rfc3339: string;
    };
    negative_vectors: {
      corrupt_sig_last_char: string;
    };
  };
}

export function loadGoldenVectors(): GoldenVectorFile {
  const goldenUrl = import.meta.resolve("@identity-agent/login-verify/golden_vectors.json");
  const raw = fs.readFileSync(fileURLToPath(goldenUrl), "utf8");
  return JSON.parse(raw) as GoldenVectorFile;
}

export async function runGoldenSelfTest(): Promise<{ ok: boolean; reason?: string }> {
  const g = loadGoldenVectors().login_assertion;
  const pub = decodeVerkeyQb64(g.signing_verkey_qb64);
  if (!pub) return { ok: false, reason: "golden: decode verkey failed" };

  const recomputed = assertionDigest({
    v: g.assertion.v,
    t: g.assertion.t,
    i: g.assertion.i,
    relationship_aid_oobi: g.assertion.relationship_aid_oobi,
    audience: g.assertion.audience,
    nonce: g.assertion.nonce,
    dt: g.assertion.dt,
    disclosures: g.assertion.disclosures,
    presented_acdcs: g.assertion.presented_acdcs,
    p_kel: g.assertion.p_kel,
    site_aid: g.assertion.site_aid,
  });
  if (recomputed !== g.said) {
    return { ok: false, reason: `golden: SAID mismatch ${recomputed} !== ${g.said}` };
  }

  const body = canonicalAssertionBody(g.assertion);
  if (body !== g.canonical_body || body.length !== g.canonical_body_len) {
    return { ok: false, reason: "golden: canonical_body byte mismatch" };
  }

  const pass = await verifyLoginAssertion(g.assertion, {
    expectedAudience: g.expected_verify.audience,
    expectedNonce: g.expected_verify.nonce,
    expectedSiteAid: g.expected_verify.site_aid,
    // The key comes from the vectors, never from a caller.
    signingPublicKey: pub,
    skipDtCheck: true,
  });
  if (!pass.valid) return { ok: false, reason: `golden: verify failed: ${pass.reason}` };

  const corrupt = { ...g.assertion, sig: g.negative_vectors.corrupt_sig_last_char };
  const reject = await verifyLoginAssertion(corrupt, {
    expectedAudience: g.expected_verify.audience,
    expectedNonce: g.expected_verify.nonce,
    expectedSiteAid: g.expected_verify.site_aid,
    signingPublicKey: pub,
    skipDtCheck: true,
  });
  if (reject.valid) return { ok: false, reason: "golden: corrupt sig should reject" };

  return { ok: true };
}