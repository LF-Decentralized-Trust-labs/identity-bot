import {
  canonicalAssertionBody,
  parseRfc3339,
  verifyCanonical,
} from "./canonical.js";
import { resolveFromDidWebs } from "./resolver.js";
import type { LoginAssertion, VerifyAssertionOptions, VerifyAssertionResult } from "./types.js";

export interface StandaloneVerifyOptions extends VerifyAssertionOptions {
  /** Bypass relay/did:webs fetch — used for golden vector conformance. */
  signingPublicKey?: Uint8Array;
  /** Skip dt freshness (golden harness supplies fixed dt). */
  skipDtCheck?: boolean;
  /** Override clock for dt skew checks. */
  nowMs?: number;
  fetchFn?: typeof fetch;
}

/** Language-agnostic verify core — HTTP microservice wraps this. */
export async function verifyLoginAssertion(
  assertion: LoginAssertion,
  opts: StandaloneVerifyOptions,
): Promise<VerifyAssertionResult> {
  if (!assertion.sig) {
    return { ok: false, reason: "missing sig" };
  }
  if (assertion.nonce !== opts.expectedNonce) {
    return { ok: false, reason: "nonce mismatch" };
  }
  if (assertion.audience !== opts.expectedAudience) {
    return { ok: false, reason: "audience mismatch" };
  }

  if (!opts.skipDtCheck) {
    const maxSkew = opts.maxSkewSeconds ?? 300;
    const now = opts.nowMs ?? Date.now();
    const dtMs = parseRfc3339(assertion.dt);
    if (Math.abs(now - dtMs) > maxSkew * 1000) {
      return { ok: false, reason: "dt outside freshness window" };
    }
  }

  let publicKey = opts.signingPublicKey;
  if (!publicKey) {
    try {
      const resolved = await resolveFromDidWebs(
        assertion.relationship_aid_oobi,
        assertion.i,
        opts.fetchFn,
      );
      publicKey = resolved.publicKey;
    } catch (err) {
      return { ok: false, reason: `key resolve failed: ${(err as Error).message}` };
    }
  }

  const body = canonicalAssertionBody(assertion);
  const valid = await verifyCanonical(body, assertion.sig, publicKey);
  if (!valid) {
    return { ok: false, reason: "invalid signature" };
  }

  return {
    ok: true,
    i: assertion.i,
    disclosures: assertion.disclosures,
    presentedAcdcs: assertion.presented_acdcs,
    customData: assertion.custom_data,
    nonce: assertion.nonce,
    audience: assertion.audience,
    dt: assertion.dt,
  };
}