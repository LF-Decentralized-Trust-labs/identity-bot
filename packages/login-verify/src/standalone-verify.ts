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
  /** Burns the assertion so it cannot be verified a second time.
   *
   *  The nonce makes a captured assertion useless against a DIFFERENT sign-in.
   *  On its own it does nothing about the same one: this function only compares
   *  the nonce it is handed, so a relying party calling it in a loop would
   *  accept the same message every time. Supply a store and the second
   *  presentation is refused. See `inMemoryConsumedNonces`. */
  consume?: ConsumedNonces;
}

/** Remembers which assertions have already been accepted. */
export interface ConsumedNonces {
  /** True if this assertion had NOT been seen, and records it. False if it had. */
  claim(key: string): Promise<boolean> | boolean;
}

/** A store for one process. A deployment with more than one verifier needs a
 *  shared one, or an assertion spent on one of them still spends on the others.
 *  Said plainly because the in-memory default looks like protection either way. */
export function inMemoryConsumedNonces(): ConsumedNonces {
  const seen = new Set<string>();
  return {
    claim(key: string) {
      if (seen.has(key)) return false;
      seen.add(key);
      return true;
    },
  };
}

/** Language-agnostic verify core — HTTP microservice wraps this. */
export async function verifyLoginAssertion(
  assertion: LoginAssertion,
  opts: StandaloneVerifyOptions,
): Promise<VerifyAssertionResult> {
  if (!assertion.sig) {
    return { valid: false, reason: "missing sig" };
  }
  if (assertion.nonce !== opts.expectedNonce) {
    return { valid: false, reason: "nonce mismatch" };
  }
  if (assertion.audience !== opts.expectedAudience) {
    return { valid: false, reason: "audience mismatch" };
  }

  if (!opts.skipDtCheck) {
    const maxSkew = opts.maxSkewSeconds ?? 300;
    const now = opts.nowMs ?? Date.now();
    const dtMs = parseRfc3339(assertion.dt);
    if (Math.abs(now - dtMs) > maxSkew * 1000) {
      return { valid: false, reason: "dt outside freshness window" };
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
      return { valid: false, reason: `key resolve failed: ${(err as Error).message}` };
    }
  }

  const body = canonicalAssertionBody(assertion);
  const validSig = await verifyCanonical(body, assertion.sig, publicKey);
  if (!validSig) {
    return { valid: false, reason: "invalid signature" };
  }

  // Burnt only once everything else has passed, so a malformed or badly signed
  // assertion cannot be used to spend a nonce the real one still needs.
  if (opts.consume) {
    const fresh = await opts.consume.claim(`${assertion.audience}|${assertion.nonce}|${assertion.i}`);
    if (!fresh) {
      return { valid: false, reason: "assertion already used" };
    }
  }

  return {
    valid: true,
    pairwiseAID: assertion.i,
    disclosures: assertion.disclosures,
    presentedAcdcs: assertion.presented_acdcs,
    customData: assertion.custom_data,
    score: typeof assertion.custom_data?.ofa_score === 'number' ? assertion.custom_data.ofa_score : undefined,
    nonce: assertion.nonce,
    audience: assertion.audience,
    dt: assertion.dt,
  };
}