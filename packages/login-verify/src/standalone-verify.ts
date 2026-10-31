import {
  canonicalAssertionBody,
  parseRfc3339,
  verifyCanonical,
} from "./canonical.js";
import { NO_KEY_RESOLVER, type KeyResolver } from "./resolver.js";
import type { LoginAssertion, VerifyAssertionOptions, VerifyAssertionResult } from "./types.js";

export interface StandaloneVerifyOptions extends VerifyAssertionOptions {
  /** Establishes the asserter's key from the key log the assertion carries.
   *  Required unless `signingPublicKey` is given; see `keyFromIdentityAgent`. */
  resolveKey?: KeyResolver;
  /** A key already known for this identity — used for golden vector conformance. */
  signingPublicKey?: Uint8Array;
  /** Skip dt freshness (golden harness supplies fixed dt). */
  skipDtCheck?: boolean;
  /** Override clock for dt skew checks. */
  nowMs?: number;
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
 *  shared one, or an assertion spent on one of them still spends on the others. */
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

/** The window an assertion's dt must fall in when none is given, either way
 *  from now: the core's default (DefaultMaxSkewSeconds in
 *  identity-agent-core/login). */
export const DEFAULT_MAX_SKEW_SECONDS = 300;

/** The widest window that is honoured, as in the core (LongestMaxSkewSeconds).
 *  A sign-in is approved within moments of being asked for, so an hour covers
 *  any honest clock; a wider window only lengthens the time a captured
 *  assertion stays usable. A wider request is narrowed to this. */
export const LONGEST_MAX_SKEW_SECONDS = 3600;

/** The freshness window in seconds that `maxSkewSeconds` asks for, by the
 *  core's rules: undefined, zero or less is the default, more than the
 *  longest is the longest. Anything but a whole number is refused, `null`
 *  included (the function returns null for a refusal): every
 *  comparison with NaN is false, so "abc", NaN or Infinity once turned the
 *  check off and an assertion from 2001 was accepted. */
export function freshnessWindowSeconds(maxSkewSeconds: unknown): number | null {
  if (maxSkewSeconds === undefined) return DEFAULT_MAX_SKEW_SECONDS;
  if (typeof maxSkewSeconds !== "number" || !Number.isSafeInteger(maxSkewSeconds)) return null;
  if (maxSkewSeconds <= 0) return DEFAULT_MAX_SKEW_SECONDS;
  return Math.min(maxSkewSeconds, LONGEST_MAX_SKEW_SECONDS);
}

/** Language-agnostic verify core — HTTP microservice wraps this.
 *
 *  The checks run in the core's order (VerifyAssertion in
 *  identity-agent-core/login), so an assertion wrong in more than one way is
 *  refused for the same reason by both: its shape, then dt, nonce, audience,
 *  site, then the signature. */
export async function verifyLoginAssertion(
  assertion: LoginAssertion,
  opts: StandaloneVerifyOptions,
): Promise<VerifyAssertionResult> {
  // The core refuses a document it cannot read before it checks anything.
  if (typeof assertion !== "object" || assertion === null || Array.isArray(assertion)) {
    return { valid: false, reason: "malformed assertion: an assertion must be an object" };
  }
  let body: string;
  try {
    body = canonicalAssertionBody(assertion);
  } catch (err) {
    return { valid: false, reason: `malformed assertion: ${(err as Error).message}` };
  }

  // Only a real true turns the time check off: a caller's "false" is a
  // string, and a string is truthy.
  if (opts.skipDtCheck !== true) {
    const maxSkew = freshnessWindowSeconds(opts.maxSkewSeconds);
    if (maxSkew === null) {
      return { valid: false, reason: "bad freshness window: maxSkewSeconds must be a whole number of seconds" };
    }
    const now = opts.nowMs ?? Date.now();
    // A clock that cannot be read is refused, not compared: every comparison
    // with NaN is false, so it would put any dt inside the window.
    if (!Number.isFinite(now)) {
      return { valid: false, reason: "bad reference time" };
    }
    const dtMs = parseRfc3339(assertion.dt);
    // An unreadable time is refused, not compared: NaN is never "outside" a window.
    if (Number.isNaN(dtMs)) {
      return { valid: false, reason: "bad dt" };
    }
    if (Math.abs(now - dtMs) > maxSkew * 1000) {
      return { valid: false, reason: "dt outside freshness window" };
    }
  }
  if (assertion.nonce !== opts.expectedNonce) {
    return { valid: false, reason: "nonce mismatch" };
  }
  if (assertion.audience !== opts.expectedAudience) {
    return { valid: false, reason: "audience mismatch" };
  }
  if (!opts.expectedSiteAid || assertion.site_aid !== opts.expectedSiteAid) {
    return { valid: false, reason: "site mismatch: the assertion answers another site's challenge" };
  }
  if (!assertion.sig) {
    return { valid: false, reason: "missing sig" };
  }

  let publicKey = opts.signingPublicKey;
  if (!publicKey) {
    if (!opts.resolveKey) {
      return { valid: false, reason: NO_KEY_RESOLVER };
    }
    try {
      publicKey = await opts.resolveKey(assertion.i, assertion.p_kel);
    } catch (err) {
      return { valid: false, reason: `key resolve failed: ${(err as Error).message}` };
    }
  }

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