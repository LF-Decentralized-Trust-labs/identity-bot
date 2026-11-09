import {
  canonicalAssertionBody,
  isBrowserKeyThumbprint,
  parseRfc3339,
  parseRfc3339Exact,
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
  /** True if this assertion had NOT been seen, and records it. False if it had.
   *  `keepUntilMs` (epoch milliseconds) is the earliest the entry may be
   *  forgotten: after it the assertion is too old to verify anyway, so a store
   *  may drop it to stay small. A store that ignores it is also correct. */
  claim(key: string, keepUntilMs?: number): Promise<boolean> | boolean;
  /** Forgets a claim made by mistake, so the same assertion can be tried again:
   *  the verifier calls it when accepting an assertion failed after the claim. */
  release?(key: string): Promise<void> | void;
}

/** The key an assertion is remembered under. */
export function consumedKey(a: { audience: string; nonce: string; i: string }): string {
  return `${a.audience}|${a.nonce}|${a.i}`;
}

/** The most a default store holds. */
const MOST_CONSUMED_IN_MEMORY = 100_000;

/** A store for one process, lost on restart. A deployment with more than one
 *  verifier, or one that restarts inside a freshness window, needs a shared and
 *  durable one (`fileConsumedNonces` in `@identity-agent/login-verify/consumed-in-files`),
 *  or an assertion spent here is still good after a restart and on the others.
 *
 *  Full, it refuses new claims rather than forgetting old ones: every entry in
 *  it can still be replayed, so dropping one to make room would accept a
 *  captured assertion. `claim` then throws, and the verifier refuses the sign-in. */
export function inMemoryConsumedNonces(): ConsumedNonces {
  const seen = new Map<string, number>();
  let sweptAt = 0;
  return {
    claim(key: string, keepUntilMs?: number) {
      const now = Date.now();
      // Entries do not expire in claim order (windows differ), so look at all
      // of them, at most once a second.
      if (now - sweptAt >= 1000) {
        sweptAt = now;
        for (const [k, until] of seen) if (until <= now) seen.delete(k);
      }
      if (seen.has(key)) return false;
      if (seen.size >= MOST_CONSUMED_IN_MEMORY) {
        throw new Error("the replay store is full of assertions that can still be replayed");
      }
      seen.set(key, keepUntilMs ?? Number.POSITIVE_INFINITY);
      return true;
    },
    release(key: string) {
      seen.delete(key);
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
    const dt = parseRfc3339Exact(assertion.dt);
    // An unreadable time is refused, not compared: NaN is never "outside" a window.
    if (dt === null) {
      return { valid: false, reason: "bad dt" };
    }
    // To the nanosecond, as the core compares: dt is `dt.ms` milliseconds and
    // `dt.subMsNs` nanoseconds past the epoch, and the clock is whole milliseconds.
    const apartNs = (BigInt(Math.floor(now)) - BigInt(dt.ms)) * 1_000_000n - BigInt(dt.subMsNs);
    const windowNs = BigInt(maxSkew) * 1_000_000_000n;
    if (apartNs > windowNs || apartNs < -windowNs) {
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
  const expectedBrowserKey = opts.expectedBrowserKey ?? "";
  if ((assertion.browser_key ?? "") !== expectedBrowserKey) {
    return { valid: false, reason: "browser key mismatch: the assertion was approved for another browser key" };
  }
  if (expectedBrowserKey !== "" && !isBrowserKeyThumbprint(expectedBrowserKey)) {
    return { valid: false, reason: "browser key mismatch: a browser key thumbprint is 43 characters of base64url (an RFC 7638 SHA-256 digest)" };
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
    // Kept until the assertion can no longer pass the time check: its dt may
    // be a window ahead of now, and is good for a window after that. With the
    // check off it never stops being good.
    const window = freshnessWindowSeconds(opts.maxSkewSeconds) ?? LONGEST_MAX_SKEW_SECONDS;
    const dtMs = parseRfc3339(assertion.dt);
    const base = Math.max(Date.now(), opts.nowMs ?? 0, Number.isNaN(dtMs) ? 0 : dtMs);
    const keepUntil = opts.skipDtCheck === true ? undefined : base + (window + 60) * 1000;
    // A store that cannot say is a refusal: accepting what cannot be recorded
    // is accepting a replay.
    let fresh: boolean;
    try {
      fresh = await opts.consume.claim(consumedKey(assertion), keepUntil);
    } catch (err) {
      return { valid: false, reason: `replay store unavailable: ${(err as Error).message}` };
    }
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