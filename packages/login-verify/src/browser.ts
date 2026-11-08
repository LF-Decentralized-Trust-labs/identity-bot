// The part of this package a web page can load: nothing here reads a file,
// starts a server or touches Buffer or node:crypto. A page that has only the
// login SDK (no back end of its own) checks the assertion it was handed with
// `checkSignInInPage`; `a-page-loads-only-what-a-browser-has.test.mjs` fails if
// anything this file imports needs Node.
export * from "./types.js";
export * from "./canonical.js";
export * from "./resolver.js";
export * from "./standalone-verify.js";

import { readAssertion } from "./canonical.js";
import { keyFromIdentityAgent } from "./resolver.js";
import { inMemoryConsumedNonces, verifyLoginAssertion, type ConsumedNonces } from "./standalone-verify.js";
import type { VerifyAssertionResult } from "./types.js";

/** What the Identity Agent hands the page that started a sign-in, once, when
 *  the person has answered (`readPageSession` in `@identity-agent/login-web`). */
export interface HandedSignIn {
  /** The signed assertion exactly as the person's Identity Agent sent it, as text. */
  assertion: string;
  /** The nonce of the challenge this answers. */
  nonce: string;
  /** The website asset's identifier the challenge was signed for. */
  siteAid: string;
  /** The thumbprint of the browser key the sign-in was for, if it named one. */
  browserKey?: string;
}

export interface CheckInPageOptions {
  /** The Identity Agent that holds the website asset: it checks the person's key log. */
  agentUrl: string;
  /** The website asset's identifier, when the page knows it. A page that pins it
   *  refuses an assertion for any other site even if the Identity Agent
   *  handed that one over. */
  expectedSiteAid?: string;
  /** Spends the assertion so it passes this check once. The same rule the back
   *  end uses: `claim(key, keepUntilMs)` is true the first time. Without one,
   *  a store shared by every check in this page is used; it is forgotten when
   *  the page is, which is as long as the page can hold a sign-in anyway. */
  consume?: ConsumedNonces;
  /** The audience the person approved: this page's own origin by default. */
  expectedAudience?: string;
  maxSkewSeconds?: number;
  fetchFn?: typeof fetch;
}

let pageSpent: ConsumedNonces | undefined;

/** Checks, in the page, the assertion an Identity Agent handed it: the person's
 *  key log (asked of the Identity Agent over its public login route, so the page
 *  carries no KERI code), the signature, the audience (this page's own origin),
 *  the nonce and site of the challenge, freshness, and that it has not been
 *  used. Never throws for a refusal: `valid` says. */
export async function checkSignInInPage(
  signIn: HandedSignIn,
  opts: CheckInPageOptions,
): Promise<VerifyAssertionResult> {
  const audience = opts.expectedAudience ?? (globalThis as { location?: { origin?: string } }).location?.origin;
  if (!audience || audience === "null") {
    return { valid: false, reason: "this page has no origin to check the audience against" };
  }
  if (opts.expectedSiteAid && opts.expectedSiteAid !== signIn.siteAid) {
    return { valid: false, reason: "site mismatch: the Identity Agent handed over another site's sign-in" };
  }
  let assertion;
  try {
    assertion = readAssertion(signIn.assertion);
  } catch (err) {
    return { valid: false, reason: `malformed assertion: ${(err as Error).message}` };
  }
  return verifyLoginAssertion(assertion, {
    expectedAudience: audience,
    expectedNonce: signIn.nonce,
    expectedSiteAid: signIn.siteAid,
    expectedBrowserKey: signIn.browserKey,
    maxSkewSeconds: opts.maxSkewSeconds,
    resolveKey: keyFromIdentityAgent(opts.agentUrl, opts.fetchFn ?? ((...a) => fetch(...a))),
    consume: opts.consume ?? (pageSpent ??= inMemoryConsumedNonces()),
  });
}
