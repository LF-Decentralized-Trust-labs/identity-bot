export type SessionState =
  | "created"
  | "scanned"
  | "connected"
  | "verified"
  | "declined"
  | "expired";

export interface RequestedCredential {
  schema_said: string;
  required: boolean;
}

export interface RequestedScore {
  min_band?: "red" | "amber" | "green";
  min_score?: number;
  required?: boolean;
}

/**
 * Ask action registry (the login contract / the shared module). The `t`
 * discriminator the IA dispatches on after fetching the Ask. Numeric + named
 * for a compact, language-neutral wire; each value MUST map to a governed
 * action in the governance Action Registry.
 */
export const AskAction = {
  login: 1,
  present: 2,
  pay: 3,
  contact: 4,
  issue: 5,
} as const;
export type AskActionCode = (typeof AskAction)[keyof typeof AskAction];

/**
 * An "Ask" — a signed, typed request one Identity Agent fetches from a minimal
 * QR pointer (`/i/{token}`). The login Ask (`t: 1`) keeps site_* fields as its
 * action params; other actions carry their own fields (see the shared module proposal).
 */
export interface LoginChallenge {
  v: "ASK1";
  t: typeof AskAction.login;
  site_aid: string;
  site_oobi: string;
  audience: string;
  nonce: string;
  dt: string;
  expiry: string;
  requested_disclosures: string[];
  requested_credentials: RequestedCredential[];
  requested_score?: RequestedScore;
  /** Org-owned membership-gated assets: anchor the scanner's relationship to
   * the ORG (the asset's delegator) so the presented pairwise is the constant
   * one the org enrolled. Signed as part of the canonical body. */
  relationship_anchor_aid?: string;
  relationship_anchor_oobi?: string;
  /** The thumbprint (RFC 7638, SHA-256, base64url) of the key a browser holds
   *  and cannot export, when the sign-in is for that browser (ADR-066).
   *  Signed; the assertion repeats it. */
  browser_key?: string;
  /** The kind of front end a sign-in to a utility app is for, `browser` or
   *  `installed_app` (ADR-072 §2, amended). Signed; the assertion repeats it,
   *  so the person approves a named kind. */
  front_end?: string;
  callback_url: string;
  session_token: string;
  sig?: string;
}

export interface ScoreAttestation {
  relationship_aid: string;
  band: "red" | "amber" | "green";
  score?: number;
  score_as_of: string;
  freshness_window_seconds: number;
  sig?: string;
}

export interface LoginAssertion {
  v: "IALOGIN10JSON";
  t: "login-assertion";
  d?: string;
  i: string;
  relationship_aid_oobi: string;
  audience: string;
  nonce: string;
  dt: string;
  disclosures: Record<string, string>;
  /** The credentials the person presented, each named by its digest (its
   *  SAID), a string (ADR-071). An assertion from an Identity Agent that has
   *  not updated carries the credential objects whole instead. */
  presented_acdcs: Array<string | unknown>;
  custom_data?: Record<string, unknown>;
  p_kel?: string;
  /** The site whose signed challenge the person approved. A relying party
   *  refuses an assertion naming any site but its own: a site's audience and
   *  nonce are text another site can copy, the key that signed its challenge
   *  is not. */
  site_aid?: string;
  /** Repeats the challenge's `browser_key` (ADR-066): the person approved a
   *  sign-in for that browser key and no other. */
  browser_key?: string;
  /** Repeats the challenge's `front_end`: the person approved a sign-in for
   *  that kind of front end and no other. */
  front_end?: string;
  sig?: string;
}

export interface CreateChallengeOptions {
  audience: string;
  requestedDisclosures: string[];
  requestedCredentials?: RequestedCredential[];
  requestScore?: RequestedScore;
  callbackUrl: string;
  sessionToken?: string;
  /** Thumbprint of the browser key this sign-in is for (ADR-066). */
  browserKey?: string;
  /** The kind of front end this sign-in is for, `browser` or `installed_app`. */
  frontEnd?: string;
}

export interface VerifyAssertionOptions {
  expectedAudience: string;
  expectedNonce: string;
  /** This site's own identifier: the assertion must name it (`site_aid`). */
  expectedSiteAid: string;
  /** The thumbprint the challenge named (ADR-066); omit when it named none. The
   *  assertion must repeat exactly it, and an assertion naming a browser key
   *  is refused when none was expected. */
  expectedBrowserKey?: string;
  /** The front end the challenge named (ADR-072 §2); omit when it named none.
   *  The assertion must repeat exactly it. */
  expectedFrontEnd?: string;
  maxSkewSeconds?: number;
}

export interface VerifyAssertionResult {
  valid: boolean;       // was: ok
  reason?: string;
  pairwiseAID?: string; // was: i
  disclosures?: Record<string, string>;
  presentedAcdcs?: unknown[];
  customData?: Record<string, unknown>;
  score?: number;       // convenience field from customData.ofa_score if present
  nonce?: string;
  audience?: string;
  dt?: string;
}

export interface SiteIdentity {
  aid: string;
  publicKey: Uint8Array;
  privateKey: Uint8Array;
  oobiUrl: string;
}

export interface SessionRecord {
  token: string;
  state: SessionState;
  challenge: LoginChallenge;
  relayOrQrUrl: string;
  expiresAt: string;
  verifiedResult?: VerifyAssertionResult;
  pairwiseAid?: string;
  appSessionToken?: string;
}