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
  presented_acdcs: unknown[];
  custom_data?: Record<string, unknown>;
  p_kel?: string;
  sig?: string;
}

export interface CreateChallengeOptions {
  audience: string;
  requestedDisclosures: string[];
  requestedCredentials?: RequestedCredential[];
  requestScore?: RequestedScore;
  callbackUrl: string;
  sessionToken?: string;
}

export interface VerifyAssertionOptions {
  expectedAudience: string;
  expectedNonce: string;
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