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
 * Ask intent registry (SEAM-8 / SM10). The `t` discriminator the IA dispatches
 * on after fetching the Ask. Numeric + named for a compact, language-neutral
 * wire; each value MUST map to a governed action in the M15 Action Registry.
 */
export const AskIntent = {
  login: 1,
  present: 2,
  pay: 3,
  contact: 4,
  issue: 5,
} as const;
export type AskIntentCode = (typeof AskIntent)[keyof typeof AskIntent];

/**
 * An "Ask" — a signed, typed request one Identity Agent fetches from a minimal
 * QR pointer (`/i/{token}`). The login Ask (`t: 1`) keeps site_* fields as its
 * intent params; other intents carry their own fields (see the SM10 proposal).
 */
export interface LoginChallenge {
  v: "ASK1";
  t: typeof AskIntent.login;
  site_aid: string;
  site_oobi: string;
  audience: string;
  nonce: string;
  dt: string;
  expiry: string;
  requested_disclosures: string[];
  requested_credentials: RequestedCredential[];
  requested_score?: RequestedScore;
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
  ok: boolean;
  reason?: string;
  i?: string;
  disclosures?: Record<string, string>;
  presentedAcdcs?: unknown[];
  customData?: Record<string, unknown>;
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