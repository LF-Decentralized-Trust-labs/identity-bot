/** Link Verification SDK shapes */

export type Outcome = "verified" | "tampered" | "unverified" | "incomplete";
export type Flow = "badge" | "link";
export type Tier = "free" | "gated";
export type Timing = "eager" | "lazy";
export type InputKind = "url" | "did_webs" | "oobi" | "qr_payload";

export interface VerifyRequest {
  input: string;
  input_kind?: InputKind;
  flow?: Flow;
  timing?: Timing;
  tier?: Tier;
  gating_token?: string;
  force_refresh?: boolean;
}

export interface Ownership {
  registered_to: string;
  disclosure: "disclosed" | "undisclosed_verified";
}

export interface VerificationResult {
  outcome: Outcome;
  aid: string | null;
  verification_path: "did_webs" | "oobi" | "none";
  kel_replay?: "ok" | "failed" | "incomplete";
  last_verified: string;
  contact_correlation: "known" | "stranger" | null;
  ownership?: Ownership | null;
  band?: string;
  band_style?: string;
  grape_score?: number;
  grape_score_as_of?: string;
  badge?: string;
  cached?: boolean;
}

export interface VerifyOptions {
  /** IA Go Core loopback base URL (default http://127.0.0.1:5050) */
  coreBaseUrl?: string;
  flow?: Flow;
  tier?: Tier;
  timing?: Timing;
  forceRefresh?: boolean;
}