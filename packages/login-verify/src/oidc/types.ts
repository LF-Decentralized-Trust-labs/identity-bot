export interface OIDCDiscoveryDocument {
  issuer: string;
  authorization_endpoint: string;
  response_types_supported: string[];
  response_modes_supported?: string[];
  grant_types_supported?: string[];
  subject_types_supported: string[];
  id_token_signing_alg_values_supported: string[];
  scopes_supported: string[];
  claims_supported: string[];
  vp_formats: Record<string, unknown>;
  eudi_arf_profile_version: string;
  siopv2_profile: string;
  openid4vp_profile: string;
  sd_jwt_vc_profile: string;
  didwebs_spec_version: string;
  ia_oidc_adapter_version: string;
  self_issued_openid_provider_metadata?: Record<string, unknown>;
}

export interface ConformanceResult {
  ok: boolean;
  errors: string[];
  profile: string;
}

export interface IDTokenVerifyResult {
  ok: boolean;
  reason?: string;
  iss?: string;
  sub?: string;
  nonce?: string;
  audience?: string;
  disclosures?: Record<string, string>;
  assertion?: import("../types.js").LoginAssertion;
  /** Whether a policy was applied. undefined means none was supplied — the
   *  caller either has no policy or forgot to pass one, and those look the
   *  same from here, so it is reported rather than assumed. */
  authorized?: boolean;
}