/** Pinned EUDI ARF profile versions (OWD-2) — must match Go oidc/profile.go */
export const EUDI_ARF_PROFILE_VERSION = "2.2.0";
export const OPENID4VP_PROFILE = "openid4vp_1_0";
export const SIOPV2_PROFILE = "siopv2_openid_connect_self_issued_v2";
export const SD_JWT_VC_PROFILE = "sd_jwt_vc_draft_08";
export const DIDWEBS_SPEC_VERSION = "seam-17-v1";
export const ADAPTER_VERSION = "ia-oidc-adapter-v1";
export const CLAIM_NAMESPACE = "https://identityagent.org/claims";

export const REQUIRED_DISCOVERY_FIELDS = [
  "issuer",
  "authorization_endpoint",
  "response_types_supported",
  "id_token_signing_alg_values_supported",
  "subject_types_supported",
  "scopes_supported",
  "claims_supported",
  "vp_formats",
  "eudi_arf_profile_version",
  "siopv2_profile",
  "openid4vp_profile",
  "sd_jwt_vc_profile",
  "didwebs_spec_version",
  "ia_oidc_adapter_version",
] as const;