import {
  ADAPTER_VERSION,
  DIDWEBS_SPEC_VERSION,
  EUDI_ARF_PROFILE_VERSION,
  OPENID4VP_PROFILE,
  REQUIRED_DISCOVERY_FIELDS,
  SD_JWT_VC_PROFILE,
  SIOPV2_PROFILE,
} from "./profile.js";
import type { ConformanceResult, OIDCDiscoveryDocument } from "./types.js";

const VP_FORMAT_SDJWT = "vc+sd-jwt";
const VP_FORMAT_ACDC = "acdc";

/** Validate discovery document against pinned EUDI ARF profile (OWD-2). */
export function validateDiscoveryConformance(doc: OIDCDiscoveryDocument): ConformanceResult {
  const errors: string[] = [];
  const check = (ok: boolean, msg: string) => {
    if (!ok) errors.push(msg);
  };

  for (const field of REQUIRED_DISCOVERY_FIELDS) {
    switch (field) {
      case "issuer":
        check(!!doc.issuer, "missing issuer");
        break;
      case "authorization_endpoint":
        check(!!doc.authorization_endpoint, "missing authorization_endpoint");
        break;
      case "response_types_supported":
        check((doc.response_types_supported?.length ?? 0) > 0, "missing response_types_supported");
        break;
      case "id_token_signing_alg_values_supported":
        check(doc.id_token_signing_alg_values_supported?.includes("EdDSA") ?? false,
          "EdDSA required in id_token_signing_alg_values_supported");
        break;
      case "subject_types_supported":
        check((doc.subject_types_supported?.length ?? 0) > 0, "missing subject_types_supported");
        break;
      case "scopes_supported":
        check(doc.scopes_supported?.includes("openid") ?? false, "openid scope required");
        break;
      case "claims_supported":
        check((doc.claims_supported?.length ?? 0) > 0, "missing claims_supported");
        break;
      case "vp_formats":
        check(!!doc.vp_formats, "missing vp_formats");
        if (doc.vp_formats) {
          check(!!doc.vp_formats[VP_FORMAT_SDJWT], "vp_formats must include vc+sd-jwt");
          check(!!doc.vp_formats[VP_FORMAT_ACDC], "vp_formats must include acdc");
        }
        break;
      case "eudi_arf_profile_version":
        check(doc.eudi_arf_profile_version === EUDI_ARF_PROFILE_VERSION,
          `eudi_arf_profile_version must be ${EUDI_ARF_PROFILE_VERSION}`);
        break;
      case "siopv2_profile":
        check(doc.siopv2_profile === SIOPV2_PROFILE, `siopv2_profile must be ${SIOPV2_PROFILE}`);
        break;
      case "openid4vp_profile":
        check(doc.openid4vp_profile === OPENID4VP_PROFILE, `openid4vp_profile must be ${OPENID4VP_PROFILE}`);
        break;
      case "sd_jwt_vc_profile":
        check(doc.sd_jwt_vc_profile === SD_JWT_VC_PROFILE, `sd_jwt_vc_profile must be ${SD_JWT_VC_PROFILE}`);
        break;
      case "didwebs_spec_version":
        check(doc.didwebs_spec_version === DIDWEBS_SPEC_VERSION,
          `didwebs_spec_version must be ${DIDWEBS_SPEC_VERSION}`);
        break;
      case "ia_oidc_adapter_version":
        check(doc.ia_oidc_adapter_version === ADAPTER_VERSION,
          `ia_oidc_adapter_version must be ${ADAPTER_VERSION}`);
        break;
    }
  }

  return { ok: errors.length === 0, errors, profile: EUDI_ARF_PROFILE_VERSION };
}