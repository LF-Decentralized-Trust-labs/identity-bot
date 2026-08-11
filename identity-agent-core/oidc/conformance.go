package oidc

import "fmt"

// ConformanceResult captures EUDI ARF profile validation against pinned versions.
type ConformanceResult struct {
	OK      bool
	Errors  []string
	Profile string
}

// ValidateDiscovery checks a discovery document against the pinned EUDI ARF profile (OWD-2).
func ValidateDiscovery(doc DiscoveryDocument) ConformanceResult {
	res := ConformanceResult{OK: true, Profile: EUDIARFProfileVersion}
	check := func(ok bool, msg string) {
		if !ok {
			res.OK = false
			res.Errors = append(res.Errors, msg)
		}
	}

	for _, field := range RequiredDiscoveryFields {
		switch field {
		case "issuer":
			check(doc.Issuer != "", "missing issuer")
		case "authorization_endpoint":
			check(doc.AuthorizationEndpoint != "", "missing authorization_endpoint")
		case "response_types_supported":
			check(len(doc.ResponseTypesSupported) > 0, "missing response_types_supported")
		case "id_token_signing_alg_values_supported":
			check(containsStr(doc.IDTokenSigningAlgValuesSupported, "EdDSA"), "EdDSA required in id_token_signing_alg_values_supported")
		case "subject_types_supported":
			check(len(doc.SubjectTypesSupported) > 0, "missing subject_types_supported")
		case "scopes_supported":
			check(containsStr(doc.ScopesSupported, "openid"), "openid scope required")
		case "claims_supported":
			check(len(doc.ClaimsSupported) > 0, "missing claims_supported")
		case "vp_formats":
			check(doc.VPFormats != nil, "missing vp_formats")
			if doc.VPFormats != nil {
				check(doc.VPFormats[VPFormatSDJWT] != nil, "vp_formats must include vc+sd-jwt")
				check(doc.VPFormats[VPFormatACDC] != nil, "vp_formats must include acdc")
			}
		case "eudi_arf_profile_version":
			check(doc.EUDIARFProfileVersion == EUDIARFProfileVersion,
				fmt.Sprintf("eudi_arf_profile_version must be %s, got %s", EUDIARFProfileVersion, doc.EUDIARFProfileVersion))
		case "siopv2_profile":
			check(doc.SIOPv2Profile == SIOPv2Profile,
				fmt.Sprintf("siopv2_profile must be %s", SIOPv2Profile))
		case "openid4vp_profile":
			check(doc.OpenID4VPProfile == OpenID4VPProfile,
				fmt.Sprintf("openid4vp_profile must be %s", OpenID4VPProfile))
		case "sd_jwt_vc_profile":
			check(doc.SDJWTVcProfile == SDJWTVcProfile,
				fmt.Sprintf("sd_jwt_vc_profile must be %s", SDJWTVcProfile))
		case "didwebs_spec_version":
			check(doc.DIDWebsSpecVersion == DIDWebsSpecVersion,
				fmt.Sprintf("didwebs_spec_version must be %s", DIDWebsSpecVersion))
		case "ia_oidc_adapter_version":
			check(doc.IAOIDCAdapterVersion == AdapterVersion,
				fmt.Sprintf("ia_oidc_adapter_version must be %s", AdapterVersion))
		}
	}
	return res
}

func containsStr(ss []string, want string) bool {
	for _, s := range ss {
		if s == want {
			return true
		}
	}
	return false
}
