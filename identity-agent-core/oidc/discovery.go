package oidc

import "fmt"

// DiscoveryDocument is the relay-hosted SIOPv2/OIDC4VP discovery surface (OWD-4).
type DiscoveryDocument struct {
	Issuer                           string                 `json:"issuer"`
	AuthorizationEndpoint            string                 `json:"authorization_endpoint"`
	ResponseTypesSupported           []string               `json:"response_types_supported"`
	ResponseModesSupported           []string               `json:"response_modes_supported"`
	GrantTypesSupported              []string               `json:"grant_types_supported"`
	SubjectTypesSupported            []string               `json:"subject_types_supported"`
	IDTokenSigningAlgValuesSupported []string               `json:"id_token_signing_alg_values_supported"`
	ScopesSupported                  []string               `json:"scopes_supported"`
	ClaimsSupported                  []string               `json:"claims_supported"`
	VPFormats                        map[string]interface{} `json:"vp_formats"`
	EUDIARFProfileVersion            string                 `json:"eudi_arf_profile_version"`
	SIOPv2Profile                    string                 `json:"siopv2_profile"`
	OpenID4VPProfile                 string                 `json:"openid4vp_profile"`
	SDJWTVcProfile                   string                 `json:"sd_jwt_vc_profile"`
	DIDWebsSpecVersion               string                 `json:"didwebs_spec_version"`
	IAOIDCAdapterVersion             string                 `json:"ia_oidc_adapter_version"`
	SelfIssuedOpenIDProviderMetadata map[string]interface{} `json:"self_issued_openid_provider_metadata,omitempty"`
}

// BuildDiscovery returns the openid-configuration document for a pairwise issuer.
func BuildDiscovery(issuerBase string) DiscoveryDocument {
	base := trimSlash(issuerBase)
	return DiscoveryDocument{
		Issuer:                           base,
		AuthorizationEndpoint:            fmt.Sprintf("%s/oidc/authorize", base),
		ResponseTypesSupported:           []string{"id_token", "vp_token", "id_token vp_token"},
		ResponseModesSupported:           []string{"fragment", "direct_post"},
		GrantTypesSupported:              []string{"implicit"},
		SubjectTypesSupported:            []string{"public"},
		IDTokenSigningAlgValuesSupported: []string{"EdDSA"},
		ScopesSupported:                  []string{"openid", "profile", "email"},
		ClaimsSupported: []string{
			"iss", "sub", "aud", "nonce", "iat", "exp", "name", "email",
			ClaimIdentityLevel,
			ClaimIdentityLevelScore,
			ClaimIdentityLevelIssuer,
			ClaimNamespace + "/seam8_assertion_digest",
		},
		VPFormats:             BuildVPFormatsMetadata(),
		EUDIARFProfileVersion: EUDIARFProfileVersion,
		SIOPv2Profile:         SIOPv2Profile,
		OpenID4VPProfile:      OpenID4VPProfile,
		SDJWTVcProfile:        SDJWTVcProfile,
		DIDWebsSpecVersion:    DIDWebsSpecVersion,
		IAOIDCAdapterVersion:  AdapterVersion,
		SelfIssuedOpenIDProviderMetadata: map[string]interface{}{
			"did_methods_supported":       []string{"did:webs"},
			"did_methods_degraded":        []string{"did:jwk"},
			"authorization_endpoint_type": "relay_hosted",
		},
	}
}

func trimSlash(s string) string {
	for len(s) > 0 && s[len(s)-1] == '/' {
		s = s[:len(s)-1]
	}
	return s
}
