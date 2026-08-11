package oidc

// Pinned EUDI ARF profile versions (OWD-2). Bump only via ADR + contract change.
const (
	EUDIARFProfileVersion = "2.2.0"
	OpenID4VPProfile      = "openid4vp_1_0"
	SIOPv2Profile         = "siopv2_openid_connect_self_issued_v2"
	SDJWTVcProfile        = "sd_jwt_vc_draft_08"
	DIDWebsSpecVersion    = "seam-17-v1"
	AdapterVersion        = "ia-oidc-adapter-v1"
)

// RequiredDiscoveryFields lists discovery keys a conforming RP must observe.
var RequiredDiscoveryFields = []string{
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
}
