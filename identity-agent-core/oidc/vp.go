package oidc

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"

	"identity-agent-core/login"
)

// VPFormat constants for vp_formats negotiation (OWD-1).
const (
	VPFormatSDJWT = "vc+sd-jwt"
	VPFormatACDC  = "acdc"
)

// BuildVPFormatsMetadata advertises supported OIDC4VP presentation formats.
func BuildVPFormatsMetadata() map[string]interface{} {
	return map[string]interface{}{
		VPFormatSDJWT: map[string]interface{}{
			"alg_values_supported": []string{"EdDSA"},
			"default":              true,
		},
		VPFormatACDC: map[string]interface{}{
			"alg_values_supported": []string{"EdDSA"},
			"keri_native":          true,
		},
	}
}

// VPToken is the OIDC4VP authorization response envelope.
type VPToken struct {
	Format string      `json:"format"`
	Token  interface{} `json:"token"`
}

// BuildVPToken packages credentials + Grape Score per negotiated format.
func BuildVPToken(format string, assertion *login.Assertion) (*VPToken, error) {
	switch format {
	case "", VPFormatSDJWT:
		return buildSDJWTVPToken(assertion)
	case VPFormatACDC:
		return buildACDCVPToken(assertion)
	default:
		return nil, fmt.Errorf("unsupported vp_format: %s", format)
	}
}

func buildACDCVPToken(assertion *login.Assertion) (*VPToken, error) {
	payload := map[string]interface{}{
		"@context":             []string{"https://identityagent.org/oidc4vp/acdc/v1"},
		"type":                 []string{"VerifiablePresentation"},
		"holder":               assertion.I,
		"verifiableCredential": assertion.PresentedACDCs,
	}
	if level := identityLevelFromAssertion(assertion); level.Level != "" {
		payload["identity_level"] = map[string]interface{}{
			"level": level.Level, "score": level.Score,
			"issuer": level.Issuer, "method": level.Method,
		}
	}
	return &VPToken{Format: VPFormatACDC, Token: payload}, nil
}

func buildSDJWTVPToken(assertion *login.Assertion) (*VPToken, error) {
	claims := map[string]interface{}{
		"sub": assertion.I,
		"iat": assertion.Dt,
	}
	if level := identityLevelFromAssertion(assertion); level.Level != "" {
		claims["identity_level"] = level.Level
		if level.Score > 0 {
			claims["identity_level_score"] = level.Score
		}
		if level.Issuer != "" {
			claims["identity_level_issuer"] = level.Issuer
		}
	}
	if len(assertion.PresentedACDCs) > 0 {
		claims["vc"] = assertion.PresentedACDCs
	}
	payloadJSON, err := json.Marshal(claims)
	if err != nil {
		return nil, err
	}
	payloadB64 := base64.RawURLEncoding.EncodeToString(payloadJSON)
	// Steel-thread SD-JWT VC: unsigned payload segment + seam8 digest binding.
	token := fmt.Sprintf("%s.%s~%s", sdJWTHeader(), payloadB64, assertion.D)
	return &VPToken{Format: VPFormatSDJWT, Token: token}, nil
}

func sdJWTHeader() string {
	hdr, _ := json.Marshal(map[string]string{"alg": "none", "typ": "vc+sd-jwt"})
	return base64.RawURLEncoding.EncodeToString(hdr)
}

// identityLevel is what an assertion says about the holder's identity level,
// flattened for the token builders.
type identityLevel struct {
	Level  string
	Score  int
	Issuer string
	Method string
}

// identityLevelFromAssertion reads the signed level attestation an assertion
// carries. The attestation names its own issuer, so no provider is assumed.
func identityLevelFromAssertion(assertion *login.Assertion) identityLevel {
	var out identityLevel
	if assertion == nil || assertion.CustomData == nil {
		return out
	}
	m, ok := assertion.CustomData["score_attestation"].(map[string]interface{})
	if !ok {
		return out
	}
	if v, ok := m["band"].(string); ok {
		out.Level = v
	}
	if v, ok := m["issuer"].(string); ok {
		out.Issuer = v
	}
	if v, ok := m["method"].(string); ok {
		out.Method = v
	}
	switch v := m["score"].(type) {
	case float64:
		out.Score = int(v)
	case int:
		out.Score = v
	}
	return out
}

// SelectVPFormat picks a format from the RP request (default SD-JWT VC).
func SelectVPFormat(requested string) string {
	requested = strings.TrimSpace(requested)
	if requested == VPFormatACDC {
		return VPFormatACDC
	}
	return VPFormatSDJWT
}
