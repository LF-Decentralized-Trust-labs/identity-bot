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
		"@context": []string{"https://identityagent.org/oidc4vp/acdc/v1"},
		"type":     []string{"VerifiablePresentation"},
		"holder":   assertion.I,
		"verifiableCredential": assertion.PresentedACDCs,
	}
	if band, score := grapeScoreFromAssertion(assertion); band != "" {
		payload["grape_score"] = map[string]interface{}{
			"band": band, "score": score,
		}
	}
	return &VPToken{Format: VPFormatACDC, Token: payload}, nil
}

func buildSDJWTVPToken(assertion *login.Assertion) (*VPToken, error) {
	claims := map[string]interface{}{
		"sub": assertion.I,
		"iat": assertion.Dt,
	}
	if band, score := grapeScoreFromAssertion(assertion); band != "" {
		claims["grape_score_band"] = band
		if score > 0 {
			claims["grape_score"] = score
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

func grapeScoreFromAssertion(assertion *login.Assertion) (band string, score int) {
	if assertion.CustomData == nil {
		return "", 0
	}
	raw, ok := assertion.CustomData["score_attestation"]
	if !ok {
		return "", 0
	}
	m, ok := raw.(map[string]interface{})
	if !ok {
		return "", 0
	}
	if b, ok := m["band"].(string); ok {
		band = b
	}
	switch v := m["score"].(type) {
	case float64:
		score = int(v)
	case int:
		score = v
	}
	return band, score
}

// SelectVPFormat picks a format from the RP request (default SD-JWT VC).
func SelectVPFormat(requested string) string {
	requested = strings.TrimSpace(requested)
	if requested == VPFormatACDC {
		return VPFormatACDC
	}
	return VPFormatSDJWT
}