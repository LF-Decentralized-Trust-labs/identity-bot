package oidc

import (
	"encoding/json"
	"strings"
	"testing"

	"identity-agent-core/login"
)

func assertionWithLevel() *login.Assertion {
	return &login.Assertion{
		I:        "EHOLDER",
		Audience: "https://rp.example",
		Nonce:    "n1",
		Dt:       "2026-07-26T00:00:00Z",
		Sig:      "0Bxxx",
		CustomData: map[string]interface{}{
			"score_attestation": map[string]interface{}{
				"band":   "green",
				"score":  float64(75),
				"issuer": "example-level-provider",
				"method": "document_check",
			},
		},
	}
}

// The protocol names what is being asserted, not who asserts it. A relying
// party integrating against these claims must not have to code against one
// provider's brand.
func TestEmittedClaimsCarryNoVendorName(t *testing.T) {
	level := identityLevelFromAssertion(assertionWithLevel())
	if level.Level != "green" || level.Score != 75 {
		t.Fatalf("level not read from the attestation: %+v", level)
	}
	if level.Issuer != "example-level-provider" {
		t.Errorf("issuer must survive to the token: %q", level.Issuer)
	}

	for _, claim := range []string{ClaimIdentityLevel, ClaimIdentityLevelScore, ClaimIdentityLevelIssuer} {
		if strings.Contains(strings.ToLower(claim), "grape") {
			t.Errorf("claim %q names a vendor", claim)
		}
	}
}

// A level with no issuer is still emitted, but the relying party can see that
// nobody vouched for it — which is the distinction that makes the level mean
// anything.
func TestLevelWithoutIssuerIsStillReadable(t *testing.T) {
	a := assertionWithLevel()
	delete(a.CustomData["score_attestation"].(map[string]interface{}), "issuer")
	level := identityLevelFromAssertion(a)
	if level.Level != "green" {
		t.Errorf("level lost when the issuer is absent: %+v", level)
	}
	if level.Issuer != "" {
		t.Errorf("issuer invented from nowhere: %q", level.Issuer)
	}
}

func TestNoLevelAttestationYieldsNothing(t *testing.T) {
	if got := identityLevelFromAssertion(&login.Assertion{I: "EHOLDER"}); got.Level != "" {
		t.Errorf("a level appeared with no attestation: %+v", got)
	}
	if got := identityLevelFromAssertion(nil); got.Level != "" {
		t.Errorf("a level appeared from a nil assertion: %+v", got)
	}
}

// The discovery document advertises what an RP can actually ask for.
func TestDiscoveryAdvertisesTheNeutralClaims(t *testing.T) {
	doc := BuildDiscovery("https://agent.example")
	encoded, err := json.Marshal(doc)
	if err != nil {
		t.Fatalf("marshal discovery: %v", err)
	}
	raw := strings.ToLower(string(encoded))
	if strings.Contains(raw, "grape") {
		t.Error("the discovery document still advertises a vendor-named claim")
	}
	if !strings.Contains(raw, "identity_level") {
		t.Error("the discovery document does not advertise the identity level claim")
	}
}
