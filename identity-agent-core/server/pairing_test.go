package server

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

// realKey is a well-formed Ed25519 public key: the owner key is checked with
// the same decoder the owner-signature path uses, so a fixture has to be one.
func realKey() string {
	pub := ed25519.NewKeyFromSeed(make([]byte, ed25519.SeedSize)).Public().(ed25519.PublicKey)
	return base64.RawURLEncoding.EncodeToString(pub)
}

// Pairing by delegation is refused, and that refusal is the point.
//
// This replaces four tests of a delegation validator that no longer exists.
// They checked that a delegation was over this instance's key, named a real
// delegator, matched its claim, and carried an owner — all correct rules for a
// mechanism we no longer use. A delegated inception names the delegator in a
// publicly resolvable key log, so a computer paired that way publishes who owns
// it. ADR-036 settled that on 2026-08-12; this is the code catching up.
func TestPairingByDelegationIsRefused(t *testing.T) {
	body, _ := json.Marshal(map[string]interface{}{
		"adoption_code": "whatever",
		"owner_aid":     "EOWNER",
		// found_as_root omitted, which is what a delegating client would send
		"dip_event": map[string]interface{}{
			"t": "dip", "i": "EDELEGATED", "di": "EROOT",
		},
	})
	req := httptest.NewRequest(http.MethodPost, "/api/pairing/complete", bytes.NewReader(body))
	rec := httptest.NewRecorder()
	(&CoreServer{}).handlePairingComplete(rec, req)

	if rec.Code == http.StatusOK {
		t.Fatal("a delegated pairing was accepted; a paired computer must found its own root")
	}
}

// Both endpoints have to answer before an owner exists — that is the only
// moment they are for — so they cannot be owner-gated.
func TestPairingEndpointsAreReachableBeforeAnOwnerExists(t *testing.T) {
	for _, route := range []struct{ method, pattern string }{
		{"POST", "/api/pairing/begin"},
		{"POST", "/api/pairing/complete"},
	} {
		if got := classify(route.method, route.pattern); got != accessPublic {
			t.Errorf("%s %s classified %q — an unadopted instance could never be adopted",
				route.method, route.pattern, got)
		}
	}
}
