package login

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// TestVerifyAssertionRoundTrip proves the RP-side assertion verification: a login
// assertion signed by the asserter's key verifies when the key is resolved from its KERI
// did.json, and is rejected on nonce/audience/tamper mismatch.
func TestVerifyAssertionRoundTrip(t *testing.T) {
	seed := make([]byte, ed25519.SeedSize)
	if _, err := rand.Read(seed); err != nil {
		t.Fatalf("seed: %v", err)
	}
	pub := ed25519.NewKeyFromSeed(seed).Public().(ed25519.PublicKey)
	aid := "EUserPairwiseAidExampleForTestOnly1234567890"

	// Stub the asserter's KEL did.json (what resolveAIDKey fetches).
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/"+aid+"/did.json" {
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"verificationMethod": []map[string]interface{}{
					{"publicKeyJwk": map[string]string{"x": base64.RawURLEncoding.EncodeToString(pub)}},
				},
			})
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	const nonce = "challenge-nonce-xyz"
	const aud = "Example RP"
	a := Assertion{
		V:                   "IALOGIN10JSON",
		T:                   "login-assertion",
		I:                   aid,
		RelationshipAIDOOBI: srv.URL + "/oobi/" + aid,
		Audience:            aud,
		Nonce:               nonce,
		Dt:                  time.Now().UTC().Format(time.RFC3339),
		Disclosures:         map[string]string{"display_name": "Test User"},
		PresentedACDCs:      []interface{}{},
	}
	sig, _, err := signUTF8(canonicalAssertionBody(a), seed)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	a.Sig = sig

	if res := VerifyAssertion(a, nonce, aud, 300, srv.Client()); !res.Valid {
		t.Fatalf("expected valid, got reason=%q", res.Reason)
	} else if res.PairwiseAID != aid {
		t.Fatalf("pairwiseAID = %q, want %q", res.PairwiseAID, aid)
	}

	// Negatives.
	if VerifyAssertion(a, "wrong-nonce", aud, 300, srv.Client()).Valid {
		t.Fatal("nonce mismatch must fail")
	}
	if VerifyAssertion(a, nonce, "Evil RP", 300, srv.Client()).Valid {
		t.Fatal("audience mismatch must fail")
	}
	tampered := a
	tampered.Disclosures = map[string]string{"display_name": "Hacker"}
	if VerifyAssertion(tampered, nonce, aud, 300, srv.Client()).Valid {
		t.Fatal("tampered body must fail")
	}
}
