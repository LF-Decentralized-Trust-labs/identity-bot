package login

import (
	"crypto/ed25519"
	"crypto/rand"
	"testing"
)

// TestSignChallengeForAssetRoundTrip proves the Go-native asset-challenge signing path:
// signing with an asset's Ed25519 seed produces a qb64 signature that verifies against
// the asset's public key over the canonical challenge body. This replaces the prior path (the asset key was discarded at creation, and the
// Python /sign-for-name stub held no key) and the by-value bug that dropped the signature.
func TestSignChallengeForAssetRoundTrip(t *testing.T) {
	seed := make([]byte, ed25519.SeedSize)
	if _, err := rand.Read(seed); err != nil {
		t.Fatalf("seed: %v", err)
	}
	pub := ed25519.NewKeyFromSeed(seed).Public().(ed25519.PublicKey)

	bundle := ChallengeBundle{
		V:                    "ASK1",
		T:                    1,
		SiteAID:              "ENkQbdw3X9QHNhwacOoFONZqNoh_vSwNBwWFmklR4kd4",
		SiteOOBI:             "https://example.org/public/oobi/ENkQbdw3X9QHNhwacOoFONZqNoh_vSwNBwWFmklR4kd4",
		Audience:             "Example RP",
		Nonce:                "test-nonce-abc",
		Dt:                   "2026-06-30T00:00:00Z",
		Expiry:               "2026-06-30T00:10:00Z",
		RequestedDisclosures: []string{"display_name"},
		RequestedCredentials: []RequestedCredential{},
		CallbackURL:          "https://example.org/api/login/callback",
		SessionToken:         "sess-123",
	}

	if err := SignChallengeForAsset(&bundle, seed); err != nil {
		t.Fatalf("SignChallengeForAsset: %v", err)
	}
	if bundle.Sig == "" {
		t.Fatal("signature not attached to bundle (by-value bug regression)")
	}

	body := canonicalChallengeBody(bundle)
	ok, err := verifyUTF8(body, bundle.Sig, pub)
	if err != nil {
		t.Fatalf("verifyUTF8: %v", err)
	}
	if !ok {
		t.Fatal("signature did not verify against the asset key")
	}

	// Tamper check: a modified body must NOT verify.
	bundle.Audience = "Evil RP"
	if ok2, _ := verifyUTF8(canonicalChallengeBody(bundle), bundle.Sig, pub); ok2 {
		t.Fatal("signature verified over tampered body — must fail")
	}
}
