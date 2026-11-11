package login

import (
	"crypto/ed25519"
	"crypto/rand"
	"strings"
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

// The front end a sign-in is for is inside the signed body: a challenge for one
// kind cannot be turned into another's, and one that names none keeps the form
// it always had.
func TestTheFrontEndIsSignedInTheChallenge(t *testing.T) {
	seed := make([]byte, ed25519.SeedSize)
	if _, err := rand.Read(seed); err != nil {
		t.Fatal(err)
	}
	pub := ed25519.NewKeyFromSeed(seed).Public().(ed25519.PublicKey)
	bundle := ChallengeBundle{V: "ASK1", T: 1, SiteAID: "ESite", Audience: "https://a.example", Nonce: "n",
		Dt: "2026-06-30T00:00:00Z", Expiry: "2026-06-30T00:10:00Z", RequestedDisclosures: []string{}, RequestedCredentials: []RequestedCredential{},
		CallbackURL: "https://a.example/cb", SessionToken: "s"}
	plain := canonicalChallengeBody(bundle)
	bundle.FrontEnd = "browser"
	if err := SignChallengeForAsset(&bundle, seed); err != nil {
		t.Fatal(err)
	}
	if ok, _ := verifyUTF8(canonicalChallengeBody(bundle), bundle.Sig, pub); !ok {
		t.Fatal("a challenge naming its front end does not verify")
	}
	if !strings.Contains(canonicalChallengeBody(bundle), `"front_end":"browser","callback_url"`) || strings.Contains(plain, "front_end") {
		t.Fatalf("the kind is not written where, and only when, it is named: %s", canonicalChallengeBody(bundle))
	}
	bundle.FrontEnd = "installed_app"
	if ok, _ := verifyUTF8(canonicalChallengeBody(bundle), bundle.Sig, pub); ok {
		t.Fatal("a challenge for the browser verified as one for the installed app")
	}
	bundle.FrontEnd = ""
	if ok, _ := verifyUTF8(canonicalChallengeBody(bundle), bundle.Sig, pub); ok {
		t.Fatal("the kind could be removed from a signed challenge")
	}
	for kind, ok := range map[string]bool{"": true, "browser": true, "installed_app": true, "Browser": false, "tablet": false} {
		if (CheckFrontEnd(kind) == nil) != ok {
			t.Fatalf("CheckFrontEnd(%q) = %v", kind, CheckFrontEnd(kind))
		}
	}
}
