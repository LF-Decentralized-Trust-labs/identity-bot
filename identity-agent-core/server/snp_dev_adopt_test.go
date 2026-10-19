package server

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"testing"

	"identity-agent-core/buildmode"
	"identity-agent-core/iacrypto"
	"identity-agent-core/secureenclave"
)

// A development box's offer: real keys, and a real-format development attestation
// bound to exactly those keys, launched at the development measurement.
func aDevelopmentBoxOffer(t *testing.T) *pairingBeginResponse {
	t.Helper()
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	nextPub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	publicKey := iacrypto.VerkeyQB64(pub)
	nextPublicKey := iacrypto.VerkeyQB64(nextPub)
	backupSigningKey := base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{7}, 32))

	bound, err := iacrypto.PairingOfferBinding(publicKey, nextPublicKey, backupSigningKey)
	if err != nil {
		t.Fatal(err)
	}
	report, err := secureenclave.GenerateDevSNPReport(bound, secureenclave.DevMeasurement())
	if err != nil {
		t.Fatal(err)
	}
	return &pairingBeginResponse{
		PublicKey:        publicKey,
		NextPublicKey:    nextPublicKey,
		BackupSigningKey: backupSigningKey,
		Attestation:      base64.StdEncoding.EncodeToString(report),
	}
}

func acceptsTheDevelopmentMeasurement(m []byte) bool {
	return bytes.Equal(m, secureenclave.DevMeasurement())
}

// In a DEVELOPMENT build, a development box is adopted through the real adopt
// path — binding, debug, measurement and chain all run; only the chain's trust
// root is the development key. Skipped in a production build, where the debug bit
// is refused before the chain is ever considered (that is the next test).
//
// Run it with:
//
//	go test ./server/ -run TestADevelopmentBoxIsAdopted \
//	  -ldflags "-X identity-agent-core/buildmode.rawMode=dev"
func TestADevelopmentBoxIsAdoptedInADevelopmentBuild(t *testing.T) {
	if !buildmode.IsDev() {
		t.Skip("exercises the development adopt path; build the test binary with " +
			"-ldflags \"-X identity-agent-core/buildmode.rawMode=dev\"")
	}
	offer := aDevelopmentBoxOffer(t)
	if err := checkOfferBeforeDelegating(offer, acceptsTheDevelopmentMeasurement, secureenclave.VerifyDevSNPReport); err != nil {
		t.Fatalf("a development build must adopt a development box through the real path: %v", err)
	}
}

// A production build refuses the very same development box at the adopt gate —
// on the debug bit, before the signature is even considered. This runs in the
// ordinary (production) test binary, so it pins the prod-rejects-dev half.
func TestProductionRefusesADevelopmentBoxAtAdoption(t *testing.T) {
	if buildmode.IsDev() {
		t.Skip("this pins the production refusal; it is meaningful only in a production build")
	}
	offer := aDevelopmentBoxOffer(t)
	// verifyChain must never be reached — the debug bit is refused first — so a
	// verifier that would wrongly accept anything proves the refusal happens earlier.
	err := checkOfferBeforeDelegating(offer, acceptsTheDevelopmentMeasurement, func([]byte) error { return nil })
	if err == nil {
		t.Fatal("a production build must refuse a development box")
	}
}
