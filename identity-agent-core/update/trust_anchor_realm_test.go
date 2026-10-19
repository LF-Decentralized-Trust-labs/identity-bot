package update

import (
	"crypto/ed25519"
	"encoding/hex"
	"errors"
	"fmt"
	"testing"
)

func TestSigningKeyIDForModeIsRealmDistinct(t *testing.T) {
	if got := signingKeyIDForMode(false); got != DefaultSigningKeyID {
		t.Fatalf("prod realm key id = %q, want %q", got, DefaultSigningKeyID)
	}
	if got := signingKeyIDForMode(true); got != DevSigningKeyID {
		t.Fatalf("dev realm key id = %q, want %q", got, DevSigningKeyID)
	}
	if DefaultSigningKeyID == DevSigningKeyID {
		t.Fatal("prod and dev signing key ids must differ, or the realms are not separated")
	}
}

// realmKeypair returns a deterministic keypair for the realm tests.
func realmKeypair(seedByte byte) (ed25519.PrivateKey, ed25519.PublicKey) {
	seed := make([]byte, ed25519.SeedSize)
	for i := range seed {
		seed[i] = seedByte
	}
	priv := ed25519.NewKeyFromSeed(seed)
	return priv, priv.Public().(ed25519.PublicKey)
}

func realmManifestJSON(signingKeyID string) []byte {
	return []byte(fmt.Sprintf(
		`{"manifest_version":%d,"signing_key_id":%q,"version":"1.0.0","components":[]}`,
		SupportedManifestVersion, signingKeyID))
}

// A development-signed release does not verify against a production trust
// anchor: the production anchor does not carry the dev key id, so the lookup
// misses before a signature is even checked.
func TestProductionAnchorRefusesADevSignedRelease(t *testing.T) {
	devPriv, _ := realmKeypair(0x11)
	_, prodPub := realmKeypair(0x22)

	prodAnchor, err := NewTrustAnchor(map[string][]byte{DefaultSigningKeyID: prodPub})
	if err != nil {
		t.Fatal(err)
	}
	signed, err := SignManifestForTest(realmManifestJSON(DevSigningKeyID), devPriv)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyManifest(signed, prodAnchor); !errors.Is(err, ErrUntrustedSigningKey) {
		t.Fatalf("prod anchor verifying a dev-signed release: got %v, want ErrUntrustedSigningKey", err)
	}
}

// The mirror: a production-signed release does not verify against a development
// trust anchor.
func TestDevAnchorRefusesAProdSignedRelease(t *testing.T) {
	prodPriv, _ := realmKeypair(0x22)
	_, devPub := realmKeypair(0x11)

	devAnchor, err := NewTrustAnchor(map[string][]byte{DevSigningKeyID: devPub})
	if err != nil {
		t.Fatal(err)
	}
	signed, err := SignManifestForTest(realmManifestJSON(DefaultSigningKeyID), prodPriv)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyManifest(signed, devAnchor); !errors.Is(err, ErrUntrustedSigningKey) {
		t.Fatalf("dev anchor verifying a prod-signed release: got %v, want ErrUntrustedSigningKey", err)
	}
}

// Even if a dev release forges the production key id, the signature was made by
// the dev key and does not verify against the production key — the second layer
// of separation, behind the key id.
func TestProductionAnchorRefusesADevKeyUnderTheProdKeyID(t *testing.T) {
	devPriv, _ := realmKeypair(0x11)
	_, prodPub := realmKeypair(0x22)

	prodAnchor, err := NewTrustAnchor(map[string][]byte{DefaultSigningKeyID: prodPub})
	if err != nil {
		t.Fatal(err)
	}
	signed, err := SignManifestForTest(realmManifestJSON(DefaultSigningKeyID), devPriv)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyManifest(signed, prodAnchor); !errors.Is(err, ErrSignatureInvalid) {
		t.Fatalf("prod anchor verifying a dev-key signature under the prod id: got %v, want ErrSignatureInvalid", err)
	}
}

// A key rotation must not introduce the other realm's reserved key id, so the
// per-realm invariant holds after rotation, not only at the initial anchor.
func TestRotationRefusesTheOtherRealmsKeyID(t *testing.T) {
	_, pub := realmKeypair(0x44)
	ta, err := NewTrustAnchor(map[string][]byte{DefaultSigningKeyID: pub})
	if err != nil {
		t.Fatal(err)
	}

	// This is a production test build, so the other realm's id is the dev id.
	refused := &Manifest{NextSigningKey: &NextSigningKey{
		KeyID:     DevSigningKeyID,
		PublicKey: EncodeBase64URL(pub),
	}}
	if err := ta.learnNextSigningKey(refused); err == nil {
		t.Fatal("learning the dev realm id into a production anchor must be refused")
	}
	if _, ok := ta.PublicKey(DevSigningKeyID); ok {
		t.Fatal("the refused key id must not have been added to the anchor")
	}

	// A new id within the build's own realm is fine.
	allowed := &Manifest{NextSigningKey: &NextSigningKey{
		KeyID:     "grape-release-2027",
		PublicKey: EncodeBase64URL(pub),
	}}
	if err := ta.learnNextSigningKey(allowed); err != nil {
		t.Fatalf("learning a same-realm next key must succeed: %v", err)
	}
	if _, ok := ta.PublicKey("grape-release-2027"); !ok {
		t.Fatal("the same-realm next key should have been added")
	}
}

// In this (production) test build, DefaultTrustAnchor anchors releases under the
// production key id, not the dev id.
func TestDefaultTrustAnchorUsesTheProductionRealmInAProdBuild(t *testing.T) {
	_, pub := realmKeypair(0x33)
	t.Setenv("UPDATE_TRUST_PUBKEY_HEX", hex.EncodeToString(pub))

	ta, err := DefaultTrustAnchor()
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := ta.PublicKey(DefaultSigningKeyID); !ok {
		t.Fatalf("a production build's anchor must carry %q", DefaultSigningKeyID)
	}
	if _, ok := ta.PublicKey(DevSigningKeyID); ok {
		t.Fatalf("a production build's anchor must not carry the dev id %q", DevSigningKeyID)
	}
}
