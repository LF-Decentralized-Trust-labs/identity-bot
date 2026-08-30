package update

import (
	"crypto/ed25519"
	"encoding/hex"
	"errors"
	"strings"
	"testing"
)

// A release key whose private half is published is not a key.
//
// This build once shipped the Ed25519 public key from RFC 8032 §7.1 Test 1 as
// its release trust anchor. The RFC prints the matching private key, so anybody
// who read the standard could sign an update that verified. Every check passed;
// there was simply nothing behind them.
func TestAPublishedTestKeyIsRefused(t *testing.T) {
	t.Setenv("UPDATE_TRUST_PUBKEY_HEX",
		"d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a")

	_, err := DefaultTrustAnchor()
	if err == nil {
		t.Fatal("the RFC 8032 test key was accepted as a release signing key; " +
			"an update signed by anybody at all would verify against it")
	}
	if !strings.Contains(err.Error(), "published test vector") {
		t.Fatalf("refused, but not for the reason somebody needs to read: %v", err)
	}
}

// The refusal must survive the obvious way of getting a build working again.
func TestPastingItBackIntoTheBinaryIsAlsoRefused(t *testing.T) {
	original := CompiledReleasePublicKeyHex
	t.Cleanup(func() { CompiledReleasePublicKeyHex = original })

	CompiledReleasePublicKeyHex = "D75A980182B10AB7D54BFED3C964073A0EE172F3DAA62325AF021A68F707511A"
	if _, err := DefaultTrustAnchor(); err == nil {
		t.Fatal("the same published key was accepted when compiled in and upper-cased")
	}
}

// No key must mean no verified update, never an unverified one.
func TestABuildWithNoKeyVerifiesNothing(t *testing.T) {
	original := CompiledReleasePublicKeyHex
	t.Cleanup(func() { CompiledReleasePublicKeyHex = original })
	CompiledReleasePublicKeyHex = ""
	t.Setenv("UPDATE_TRUST_PUBKEY_HEX", "")

	_, err := DefaultTrustAnchor()
	if !errors.Is(err, ErrNoReleaseKey) {
		t.Fatalf("a build with no release key should say so plainly; got %v", err)
	}
}

// A real key still works, so the guard protects rather than obstructs.
func TestARealKeyIsAccepted(t *testing.T) {
	pub, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("UPDATE_TRUST_PUBKEY_HEX", hex.EncodeToString(pub))

	ta, err := DefaultTrustAnchor()
	if err != nil {
		t.Fatalf("a genuine release key was refused: %v", err)
	}
	if ta == nil {
		t.Fatal("no trust anchor returned for a genuine key")
	}
}

// Something that is not a key at all must be named as such rather than
// truncated, padded or quietly accepted.
func TestSomethingThatIsNotAKeyIsNamed(t *testing.T) {
	t.Setenv("UPDATE_TRUST_PUBKEY_HEX", "abcd")
	if _, err := DefaultTrustAnchor(); err == nil {
		t.Fatal("two bytes were accepted as an Ed25519 public key")
	}
}
