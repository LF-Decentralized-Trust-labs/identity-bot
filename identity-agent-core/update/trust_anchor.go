package update

import (
	"crypto/ed25519"
	"encoding/hex"
	"fmt"
	"os"
	"strings"
)

// DefaultSigningKeyID is the compiled-in release key identifier.
const DefaultSigningKeyID = "grape-release-2026"

// CompiledReleasePublicKeyHex is the release signing key this build trusts.
//
// EMPTY BY DEFAULT, AND THAT IS THE POINT. It is supplied at build time:
//
//	go build -ldflags "-X identity-agent-core/update.CompiledReleasePublicKeyHex=<hex>"
//
// A build that does not supply one verifies no update at all, which is the safe
// failure: refusing every update costs a manual reinstall, while accepting an
// unverified one costs the machine.
//
// It held a default until 2026-08-30, and the default was the Ed25519 public key
// from RFC 8032 §7.1 Test 1 — whose PRIVATE key is printed in the RFC. Anybody
// who read the standard could sign an update this agent would accept. The
// signature check was sound the whole time; the lock was good and the key was
// published. That is why the guard below refuses that value by name rather than
// merely changing it: a constant can be pasted back by anyone who wants a build
// to "just work", and the point is that it must not.
var CompiledReleasePublicKeyHex = ""

// publishedTestKeys are public keys whose private halves are published, so that
// a signature made with them proves nothing.
//
// Test vectors are exactly the right thing to develop against and exactly the
// wrong thing to ship. Naming them here means a build that reaches for one fails
// loudly at the moment somebody tries, rather than passing every check for years.
var publishedTestKeys = map[string]string{
	"d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a": "RFC 8032 §7.1 Test 1",
}

// ErrNoReleaseKey says this build cannot verify a release.
var ErrNoReleaseKey = fmt.Errorf("no release signing key is compiled into this build, so no update can be verified")

// DefaultTrustAnchor returns the key this build verifies releases against.
//
// It refuses rather than falling back. A fallback here is indistinguishable from
// a working configuration right up to the moment somebody signs something.
func DefaultTrustAnchor() (*TrustAnchor, error) {
	hexKey := strings.TrimSpace(os.Getenv("UPDATE_TRUST_PUBKEY_HEX"))
	if hexKey == "" {
		hexKey = strings.TrimSpace(CompiledReleasePublicKeyHex)
	}
	if hexKey == "" {
		return nil, ErrNoReleaseKey
	}
	if which, published := publishedTestKeys[strings.ToLower(hexKey)]; published {
		return nil, fmt.Errorf(
			"the release signing key for this build is %s, a published test vector whose "+
				"private key anybody can read — an update signed by anyone at all would verify "+
				"against it. Supply a real release key", which)
	}
	raw, err := hex.DecodeString(hexKey)
	if err != nil {
		return nil, fmt.Errorf("the release signing key is not hex: %w", err)
	}
	if len(raw) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("a release signing key is %d bytes, got %d",
			ed25519.PublicKeySize, len(raw))
	}
	return NewTrustAnchor(map[string][]byte{
		DefaultSigningKeyID: raw,
	})
}

// TestTrustAnchor returns a deterministic test keypair for golden vectors.
func TestTrustAnchor() (*TrustAnchor, ed25519.PrivateKey, ed25519.PublicKey) {
	seed := make([]byte, ed25519.SeedSize)
	for i := range seed {
		seed[i] = byte(i + 1)
	}
	priv := ed25519.NewKeyFromSeed(seed)
	pub := priv.Public().(ed25519.PublicKey)
	ta, _ := NewTrustAnchor(map[string][]byte{
		"grape-release-test": pub,
	})
	return ta, priv, pub
}
