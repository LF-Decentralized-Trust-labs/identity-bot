package update

import (
	"crypto/ed25519"
	"encoding/hex"
	"os"
)

// DefaultSigningKeyID is the compiled-in release key identifier.
const DefaultSigningKeyID = "grape-release-2026"

// CompiledReleasePublicKeyHex is the trust anchor compiled into the binary at build time.
// Override via UPDATE_TRUST_PUBKEY_HEX env for development/testing.
var CompiledReleasePublicKeyHex = "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a"

func DefaultTrustAnchor() (*TrustAnchor, error) {
	hexKey := os.Getenv("UPDATE_TRUST_PUBKEY_HEX")
	if hexKey == "" {
		hexKey = CompiledReleasePublicKeyHex
	}
	raw, err := hex.DecodeString(hexKey)
	if err != nil {
		return nil, err
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