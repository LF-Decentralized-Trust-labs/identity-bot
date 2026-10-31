package update

import (
	"crypto/ed25519"
	"encoding/hex"
	"strings"
	"testing"
)

// The release key is read in lowercase hex, the case it is written in. An
// uppercase copy of a published test key also slipped past the check that
// refuses those, which compared after lowercasing.
func TestAnUppercaseReleaseKeyIsRefused(t *testing.T) {
	pub, _, _ := ed25519.GenerateKey(nil)
	upper := strings.ToUpper(hex.EncodeToString(pub))
	if upper == hex.EncodeToString(pub) {
		t.Skip("this key has no hex letters")
	}
	t.Setenv("UPDATE_TRUST_PUBKEY_HEX", upper)
	if _, err := DefaultTrustAnchor(); err == nil {
		t.Fatal("an uppercase release key was accepted")
	}
}
