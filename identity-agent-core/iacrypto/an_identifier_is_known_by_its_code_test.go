package iacrypto

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"strings"
	"testing"
)

// An identifier is told by its CESR code and the length that code carries:
// a self-addressing or Ed25519 one is 44 characters, a machine's P-256 one
// 48, and a word is none.
func TestAnIdentifierIsKnownByItsCode(t *testing.T) {
	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	ed := NonTransferableAIDQB64(pub)
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	machine, err := MachineAIDQB64(elliptic.Marshal(elliptic.P256(), key.X, key.Y))
	if err != nil {
		t.Fatal(err)
	}
	self := "E" + ed[1:]
	for s, want := range map[string]bool{
		self:                          true,
		ed:                            true,
		machine:                       true,
		"apps":                        false,
		"login":                       false,
		"":                            false,
		self[:43]:                     false,
		machine[:47]:                  false,
		"1AAI" + self[1:]:             false,
		"E" + strings.Repeat("!", 43): false,
		"X" + self[1:]:                false,
	} {
		if got := IsIdentifierQB64(s); got != want {
			t.Errorf("%q (%d characters) is an identifier: %v, want %v", s, len(s), got, want)
		}
	}
	if len(machine) != 48 || len(self) != 44 {
		t.Fatalf("lengths: machine %d, self-addressing %d", len(machine), len(self))
	}
}
