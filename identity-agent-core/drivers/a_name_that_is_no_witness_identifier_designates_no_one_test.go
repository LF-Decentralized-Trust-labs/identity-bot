package drivers

import (
	"crypto/ed25519"
	"crypto/rand"
	"testing"

	"identity-agent-core/iacrypto"
)

// Designates matches by the key a witness identifier is made of. A name that is
// not a witness identifier is designated by no list, not even one that holds
// that very string: a string compare would count it, and so would stand a
// witness down for a cut of it or keep a receipt it signed.
func TestANameThatIsNoWitnessIdentifierIsDesignatedByNoList(t *testing.T) {
	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	real := iacrypto.NonTransferableAIDQB64(pub)
	for _, name := range []string{
		"", "BNotAWitnessKey0123456789ABCDEFGHIJKLMNOPQR", "Dnot-a-non-transferable-code", real + "A", real[:len(real)-1],
	} {
		if _, ok := WitnessKey(name); ok {
			t.Fatalf("%q was read as a witness identifier", name)
		}
		if Designates([]string{name, real}, name) {
			t.Fatalf("%q, which is no witness identifier, was designated by a list holding that string", name)
		}
	}
	if !Designates([]string{"BNotAWitnessKey0123456789ABCDEFGHIJKLMNOPQR", real}, real) {
		t.Fatal("a witness the list holds was not designated")
	}
	if Designates(nil, real) {
		t.Fatal("an empty list designated a witness")
	}
}
