package drivers

import (
	"crypto/ed25519"
	"crypto/rand"
	"testing"

	"identity-agent-core/iacrypto"
)

// A witness is designated when its key is in the list. A name that is no
// witness identifier designates no one, itself included, so two equal strings
// are not one witness merely for being equal.
func TestAWitnessIsDesignatedByItsKeyAndANameThatIsNoWitnessByNothing(t *testing.T) {
	pubA, _, _ := ed25519.GenerateKey(rand.Reader)
	pubB, _, _ := ed25519.GenerateKey(rand.Reader)
	a, b := iacrypto.NonTransferableAIDQB64(pubA), iacrypto.NonTransferableAIDQB64(pubB)
	if !Designates([]string{b, a}, a) {
		t.Fatal("a witness in the list was not designated")
	}
	if Designates([]string{b}, a) {
		t.Fatal("a witness not in the list was designated")
	}
	if Designates(nil, a) {
		t.Fatal("an empty list designated a witness")
	}
	for _, junk := range []string{"", "BW1", "not-a-witness", "EA"} {
		if Designates([]string{junk}, junk) {
			t.Fatalf("%q, which is no witness identifier, designated itself", junk)
		}
	}
}
