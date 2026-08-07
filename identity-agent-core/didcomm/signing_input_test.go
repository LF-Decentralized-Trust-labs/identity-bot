package didcomm

import (
	"bytes"
	"testing"
)

// Two different key sets must never produce the same signing input. A
// delimiter-separated construction fails this the moment a field can contain
// the delimiter, and AID and Suite have no enforced character set — so a
// signature over one set of keys would verify over another.
func TestNoTwoKeySetsShareSigningInput(t *testing.T) {
	cases := []struct {
		name string
		a, b DID
	}{
		{
			"a newline in the AID cannot absorb the next field",
			DID{AID: "EONE\nkeymaterial", Ed: "REAL", Dsa: "d", X25519: "x", MlKem: "m", Suite: "s"},
			DID{AID: "EONE", Ed: "keymaterial\nREAL", Dsa: "d", X25519: "x", MlKem: "m", Suite: "s"},
		},
		{
			"a field boundary cannot be moved",
			DID{AID: "AB", Ed: "CD", Dsa: "d", X25519: "x", MlKem: "m", Suite: "s"},
			DID{AID: "A", Ed: "BCD", Dsa: "d", X25519: "x", MlKem: "m", Suite: "s"},
		},
		{
			"an empty field is distinguishable from an absent one",
			DID{AID: "E1", Ed: "", Dsa: "d", X25519: "x", MlKem: "m", Suite: "s"},
			DID{AID: "E1", Ed: "d", Dsa: "", X25519: "x", MlKem: "m", Suite: "s"},
		},
	}
	for _, c := range cases {
		if bytes.Equal(c.a.SigningInput(), c.b.SigningInput()) {
			t.Errorf("%s: two different key sets produced identical signing input, so a "+
				"signature over one verifies over the other", c.name)
		}
	}
}

// The same keys must always produce the same bytes, or nothing verifies twice.
func TestSigningInputIsStable(t *testing.T) {
	d := DID{AID: "EABC", Ed: "e", Dsa: "d", X25519: "x", MlKem: "m", Suite: CipherSuite}
	if !bytes.Equal(d.SigningInput(), d.SigningInput()) {
		t.Fatal("signing input is not stable across calls")
	}
	// The signature itself is not covered — it cannot be, since it is the output.
	signed := d
	signed.KelSig = "a-signature"
	if !bytes.Equal(d.SigningInput(), signed.SigningInput()) {
		t.Error("the signature field changed the signing input, so it can never verify")
	}
}
