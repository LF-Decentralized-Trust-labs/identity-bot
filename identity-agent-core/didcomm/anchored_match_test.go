package didcomm

import (
	"crypto/rand"
	"testing"
)

func rawKeys(t *testing.T) (x, kem []byte) {
	t.Helper()
	x, kem = make([]byte, 32), make([]byte, 1184)
	if _, err := rand.Read(x); err != nil {
		t.Fatal(err)
	}
	if _, err := rand.Read(kem); err != nil {
		t.Fatal(err)
	}
	return x, kem
}

// The point of the whole exercise: keys that an identifier did not commit to
// must be refused, however well-formed they are.
func TestKeysTheIdentifierDidNotCommitToAreRefused(t *testing.T) {
	x, kem := rawKeys(t)
	good := DID{AID: "EBOX", X25519: b64.EncodeToString(x), MlKem: b64.EncodeToString(kem)}
	if err := good.MatchesAnchoredKeys(x, kem); err != nil {
		t.Fatalf("the committed keys were rejected: %v", err)
	}

	substituteX, substituteKem := rawKeys(t)

	// What an attacker terminating the connection actually does: serve their
	// own keys for a real identifier.
	attacker := DID{AID: "EBOX",
		X25519: b64.EncodeToString(substituteX),
		MlKem:  b64.EncodeToString(substituteKem)}
	if err := attacker.MatchesAnchoredKeys(x, kem); err == nil {
		t.Error("substituted keys were accepted for a committed identifier")
	}

	// Half a substitution is still a substitution — anything they can decrypt
	// is a break, and the two keys are combined.
	halfX := DID{AID: "EBOX", X25519: b64.EncodeToString(substituteX), MlKem: b64.EncodeToString(kem)}
	if err := halfX.MatchesAnchoredKeys(x, kem); err == nil {
		t.Error("a substituted agreement key was accepted because the other one matched")
	}
	halfKem := DID{AID: "EBOX", X25519: b64.EncodeToString(x), MlKem: b64.EncodeToString(substituteKem)}
	if err := halfKem.MatchesAnchoredKeys(x, kem); err == nil {
		t.Error("a substituted encapsulation key was accepted because the other one matched")
	}
}

// An empty or malformed offering must fail rather than compare as equal to
// something.
func TestAMalformedOfferingIsRefused(t *testing.T) {
	x, kem := rawKeys(t)
	for _, d := range []DID{
		{AID: "EBOX"},
		{AID: "EBOX", X25519: "!!!not base64!!!", MlKem: b64.EncodeToString(kem)},
		{AID: "EBOX", X25519: b64.EncodeToString(x), MlKem: "!!!"},
		{AID: "EBOX", X25519: b64.EncodeToString(x[:16]), MlKem: b64.EncodeToString(kem)},
	} {
		if err := d.MatchesAnchoredKeys(x, kem); err == nil {
			t.Errorf("a malformed offering was accepted: %+v", d.X25519)
		}
	}
}
